#!/usr/bin/env bash
# Nightly scan-regression lab: three targets on an internal Docker network
# (Juice Shop, DVWA, a clean nginx control) and DORM in its own container.
# DORM is set up while it still has internet (Chromium, build, CVE sync),
# then moved onto the internal network only, so no payload of the scan can
# reach a host that is not a lab target.
#
#   .github/scanregress/lab.sh            compare with baseline.json
#   .github/scanregress/lab.sh -record    write a candidate baseline
#
# Writes findings.json, dorm.log and scan-summary.md into the repo root.
# SRC overrides the host path mounted as the repo (e.g. a Windows path).
set -euo pipefail

SRC=${SRC:-$PWD}
NET=dormlab

# DORM writes its scan history to dorm_engine.db in the working directory.
# On a developer's own checkout that is their real history: run the lab
# from a fresh clone instead (CI always starts from one).
if [ -z "${CI:-}" ] && [ -f "$SRC/dorm_engine.db" ]; then
  echo "lab.sh: $SRC/dorm_engine.db exists; the lab scan would be added to that history. Run it from a fresh clone." >&2
  exit 1
fi
GO_IMAGE=golang:1.27.3-bookworm # keep in step with go.mod
JUICE=bkimminich/juice-shop:v20.3.0@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27
DVWA=vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7
CLEAN=nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60
TARGETS=juiceshop=172.30.0.10:3000,dvwa=172.30.0.11:80,clean=172.30.0.12:80

docker rm -f juiceshop dvwa clean dorm >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --internal --subnet 172.30.0.0/24 "$NET" >/dev/null

# Under a full scan Juice Shop's Node heap grows until it dies (seen at 2 GB
# and at 4 GB, a few minutes in); it restarts so the rest of the scan still
# reaches it, and the workflow's survival check flags the run.
docker run -d --name juiceshop --network "$NET" --ip 172.30.0.10 --restart on-failure \
  -e NODE_OPTIONS=--max-old-space-size=4096 "$JUICE" >/dev/null
docker run -d --name dvwa --network "$NET" --ip 172.30.0.11 "$DVWA" >/dev/null
docker run -d --name clean --network "$NET" --ip 172.30.0.12 "$CLEAN" >/dev/null

echo "== DORM setup (online)"
docker run -d --name dorm -v "$SRC:/src" -w /src "$GO_IMAGE" sleep infinity >/dev/null
docker exec dorm sh -c 'apt-get update -qq && apt-get install -y -qq chromium >/dev/null 2>&1 && chromium --version'
docker exec dorm go build -o /usr/local/bin/dorm .
docker exec dorm go build -o /usr/local/bin/scanregress .github/scanregress/main.go
docker exec -d dorm sh -c 'dorm > /src/dorm.log 2>&1'
# DORM serves HTTP only after the CVE database is loaded.
docker exec dorm sh -c 'for i in $(seq 1 180); do curl -sf -o /dev/null http://127.0.0.1:8080/plugins && exit 0; sleep 5; done; echo "::error::DORM never came up"; tail -30 /src/dorm.log; exit 1'

echo "== cutting DORM off the internet"
docker network connect --ip 172.30.0.200 "$NET" dorm
docker network disconnect bridge dorm
if docker exec dorm curl -s -m 5 -o /dev/null https://github.com; then
  echo "::error::DORM container still reaches the internet; refusing to scan"
  exit 1
fi

for spec in ${TARGETS//,/ }; do
  addr=${spec#*=}
  docker exec dorm sh -c "for i in \$(seq 1 60); do curl -s -o /dev/null http://$addr/ && exit 0; sleep 3; done; exit 1" \
    || { echo "::error::target $spec never came up"; exit 1; }
  echo "target ready: $spec"
done

echo "== scan"
docker exec -e GITHUB_STEP_SUMMARY=/src/scan-summary.md dorm \
  scanregress -targets "$TARGETS" -out /src/findings.json "$@"
