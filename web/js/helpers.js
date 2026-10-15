// --- HELPER FUNCTIONS ---
function escapeHtml(text) {
    if (text == null) return '';
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Human-readable message from anything that can be thrown/rejected.
function errMsg(e) {
    return (e && e.message) ? e.message : String(e);
}

// --- API LAYER ---
// fetch() only rejects on network failure; a 4xx/5xx resolves normally, so
// callers that skip the resp.ok check treat a server error as success (or
// crash later in .json()). apiFetch() turns any non-2xx into a thrown Error
// whose message carries the server's `{error: "..."}` JSON field or plain
// body text, so one try/catch at the call site covers both failure modes.
async function apiFetch(url, opts) {
    const resp = await fetch(url, opts);
    if (!resp.ok) {
        let detail = '';
        try {
            const text = (await resp.text()).trim();
            try {
                const j = JSON.parse(text);
                detail = (j && j.error) ? String(j.error) : text;
            } catch (_) {
                detail = text;
            }
        } catch (_) { /* unreadable body — status alone is enough */ }
        throw new Error(`HTTP ${resp.status}${detail ? ': ' + detail.slice(0, 200) : ''}`);
    }
    return resp;
}

async function apiJSON(url, opts) {
    return (await apiFetch(url, opts)).json();
}

// --- TOASTS ---
// Non-blocking replacement for alert(): self-contained (no CSS dependency in
// dashboard.html), uses textContent so message text is never parsed as HTML.
function showToast(message, type = 'info', durationMs = 4500) {
    const colors = { error: '#EF4444', success: '#10B981', warn: '#F59E0B', info: '#3B82F6' };
    const color = colors[type] || colors.info;

    let host = document.getElementById('dorm-toast-host');
    if (!host) {
        host = document.createElement('div');
        host.id = 'dorm-toast-host';
        host.style.cssText = 'position:fixed; top:16px; right:16px; z-index:100000; display:flex; flex-direction:column; gap:8px; max-width:380px; pointer-events:none;';
        document.body.appendChild(host);
    }

    const toast = document.createElement('div');
    toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
    toast.style.cssText = `pointer-events:auto; cursor:pointer; background:#161B22; color:#E6EDF3; border:1px solid rgba(255,255,255,0.1); border-left:3px solid ${color}; border-radius:6px; padding:10px 14px; font-size:13px; line-height:1.5; box-shadow:0 6px 20px rgba(0,0,0,0.45); white-space:pre-wrap; word-break:break-word;`;
    toast.textContent = message;
    toast.onclick = () => toast.remove();
    host.appendChild(toast);
    setTimeout(() => toast.remove(), durationMs);
}

// --- BATCHED REDRAWS ---
// Chart.update() / tab-bar rebuilds are expensive; a live scan can emit
// dozens of findings per second. Coalesce them to at most one per ~60ms.
// Deliberately setTimeout, not requestAnimationFrame: rAF is suspended while
// the tab is hidden, so a scan that finished in a background tab would leave
// the chart and target tabs stale until the user switched back.
const _queuedRedraws = new Set();
function queueRedraw(key, fn) {
    if (_queuedRedraws.has(key)) return;
    _queuedRedraws.add(key);
    setTimeout(() => {
        _queuedRedraws.delete(key);
        fn();
    }, 60);
}

// --- VULNERABILITY ROW RENDERING (shared by live scan + archived scan view) ---
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

// The /scan SSE stream interleaves findings with control/keep-alive frames
// ({"Status":"CRAWLING_DOM"} every 3s during the DOM pre-scan, plus any
// status type added later). A real finding always carries Name and/or
// Severity (the plugin contract); control frames carry neither. Don't key off
// `Status` — models.Vulnerability has that field too (always empty today, but
// not a safe discriminator). Anything that is not a finding must be skipped,
// never rendered as an "Unnamed finding" row.
function isFinding(data) {
    return !!data && typeof data === 'object' && !!(data.Name || data.Severity);
}

// Normalizes one finding coming off the wire. Any field a plugin forgot to
// set must degrade to a sane default instead of throwing — one bad finding
// used to abort the whole SSE handler (TypeError on `.toUpperCase()`).
function normalizeFinding(data) {
    const target = data.Target || {};
    const name = String(data.Name || 'Unnamed finding');
    const severity = String(data.Severity || 'INFO').toUpperCase();
    return {
        name,
        severity,
        severityIndex: SEVERITY_ORDER.indexOf(severity),
        cvss: Number.isFinite(Number(data.CVSS)) ? Number(data.CVSS) : 0,
        host: String(target.IP || 'unknown'),
        port: target.Port != null ? target.Port : '',
        description: data.Description,
        solution: data.Solution,
        reference: data.Reference,
        engine: name.includes('Exploit') ? 'EDB' : (name.includes('Spider') ? 'Spider' : 'Plugin')
    };
}

// Builds the summary <tr> + hidden detail <tr> pair for one finding.
// `rowId`/`detailId` are the element ids; `onclickAttr` is the full inline
// handler string for the summary row (callers differ in toggleDetail args).
function buildVulnRowHTML(f, rowId, detailId, onclickAttr) {
    const sev = escapeHtml(f.severity);
    const host = escapeHtml(f.host);
    return `
            <tr class="vuln-row" data-severity="${sev}" data-target="${host}" id="${rowId}" onclick="${onclickAttr}">
                <td><span class="badge sev-${sev}">${sev}</span></td>
                <td style="font-weight:bold; color:#fff;">${f.cvss.toFixed(1)}</td>
                <td style="color:#fff;">${escapeHtml(f.name)}</td>
                <td style="color:var(--text-dim); font-size:0.9em;">${f.engine}</td>
                <td>${host}:${escapeHtml(f.port)}</td>
                <td class="arrow"><i class="fas fa-chevron-down"></i></td>
            </tr>
            <tr class="detail-row" data-severity="${sev}" data-target="${host}" id="${detailId}">
                <td colspan="6" style="padding:0; border:none;">
                    <div class="detail-content">
                        <strong style="color:var(--accent)">ANALYSIS:</strong><br>${escapeHtml(f.description).replace(/\n/g, '<br>')}<br><br>
                        <strong style="color:var(--success)">SOLUTION:</strong><br>${escapeHtml(f.solution || "Apply patches.")}<br><br>
                        <em style="font-size:0.8em">Ref: ${escapeHtml(f.reference)}</em>
                    </div>
                </td>
            </tr>`;
}

function toggleAuth() {
    const el = document.getElementById('authContainer');
    const arrow = document.getElementById('authArrow');
    if (el.style.display === 'block') {
        el.style.display = 'none';
        arrow.classList.replace('fa-chevron-down', 'fa-chevron-right');
    } else {
        el.style.display = 'block';
        arrow.classList.replace('fa-chevron-right', 'fa-chevron-down');
    }
}

function toggleDetail(detailId, parentId) {
    // If only one arg passed, it's the old scanner logic where id is a number
    if (parentId === undefined) {
        parentId = 'row-' + detailId;
        detailId = 'detail-' + detailId;
    }
    const row = document.getElementById(detailId);
    const parent = document.getElementById(parentId);
    if (!row || !parent) return;
    if (row.style.display === 'table-row') {
        row.style.display = 'none';
        parent.classList.remove('open');
    } else {
        row.style.display = 'table-row';
        parent.classList.add('open');
    }
}
