import re
import os

errors_text = """
  Error: plugins/bfla_bola.go:196:22: Error return value of `respBase.Body.Close` is not checked (errcheck)
  Error: plugins/blindrce.go:146:22: Error return value of `resp2.Body.Close` is not checked (errcheck)
  Error: plugins/blindrce.go:218:23: Error return value of `resp2.Body.Close` is not checked (errcheck)
  Error: plugins/bruteforce.go:300:18: Error return value of `conn.SetDeadline` is not checked (errcheck)
  Error: plugins/bruteforce.go:303:12: Error return value of `conn.Close` is not checked (errcheck)
  Error: plugins/bypass403.go:87:27: Error return value of `respHeader.Body.Close` is not checked (errcheck)
  Error: plugins/bypass403.go:98:26: Error return value of `respHeader.Body.Close` is not checked (errcheck)
  Error: plugins/bypass403.go:108:25: Error return value of `respPath.Body.Close` is not checked (errcheck)
  Error: plugins/bypass403.go:119:24: Error return value of `respPath.Body.Close` is not checked (errcheck)
  Error: plugins/codeigniter.go:31:22: Error return value of `probeResp.Body.Close` is not checked (errcheck)
  Error: plugins/codeigniter.go:45:22: Error return value of `idxResp.Body.Close` is not checked (errcheck)
  Error: plugins/codeigniter.go:69:21: Error return value of `errResp.Body.Close` is not checked (errcheck)
  Error: plugins/codeigniter.go:94:21: Error return value of `dbResp.Body.Close` is not checked (errcheck)
  Error: plugins/codeigniter.go:114:22: Error return value of `cfgResp.Body.Close` is not checked (errcheck)
  Error: plugins/codeigniter.go:134:22: Error return value of `dirResp.Body.Close` is not checked (errcheck)
  Error: plugins/codeigniter.go:154:21: Error return value of `ppResp.Body.Close` is not checked (errcheck)
  Error: plugins/codeigniter.go:197:24: Error return value of `sparkResp.Body.Close` is not checked (errcheck)
  Error: plugins/configjson.go:24:18: Error return value of `resp.Body.Read` is not checked (errcheck)
  Error: plugins/corscheck.go:99:25: Error return value of `respOpts.Body.Close` is not checked (errcheck)
  Error: plugins/crlf.go:121:28: Error return value of `respXSS.Body.Close` is not checked (errcheck)
  Error: plugins/dangerousmethods.go:25:31: Error return value of `respOptions.Body.Close` is not checked (errcheck)
  Error: plugins/dangerousmethods.go:52:20: Error return value of `respPut.Body.Close` is not checked (errcheck)
  Error: plugins/dangerousmethods.go:60:28: Error return value of `respGet.Body.Close` is not checked (errcheck)
  Error: plugins/dangerousmethods.go:68:26: Error return value of `(*net/http.Client).Do` is not checked (errcheck)
  Error: plugins/dirbuster.go:59:13: Error return value of `f.Close` is not checked (errcheck)
  Error: plugins/django.go:30:23: Error return value of `adminResp.Body.Close` is not checked (errcheck)
  Error: plugins/django.go:41:23: Error return value of `randResp.Body.Close` is not checked (errcheck)
  Error: plugins/django.go:67:21: Error return value of `errResp.Body.Close` is not checked (errcheck)
  Error: plugins/django.go:96:19: Error return value of `aResp.Body.Close` is not checked (errcheck)
  Error: plugins/django.go:112:20: Error return value of `dtResp.Body.Close` is not checked (errcheck)
  Error: plugins/django.go:128:21: Error return value of `apiResp.Body.Close` is not checked (errcheck)
  Error: plugins/django.go:146:20: Error return value of `sResp.Body.Close` is not checked (errcheck)
  Error: plugins/django.go:164:24: Error return value of `staticResp.Body.Close` is not checked (errcheck)
  Error: plugins/dockerregistry.go:21:17: Error return value of `resp.Body.Read` is not checked (errcheck)
  Error: plugins/edb.go:25:18: Error return value of `conn.Close` is not checked (errcheck)
  Error: plugins/edb.go:28:14: Error return value of `fmt.Fprintf` is not checked (errcheck)
  Error: plugins/edb.go:31:22: Error return value of `conn.SetReadDeadline` is not checked (errcheck)
  Error: plugins/elastic.go:21:17: Error return value of `resp.Body.Read` is not checked (errcheck)
  Error: plugins/expressjs.go:28:22: Error return value of `probeResp.Body.Close` is not checked (errcheck)
  Error: plugins/expressjs.go:67:21: Error return value of `pkgResp.Body.Close` is not checked (errcheck)
  Error: plugins/expressjs.go:85:20: Error return value of `lResp.Body.Close` is not checked (errcheck)
  Error: plugins/expressjs.go:103:20: Error return value of `nmResp.Body.Close` is not checked (errcheck)
  Error: plugins/expressjs.go:119:21: Error return value of `envResp.Body.Close` is not checked (errcheck)
  Error: plugins/sqliengine/plugin.go:189:23: Error return value of `baseResp.Body.Close` is not checked (errcheck)
  Error: plugins/sqliengine/time_based.go:25:22: Error return value of `baseResp.Body.Close` is not checked (errcheck)
  Error: plugins/wafengine/behavior_probe.go:24:21: Error return value of `baseResp.Body.Close` is not checked (errcheck)
  Error: plugins/wafengine/behavior_probe.go:77:18: Error return value of `resp.Body.Close` is not checked (errcheck)
  Error: plugins/wafengine/cdn_detector.go:127:23: Error return value of `resp.Body.Close` is not checked (errcheck)
  Error: plugins/wafengine/header_analyzer.go:22:23: Error return value of `resp.Body.Close` is not checked (errcheck)
  Error: sci/sci.go:327:20: Error return value of `resp2.Body.Close` is not checked (errcheck)
"""

files_to_lines = {}
for line in errors_text.strip().split('\n'):
    m = re.match(r'^\s*Error: ([^:]+):(\d+):\d+: Error return value of `([^`]+)` is not checked \(errcheck\)', line)
    if m:
        filepath = m.group(1)
        lineno = int(m.group(2))
        files_to_lines.setdefault(filepath, set()).add(lineno)

for filepath, linenos in files_to_lines.items():
    if not os.path.exists(filepath):
        print(f'File not found: {filepath}')
        continue
    
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    changed = False
    for lineno in linenos:
        idx = lineno - 1
        orig = lines[idx]
        
        # Check what the call is
        if 'defer ' in orig:
            lines[idx] = orig.replace('defer ', 'defer func() { _ = ')
            if lines[idx].endswith(')\n'):
                lines[idx] = lines[idx].replace(')\n', ') }()\n')
            elif lines[idx].endswith(')\r\n'):
                lines[idx] = lines[idx].replace(')\r\n', ') }()\r\n')
            changed = True
        else:
            # Just add _ = 
            match = re.search(r'^(\s*)(.+)', orig)
            if match:
                indent = match.group(1)
                code = match.group(2)
                if code.startswith('models.GetClient().Do'):
                    lines[idx] = indent + '_, _ = ' + code + '\n'
                elif '.Read(' in code:
                    lines[idx] = indent + '_, _ = ' + code + '\n'
                elif 'fmt.Fprintf(' in code:
                    lines[idx] = indent + '_, _ = ' + code + '\n'
                else:
                    lines[idx] = indent + '_ = ' + code + '\n'
                changed = True
                
    if changed:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        print(f'Fixed errchecks in {filepath}')
