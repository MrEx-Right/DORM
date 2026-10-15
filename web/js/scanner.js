// --- TARGET EDITOR LINE NUMBERS ---
// Keeps the #targetLineNumbers gutter in sync with #targetInput's line count
// and scroll position, so the multi-target textarea reads like a code/terminal
// list rather than a plain prose text box.
function syncTargetLineNumbers() {
    const ta = document.getElementById('targetInput');
    const gutter = document.getElementById('targetLineNumbers');
    if (!ta || !gutter) return;
    const lineCount = ta.value.split('\n').length;
    let numbers = '';
    for (let i = 1; i <= lineCount; i++) numbers += i + '\n';
    gutter.textContent = numbers;
    gutter.scrollTop = ta.scrollTop;
}

function initTargetLineNumbers() {
    const ta = document.getElementById('targetInput');
    if (!ta) return;
    ta.addEventListener('input', syncTargetLineNumbers);
    ta.addEventListener('scroll', syncTargetLineNumbers);
    syncTargetLineNumbers();
}

// --- SCANNER LOGIC ---
function startScan() {
    // 1. Get raw input from textarea
    const rawTargets = document.getElementById('targetInput').value;
    const btn = document.getElementById('scanBtn');

    // STOP LOGIC: If button is red (STOP mode), halt the scan.
    if (btn.classList.contains('btn-danger')) {
        stopScan();
        return;
    }

    const authHeader = document.getElementById('authInput').value;

    // --- WAF SETTINGS ---
    const wafDelay = document.getElementById('wafDelayInput') ? document.getElementById('wafDelayInput').value : "0";
    const wafJitter = document.getElementById('wafJitterInput') ? document.getElementById('wafJitterInput').value : "0";
    const wafNullByte = document.getElementById('wafNullByteToggle') ? document.getElementById('wafNullByteToggle').checked : false;
    const wafUEP = document.getElementById('wafUEPToggle') ? document.getElementById('wafUEPToggle').checked : false;
    const wafTLS = document.getElementById('wafTLSToggle') ? document.getElementById('wafTLSToggle').checked : false;
    const wafCaseAlt = document.getElementById('wafCaseAltToggle') ? document.getElementById('wafCaseAltToggle').checked : false;
    const wafHPP = document.getElementById('wafHPPToggle') ? document.getElementById('wafHPPToggle').checked : false;

    // 2. Get selected plugins from grid
    const selected = Array.from(document.querySelectorAll('.plugin-check:checked')).map(c => c.value);

    // 3. MULTI-TARGET LOGIC: Split by newline, trim, and remove empty lines
    const targetsArray = rawTargets.split('\n').map(t => t.trim()).filter(t => t !== '');
    if (targetsArray.length === 0) return showToast("Please enter at least one target!", 'warn');

    // Join multiple targets with a comma to send via GET request
    const targetString = targetsArray.join(',');

    document.getElementById('tableBody').innerHTML = '';
    vulnCount = 0; scanResults = [];
    vulnChart.data.datasets[0].data = [0, 0, 0, 0, 0];
    vulnChart.update();
    liveTargetFilter = 'ALL';
    liveTargetCounts = {};
    renderTargetTabs('targetTabs', liveTargetCounts, liveTargetFilter, selectLiveTarget);

    // Reset DOM Crawler feed on new scan
    if (typeof clearDOMFeed === 'function') {
        clearDOMFeed();
    }



    // UI: Switch to STOP SCAN Mode
    btn.innerHTML = '<i class="fas fa-stop"></i> STOP SCAN';
    btn.classList.remove('btn-success');
    btn.classList.add('btn-danger');
    btn.style.backgroundColor = '#da3633';

    timerSeconds = 0; clearInterval(timerInterval);
    timerInterval = setInterval(() => {
        timerSeconds++;
        const m = Math.floor(timerSeconds / 60).toString().padStart(2, '0');
        const s = (timerSeconds % 60).toString().padStart(2, '0');
        document.getElementById('timerDisplay').innerText = `${m}:${s}`;
    }, 1000);

    // Get Proxy URL and state from the Proxy Settings view
    const proxyEnabled = document.getElementById('proxyToggle').checked;
    const proxyUrl = document.getElementById('proxyUrlInput').value || "http://127.0.0.1:8081";

    const cveRadar = false; // Toggle was removed from UI

    // Assign to global variable (Notice: query param is now "targets")
    scanEventSource = new EventSource(`/scan?targets=${encodeURIComponent(targetString)}&plugins=${encodeURIComponent(selected.join(","))}&auth=${encodeURIComponent(authHeader)}&proxyEnabled=${proxyEnabled}&proxyUrl=${encodeURIComponent(proxyUrl)}&wafDelay=${wafDelay}&wafJitter=${wafJitter}&wafNullByte=${wafNullByte}&wafUEP=${wafUEP}&wafTLS=${wafTLS}&wafCaseAlt=${wafCaseAlt}&wafHPP=${wafHPP}`);

    scanEventSource.onmessage = (e) => {
        let data;
        try {
            data = JSON.parse(e.data);
        } catch (err) {
            console.error("Malformed SSE frame, skipped:", e.data, err);
            return;
        }

        if (data.Status === "STARTED") {
            if (data.ScanID) {
                window.currentSitemapScanID = data.ScanID;
            }
            return;
        }

        if (data.Status === "DONE") {
            if (data.ScanID) {
                window.currentSitemapScanID = data.ScanID; // Save latest scan ID
            }
            if (sitemapPollInterval) {
                clearInterval(sitemapPollInterval);
                sitemapPollInterval = null;
                // do one last refresh
                if (typeof refreshSitemapSilently === 'function') refreshSitemapSilently();
            }
            finishScanUI(); // Reset UI
            return;
        }

        if (data.Status === "ERROR") {
            showToast("Scan Error: " + data.Message, 'error', 8000);
            finishScanUI(); // Reset UI immediately on error
            if (sitemapPollInterval) {
                clearInterval(sitemapPollInterval);
                sitemapPollInterval = null;
            }
            return;
        }

        // Keep-alive / control frames (e.g. CRAWLING_DOM) are not findings.
        if (!isFinding(data)) return;

        const f = normalizeFinding(data);
        vulnCount++; scanResults.push(data);

        document.getElementById('tableBody').insertAdjacentHTML('beforeend',
            buildVulnRowHTML(f, `row-${vulnCount}`, `detail-${vulnCount}`, `toggleDetail(${vulnCount})`));

        liveTargetCounts[f.host] = (liveTargetCounts[f.host] || 0) + 1;
        queueRedraw('live-target-tabs', () =>
            renderTargetTabs('targetTabs', liveTargetCounts, liveTargetFilter, selectLiveTarget));
        // Only fold the freshly-inserted row into the current filter — a
        // full applyResultFilters() pass would collapse any detail panel
        // the user already has open while the scan is still streaming.
        const newRow = document.getElementById('row-' + vulnCount);
        if (newRow && !isRowVisible(newRow, vulnChart, liveTargetFilter)) {
            newRow.style.display = 'none';
        }

        if (f.severityIndex !== -1) {
            vulnChart.data.datasets[0].data[f.severityIndex]++;
            queueRedraw('live-chart', () => vulnChart.update());
        }
    };

    scanEventSource.onerror = (err) => {
        console.error("SSE Connection Error:", err);
        // /scan is a GET that STARTS a scan, so the browser's automatic
        // EventSource reconnect is never a resume: the reconnect is a brand-new
        // /scan request, and the server cancels the scan that is still running
        // (handleScan -> activeScanCancel) and starts over — duplicated results,
        // a half-finished "Stopped" history record. So any error is final here:
        // close the stream ourselves (CLOSED = the browser already gave up;
        // CONNECTING = it was about to reconnect) and reset the UI. The server
        // keeps scanning to the end on its own context; results land in History.
        if (scanEventSource) {
            showToast("Lost connection to the scanner. The scan may still be finishing on the server — check Scan History.", 'error', 10000);
            finishScanUI();
        }
    };
}

// NEW: STOP SCAN FUNCTION
async function stopScan() {
    try {
        await apiFetch('/stop'); // Send signal to backend
    } catch (e) {
        // Still tear the UI down below — a dead backend must not leave the
        // button stuck on STOP — but tell the user the stop may not have landed.
        showToast("Could not confirm the scan was stopped: " + errMsg(e), 'warn', 8000);
    }

    if (scanEventSource) {
        scanEventSource.close(); // Cut the connection
        scanEventSource = null;
    }

    finishScanUI(); // Revert button

    document.getElementById('tableBody').insertAdjacentHTML('beforeend',
        '<tr><td colspan="6" style="text-align:center; color:#da3633; font-weight:bold; padding:20px;">⛔ SCAN ABORTED BY USER</td></tr>');
}

// NEW: UI RESET HELPER
function finishScanUI() {
    clearInterval(timerInterval);

    const btn = document.getElementById('scanBtn');

    if (scanEventSource) {
        scanEventSource.close();
        scanEventSource = null;
    }

    // Ensure DOM crawler pulse is turned off
    const pulse = document.getElementById('dom-nav-pulse');
    if (pulse) pulse.style.display = 'none';
    setDOMStatus('IDLE', '#94A3B8', 'rgba(148,163,184,0.1)', 'rgba(148,163,184,0.2)');

    // Hide CVE Banner if visible
    const banner = document.getElementById('cveScanningBanner');
    if (banner) banner.style.display = 'none';

    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-play"></i> START SCAN';
    btn.classList.remove('btn-danger');
    btn.style.backgroundColor = ''; // Revert to CSS color
    loadHistory();
}
