// --- GLOBAL VARIABLES ---
let timerInterval, timerSeconds = 0, vulnCount = 0, scanResults = [];
let scanEventSource = null; // <--- MADE GLOBAL (To enable stopping)
window.allScanRecords = []; // Store history records for viewing
let detailResults = []; // Store results for the detail view

const ctx = document.getElementById('vulnChart').getContext('2d');
const detailCtx = document.getElementById('detailVulnChart').getContext('2d');

// --- CHART CONFIG ---
let vulnChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: ['#ff7b72', '#ff9b5e', '#d29922', '#e3b341', '#58a6ff'], borderWidth: 0 }] },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'right',
                labels: { color: '#c9d1d9', font: { family: 'Segoe UI' } },
                onClick: function (e, legendItem, legend) {
                    const index = legendItem.index;
                    const chart = legend.chart;
                    
                    // Manually toggle data visibility in Chart.js 4+
                    chart.toggleDataVisibility(index);
                    chart.update();

                    const isHidden = !chart.getDataVisibility(index);
                    const severity = chart.data.labels[index];

                    const rows = document.querySelectorAll('.vuln-row[data-severity="' + severity + '"]');
                    const detailRows = document.querySelectorAll('.detail-row[data-severity="' + severity + '"]');

                    rows.forEach(r => { r.style.display = isHidden ? 'none' : 'table-row'; });
                    // Close details if hidden
                    detailRows.forEach(r => { r.style.display = 'none'; });
                    if (isHidden) {
                        rows.forEach(r => r.classList.remove('open'));
                    }
                }
            }
        }
    }
});

let detailVulnChart = new Chart(detailCtx, {
    type: 'doughnut',
    data: { labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: ['#ff7b72', '#ff9b5e', '#d29922', '#e3b341', '#58a6ff'], borderWidth: 0 }] },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'right',
                labels: { color: '#c9d1d9', font: { family: 'Segoe UI' } },
                onClick: function (e, legendItem, legend) {
                    const index = legendItem.index;
                    const chart = legend.chart;
                    
                    chart.toggleDataVisibility(index);
                    chart.update();

                    const isHidden = !chart.getDataVisibility(index); 
                    const severity = chart.data.labels[index];

                    const rows = document.querySelectorAll('#detailTableBody .vuln-row[data-severity="' + severity + '"]');
                    const detailRows = document.querySelectorAll('#detailTableBody .detail-row[data-severity="' + severity + '"]');

                    rows.forEach(r => { r.style.display = isHidden ? 'none' : 'table-row'; });
                    detailRows.forEach(r => { r.style.display = 'none'; });
                    if (isHidden) {
                        rows.forEach(r => r.classList.remove('open'));
                    }
                }
            }
        }
    }
});

// --- INITIALIZATION ---
window.onload = async () => {
    try {
        // Load Plugins
        const resp = await fetch('/plugins');
        const groupedPlugins = await resp.json();
        const grid = document.getElementById('pluginGrid');

        grid.innerHTML = '';

        for (const [category, plugins] of Object.entries(groupedPlugins)) {

            // Add Category Header
            const catClass = category.replace(/\W/g, '');
            grid.innerHTML += `
                <div style="grid-column: 1 / -1; margin-top: 10px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 5px; margin-bottom: 5px; display: flex; justify-content: space-between; align-items: center;">
                    <h4 style="margin:0; color: var(--accent); font-size: 13px; text-transform: uppercase; letter-spacing: 1px;">${escapeHtml(category)}</h4>
                    <label style="font-size: 11px; color: var(--text-dim); cursor: pointer; display: flex; align-items: center; gap: 4px;">
                        <input type="checkbox" checked onchange="toggleCategory(this, '${catClass}')" style="margin:0;"> Select/deselect Group
                    </label>
                </div>
            `;

            plugins.forEach(p => {
                const escaped = escapeHtml(p);
                grid.innerHTML += `
                    <label class="plugin-item active-plugin category-${catClass}">
                        <div class="plugin-checkbox-wrapper">
                            <input type="checkbox" class="plugin-check custom-checkbox" onchange="this.closest('.plugin-item').classList.toggle('active-plugin', this.checked)" value="${escaped}" checked>
                            <span>${escaped}</span>
                        </div>
                    </label>
                `;
            });
        }

        await loadHistory();
    } catch (e) {
        console.error("Initialization error:", e);
    } finally {
        // Check if loader has already been shown in this session
        const loader = document.getElementById('dorm-loader');
        const hasBeenShown = sessionStorage.getItem('dorm_loader_shown');

        if (!hasBeenShown && loader) {
            // First time: Wait longer to show off the advanced animation (3.5s)
            setTimeout(() => {
                loader.classList.add('loader-hidden');
                setTimeout(() => {
                    loader.style.display = 'none';
                    sessionStorage.setItem('dorm_loader_shown', 'true');
                }, 1000); // Wait for CSS transition
            }, 10000);
        } else if (loader) {
            // F5/Refresh: Loader is already hidden by inline CSS, just clean up DOM state
            loader.style.display = 'none';
        }
    }
};

window.toggleCategory = function (cb, catClass) {
    document.querySelectorAll('.category-' + catClass + ' .plugin-check').forEach(input => {
        input.checked = cb.checked;
        input.closest('.plugin-item').classList.toggle('active-plugin', cb.checked);
    });
};

// --- VIEW SWITCHING ---
let sitemapPollInterval = null;

function switchView(viewName) {
    if (sitemapPollInterval) {
        clearInterval(sitemapPollInterval);
        sitemapPollInterval = null;
    }
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    event.currentTarget.classList.add('active');
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    document.getElementById('view-' + viewName).classList.add('active');
    document.querySelector('.main-content').scrollTop = 0; // Reset scroll position
    if (viewName === 'history') loadHistory();
    if (viewName === 'cvecenter') loadCVECenter();
    if (viewName === 'sitemap') initSitemapView();
    if (viewName === 'sci') initSCIView();
}

// ============================================================
// DOM CRAWLER — Real-Time Event Feed
// ============================================================

let domEventSource = null;
let domEventCount = 0;
let domStats = { navigate: 0, click: 0, xhr: 0, spa_route: 0, error: 0 };
const DOM_MAX_ROWS = 300; // keep feed from growing forever

const domIconMap = {
    navigate:  { icon: 'fa-compass',        cls: 'dom-icon-navigate', label: 'Navigate',  color: '#60A5FA' },
    click:     { icon: 'fa-mouse-pointer',  cls: 'dom-icon-click',    label: 'Click',     color: '#34D399' },
    xhr:       { icon: 'fa-exchange-alt',   cls: 'dom-icon-xhr',      label: 'XHR/Fetch', color: '#FBBF24' },
    spa_route: { icon: 'fa-route',          cls: 'dom-icon-spa_route',label: 'SPA Route', color: '#A78BFA' },
    form:      { icon: 'fa-wpforms',        cls: 'dom-icon-form',     label: 'Form',      color: '#F87171' },
    error:     { icon: 'fa-exclamation-triangle', cls: 'dom-icon-error', label: 'Error', color: '#EF4444' },
    done:      { icon: 'fa-check-circle',   cls: 'dom-icon-done',     label: 'Done',      color: '#10B981' },
};

function initDOMCrawlerFeed() {
    if (domEventSource) return; // already connected

    domEventSource = new EventSource('/dom-events');

    domEventSource.onopen = () => {
        setDOMStatus('CONNECTED', '#10B981', 'rgba(16,185,129,0.15)', 'rgba(16,185,129,0.3)');
    };

    domEventSource.onmessage = (e) => {
        try {
            const ev = JSON.parse(e.data);
            appendDOMEvent(ev);
        } catch (_) {}
    };

    domEventSource.onerror = () => {
        setDOMStatus('IDLE', '#94A3B8', 'rgba(148,163,184,0.1)', 'rgba(148,163,184,0.2)');
    };
}

function setDOMStatus(text, color, bg, border) {
    const badge = document.getElementById('dom-status-badge');
    if (!badge) return;
    badge.textContent = text;
    badge.style.color = color;
    badge.style.background = bg;
    badge.style.borderColor = border;
}

function appendDOMEvent(ev) {
    const feed = document.getElementById('domFeed');
    if (!feed) return;

    // Hide empty state on first event
    const empty = document.getElementById('dom-empty-state');
    if (empty) empty.style.display = 'none';

    // Update status badge
    setDOMStatus('CRAWLING', '#10B981', 'rgba(16,185,129,0.15)', 'rgba(16,185,129,0.3)');

    // Show pulse on nav item
    const pulse = document.getElementById('dom-nav-pulse');
    if (pulse) pulse.style.display = 'inline-block';

    // Update counters
    domEventCount++;
    const countEl = document.getElementById('dom-event-count');
    if (countEl) countEl.textContent = domEventCount + ' event' + (domEventCount !== 1 ? 's' : '');

    if (ev.kind === 'navigate') { domStats.navigate++; updateDOMStat('dom-stat-pages', domStats.navigate); }
    if (ev.kind === 'click')    { domStats.click++;    updateDOMStat('dom-stat-clicks', domStats.click); }
    if (ev.kind === 'xhr')      { domStats.xhr++;      updateDOMStat('dom-stat-xhr', domStats.xhr); }
    if (ev.kind === 'spa_route'){ domStats.spa_route++;updateDOMStat('dom-stat-routes', domStats.spa_route); }
    if (ev.kind === 'error')    { domStats.error++;    updateDOMStat('dom-stat-errors', domStats.error); }

    if (ev.kind === 'done') {
        setDOMStatus('DONE', '#10B981', 'rgba(16,185,129,0.15)', 'rgba(16,185,129,0.3)');
        if (pulse) setTimeout(() => { pulse.style.display = 'none'; }, 2000);
    }

    const meta = domIconMap[ev.kind] || domIconMap['navigate'];
    const timeStr = new Date(ev.timestamp).toLocaleTimeString('en-GB', { hour12: false });
    const urlTrunc = ev.url ? (ev.url.length > 80 ? ev.url.slice(0, 77) + '…' : ev.url) : '';
    const detailText = ev.detail || ev.selector || ev.label || '';

    const row = document.createElement('div');
    row.className = 'dom-event-row new';

    row.innerHTML = `
        <div class="dom-event-icon ${meta.cls}">
            <i class="fas ${meta.icon}"></i>
        </div>
        <div class="dom-event-body">
            <div class="dom-event-label" style="color:${meta.color};">${meta.label}</div>
            ${urlTrunc ? `<div class="dom-event-url">${escapeHtml(urlTrunc)}</div>` : ''}
            ${detailText ? `<div class="dom-event-detail">${escapeHtml(detailText)}</div>` : ''}
        </div>
        <div class="dom-event-time">${timeStr}</div>
    `;

    // Prepend so newest is always at top
    feed.insertBefore(row, feed.firstChild);

    // Remove 'new' class after animation completes (avoids re-trigger on scroll)
    setTimeout(() => row.classList.remove('new'), 900);

    // Trim old rows
    const rows = feed.querySelectorAll('.dom-event-row');
    if (rows.length > DOM_MAX_ROWS) {
        for (let i = DOM_MAX_ROWS; i < rows.length; i++) rows[i].remove();
    }
}

function updateDOMStat(id, val) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val;
    // Brief scale-up animation
    el.style.transform = 'scale(1.3)';
    setTimeout(() => { el.style.transform = 'scale(1)'; el.style.transition = 'transform 0.2s ease'; }, 120);
}

function clearDOMFeed() {
    const feed = document.getElementById('domFeed');
    if (!feed) return;
    feed.innerHTML = `
        <div class="dom-empty" id="dom-empty-state">
            <i class="fas fa-spider"></i>
            <p style="font-size:15px;font-weight:600;color:var(--text-main);margin:0 0 6px;">Feed cleared</p>
            <p style="font-size:13px;margin:0;">New events will appear here as the DOM Crawler runs.</p>
        </div>
    `;
    domEventCount = 0;
    domStats = { navigate: 0, click: 0, xhr: 0, spa_route: 0, error: 0 };
    ['dom-stat-pages','dom-stat-clicks','dom-stat-xhr','dom-stat-routes','dom-stat-errors'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '0';
    });
    const countEl = document.getElementById('dom-event-count');
    if (countEl) countEl.textContent = '0 events';
}

// Auto-start SSE connection when page loads (stays connected in background)
window.addEventListener('load', () => {
    initDOMCrawlerFeed();
});


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

function togglePlugins() { const s = document.getElementById('plugin-section'); s.style.display = s.style.display === 'block' ? 'none' : 'block'; }

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

function toggleCveSection() {
	const el = document.getElementById('cveContainer');
	const arrow = document.getElementById('cveArrow');
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
    if (row.style.display === 'table-row') {
        row.style.display = 'none';
        parent.classList.remove('open');
    } else {
        row.style.display = 'table-row';
        parent.classList.add('open');
    }
}

// --- HISTORY LOGIC ---
async function loadHistory() {
    const tbody = document.getElementById('historyBody');
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:#58a6ff;">Loading history...</td></tr>';
    try {
        const resp = await fetch('/api/history');
        const records = await resp.json();
        window.allScanRecords = records || [];
        tbody.innerHTML = '';
        if (!records || records.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:#8b949e;">No scan history found.</td></tr>';
            return;
        }
        records.forEach(rec => {
            const date = new Date(rec.start_time).toLocaleString();
            const duration = rec.end_time ? Math.round((new Date(rec.end_time) - new Date(rec.start_time)) / 1000) + 's' : 'Running...';
            const statusClass = rec.status === 'Completed' ? 'status-completed' : 'status-running';
            const html = `
                <tr>
                    <td class="${statusClass}">${escapeHtml(rec.status)}</td>
                    <td style="color:#fff; font-weight:bold;">${escapeHtml(rec.target)}</td>
                    <td style="color:var(--text-dim); font-size:0.9em;">${date}</td>
                    <td style="font-family:'Consolas'">${duration}</td>
                    <td>
                        <span style="color:#ff7b72; font-weight:bold;">${rec.severity_stats['CRITICAL'] || 0}</span> /
                        <span style="color:#ff9b5e; font-weight:bold;">${rec.severity_stats['HIGH'] || 0}</span>
                        <span style="color:var(--text-dim); font-size:0.8em; margin-left:5px;">(Total: ${rec.total_vulns})</span>
                    </td>
                    <td>
                        <div style="display: flex; justify-content: flex-end; gap: 8px;">
                            <button data-id="${escapeHtml(rec.id)}" onclick="viewScan(this.dataset.id)" class="btn-icon" style="background: rgba(59, 130, 246, 0.2); color: var(--accent); border: 1px solid rgba(59, 130, 246, 0.3);" title="View Details"><i class="fas fa-eye"></i></button>
                            <button data-id="${escapeHtml(rec.id)}" onclick="deleteScan(this.dataset.id)" class="btn-danger btn-icon" title="Delete Scan"><i class="fas fa-trash"></i></button>
                        </div>
                    </td>
                </tr>`;
            tbody.insertAdjacentHTML('beforeend', html);
        });
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" style="color:red">Error loading history: ${e}</td></tr>`;
    }
}

async function deleteScan(id) {
    if (!confirm("Are you sure you want to delete this scan record?")) return;
    await fetch('/api/history/delete?id=' + id, { method: 'POST' });
    loadHistory();
}

async function deleteAllHistory() {
    if (!confirm("CRITICAL ACTION: Are you sure you want to PERMANENTLY DELETE all scan history? This cannot be undone.")) return;
    try {
        const resp = await fetch('/api/history/delete_all', { method: 'POST' });
        if (resp.ok) {
            loadHistory();
        } else {
            alert("Failed to delete history: " + await resp.text());
        }
    } catch (e) {
        alert("Error: " + e);
    }
}

function viewScan(id) {
    const rec = window.allScanRecords.find(r => r.id === id);
    if (!rec) return;

    window.currentDetailScanID = id; // Save for Sitemap button

    // Switch view to history detail
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    document.getElementById('view-history-detail').classList.add('active');
    document.querySelector('.main-content').scrollTop = 0; // Reset scroll position

    // Populate UI
    document.getElementById('detailTarget').innerText = rec.target;
    document.getElementById('detailDate').innerText = new Date(rec.start_time).toLocaleString();
    document.getElementById('detailTableBody').innerHTML = '';
    
    let detailVulnCount = 0; 
    detailResults = [];
    detailVulnChart.data.datasets[0].data = [0, 0, 0, 0, 0];
    
    if (rec.vulnerabilities && rec.vulnerabilities.length > 0) {
        rec.vulnerabilities.forEach(data => {
            detailVulnCount++;
            detailResults.push(data);
            const badgeClass = "sev-" + escapeHtml(data.Severity.toUpperCase());
            let engineLabel = 'Plugin';
            if (data.Name.includes("Exploit")) engineLabel = 'EDB';
            else if (data.Name.includes("Spider")) engineLabel = 'Spider';
            
            const html = `
                <tr class="vuln-row" data-severity="${escapeHtml(data.Severity.toUpperCase())}" id="detail-row-${detailVulnCount}" onclick="toggleDetail('detail-detail-${detailVulnCount}', 'detail-row-${detailVulnCount}')">
                    <td><span class="badge ${badgeClass}">${escapeHtml(data.Severity)}</span></td>
                    <td style="font-weight:bold; color:#fff;">${data.CVSS.toFixed(1)}</td>
                    <td style="color:#fff;">${escapeHtml(data.Name)}</td>
                    <td style="color:var(--text-dim); font-size:0.9em;">${engineLabel}</td>
                    <td>${escapeHtml(data.Target.IP)}:${data.Target.Port}</td>
                    <td class="arrow"><i class="fas fa-chevron-down"></i></td>
                </tr>
                <tr class="detail-row" data-severity="${escapeHtml(data.Severity.toUpperCase())}" id="detail-detail-${detailVulnCount}">
                    <td colspan="6" style="padding:0; border:none;">
                        <div class="detail-content">
                            <strong style="color:var(--accent)">ANALYSIS:</strong><br>${escapeHtml(data.Description).replace(/\n/g, '<br>')}<br><br>
                            <strong style="color:var(--success)">SOLUTION:</strong><br>${escapeHtml(data.Solution || "Apply patches.")}<br><br>
                            <em style="font-size:0.8em">Ref: ${escapeHtml(data.Reference)}</em>
                        </div>
                    </td>
                </tr>`;
            document.getElementById('detailTableBody').insertAdjacentHTML('beforeend', html);
            
            const idx = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(data.Severity.toUpperCase());
            if (idx !== -1) { detailVulnChart.data.datasets[0].data[idx]++; }
        });
    }
    
    detailVulnChart.update();
    
    // Set timer display based on duration
    if (rec.start_time && rec.end_time) {
        const diff = Math.round((new Date(rec.end_time) - new Date(rec.start_time)) / 1000);
        const m = Math.floor(diff / 60).toString().padStart(2, '0');
        const s = (diff % 60).toString().padStart(2, '0');
        document.getElementById('detailTimer').innerText = `${m}:${s}`;
    } else {
        document.getElementById('detailTimer').innerText = 'Running...';
    }
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

    // 2. Get selected plugins from grid
    const selected = Array.from(document.querySelectorAll('.plugin-check:checked')).map(c => c.value);

    // 3. MULTI-TARGET LOGIC: Split by newline, trim, and remove empty lines
    const targetsArray = rawTargets.split('\n').map(t => t.trim()).filter(t => t !== '');
    if (targetsArray.length === 0) return alert("Please enter at least one target!");

    // Join multiple targets with a comma to send via GET request
    const targetString = targetsArray.join(',');

    document.getElementById('tableBody').innerHTML = '';
    vulnCount = 0; scanResults = [];
    vulnChart.data.datasets[0].data = [0, 0, 0, 0, 0];
    vulnChart.update();

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
    scanEventSource = new EventSource(`/scan?targets=${encodeURIComponent(targetString)}&plugins=${encodeURIComponent(selected.join(","))}&auth=${encodeURIComponent(authHeader)}&proxyEnabled=${proxyEnabled}&proxyUrl=${encodeURIComponent(proxyUrl)}&wafDelay=${wafDelay}&wafJitter=${wafJitter}&wafNullByte=${wafNullByte}&wafUEP=${wafUEP}&wafTLS=${wafTLS}`);

    scanEventSource.onmessage = (e) => {
        const data = JSON.parse(e.data);

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
            alert("Scan Error: " + data.Message);
            finishScanUI(); // Reset UI immediately on error
            if (sitemapPollInterval) {
                clearInterval(sitemapPollInterval);
                sitemapPollInterval = null;
            }
            return;
        }

        vulnCount++; scanResults.push(data);



        const badgeClass = "sev-" + escapeHtml(data.Severity.toUpperCase());

        let engineLabel = 'Plugin';
        if (data.Name.includes("Exploit")) engineLabel = 'EDB';
        else if (data.Name.includes("Spider")) engineLabel = 'Spider';

        const html = `
            <tr class="vuln-row" data-severity="${escapeHtml(data.Severity.toUpperCase())}" id="row-${vulnCount}" onclick="toggleDetail(${vulnCount})">
                <td><span class="badge ${badgeClass}">${escapeHtml(data.Severity)}</span></td>
                <td style="font-weight:bold; color:#fff;">${data.CVSS.toFixed(1)}</td>
                <td style="color:#fff;">${escapeHtml(data.Name)}</td>
                <td style="color:var(--text-dim); font-size:0.9em;">${engineLabel}</td>
                <td>${escapeHtml(data.Target.IP)}:${data.Target.Port}</td>
                <td class="arrow"><i class="fas fa-chevron-down"></i></td>
            </tr>
            <tr class="detail-row" data-severity="${escapeHtml(data.Severity.toUpperCase())}" id="detail-${vulnCount}">
                <td colspan="6" style="padding:0; border:none;">
                    <div class="detail-content">
                        <strong style="color:var(--accent)">ANALYSIS:</strong><br>${escapeHtml(data.Description).replace(/\n/g, '<br>')}<br><br>
                        <strong style="color:var(--success)">SOLUTION:</strong><br>${escapeHtml(data.Solution || "Apply patches.")}<br><br>
                        <em style="font-size:0.8em">Ref: ${escapeHtml(data.Reference)}</em>
                    </div>
                </td>
            </tr>`;

        document.getElementById('tableBody').insertAdjacentHTML('beforeend', html);

        const idx = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(data.Severity.toUpperCase());
        if (idx !== -1) { vulnChart.data.datasets[0].data[idx]++; vulnChart.update(); }
    };

    scanEventSource.onerror = (err) => {
        console.error("SSE Connection Error:", err);
        // Do not call stopScan() here, because EventSource auto-reconnects on temporary network drops.
        // Calling stopScan() was aborting the entire scan incorrectly.
    };
}

// NEW: STOP SCAN FUNCTION
async function stopScan() {
    await fetch('/stop'); // Send signal to backend

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

// --- REPORT HELPERS ---
function getTargetDisplayString() {
    const rawTargets = document.getElementById('targetInput').value;
    const arr = rawTargets.split('\n').map(t => t.trim()).filter(t => t !== '');
    if (arr.length > 3) return arr.slice(0, 3).join(', ') + ` (+${arr.length - 3} more)`;
    return arr.join(', ');
}

function downloadReport() {
    if (scanResults.length === 0) return alert("No results to export!");
    const targetDisplay = getTargetDisplayString();
    const date = new Date().toLocaleString();

    let html = `<html><head><title>DORM Report</title><style>body{font-family:sans-serif;padding:30px;color:#333}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #ddd;padding:12px;text-align:left}th{background:#f4f4f4}.CRITICAL{color:#d32f2f;font-weight:bold}.HIGH{color:#f57c00;font-weight:bold}</style></head><body>`;
    html += `<h1>DORM Security Report</h1><p>Target(s): ${escapeHtml(targetDisplay)}<br>Date: ${date}</p><table><thead><tr><th>Sev</th><th>Vuln</th><th>Details</th></tr></thead><tbody>`;
    scanResults.forEach(r => html += `<tr><td class="${r.Severity}">${r.Severity}</td><td>${escapeHtml(r.Name)}</td><td>${escapeHtml(r.Description)}</td></tr>`);
    html += `</tbody></table></body></html>`;

    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([html], { type: "text/html" }));
    link.download = `DORM_Report_${Date.now()}.html`;
    link.click();
}

function downloadPDF() {
    if (scanResults.length === 0) return alert("No results to export!");
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const targetDisplay = getTargetDisplayString();
    const date = new Date().toLocaleString();

    doc.setFillColor(13, 17, 23);
    doc.rect(0, 0, 210, 40, 'F');
    doc.setFontSize(22); doc.setTextColor(88, 166, 255); doc.text("DORM SECURITY REPORT", 14, 20);
    doc.setFontSize(10); doc.setTextColor(201, 209, 217); doc.text(`Target(s): ${targetDisplay}`, 14, 30); doc.text(`Date: ${date}`, 14, 35);

    const tableRows = scanResults.map(vuln => [
        vuln.Severity, vuln.CVSS.toFixed(1), vuln.Name,
        vuln.Description.replace(/<br>/g, "\n").substring(0, 200) + (vuln.Description.length > 200 ? "..." : "")
    ]);

    doc.autoTable({
        head: [['SEVERITY', 'CVSS', 'VULNERABILITY', 'DETAILS']],
        body: tableRows,
        startY: 45,
        theme: 'grid',
        headStyles: { fillColor: [22, 27, 34], textColor: [255, 255, 255], fontStyle: 'bold' },
        styles: { fontSize: 9, cellPadding: 4, overflow: 'linebreak' },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 25 }, 1: { cellWidth: 15, halign: 'center' }, 2: { cellWidth: 50 }, 3: { cellWidth: 'auto' } },
        didParseCell: function (data) {
            if (data.section === 'body' && data.column.index === 0) {
                const sev = data.cell.raw.toUpperCase();
                if (sev === 'CRITICAL') data.cell.styles.textColor = [255, 123, 114];
                else if (sev === 'HIGH') data.cell.styles.textColor = [255, 155, 94];
                else if (sev === 'MEDIUM') data.cell.styles.textColor = [210, 153, 34];
                else if (sev === 'LOW') data.cell.styles.textColor = [227, 179, 65];
                else data.cell.styles.textColor = [88, 166, 255];
            }
        }
    });

    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8); doc.setTextColor(150);
        doc.text(`Page ${i} of ${pageCount} - Generated by DORM Scanner`, 105, 290, null, null, "center");
    }
    doc.save(`DORM_Report_${Date.now()}.pdf`);
}

function downloadDetailReport() {
    if (detailResults.length === 0) return alert("No results to export!");
    const targetDisplay = document.getElementById('detailTarget').innerText;
    const date = document.getElementById('detailDate').innerText;

    let html = `<html><head><title>DORM Report</title><style>body{font-family:sans-serif;padding:30px;color:#333}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #ddd;padding:12px;text-align:left}th{background:#f4f4f4}.CRITICAL{color:#d32f2f;font-weight:bold}.HIGH{color:#f57c00;font-weight:bold}</style></head><body>`;
    html += `<h1>DORM Security Report (Archived)</h1><p>Target(s): ${escapeHtml(targetDisplay)}<br>Date: ${escapeHtml(date)}</p><table><thead><tr><th>Sev</th><th>Vuln</th><th>Details</th></tr></thead><tbody>`;
    detailResults.forEach(r => html += `<tr><td class="${r.Severity}">${r.Severity}</td><td>${escapeHtml(r.Name)}</td><td>${escapeHtml(r.Description)}</td></tr>`);
    html += `</tbody></table></body></html>`;

    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([html], { type: "text/html" }));
    link.download = `DORM_Report_Archive_${Date.now()}.html`;
    link.click();
}

function downloadDetailPDF() {
    if (detailResults.length === 0) return alert("No results to export!");
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const targetDisplay = document.getElementById('detailTarget').innerText;
    const date = document.getElementById('detailDate').innerText;

    doc.setFillColor(13, 17, 23);
    doc.rect(0, 0, 210, 40, 'F');
    doc.setFontSize(22); doc.setTextColor(88, 166, 255); doc.text("DORM SECURITY REPORT", 14, 20);
    doc.setFontSize(10); doc.setTextColor(201, 209, 217); doc.text(`Target(s): ${targetDisplay} (Archived)`, 14, 30); doc.text(`Date: ${date}`, 14, 35);

    const tableRows = detailResults.map(vuln => [
        vuln.Severity, vuln.CVSS.toFixed(1), vuln.Name,
        vuln.Description.replace(/<br>/g, "\n").substring(0, 200) + (vuln.Description.length > 200 ? "..." : "")
    ]);

    doc.autoTable({
        head: [['SEVERITY', 'CVSS', 'VULNERABILITY', 'DETAILS']],
        body: tableRows,
        startY: 45,
        theme: 'grid',
        headStyles: { fillColor: [22, 27, 34], textColor: [255, 255, 255], fontStyle: 'bold' },
        styles: { fontSize: 9, cellPadding: 4, overflow: 'linebreak' },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 25 }, 1: { cellWidth: 15, halign: 'center' }, 2: { cellWidth: 50 }, 3: { cellWidth: 'auto' } },
        didParseCell: function (data) {
            if (data.section === 'body' && data.column.index === 0) {
                const sev = data.cell.raw.toUpperCase();
                if (sev === 'CRITICAL') data.cell.styles.textColor = [255, 123, 114];
                else if (sev === 'HIGH') data.cell.styles.textColor = [255, 155, 94];
                else if (sev === 'MEDIUM') data.cell.styles.textColor = [210, 153, 34];
                else if (sev === 'LOW') data.cell.styles.textColor = [227, 179, 65];
                else data.cell.styles.textColor = [88, 166, 255];
            }
        }
    });

    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8); doc.setTextColor(150);
        doc.text(`Page ${i} of ${pageCount} - Generated by DORM Scanner (Archived)`, 105, 290, null, null, "center");
    }
    doc.save(`DORM_Report_Archive_${Date.now()}.pdf`);
}

function checkAllPlugins(state) {
    document.querySelectorAll('.plugin-check').forEach(cb => {
        cb.checked = state;
        cb.closest('.plugin-item').classList.toggle('active-plugin', state);
    });
}

// --- CVE DB LOGIC ---
async function loadCVEDatabase() {
    const tbody = document.getElementById('cveTableBody');
    const statsEl = document.getElementById('cveStats');
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:40px; color:var(--accent);">Loading CVE records...</td></tr>';
    
    try {
        const resp = await fetch('/api/cvedb');
        const data = await resp.json();

        // Backend returns { stats: {total_cves, ...}, cves: [...] }
        const cves = data.cves || [];
        const totalCount = (data.stats && data.stats.total_cves) ? data.stats.total_cves : cves.length;

        statsEl.innerText = `Total Records: ${totalCount.toLocaleString()}`;
        
        tbody.innerHTML = '';
        if (cves.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:40px; color:var(--text-dim);">No records found in local database.</td></tr>';
            return;
        }
        
        renderCVELines(cves);
    } catch(e) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:red; padding:40px;">Error: ${e}</td></tr>`;
    }
}

async function searchCVEs() {
    const query = document.getElementById('cveSearchInput').value.trim();
    if (!query) {
        loadCVEDatabase();
        return;
    }
    
    const tbody = document.getElementById('cveTableBody');
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:40px; color:var(--accent);">Searching...</td></tr>';
    
    try {
        const resp = await fetch(`/api/cvedb/search?q=${encodeURIComponent(query)}`);
        const cves = await resp.json();
        
        tbody.innerHTML = '';
        if (!cves || cves.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:40px; color:var(--text-dim);">No matching vulnerability records found.</td></tr>';
            return;
        }
        
        renderCVELines(cves);
    } catch(e) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:red; padding:40px;">Error: ${e}</td></tr>`;
    }
}

function renderCVELines(cves) {
    const tbody = document.getElementById('cveTableBody');
    cves.forEach(c => {
        let badgeClass;
        if (c.cvss >= 9.0)      badgeClass = 'sev-CRITICAL';
        else if (c.cvss >= 7.0) badgeClass = 'sev-HIGH';
        else if (c.cvss >= 4.0) badgeClass = 'sev-MEDIUM';
        else if (c.cvss > 0)    badgeClass = 'sev-LOW';
        else                    badgeClass = 'sev-INFO';

        const html = `
            <tr class="vuln-row">
                <td style="font-weight:bold; color:var(--accent);">${escapeHtml(c.id)}</td>
                <td style="color:#fff; font-weight:600;">${escapeHtml(c.product)}</td>
                <td style="color:var(--text-main); font-size:13px;">${escapeHtml(c.description)}</td>
                <td><span class="badge ${badgeClass}">${c.cvss > 0 ? c.cvss.toFixed(1) : 'N/A'}</span></td>
            </tr>
        `;
        tbody.insertAdjacentHTML('beforeend', html);
    });
}

// =============================================
// SITEMAP LOGIC
// =============================================
let currentSiteMapData = null;
window.currentSitemapScanID = '';

function viewSitemapForScan() {
    window.currentSitemapScanID = window.currentDetailScanID;
    switchView('sitemap');
}

async function initSitemapView() {
    // Populate host dropdown from DB based on current scan
    try {
        const url = window.currentSitemapScanID ? `/api/sitemap/list?scan_id=${window.currentSitemapScanID}` : `/api/sitemap/list`;
        const resp = await fetch(url);
        const hosts = await resp.json();
        const select = document.getElementById('sitemapHostSelect');
        select.innerHTML = '<option value="">— Select Target —</option>';
        (hosts || []).forEach(h => {
            select.innerHTML += `<option value="${escapeHtml(h)}">${escapeHtml(h)}</option>`;
        });
        
        const content = document.getElementById('sitemapContent');
        if (hosts && hosts.length === 1) {
            select.value = hosts[0];
            await loadSitemap(hosts[0]);
        } else if (!hosts || hosts.length === 0) {
            content.innerHTML = '<div class="sm-empty"><i class="fas fa-map-marked-alt"></i><p style="font-size: 16px; font-weight: 600; color: var(--text-main); margin: 0 0 8px;">No Sitemap Available</p><p style="font-size: 14px; margin: 0;">Run a scan first or select a scan from History.</p></div>';
        } else {
            content.innerHTML = '<div class="sm-empty"><i class="fas fa-list"></i><p style="font-size: 16px; font-weight: 600; color: var(--text-main); margin: 0 0 8px;">Multiple Targets Detected</p><p style="font-size: 14px; margin: 0;">Please select a target from the dropdown above to view its sitemap.</p></div>';
        }
    } catch(e) {
        console.error('Sitemap list error:', e);
    }
}

async function loadSitemap(host) {
    if (!host) return;
    const content = document.getElementById('sitemapContent');
    content.innerHTML = '<div class="sm-empty"><i class="fas fa-spinner fa-spin"></i><p style="color:var(--text-dim); margin:0;">Loading site map...</p></div>';
    try {
        let url = `/api/sitemap?target=${encodeURIComponent(host)}`;
        if (window.currentSitemapScanID) {
            url += `&scan_id=${window.currentSitemapScanID}`;
        }
        const resp = await fetch(url);
        if (!resp.ok) {
            content.innerHTML = '<div class="sm-empty"><i class="fas fa-exclamation-triangle" style="color:#F87171;"></i><p style="color:#F87171; font-weight:600; margin:0 0 8px;">No sitemap found</p><p style="margin:0;">Run a scan for this target first.</p></div>';
            return;
        }
        const data = await resp.json();
        currentSiteMapData = data;
        renderSitemapView(data);
        
        // Start polling if a scan is active
        const btn = document.getElementById('scanBtn');
        if (btn && btn.classList.contains('btn-danger') && !sitemapPollInterval) {
            sitemapPollInterval = setInterval(refreshSitemapSilently, 2000);
        }
    } catch(e) {
        content.innerHTML = `<div class="sm-empty"><i class="fas fa-times-circle" style="color:#F87171;"></i><p style="color:#F87171; margin:0;">Error: ${escapeHtml(String(e))}</p></div>`;
    }
}

async function refreshSitemapSilently() {
    const host = document.getElementById('sitemapHostSelect').value;
    if (!host) return;
    try {
        let url = `/api/sitemap?target=${encodeURIComponent(host)}`;
        if (window.currentSitemapScanID) {
            url += `&scan_id=${window.currentSitemapScanID}`;
        }
        const resp = await fetch(url);
        if (resp.ok) {
            const data = await resp.json();
            currentSiteMapData = data;
            renderSitemapView(data);
        }
    } catch(e) {}
}

async function refreshSitemap() {
    const host = document.getElementById('sitemapHostSelect').value;
    if (host) await loadSitemap(host);
}

function exportSitemapJSON() {
    if (!currentSiteMapData) return;
    const host = currentSiteMapData.host || 'target';
    const date = new Date().toISOString().split('T')[0];
    const blob = new Blob([JSON.stringify(currentSiteMapData, null, 2)], {type: 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sitemap_${host}_${date}.json`;
    a.click();
}

function getStatusClass(code) {
    if (code === 200) return 'sm-status-200';
    if (code === 301 || code === 302) return 'sm-status-301';
    if (code === 403 || code === 401) return 'sm-status-403';
    if (code === 404 || code >= 500) return 'sm-status-404';
    return 'sm-status-other';
}

function getMethodClass(method) {
    const m = (method || 'GET').toUpperCase();
    if (m === 'GET') return 'sm-method-GET';
    if (m === 'POST') return 'sm-method-POST';
    if (m === 'PUT') return 'sm-method-PUT';
    if (m === 'DELETE') return 'sm-method-DELETE';
    return 'sm-method-other';
}

function toggleJSPaths(id) {
    const el = document.getElementById('jspaths-' + id);
    if (el) el.classList.toggle('open');
}

function renderSitemapView(data) {
    const content = document.getElementById('sitemapContent');
    
    // Remember open accordions before rewriting DOM
    const openJS = new Set();
    document.querySelectorAll('.sm-js-paths.open').forEach(el => openJS.add(el.id));

    const stats = data.stats || {};
    const pages = data.pages || [];
    const endpoints = data.endpoints || [];
    const forms = data.forms || [];
    const jsFiles = data.js_files || [];
    const disallows = data.robot_disallows || [];
    const techs = stats.technologies || {};

    // ── Stats row
    let statsHTML = `<div class="sm-stat-grid">
        <div class="sm-stat-card"><i class="fas fa-file-alt"></i><div class="sm-stat-num">${stats.total_pages || 0}</div><div class="sm-stat-label">Pages</div></div>
        <div class="sm-stat-card"><i class="fas fa-link"></i><div class="sm-stat-num">${stats.total_endpoints || 0}</div><div class="sm-stat-label">Endpoints</div></div>
        <div class="sm-stat-card"><i class="fas fa-wpforms"></i><div class="sm-stat-num">${stats.total_forms || 0}</div><div class="sm-stat-label">Forms</div></div>
        <div class="sm-stat-card"><i class="fab fa-js-square"></i><div class="sm-stat-num">${stats.total_js_files || 0}</div><div class="sm-stat-label">JS Files</div></div>
    </div>`;

    // ── Tech tags
    let techHTML = '';
    const techKeys = Object.keys(techs);
    if (techKeys.length > 0) {
        techHTML = '<div class="sm-tech-row"><span style="font-size:12px; color:var(--text-dim); font-weight:600; margin-right:4px;">Detected:</span>';
        techKeys.forEach(t => { techHTML += `<span class="sm-tech-tag">${escapeHtml(t)}</span>`; });
        techHTML += '</div>';
    }

    // ── robots.txt disallows
    let disallowHTML = '';
    if (disallows.length > 0) {
        disallowHTML = `<div class="sm-disallow-panel">
            <div class="sm-disallow-header"><i class="fas fa-ban"></i> Disallowed by robots.txt (${disallows.length} paths — potential hidden surface)</div>
            <div>`;
        disallows.forEach(p => { disallowHTML += `<span class="sm-disallow-path">${escapeHtml(p)}</span>`; });
        disallowHTML += '</div></div>';
    }

    // ── Pages panel
    let pagesHTML = `<div class="sm-panel">
        <div class="sm-panel-header"><i class="fas fa-file-alt"></i> Pages (${pages.length})</div>
        <div class="sm-panel-body">`;
    if (pages.length === 0) {
        pagesHTML += '<div style="padding:20px; text-align:center; color:var(--text-dim); font-size:13px;">No pages discovered</div>';
    } else {
        pages.forEach(p => {
            const sCls = getStatusClass(p.status_code);
            const title = p.title ? `<span style="color:var(--text-dim); font-size:10px; display:block; margin-top:2px;">${escapeHtml(p.title)}</span>` : '';
            pagesHTML += `<div class="sm-page-item">
                <span class="sm-status ${sCls}">${p.status_code || '?'}</span>
                <div class="sm-page-url">${escapeHtml(p.url)}${title}</div>
            </div>`;
        });
    }
    pagesHTML += '</div></div>';

    // ── Endpoints panel
    let epsHTML = `<div class="sm-panel">
        <div class="sm-panel-header"><i class="fas fa-code-branch"></i> Endpoints (${endpoints.length})</div>
        <div class="sm-panel-body">`;
    if (endpoints.length === 0) {
        epsHTML += '<div style="padding:20px; text-align:center; color:var(--text-dim); font-size:13px;">No endpoints found</div>';
    } else {
        endpoints.forEach(ep => {
            const mCls = getMethodClass(ep.method);
            const params = (ep.params || []).length > 0
                ? `<span style="color:var(--accent); font-size:10px; margin-left:6px;">[${escapeHtml(ep.params.join(', '))}]</span>` : '';
            const srcBadge = ep.source ? `<span style="font-size:9px; color:var(--text-dim); margin-left:4px;">${escapeHtml(ep.source)}</span>` : '';
            epsHTML += `<div class="sm-page-item">
                <span class="sm-method ${mCls}">${escapeHtml(ep.method || 'GET')}</span>
                <div class="sm-page-url">${escapeHtml(ep.url)}${params}${srcBadge}</div>
            </div>`;
        });
    }
    epsHTML += '</div></div>';

    // ── Forms panel
    let formsHTML = `<div class="sm-panel">
        <div class="sm-panel-header"><i class="fas fa-wpforms"></i> Forms (${forms.length})</div>
        <div class="sm-panel-body">`;
    if (forms.length === 0) {
        formsHTML += '<div style="padding:20px; text-align:center; color:var(--text-dim); font-size:13px;">No forms found</div>';
    } else {
        forms.forEach(f => {
            const mCls = getMethodClass(f.method);
            const inputs = (f.inputs || []).map(inp => {
                const tc = escapeHtml(`type-${(inp.type||'text').toLowerCase()}`);
                return `<span class="sm-input-tag ${tc}">${escapeHtml(inp.name)}${inp.type ? ':'+escapeHtml(inp.type) : ''}</span>`;
            }).join('');
            formsHTML += `<div class="sm-form-item">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                    <span class="sm-method ${mCls}">${escapeHtml(f.method||'GET')}</span>
                    <span class="sm-form-action">${escapeHtml(f.action)}</span>
                </div>
                <div class="sm-form-inputs">${inputs}</div>
            </div>`;
        });
    }
    formsHTML += '</div></div>';

    // ── JS files accordion
    let jsHTML = '';
    if (jsFiles.length > 0) {
        jsHTML = `<div style="margin-bottom:16px;">
            <div class="sm-panel-header" style="padding: 14px 0; border: none;"><i class="fab fa-js-square" style="color:#FBBF24;"></i> JS Files &amp; Extracted Endpoints</div>
            <div class="sm-js-accordion">`;
        jsFiles.forEach((jf, idx) => {
            const paths = jf.paths || [];
            const pathsHTML = paths.length > 0
                ? paths.map(p => `<span class="sm-js-path">${escapeHtml(p)}</span>`).join('')
                : '<span style="color:var(--text-dim); font-size:11px;">No endpoints extracted</span>';
            jsHTML += `<div class="sm-js-item">
                <div class="sm-js-toggle" onclick="toggleJSPaths(${idx})">
                    <i class="fab fa-js"></i>
                    <span class="sm-js-url">${escapeHtml(jf.url)}</span>
                    <span class="sm-js-count">${paths.length} endpoints</span>
                    <i class="fas fa-chevron-down" style="color:var(--text-dim); font-size:10px;"></i>
                </div>
                <div class="sm-js-paths" id="jspaths-${idx}">${pathsHTML}</div>
            </div>`;
        });
        jsHTML += '</div></div>';
    }

    content.innerHTML = statsHTML + techHTML + disallowHTML +
        `<div class="sm-columns">${pagesHTML}${epsHTML}${formsHTML}</div>` + jsHTML;
        
    openJS.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add('open');
    });
}

// --- CVE CENTER LOGIC ---

async function searchCVE() {
    const query = document.getElementById('cveSearchInput').value.trim();
    const tbody = document.getElementById('cveDbResults');
    
    if (!query) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 30px; color: var(--text-dim);">Please enter a search term...</td></tr>';
        return;
    }
    
    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 30px; color: var(--accent);"><i class="fas fa-spinner fa-spin"></i> Searching database...</td></tr>';
    
    try {
        const resp = await fetch('/api/cvedb/search?q=' + encodeURIComponent(query));
        const data = await resp.json();
        
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 30px; color: var(--text-dim);">No matching CVEs found.</td></tr>';
            return;
        }
        
        tbody.innerHTML = '';
        data.forEach(cve => {
            let cvssColor = '#58a6ff';
            if (cve.cvss >= 9.0) cvssColor = '#ff7b72'; // Critical
            else if (cve.cvss >= 7.0) cvssColor = '#ff9b5e'; // High
            else if (cve.cvss >= 4.0) cvssColor = '#d29922'; // Medium
            
            tbody.innerHTML += `
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); cursor: pointer; transition: background 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.02)'" onmouseout="this.style.background='transparent'" data-id="${escapeHtml(cve.id)}" onclick="selectCVE(this.dataset.id)">
                    <td style="padding: 10px; color: #fff; font-family: 'Consolas', monospace;">${escapeHtml(cve.id)}</td>
                    <td style="padding: 10px; text-align: center; color: ${cvssColor}; font-weight: bold;">${cve.cvss.toFixed(1)}</td>
                    <td style="padding: 10px; color: var(--text-dim);">${escapeHtml(cve.product || '-')}</td>
                    <td style="padding: 10px; text-align: right;">
                        <button style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #10B981; padding: 4px 10px; border-radius: 4px; font-size: 11px; cursor: pointer;">
                            <i class="fas fa-crosshairs"></i> Target
                        </button>
                    </td>
                </tr>
            `;
        });
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; padding: 30px; color: #EF4444;">Error searching database: ${e}</td></tr>`;
    }
}

function selectCVE(cveId) {
    document.getElementById('targetCveInput').value = cveId;
    
    // Highlight input briefly
    const input = document.getElementById('targetCveInput');
    input.style.borderColor = '#10B981';
    setTimeout(() => {
        input.style.borderColor = 'var(--panel-border)';
    }, 500);
}

let cveCenterLoaded = false;
async function loadCVECenter() {
    if (cveCenterLoaded) return; // Load only once to save bandwidth
    
    try {
        const resp = await fetch('/api/cvedb');
        const data = await resp.json();
        
        // Update Stats
        if (data.stats) {
            document.getElementById('statTotalCve').innerText = (data.stats.total_cves || 0).toLocaleString();
            if (data.stats.severity_counts) {
                
                // Draw Donut Chart
                const ctx = document.getElementById('cveSeverityChart').getContext('2d');
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low'],
                        datasets: [{
                            data: [
                                data.stats.severity_counts.critical || 0,
                                data.stats.severity_counts.high || 0,
                                data.stats.severity_counts.medium || 0,
                                data.stats.severity_counts.low || 0
                            ],
                            backgroundColor: ['#ff7b72', '#ff9b5e', '#d29922', '#58a6ff'],
                            borderWidth: 0,
                            cutout: '75%'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { 
                                display: true, 
                                position: 'right', 
                                labels: { color: '#ccc', font: { size: 14, family: 'sans-serif' }, padding: 20 } 
                            },
                            tooltip: {
                                callbacks: {
                                    label: function(context) {
                                        return ' ' + context.label + ': ' + context.raw.toLocaleString();
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
        
        cveCenterLoaded = true;
    } catch (e) {
        console.error("Failed to load CVE Center data", e);
    }
    
    // Load KEV Data
    try {
        const kevResp = await fetch('/api/kev');
        const kevData = await kevResp.json();
        
        renderKEVList('kev-bucket-1', kevData.sinceYesterday);
        renderKEVList('kev-bucket-2', kevData.last7Days);
        renderKEVList('kev-bucket-3', kevData.last30Days);
    } catch (e) {
        console.error("Failed to load KEV data", e);
        document.getElementById('kev-bucket-1').innerHTML = `<div style="color:red; text-align:center; padding:10px; font-size: 12px;">Failed to load KEV data.</div>`;
        document.getElementById('kev-bucket-2').innerHTML = '';
        document.getElementById('kev-bucket-3').innerHTML = '';
    }
}

function renderKEVList(elementId, items) {
    const el = document.getElementById(elementId);
    if (!items || items.length === 0) {
        el.innerHTML = `<div style="text-align: center; color: var(--text-dim); padding: 20px; font-size: 12px;">No KEVs reported in this timeframe.</div>`;
        return;
    }
    
    let html = '';
    items.forEach(k => {
        let epssBadge = `<span style="background: rgba(16, 185, 129, 0.2); border: 1px solid rgba(16, 185, 129, 0.4); color: #6EE7B7; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">EPSS: ${(k.epssScore*100).toFixed(1)}%</span>`;
        if (k.epssScore >= 0.5) epssBadge = `<span style="background: rgba(220, 38, 38, 0.2); border: 1px solid rgba(220, 38, 38, 0.4); color: #FCA5A5; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">EPSS: ${(k.epssScore*100).toFixed(1)}%</span>`;
        else if (k.epssScore >= 0.1) epssBadge = `<span style="background: rgba(245, 158, 11, 0.2); border: 1px solid rgba(245, 158, 11, 0.4); color: #FCD34D; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">EPSS: ${(k.epssScore*100).toFixed(1)}%</span>`;
        
        let rwBadge = '';
        if (k.ransomwareUse === 'Known') {
            rwBadge = `<span style="margin-left: 5px; background: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;"><i class="fas fa-skull-crossbones"></i> Ransomware</span>`;
        }

        let cvssBadge = '';
        if (k.cvssScore) {
            let color = '#38BDF8';
            let bg = 'rgba(56, 189, 248, 0.2)';
            let border = 'rgba(56, 189, 248, 0.4)';
            if (k.cvssScore >= 9.0) {
                color = '#FCA5A5'; bg = 'rgba(220, 38, 38, 0.2)'; border = 'rgba(220, 38, 38, 0.4)';
            } else if (k.cvssScore >= 7.0) {
                color = '#FCD34D'; bg = 'rgba(245, 158, 11, 0.2)'; border = 'rgba(245, 158, 11, 0.4)';
            }
            cvssBadge = `<span style="margin-right: 5px; background: ${bg}; border: 1px solid ${border}; color: ${color}; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">CVSS: ${k.cvssScore.toFixed(1)}</span>`;
        }
        
        html += `
        <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); border-radius: 6px; padding: 12px; transition: all 0.2s; cursor: pointer;" onmouseover="this.style.background='rgba(255,255,255,0.08)'" onmouseout="this.style.background='rgba(255,255,255,0.03)'">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                <div style="color: #38BDF8; font-weight: bold; font-family: 'Consolas', monospace; font-size: 13px;">${escapeHtml(k.cveID)}</div>
                <div style="font-size: 10px; color: var(--text-dim);">${escapeHtml(k.dateAdded)}</div>
            </div>
            <div style="color: #fff; font-size: 13px; font-weight: bold; margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(k.product)}">
                ${escapeHtml(k.vendorProject)} - ${escapeHtml(k.product)}
            </div>
            <div style="color: var(--text-dim); font-size: 11px; margin-bottom: 10px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;" title="${escapeHtml(k.vulnerabilityName)}">
                ${escapeHtml(k.vulnerabilityName)}
            </div>
            <div style="display: flex; align-items: center;">
                ${cvssBadge}
                ${epssBadge}
                ${rwBadge}
            </div>
        </div>
        `;
    });
    
    el.innerHTML = html;
}

// ============================================================
// SUPPLY CHAIN INTERFACE (SCI)
// ============================================================

let sciCurrentData = null;

// Called when SCI view is opened
function initSCIView() {
    if (sciCurrentData) {
        renderSCIResults(sciCurrentData);
    }
}

// Analyze a target manually (standalone mode)
async function analyzeSCI() {
    const input = document.getElementById('sciTargetInput');
    let target = (input.value || '').trim();
    if (!target) { input.focus(); return; }
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
        target = 'https://' + target;
    }

    const resultsArea = document.getElementById('sciResultsArea');
    const statsBar    = document.getElementById('sciStatsBar');
    const btn         = document.getElementById('sciAnalyzeBtn');

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
    statsBar.style.display = 'none';
    resultsArea.innerHTML = `
        <div class="sci-loading">
            <div class="sci-loading-ring"></div>
            Analyzing supply chain for <strong style="color:var(--accent); margin-left:4px;">${escapeHtml(target)}</strong>...
        </div>`;

    try {
        const resp = await fetch('/api/sci?target=' + encodeURIComponent(target));
        const data = await resp.json();
        if (data.error) {
            resultsArea.innerHTML = `
                <div class="sci-empty">
                    <i class="fas fa-exclamation-triangle" style="font-size:40px; color:#F87171; display:block; margin-bottom:16px;"></i>
                    <p style="color:#F87171; font-weight:700; font-size:15px; margin:0 0 8px;">${escapeHtml(data.error)}</p>
                    <p style="font-size:13px; margin:0;">Check the target URL and try again.</p>
                </div>`;
            return;
        }
        sciCurrentData = data;
        renderSCIResults(data);
    } catch (e) {
        resultsArea.innerHTML = `
            <div class="sci-empty">
                <i class="fas fa-wifi-slash" style="font-size:40px; color:#F87171; display:block; margin-bottom:16px;"></i>
                <p style="color:#F87171; font-weight:700; font-size:15px; margin:0 0 8px;">Connection error</p>
                <p style="font-size:13px; margin:0;">${escapeHtml(e.message)}</p>
            </div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-search-plus"></i> ANALYZE';
    }
}

// Render the full SCI results
function renderSCIResults(data) {
    const resultsArea = document.getElementById('sciResultsArea');
    const statsBar    = document.getElementById('sciStatsBar');

    const s = data.risk_summary || {};
    document.getElementById('sciStatTotal').textContent     = s.total_components || 0;
    document.getElementById('sciStatWithCVEs').textContent  = s.with_cves || 0;
    document.getElementById('sciStatCritical').textContent  = s.critical || 0;
    document.getElementById('sciStatHigh').textContent      = s.high || 0;
    document.getElementById('sciStatMedium').textContent    = s.medium || 0;
    document.getElementById('sciStatTotalCVEs').textContent = data.total_cves || 0;
    statsBar.style.display = 'grid';

    if (!data.components || !data.components.length) {
        resultsArea.innerHTML = `
            <div class="sci-empty">
                <i class="fas fa-check-circle" style="font-size:48px; color:#10B981; display:block; margin-bottom:16px;"></i>
                <p style="font-size:16px; font-weight:700; color:var(--text-main); margin:0 0 8px;">No Known Components Detected</p>
                <p style="font-size:13px; margin:0;">Could not identify common frameworks, libraries, or infrastructure from the target response.</p>
            </div>`;
        return;
    }

    // Group by category
    const categories = {};
    data.components.forEach(c => {
        const cat = c.category || 'Other';
        if (!categories[cat]) categories[cat] = [];
        categories[cat].push(c);
    });

    const catOrder = ['Infrastructure','Backend','CMS','Frontend','CDN','Database','Security','Build Tool','Analytics','Payment','Storage','Other'];
    const sorted   = [...catOrder.filter(c => categories[c]), ...Object.keys(categories).filter(c => !catOrder.includes(c))];

    let html = '';
    sorted.forEach(cat => {
        const comps = categories[cat];
        if (!comps || !comps.length) return;
        const catIcon  = sciCategoryIcon(cat);
        const catColor = sciCategoryColor(cat);

        html += `
        <div class="sci-category-group">
            <div class="sci-category-header">
                <i class="fas ${catIcon}" style="color:${catColor};"></i>
                ${escapeHtml(cat)}
                <span class="sci-category-count">${comps.length}</span>
            </div>
            <div class="sci-component-grid">`;

        comps.forEach((comp, idx) => {
            const riskClass = 'risk-' + (comp.risk_level || 'unknown').toLowerCase();
            const iconBg    = sciCategoryBg(cat);
            const cardId    = 'sci-card-' + cat.replace(/\W/g,'') + '-' + idx;
            const version   = comp.version
                ? `v${escapeHtml(comp.version)}`
                : '<span style="color:rgba(148,163,184,0.35);">version unknown</span>';
            const src = comp.source ? `<div class="sci-card-source">via: ${escapeHtml(comp.source)}</div>` : '';

            let cveFooter = '';
            if (comp.cve_count > 0) {
                const c = comp.risk_level;
                const badgeColor = c==='CRITICAL'?'#EF4444':c==='HIGH'?'#F97316':c==='MEDIUM'?'#F59E0B':'#3B82F6';
                cveFooter = `
                <div class="sci-card-footer">
                    <div class="sci-cve-toggle" onclick="toggleSCICVEs('${cardId}-cves')">
                        <i class="fas fa-chevron-right" id="${cardId}-chevron" style="font-size:10px; transition:transform 0.2s;"></i>
                        <span style="color:${badgeColor}; font-weight:800;">${comp.cve_count} CVE${comp.cve_count>1?'s':''}</span>
                        <span style="color:var(--text-dim);">— CVSS max: <strong style="color:#fff;">${(comp.highest_cvss||0).toFixed(1)}</strong></span>
                        <span style="margin-left:auto; font-size:10px; color:rgba(148,163,184,0.4);">click to expand</span>
                    </div>
                    <div class="sci-cve-list" id="${cardId}-cves">${renderCVEList(comp.cves)}</div>
                </div>`;
            } else {
                cveFooter = `
                <div class="sci-card-footer">
                    <span style="font-size:11px; color:rgba(16,185,129,0.7); font-weight:600;">
                        <i class="fas fa-shield-check"></i> No CVEs found
                    </span>
                </div>`;
            }

            html += `
            <div class="sci-component-card ${riskClass}">
                <div class="sci-card-header">
                    <div class="sci-card-icon" style="background:${iconBg}; color:${catColor}; border:1px solid ${catColor}33;">
                        <i class="fas ${sciCategoryIcon(cat)}"></i>
                    </div>
                    <div class="sci-card-info">
                        <div class="sci-card-name" title="${escapeHtml(comp.name)}">${escapeHtml(comp.name)}</div>
                        <div class="sci-card-version">${version}</div>
                        ${src}
                    </div>
                    <div class="sci-risk-badge ${riskClass}">${escapeHtml(comp.risk_level||'UNKNOWN')}</div>
                </div>
                ${cveFooter}
            </div>`;
        });
        html += `</div></div>`;
    });

    if (data.scan_duration) {
        html += `<div style="text-align:center; color:rgba(148,163,184,0.35); font-size:11px; padding:20px 0;">
            Analysis completed in ${escapeHtml(data.scan_duration)}
        </div>`;
    }
    resultsArea.innerHTML = html;
}

// Render CVE rows for a component
function renderCVEList(cves) {
    if (!cves || !cves.length) return '';
    return cves.map(cve => {
        const sc = cve.severity||'';
        const sevColor = sc==='CRITICAL'?'#EF4444':sc==='HIGH'?'#F97316':sc==='MEDIUM'?'#F59E0B':sc==='LOW'?'#3B82F6':'#94A3B8';
        const cvss = cve.cvss != null ? Number(cve.cvss).toFixed(1) : '-';
        const desc = (cve.description||'').substring(0,200) + ((cve.description||'').length>200?'...':'');
        return `
        <div class="sci-cve-item">
            <div class="sci-cve-top">
                <span class="sci-cve-id">${escapeHtml(cve.id||'')}</span>
                <span class="sci-cve-severity" style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}55;">${escapeHtml(sc||'?')}</span>
                <span class="sci-cve-cvss" style="color:${sevColor};">CVSS ${cvss}</span>
            </div>
            <div class="sci-cve-desc">${escapeHtml(desc)}</div>
        </div>`;
    }).join('');
}

// Toggle CVE accordion
function toggleSCICVEs(listId) {
    const list    = document.getElementById(listId);
    const chevron = document.getElementById(listId.replace('-cves','-chevron'));
    if (!list) return;
    const isOpen = list.classList.toggle('open');
    if (chevron) chevron.style.transform = isOpen ? 'rotate(90deg)' : 'rotate(0deg)';
}

// Clear SCI results
function clearSCI() {
    sciCurrentData = null;
    document.getElementById('sciTargetInput').value = '';
    document.getElementById('sciStatsBar').style.display = 'none';
    document.getElementById('sciResultsArea').innerHTML = `
        <div class="sci-empty">
            <i class="fas fa-link sci-empty-icon"></i>
            <p style="font-size:17px; font-weight:700; color:var(--text-main); margin:0 0 8px;">Supply Chain Analysis</p>
            <p style="font-size:13px; margin:0 0 20px;">Enter a target URL above and click Analyze to detect all components — frameworks, libraries, CDN, analytics, and their CVEs.</p>
        </div>`;
}

// Category helpers
function sciCategoryIcon(cat) {
    return { Infrastructure:'fa-server', Backend:'fa-code', CMS:'fa-newspaper', Frontend:'fa-laptop-code',
             CDN:'fa-network-wired', Database:'fa-database', Analytics:'fa-chart-line', Security:'fa-shield-halved',
             'Build Tool':'fa-hammer', Payment:'fa-credit-card', Storage:'fa-cloud' }[cat] || 'fa-cube';
}
function sciCategoryColor(cat) {
    return { Infrastructure:'#60A5FA', Backend:'#A78BFA', CMS:'#FBBF24', Frontend:'#34D399',
             CDN:'#38BDF8', Database:'#F87171', Analytics:'#FB923C', Security:'#4ADE80',
             'Build Tool':'#94A3B8', Payment:'#F472B6', Storage:'#67E8F9' }[cat] || '#94A3B8';
}
function sciCategoryBg(cat) {
    const c = sciCategoryColor(cat);
    // convert hex to rgba with low alpha
    const r = parseInt(c.slice(1,3),16), g = parseInt(c.slice(3,5),16), b = parseInt(c.slice(5,7),16);
    return `rgba(${r},${g},${b},0.1)`;
}


