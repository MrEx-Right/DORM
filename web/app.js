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
                    Chart.defaults.plugins.legend.onClick.call(this, e, legendItem, legend);

                    const index = legendItem.index;
                    const meta = vulnChart.getDatasetMeta(0);
                    const isHidden = meta.data[index].hidden; // Chart.js 3+
                    const severity = vulnChart.data.labels[index];

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
                    Chart.defaults.plugins.legend.onClick.call(this, e, legendItem, legend);

                    const index = legendItem.index;
                    const meta = detailVulnChart.getDatasetMeta(0);
                    const isHidden = meta.data[index].hidden; 
                    const severity = detailVulnChart.data.labels[index];

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
    if (viewName === 'cvedb') loadCVEDatabase();
    if (viewName === 'sitemap') initSitemapView();
}

// --- HELPER FUNCTIONS ---
function escapeHtml(text) {
    if (!text) return text;
    const div = document.createElement('div');
    div.innerText = text;
    return div.innerHTML;
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
                            <button onclick="viewScan('${rec.id}')" class="btn-icon" style="background: rgba(59, 130, 246, 0.2); color: var(--accent); border: 1px solid rgba(59, 130, 246, 0.3);" title="View Details"><i class="fas fa-eye"></i></button>
                            <button onclick="deleteScan('${rec.id}')" class="btn-danger btn-icon" title="Delete Scan"><i class="fas fa-trash"></i></button>
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
                const tc = `type-${(inp.type||'text').toLowerCase()}`;
                return `<span class="sm-input-tag ${tc}">${escapeHtml(inp.name)}${inp.type ? ':'+inp.type : ''}</span>`;
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
        
    // Restore open accordions
    openJS.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add('open');
    });
}
