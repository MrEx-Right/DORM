// --- GLOBAL VARIABLES ---
let timerInterval, timerSeconds = 0, vulnCount = 0, scanResults = [];
let scanEventSource = null; // <--- MADE GLOBAL (To enable stopping)

const ctx = document.getElementById('vulnChart').getContext('2d');

// --- CHART CONFIG ---
let vulnChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], datasets: [{ data: [0,0,0,0,0], backgroundColor: ['#ff7b72', '#ff9b5e', '#d29922', '#e3b341', '#58a6ff'], borderWidth: 0 }] },
    options: { 
        responsive: true, 
        maintainAspectRatio: false, 
        plugins: { 
            legend: { 
                position: 'right', 
                labels: { color: '#c9d1d9', font: {family: 'Segoe UI'} },
                onClick: function(e, legendItem, legend) {
                    Chart.defaults.plugins.legend.onClick.call(this, e, legendItem, legend);
                    
                    const index = legendItem.index;
                    const meta = vulnChart.getDatasetMeta(0);
                    const isHidden = meta.data[index].hidden; // Chart.js 3+
                    const severity = vulnChart.data.labels[index];
                    
                    const rows = document.querySelectorAll('.vuln-row[data-severity="'+severity+'"]');
                    const detailRows = document.querySelectorAll('.detail-row[data-severity="'+severity+'"]');
                    
                    rows.forEach(r => { r.style.display = isHidden ? 'none' : 'table-row'; });
                    // Close details if hidden
                    detailRows.forEach(r => { r.style.display = 'none'; });
                    if(isHidden) {
                        rows.forEach(r => r.classList.remove('open'));
                    }
                }
            } 
        } 
    }
});

// --- INITIALIZATION ---
window.onload = async () => {
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
                    <input type="checkbox" checked onchange="toggleCategory(this, '${catClass}')" style="margin:0;"> Grup Seç / Bırak
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

    loadHistory();
};

window.toggleCategory = function(cb, catClass) {
    document.querySelectorAll('.category-' + catClass + ' .plugin-check').forEach(input => {
        input.checked = cb.checked;
        input.closest('.plugin-item').classList.toggle('active-plugin', cb.checked);
    });
};

// --- VIEW SWITCHING ---
function switchView(viewName) {
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    event.currentTarget.classList.add('active');
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    document.getElementById('view-' + viewName).classList.add('active');
    if(viewName === 'history') loadHistory();
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

function toggleDetail(id) { 
    const row = document.getElementById('detail-' + id); 
    const parent = document.getElementById('row-' + id);
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
        tbody.innerHTML = '';
        if(!records || records.length === 0) {
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
                    <td style="text-align:right;">
                        <button onclick="deleteScan('${rec.id}')" class="btn-danger btn-icon" title="Delete Scan"><i class="fas fa-trash"></i></button>
                    </td>
                </tr>`;
            tbody.insertAdjacentHTML('beforeend', html);
        });
    } catch(e) {
        tbody.innerHTML = `<tr><td colspan="6" style="color:red">Error loading history: ${e}</td></tr>`;
    }
}

async function deleteScan(id) {
    if(!confirm("Are you sure you want to delete this scan record?")) return;
    await fetch('/api/history/delete?id=' + id, { method: 'POST' });
    loadHistory(); 
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

    const rotateUA = document.getElementById('uaToggle').checked;
    const speed = "300"; 
    const authHeader = document.getElementById('authInput').value;

    // 2. Get selected plugins from grid
    const selected = Array.from(document.querySelectorAll('.plugin-check:checked')).map(c => c.value);

    // 3. MULTI-TARGET LOGIC: Split by newline, trim, and remove empty lines
    const targetsArray = rawTargets.split('\n').map(t => t.trim()).filter(t => t !== '');
    if (targetsArray.length === 0) return alert("Please enter at least one target!");
    
    // Join multiple targets with a comma to send via GET request
    const targetString = targetsArray.join(',');
    
    document.getElementById('tableBody').innerHTML = '';
    vulnCount = 0; scanResults = [];
    vulnChart.data.datasets[0].data = [0,0,0,0,0];
    vulnChart.update();
    
    // UI: Switch to STOP SCAN Mode
    btn.innerHTML = '<i class="fas fa-stop"></i> STOP SCAN';
    btn.classList.remove('btn-success'); 
    btn.classList.add('btn-danger');     
    btn.style.backgroundColor = '#da3633'; 

    timerSeconds = 0; clearInterval(timerInterval);
    timerInterval = setInterval(() => {
        timerSeconds++;
        const m = Math.floor(timerSeconds/60).toString().padStart(2,'0');
        const s = (timerSeconds%60).toString().padStart(2,'0');
        document.getElementById('timerDisplay').innerText = `${m}:${s}`;
    }, 1000);

    // Get Proxy URL and state from the Proxy Settings view
    const proxyEnabled = document.getElementById('proxyToggle').checked;
    const proxyUrl = document.getElementById('proxyUrlInput').value || "http://127.0.0.1:8081";

    // Assign to global variable (Notice: query param is now "targets")
    scanEventSource = new EventSource(`/scan?targets=${encodeURIComponent(targetString)}&plugins=${encodeURIComponent(selected.join(","))}&delay=${speed}&rotateUA=${rotateUA}&auth=${encodeURIComponent(authHeader)}&proxyEnabled=${proxyEnabled}&proxyUrl=${encodeURIComponent(proxyUrl)}`);

    scanEventSource.onmessage = (e) => {
        const data = JSON.parse(e.data);
        
        if(data.Status === "DONE") { 
            finishScanUI(); // Reset UI
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
        
        const idx = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].indexOf(data.Severity.toUpperCase());
        if(idx !== -1) { vulnChart.data.datasets[0].data[idx]++; vulnChart.update(); }
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
    link.href = URL.createObjectURL(new Blob([html], {type:"text/html"}));
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
        didParseCell: function(data) {
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
    for(let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8); doc.setTextColor(150);
        doc.text(`Page ${i} of ${pageCount} - Generated by DORM Scanner`, 105, 290, null, null, "center");
    }
    doc.save(`DORM_Report_${Date.now()}.pdf`);
}

function checkAllPlugins(state) {
    document.querySelectorAll('.plugin-check').forEach(cb => {
        cb.checked = state;
        cb.closest('.plugin-item').classList.toggle('active-plugin', state);
    });
}
