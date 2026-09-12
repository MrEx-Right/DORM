// --- HISTORY LOGIC ---
async function loadHistory() {
    const tbody = document.getElementById('historyBody');
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:#3B82F6;">Loading history...</td></tr>';
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
                        <span style="color:#EF4444; font-weight:bold;">${rec.severity_stats['CRITICAL'] || 0}</span> /
                        <span style="color:#F97316; font-weight:bold;">${rec.severity_stats['HIGH'] || 0}</span>
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
    detailTargetFilter = 'ALL';
    detailTargetCounts = {};

    if (rec.vulnerabilities && rec.vulnerabilities.length > 0) {
        rec.vulnerabilities.forEach(data => {
            detailVulnCount++;
            detailResults.push(data);
            const badgeClass = "sev-" + escapeHtml(data.Severity.toUpperCase());
            const host = data.Target.IP;
            let engineLabel = 'Plugin';
            if (data.Name.includes("Exploit")) engineLabel = 'EDB';
            else if (data.Name.includes("Spider")) engineLabel = 'Spider';

            const html = `
                <tr class="vuln-row" data-severity="${escapeHtml(data.Severity.toUpperCase())}" data-target="${escapeHtml(host)}" id="detail-row-${detailVulnCount}" onclick="toggleDetail('detail-detail-${detailVulnCount}', 'detail-row-${detailVulnCount}')">
                    <td><span class="badge ${badgeClass}">${escapeHtml(data.Severity)}</span></td>
                    <td style="font-weight:bold; color:#fff;">${data.CVSS.toFixed(1)}</td>
                    <td style="color:#fff;">${escapeHtml(data.Name)}</td>
                    <td style="color:var(--text-dim); font-size:0.9em;">${engineLabel}</td>
                    <td>${escapeHtml(data.Target.IP)}:${data.Target.Port}</td>
                    <td class="arrow"><i class="fas fa-chevron-down"></i></td>
                </tr>
                <tr class="detail-row" data-severity="${escapeHtml(data.Severity.toUpperCase())}" data-target="${escapeHtml(host)}" id="detail-detail-${detailVulnCount}">
                    <td colspan="6" style="padding:0; border:none;">
                        <div class="detail-content">
                            <strong style="color:var(--accent)">ANALYSIS:</strong><br>${escapeHtml(data.Description).replace(/\n/g, '<br>')}<br><br>
                            <strong style="color:var(--success)">SOLUTION:</strong><br>${escapeHtml(data.Solution || "Apply patches.")}<br><br>
                            <em style="font-size:0.8em">Ref: ${escapeHtml(data.Reference)}</em>
                        </div>
                    </td>
                </tr>`;
            document.getElementById('detailTableBody').insertAdjacentHTML('beforeend', html);
            detailTargetCounts[host] = (detailTargetCounts[host] || 0) + 1;

            const idx = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(data.Severity.toUpperCase());
            if (idx !== -1) { detailVulnChart.data.datasets[0].data[idx]++; }
        });
    }

    detailVulnChart.update();
    renderTargetTabs('detailTargetTabs', detailTargetCounts, detailTargetFilter, selectDetailTarget);

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
