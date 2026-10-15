// --- HISTORY LOGIC ---

// A scan interrupted before it could set a real EndTime (crash, stop, app
// restart) either has status !== 'Completed' or an end_time that is Go's
// zero-value timestamp — computing a diff against that produces a bogus
// multi-billion-second duration, so guard against both explicitly.
function formatScanDuration(rec) {
    if (rec.status === 'Running') return 'Running...';
    if (rec.status !== 'Completed') return '-';
    if (!rec.end_time || rec.end_time.startsWith('0001-01-01')) return '-';

    const diff = Math.round((new Date(rec.end_time) - new Date(rec.start_time)) / 1000);
    if (!Number.isFinite(diff) || diff < 0) return '-';
    return diff + 's';
}

async function loadHistory() {
    const tbody = document.getElementById('historyBody');
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:#3B82F6;">Loading history...</td></tr>';
    try {
        const records = await apiJSON('/api/history');
        window.allScanRecords = records || [];
        tbody.innerHTML = '';
        if (!records || records.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:#8b949e;">No scan history found.</td></tr>';
            return;
        }
        records.forEach(rec => {
            const date = new Date(rec.start_time).toLocaleString();
            const duration = formatScanDuration(rec);
            const stats = rec.severity_stats || {};
            const statusClass = rec.status === 'Completed' ? 'status-completed'
                : rec.status === 'Running' ? 'status-running'
                : 'status-stopped';
            const html = `
                <tr>
                    <td class="${statusClass}">${escapeHtml(rec.status)}</td>
                    <td style="color:#fff; font-weight:bold;">${escapeHtml(rec.target)}</td>
                    <td style="color:var(--text-dim); font-size:0.9em;">${escapeHtml(date)}</td>
                    <td style="font-family:'Consolas'">${escapeHtml(duration)}</td>
                    <td>
                        <span style="color:#EF4444; font-weight:bold;">${Number(stats['CRITICAL']) || 0}</span> /
                        <span style="color:#F97316; font-weight:bold;">${Number(stats['HIGH']) || 0}</span>
                        <span style="color:var(--text-dim); font-size:0.8em; margin-left:5px;">(Total: ${Number(rec.total_vulns) || 0})</span>
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
        tbody.innerHTML = `<tr><td colspan="6" style="color:red">Error loading history: ${escapeHtml(errMsg(e))}</td></tr>`;
    }
}

async function deleteScan(id) {
    if (!confirm("Are you sure you want to delete this scan record?")) return;
    try {
        await apiFetch('/api/history/delete?id=' + encodeURIComponent(id), { method: 'POST' });
    } catch (e) {
        showToast("Failed to delete scan: " + errMsg(e), 'error');
    }
    loadHistory();
}

async function deleteAllHistory() {
    if (!confirm("CRITICAL ACTION: Are you sure you want to PERMANENTLY DELETE all scan history? This cannot be undone.")) return;
    try {
        await apiFetch('/api/history/delete_all', { method: 'POST' });
        loadHistory();
    } catch (e) {
        showToast("Failed to delete history: " + errMsg(e), 'error');
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
            const f = normalizeFinding(data);
            const host = f.host;

            document.getElementById('detailTableBody').insertAdjacentHTML('beforeend',
                buildVulnRowHTML(f, `detail-row-${detailVulnCount}`, `detail-detail-${detailVulnCount}`,
                    `toggleDetail('detail-detail-${detailVulnCount}', 'detail-row-${detailVulnCount}')`));
            detailTargetCounts[host] = (detailTargetCounts[host] || 0) + 1;

            if (f.severityIndex !== -1) { detailVulnChart.data.datasets[0].data[f.severityIndex]++; }
        });
    }

    detailVulnChart.update();
    renderTargetTabs('detailTargetTabs', detailTargetCounts, detailTargetFilter, selectDetailTarget);

    // Set timer display based on duration
    if (rec.status === 'Completed' && rec.start_time && rec.end_time && !rec.end_time.startsWith('0001-01-01')) {
        const diff = Math.round((new Date(rec.end_time) - new Date(rec.start_time)) / 1000);
        const m = Math.floor(diff / 60).toString().padStart(2, '0');
        const s = (diff % 60).toString().padStart(2, '0');
        document.getElementById('detailTimer').innerText = (diff >= 0) ? `${m}:${s}` : '--:--';
    } else if (rec.status === 'Running') {
        document.getElementById('detailTimer').innerText = 'Running...';
    } else {
        document.getElementById('detailTimer').innerText = '--:--';
    }
}
