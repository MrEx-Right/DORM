// --- TARGET GROUPING / FILTERING ---
// Renders the "ALL / host (count)" tab bar for a results table, and wires
// each tab to filter that table's rows by host. `counts` is a plain object
// of host -> count (insertion order preserved by V8/modern engines).
function renderTargetTabs(containerId, counts, activeFilter, onSelect) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const hosts = Object.keys(counts);
    if (hosts.length < 2) {
        // Nothing to disambiguate with a single target — stay out of the way.
        container.style.display = 'none';
        container.innerHTML = '';
        return;
    }

    container.style.display = 'flex';
    const total = hosts.reduce((sum, h) => sum + counts[h], 0);

    let html = `<span class="target-tab${activeFilter === 'ALL' ? ' active' : ''}" data-target-tab="ALL">
        <i class="fas fa-layer-group"></i> All <span class="target-tab-count">${total}</span>
    </span>`;
    hosts.forEach(host => {
        html += `<span class="target-tab${activeFilter === host ? ' active' : ''}" data-target-tab="${escapeHtml(host)}">
            ${escapeHtml(host)} <span class="target-tab-count">${counts[host]}</span>
        </span>`;
    });
    container.innerHTML = html;

    container.querySelectorAll('.target-tab').forEach(tab => {
        tab.onclick = () => onSelect(tab.dataset.targetTab);
    });
}

function selectLiveTarget(host) {
    liveTargetFilter = host;
    renderTargetTabs('targetTabs', liveTargetCounts, liveTargetFilter, selectLiveTarget);
    applyResultFilters('#tableBody', vulnChart, liveTargetFilter);
}

function selectDetailTarget(host) {
    detailTargetFilter = host;
    renderTargetTabs('detailTargetTabs', detailTargetCounts, detailTargetFilter, selectDetailTarget);
    applyResultFilters('#detailTableBody', detailVulnChart, detailTargetFilter);
}

// Whether a single row should be visible under the current Chart.js
// severity-legend state plus the selected target-tab host.
function isRowVisible(row, chart, targetFilter) {
    const idx = chart.data.labels.indexOf(row.dataset.severity);
    const severityVisible = idx === -1 ? true : chart.getDataVisibility(idx);
    return severityVisible && (targetFilter === 'ALL' || row.dataset.target === targetFilter);
}

// Recomputes row visibility for EVERY row in one results table — used when
// a filter control itself changes (severity legend click, target tab
// click). Also collapses any open detail rows, matching the existing
// severity-toggle behavior of always closing details on a filter change.
// Do NOT call this per-incoming-result during a live scan — it would
// collapse a detail panel the user has open while new findings stream in;
// use isRowVisible() on just the new row for that instead.
function applyResultFilters(tableBodySelector, chart, targetFilter) {
    document.querySelectorAll(tableBodySelector + ' .vuln-row').forEach(row => {
        const visible = isRowVisible(row, chart, targetFilter);
        row.style.display = visible ? 'table-row' : 'none';
        if (!visible) row.classList.remove('open');
    });
    document.querySelectorAll(tableBodySelector + ' .detail-row').forEach(row => {
        row.style.display = 'none';
    });
}
