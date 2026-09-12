// ============================================================
// LEGACY / DEAD CODE — verified unreferenced as of the web/js/ split.
// Not called from any onclick/onchange/onkeypress attribute in
// dashboard.html, and not called from any onclick string generated
// dynamically elsewhere in web/js/*.js.
//   - toggleCveSection: targets #cveContainer/#cveArrow, which do not
//     exist anywhere in dashboard.html.
//   - loadCVEDatabase / searchCVEs / renderCVELines: target
//     #cveTableBody/#cveStats, which also do not exist in dashboard.html.
// Kept wired via a <script> tag for exact behavioral parity with the
// pre-split app.js. Safe to delete this file and its one <script> tag
// in dashboard.html once you've independently confirmed the above.
// ============================================================

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
