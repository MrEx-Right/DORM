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
