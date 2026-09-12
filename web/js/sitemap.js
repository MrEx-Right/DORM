// =============================================
// SITEMAP LOGIC
// =============================================
let currentSiteMapData = null;

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
