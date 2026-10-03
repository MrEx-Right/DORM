// --- SCAN TEMPLATES (personal, UI-built vulnerability checks) ---
// A "Scan Template" is DORM's UI-built equivalent of a single-request
// Nuclei YAML template: an HTTP request definition + a matcher condition,
// built entirely with dropdowns/toggles/textboxes instead of hand-written
// YAML. This whole page is self-contained (mirroring cve-center.js) —
// building, managing AND running templates all happen right here. The
// "run" side is deliberately styled as a terminal/console rather than a
// copy of the New Scan page's control-panel + table, so it never reads as
// a second, parallel scan screen.

let cachedTemplateOptions = null;
let cachedTemplateList = [];
let selectedTemplateIds = new Set();

async function initTemplatesView() {
    if (!cachedTemplateOptions) {
        try {
            const resp = await fetch('/api/templates/options');
            cachedTemplateOptions = await resp.json();
        } catch (e) {
            console.error('Failed to load template builder options:', e);
            cachedTemplateOptions = { methods: ['GET', 'POST'], severities: ['MEDIUM'], matcherTypes: ['word'], matcherParts: ['body'], conditions: ['OR'] };
        }
    }
    await loadTemplateList();
}

async function loadTemplateList() {
    const empty = document.getElementById('templateListEmpty');
    try {
        const resp = await fetch('/api/templates');
        cachedTemplateList = await resp.json() || [];
    } catch (e) {
        console.error('Failed to load templates:', e);
        cachedTemplateList = [];
    }

    // Drop selections for templates deleted since the last render.
    const validIds = new Set(cachedTemplateList.map(t => t.id));
    selectedTemplateIds.forEach(id => { if (!validIds.has(id)) selectedTemplateIds.delete(id); });

    renderTemplateList(cachedTemplateList);
    empty.style.display = cachedTemplateList.length === 0 ? 'block' : 'none';
    document.getElementById('templateSelectAllToggle').style.display = cachedTemplateList.length === 0 ? 'none' : 'inline';
    onTemplateSelectionChange();
}

function severityColor(sev) {
    switch ((sev || '').toUpperCase()) {
        case 'CRITICAL': return '#EF4444';
        case 'HIGH': return '#F97316';
        case 'MEDIUM': return '#F59E0B';
        case 'LOW': return '#3B82F6';
        default: return '#94A3B8';
    }
}

function renderTemplateList(list) {
    const grid = document.getElementById('templateListGrid');
    grid.innerHTML = list.map(t => {
        const color = severityColor(t.severity);
        const checked = selectedTemplateIds.has(t.id);
        return `
            <div class="tpl-list-item${checked ? ' selected' : ''}" style="display:flex; align-items:flex-start; gap:10px; padding:11px; border:1px solid var(--panel-border); border-radius:8px; background:rgba(0,0,0,0.18);">
                <input type="checkbox" class="tpl-select-check custom-checkbox" value="${t.id}" ${checked ? 'checked' : ''} onchange="onTemplateSelectionChange()" style="margin-top:3px; flex-shrink:0;">
                <div style="flex:1; min-width:0;">
                    <div style="display:flex; justify-content:space-between; align-items:center; gap:6px;">
                        <span style="font-weight:600; color:#fff; font-size:13px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(t.name)}</span>
                        <span style="font-size:9px; font-weight:700; color:${color}; border:1px solid ${color}; padding:1px 6px; border-radius:4px; white-space:nowrap; flex-shrink:0;">${escapeHtml(t.severity || 'INFO')}</span>
                    </div>
                    <div style="font-size:11px; color:var(--text-dim); margin-top:5px; font-family:'Consolas',monospace; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(t.request?.method || 'GET')} ${escapeHtml(t.request?.path || '/')}</div>
                    <div style="display:flex; gap:14px; margin-top:9px;">
                        <span onclick="openTemplateEditor('${t.id}')" style="font-size:11px; color:var(--accent); cursor:pointer;"><i class="fas fa-pen"></i> Edit</span>
                        <span onclick="deleteTemplate('${t.id}')" style="font-size:11px; color:var(--danger); cursor:pointer;"><i class="fas fa-trash"></i> Delete</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function getSelectedTemplateIds() {
    return Array.from(document.querySelectorAll('.tpl-select-check:checked')).map(c => c.value);
}

function onTemplateSelectionChange() {
    document.querySelectorAll('.tpl-select-check').forEach(cb => {
        cb.closest('.tpl-list-item').classList.toggle('selected', cb.checked);
    });
    selectedTemplateIds = new Set(getSelectedTemplateIds());

    const n = selectedTemplateIds.size;
    const hint = document.getElementById('tplScanHint');
    const scanBtn = document.getElementById('tplScanBtn');
    if (n === 0) {
        hint.textContent = 'Select at least one template on the left to enable RUN.';
    } else {
        hint.textContent = `${n} template${n > 1 ? 's' : ''} selected — the full plugin suite is skipped, only ${n > 1 ? 'these run' : 'this runs'}.`;
    }
    if (scanBtn && !scanBtn.classList.contains('tpl-running')) {
        scanBtn.disabled = (n === 0);
        scanBtn.style.opacity = (n === 0) ? '0.45' : '1';
    }

    const allToggle = document.getElementById('templateSelectAllToggle');
    const total = document.querySelectorAll('.tpl-select-check').length;
    allToggle.textContent = (total > 0 && n === total) ? 'Deselect all' : 'Select all';
}

function toggleSelectAllTemplates() {
    const boxes = document.querySelectorAll('.tpl-select-check');
    const allChecked = Array.from(boxes).every(cb => cb.checked) && boxes.length > 0;
    boxes.forEach(cb => { cb.checked = !allChecked; });
    onTemplateSelectionChange();
}

function fillSelect(id, options, selected) {
    const el = document.getElementById(id);
    el.innerHTML = options.map(o => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join('');
    if (selected) el.value = selected;
}

function addTemplateHeaderRow(key, value) {
    const container = document.getElementById('tplHeadersList');
    const row = document.createElement('div');
    row.className = 'tpl-header-row';
    row.style.cssText = 'display:flex; gap:6px;';
    row.innerHTML = `
        <input type="text" class="tpl-header-key" placeholder="Header-Name" value="${escapeHtml(key || '')}" style="flex:1;">
        <input type="text" class="tpl-header-value" placeholder="value (supports {{payload}})" value="${escapeHtml(value || '')}" style="flex:2; font-family:'Consolas',monospace;">
        <span onclick="this.closest('.tpl-header-row').remove()" style="cursor:pointer; color:var(--danger); padding:6px 8px;"><i class="fas fa-times"></i></span>
    `;
    container.appendChild(row);
}

function collectHeadersFromRows() {
    const headers = {};
    document.querySelectorAll('#tplHeadersList .tpl-header-row').forEach(row => {
        const key = row.querySelector('.tpl-header-key').value.trim();
        const value = row.querySelector('.tpl-header-value').value;
        if (key) headers[key] = value;
    });
    return headers;
}

function onMatcherTypeChange() {
    const type = document.getElementById('tplMatcherType').value;
    document.getElementById('tplMatcherPartWrap').style.display = (type === 'status_code') ? 'none' : 'block';
}

function resetTemplateEditorForm() {
    document.getElementById('tplEditingId').value = '';
    document.getElementById('tplName').value = '';
    document.getElementById('tplCVSS').value = '';
    document.getElementById('tplDescription').value = '';
    document.getElementById('tplSolution').value = '';
    document.getElementById('tplReference').value = '';
    document.getElementById('tplPath').value = '';
    document.getElementById('tplBody').value = '';
    document.getElementById('tplPayloads').value = '';
    document.getElementById('tplMatcherValues').value = '';
    document.getElementById('tplMatcherNegate').checked = false;
    document.getElementById('tplHeadersList').innerHTML = '';

    fillSelect('tplSeverity', cachedTemplateOptions.severities, 'MEDIUM');
    fillSelect('tplMethod', cachedTemplateOptions.methods, 'GET');
    fillSelect('tplMatcherType', cachedTemplateOptions.matcherTypes, 'word');
    fillSelect('tplMatcherPart', cachedTemplateOptions.matcherParts, 'body');
    fillSelect('tplMatcherCondition', cachedTemplateOptions.conditions, 'OR');
    onMatcherTypeChange();
}

async function openTemplateEditor(id) {
    if (!cachedTemplateOptions) await initTemplatesView();
    resetTemplateEditorForm();

    document.getElementById('templateEditorTitle').textContent = id ? 'Edit Scan Template' : 'New Scan Template';

    if (id) {
        try {
            const resp = await fetch('/api/templates/get?id=' + encodeURIComponent(id));
            if (!resp.ok) throw new Error('Template not found');
            const t = await resp.json();

            document.getElementById('tplEditingId').value = t.id;
            document.getElementById('tplName').value = t.name || '';
            document.getElementById('tplSeverity').value = t.severity || 'MEDIUM';
            document.getElementById('tplCVSS').value = t.cvss || '';
            document.getElementById('tplDescription').value = t.description || '';
            document.getElementById('tplSolution').value = t.solution || '';
            document.getElementById('tplReference').value = t.reference || '';

            const req = t.request || {};
            document.getElementById('tplMethod').value = req.method || 'GET';
            document.getElementById('tplPath').value = req.path || '';
            document.getElementById('tplBody').value = req.body || '';
            document.getElementById('tplPayloads').value = (req.payloads || []).join('\n');
            Object.entries(req.headers || {}).forEach(([k, v]) => addTemplateHeaderRow(k, v));

            const m = t.matcher || {};
            document.getElementById('tplMatcherType').value = m.type || 'word';
            document.getElementById('tplMatcherPart').value = m.part || 'body';
            document.getElementById('tplMatcherCondition').value = m.condition || 'OR';
            document.getElementById('tplMatcherValues').value = (m.values || []).join('\n');
            document.getElementById('tplMatcherNegate').checked = !!m.negate;
            onMatcherTypeChange();
        } catch (e) {
            alert('Failed to load template: ' + e);
            return;
        }
    }

    document.getElementById('templateEditorModal').style.display = 'flex';
}

function closeTemplateEditor() {
    document.getElementById('templateEditorModal').style.display = 'none';
}

function collectTemplateFormToObject() {
    const linesToArray = (val) => val.split('\n').map(s => s.trim()).filter(s => s !== '');

    return {
        id: document.getElementById('tplEditingId').value || undefined,
        name: document.getElementById('tplName').value.trim(),
        severity: document.getElementById('tplSeverity').value,
        cvss: parseFloat(document.getElementById('tplCVSS').value) || 0,
        description: document.getElementById('tplDescription').value,
        solution: document.getElementById('tplSolution').value,
        reference: document.getElementById('tplReference').value,
        request: {
            method: document.getElementById('tplMethod').value,
            path: document.getElementById('tplPath').value,
            headers: collectHeadersFromRows(),
            body: document.getElementById('tplBody').value,
            payloads: linesToArray(document.getElementById('tplPayloads').value)
        },
        matcher: {
            type: document.getElementById('tplMatcherType').value,
            part: document.getElementById('tplMatcherPart').value,
            condition: document.getElementById('tplMatcherCondition').value,
            values: linesToArray(document.getElementById('tplMatcherValues').value),
            negate: document.getElementById('tplMatcherNegate').checked
        }
    };
}

async function saveTemplate() {
    const tpl = collectTemplateFormToObject();
    if (!tpl.name) {
        alert('Please give this template a name.');
        return;
    }
    if (!tpl.request.path) {
        alert('Please set a request path.');
        return;
    }

    const isUpdate = !!tpl.id;
    try {
        const resp = await fetch(isUpdate ? '/api/templates/update' : '/api/templates', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(tpl)
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Save failed');

        closeTemplateEditor();
        await loadTemplateList();
    } catch (e) {
        alert('Failed to save template: ' + e.message);
    }
}

async function deleteTemplate(id) {
    if (!confirm('Delete this template? This cannot be undone.')) return;
    try {
        await fetch('/api/templates/delete?id=' + encodeURIComponent(id), { method: 'POST' });
        await loadTemplateList();
    } catch (e) {
        alert('Failed to delete template: ' + e);
    }
}

// --- RUN SCAN — console-style runner, scoped to this page only ---
// Runs ONLY the templates checked above against the target(s) entered in
// the prompt. Reuses the existing /scan SSE endpoint with a plugin-name
// value no real static plugin can ever match, so the static-plugin filter
// excludes every built-in plugin — handleScan then re-adds each selected
// template's own name to AllowedPlugins, so only those run (see
// handlers.go's customTemplates handling). The pre-scan DOM-Crawler step is
// also skipped server-side whenever customTemplates is present.
let tplScanEventSource = null;
let tplTimerInterval = null;
let tplTimerSeconds = 0;
let tplRunCount = 0;

function startTemplateScan() {
    const btn = document.getElementById('tplScanBtn');

    if (btn.classList.contains('tpl-running')) {
        stopTemplateScan();
        return;
    }

    const ids = getSelectedTemplateIds();
    if (ids.length === 0) {
        alert('Select at least one template first.');
        return;
    }

    const rawTarget = document.getElementById('tplTargetInput').value;
    const targetsArray = rawTarget.split(',').map(t => t.trim()).filter(t => t !== '');
    if (targetsArray.length === 0) {
        alert('Enter a target first.');
        return;
    }
    const targetString = targetsArray.join(',');

    tplRunCount = 0;
    document.getElementById('tplConsoleFeed').innerHTML = `<div style="color:#4B5563;">// scanning ${escapeHtml(targetString)} with ${ids.length} template${ids.length > 1 ? 's' : ''}...</div>`;

    btn.classList.add('tpl-running');
    btn.innerHTML = '<i class="fas fa-stop"></i> STOP';
    btn.style.background = '#da3633';
    btn.style.borderColor = '#da3633';
    btn.style.opacity = '1';

    tplTimerSeconds = 0;
    clearInterval(tplTimerInterval);
    tplTimerInterval = setInterval(() => {
        tplTimerSeconds++;
        const m = Math.floor(tplTimerSeconds / 60).toString().padStart(2, '0');
        const s = (tplTimerSeconds % 60).toString().padStart(2, '0');
        document.getElementById('tplScanTimer').innerText = `${m}:${s}`;
    }, 1000);

    const url = `/scan?targets=${encodeURIComponent(targetString)}&plugins=${encodeURIComponent('__dorm_templates_only__')}&customTemplates=${encodeURIComponent(ids.join(','))}`;
    tplScanEventSource = new EventSource(url);

    tplScanEventSource.onmessage = (e) => {
        const data = JSON.parse(e.data);

        if (data.Status === 'STARTED' || data.Status === 'CRAWLING_DOM') return;

        if (data.Status === 'DONE') {
            finishTemplateScanUI();
            return;
        }

        if (data.Status === 'ERROR') {
            consoleLog(`<span style="color:#EF4444;">ERROR</span> ${escapeHtml(data.Message)}`);
            finishTemplateScanUI();
            return;
        }

        renderTemplateConsoleEntry(data);
    };

    tplScanEventSource.onerror = () => {
        // EventSource auto-reconnects on transient drops — not a hard failure.
    };
}

function consoleLog(html) {
    document.getElementById('tplConsoleFeed').insertAdjacentHTML('beforeend', `<div style="margin-top:6px;">${html}</div>`);
}

// Renders one custom-template finding as a terminal-style log line, not a
// table row — click to expand analysis/solution inline.
function renderTemplateConsoleEntry(data) {
    tplRunCount++;
    const color = severityColor(data.Severity);
    const host = data.Target.IP;
    const entryId = 'tpl-console-' + tplRunCount;

    const html = `
        <div style="margin-top:10px; padding-bottom:10px; border-bottom:1px dashed rgba(255,255,255,0.06); cursor:pointer;" onclick="toggleTplConsoleDetail('${entryId}')">
            <span style="color:${color}; font-weight:700;">[${escapeHtml((data.Severity || 'INFO').toUpperCase())}]</span>
            <span style="color:#E6EDF3;">${escapeHtml(data.Name)}</span>
            <span style="color:#6B7280;"> → ${escapeHtml(host)}:${data.Target.Port}</span>
            <i class="fas fa-chevron-down" style="font-size:9px; margin-left:6px; color:#6B7280;"></i>
            <div id="${entryId}" style="display:none; margin-top:8px; padding:10px 14px; background:rgba(255,255,255,0.03); border-left:2px solid ${color}; color:#9CA3AF; font-size:12px; line-height:1.7;">
                <div><span style="color:#F59E0B; font-weight:700;">ANALYSIS</span> ${escapeHtml(data.Description || 'No description provided.').replace(/\n/g, '<br>')}</div>
                <div style="margin-top:6px;"><span style="color:#10B981; font-weight:700;">SOLUTION</span> ${escapeHtml(data.Solution || 'Review and patch the affected endpoint.')}</div>
                <div style="margin-top:6px; opacity:0.7;">REF: ${escapeHtml(data.Reference || 'N/A')}</div>
            </div>
        </div>`;

    if (tplRunCount === 1) {
        document.getElementById('tplConsoleFeed').innerHTML = '';
    }
    document.getElementById('tplConsoleFeed').insertAdjacentHTML('beforeend', html);
}

function stopTemplateScan() {
    fetch('/stop');
    if (tplScanEventSource) {
        tplScanEventSource.close();
        tplScanEventSource = null;
    }
    finishTemplateScanUI();
    consoleLog('<span style="color:#da3633; font-weight:700;">⛔ SCAN ABORTED BY USER</span>');
}

function finishTemplateScanUI() {
    clearInterval(tplTimerInterval);
    if (tplScanEventSource) {
        tplScanEventSource.close();
        tplScanEventSource = null;
    }

    const btn = document.getElementById('tplScanBtn');
    btn.classList.remove('tpl-running');
    btn.innerHTML = 'RUN <i class="fas fa-caret-right"></i>';
    btn.style.background = '#F59E0B';
    btn.style.borderColor = '#F59E0B';

    if (tplRunCount === 0) {
        document.getElementById('tplConsoleFeed').innerHTML = '<div style="color:#4B5563;">// no findings — the selected template(s) did not match on this target.</div>';
    }

    onTemplateSelectionChange(); // re-sync RUN's disabled/opacity state now that it's idle
}

function toggleTplConsoleDetail(entryId) {
    const el = document.getElementById(entryId);
    el.style.display = (el.style.display === 'block') ? 'none' : 'block';
}
