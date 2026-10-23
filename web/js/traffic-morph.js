// --- TRAFFIC MORPH (live OpSec / identity panel) ---
// Polls /api/identity while the view is open (and lightly in the background
// while a scan runs, for the sidebar icon). The route sent along is the one
// the Proxy Settings page would give the next scan, read the same way
// scanner.js reads it.
let morphPollInterval = null;
let morphLastData = null;
let morphBusy = false;
let morphToggleBusy = false;
let morphNavUA; // last persona UA the sidebar icon saw (undefined until the first poll)

function morphRouteQuery() {
    const enabled = document.getElementById('proxyToggle').checked;
    const url = document.getElementById('proxyUrlInput').value || "http://127.0.0.1:8081";
    return `proxyEnabled=${enabled}&proxyUrl=${encodeURIComponent(url)}`;
}

// Was the last egress check run on this same route?
function morphEgressMatches(d) {
    const e = d.egress;
    return !!e && e.routeMode === d.configured.mode && (e.routeProxyUrl || '') === (d.configured.proxyUrl || '');
}

// Green only once an egress check on this route confirmed a Tor exit; a
// configured-but-unverified Tor/proxy route is amber, a failed check is red.
function morphRouteTone(d) {
    const mode = d.configured.mode;
    if (mode === 'direct' || mode === 'analyzer' || mode === 'invalid') return 'tm-bad';
    if (morphEgressMatches(d)) {
        if (d.egress.error) return 'tm-bad';
        if (d.egress.isTor === true) return 'tm-good';
    }
    return 'tm-warn';
}

// The default route (the built-in analyzer) gets no badge: it is what every
// scan uses unless the Proxy Settings change it, so the label was just noise.
const MORPH_NAV_LABEL = {
    direct: 'DIRECT', analyzer: '', local_proxy: 'PROXY', tor: 'TOR',
    socks: 'SOCKS', http_proxy: 'PROXY', invalid: 'ERROR'
};

function morphAgo(iso) {
    if (!iso) return '—';
    const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s ago`;
    return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m ago`;
}

function morphTag(text, tone) {
    return `<span class="tm-tag ${tone || ''}">${escapeHtml(text)}</span>`;
}

async function refreshMorph() {
    try {
        const d = await apiJSON('/api/identity?' + morphRouteQuery());
        morphLastData = d;
        updateMorphNav(d);
        if (document.getElementById('view-morph').classList.contains('active')) renderMorph(d);
    } catch (e) {
        console.error('Traffic Morph:', e);
        const st = document.getElementById('tmStatus');
        if (st) st.innerHTML = `<span class="tm-note tm-bad">Identity API unavailable: ${escapeHtml(errMsg(e))}</span>`;
    }
}

function updateMorphNav(d) {
    const badge = document.getElementById('morph-nav-badge');
    const nav = document.getElementById('nav-morph');
    if (!badge || !nav) return;
    const mode = d.configured.mode;
    const label = mode in MORPH_NAV_LABEL ? MORPH_NAV_LABEL[mode] : mode.toUpperCase();
    badge.textContent = label;
    badge.style.display = label ? '' : 'none';
    badge.className = 'tm-nav-badge ' + morphRouteTone(d);
    badge.title = d.configured.label + ' — ' + d.configured.egress;
    nav.classList.toggle('tm-live', !!d.live);
    nav.classList.toggle('tm-off', !d.enabled);

    // Swap the masks once per User-Agent rotation. A scan start resets the
    // backend's last UA to '', which is not a rotation.
    const ua = d.persona.current || '';
    if (morphNavUA && ua && ua !== morphNavUA) swapMorphMasks();
    if (ua) morphNavUA = ua;
}

function swapMorphMasks() {
    const icon = document.querySelector('#nav-morph .tm-masks');
    if (!icon) return;
    const toSwapped = !icon.classList.contains('swapped');
    icon.classList.remove('tm-swap-in', 'tm-swap-out');
    void icon.offsetWidth; // restart the animation even if one is still running
    icon.classList.toggle('swapped', toSwapped);
    icon.classList.add(toSwapped ? 'tm-swap-in' : 'tm-swap-out');
}

function renderMorph(d) {
    const cfg = d.configured;
    const act = d.active;

    // On/off switch. Off, persona mode and NEW IDENTITY are locked; the rest
    // of the panel keeps reporting.
    const toggle = document.getElementById('tmEnabledToggle');
    if (!morphToggleBusy) toggle.checked = !!d.enabled;
    document.getElementById('tmEnabledLabel').textContent = d.enabled ? 'MORPH ON' : 'MORPH OFF';
    document.getElementById('tmModeRotate').disabled = !d.enabled;
    document.getElementById('tmModeSticky').disabled = !d.enabled;
    const idBtn = document.getElementById('tmIdentityBtn');
    idBtn.disabled = !d.enabled || morphBusy;
    idBtn.classList.toggle('tm-locked', !d.enabled);
    idBtn.title = d.enabled ? '' : 'Turn Traffic Morph on to use NEW IDENTITY';

    // Status strip
    document.getElementById('tmStatus').innerHTML = `
        <span>Morph <b>${d.enabled ? 'ON' : 'OFF'}</b></span>
        <span><span class="tm-live-dot ${d.live ? 'on' : ''}"></span><b>${d.live ? 'TRAFFIC FLOWING' : 'IDLE'}</b></span>
        <span>Identity <b>#${d.generation}</b> · since ${escapeHtml(morphAgo(d.identitySince))}</span>
        <span>Isolation tag <b class="tm-mono">${escapeHtml(d.isolationTag)}…</b></span>
        <span>Persona mode <b>${d.persona.mode === 'sticky' ? 'STICKY' : 'ROTATE'}</b></span>`;
    document.getElementById('tmModeRotate').classList.toggle('active', d.persona.mode !== 'sticky');
    document.getElementById('tmModeSticky').classList.toggle('active', d.persona.mode === 'sticky');

    // Route
    const tone = morphRouteTone(d);
    document.getElementById('tmRouteTag').innerHTML = morphTag(cfg.label, tone);
    const hops = cfg.hops.map((h, i) =>
        `<span class="tm-hop ${i === 0 ? 'tm-hop-self' : ''}">${escapeHtml(h)}</span>`
    ).join('<i class="fas fa-chevron-right"></i>');
    let routeHTML = `
        <div class="tm-chain">${hops}</div>
        <div class="tm-kv">
            <div>Proxy</div><div class="tm-mono">${escapeHtml(cfg.proxyUrl || 'none')}</div>
            <div>Target sees</div><div>${escapeHtml(cfg.egress)}</div>
            <div>New identity</div><div>${escapeHtml(cfg.rotatesIdentity)}</div>
        </div>`;
    routeHTML += cfg.warnings.map(w => `<div class="tm-note tm-bad">${escapeHtml(w)}</div>`).join('');
    if (act && (act.mode !== cfg.mode || (act.proxyUrl || '') !== (cfg.proxyUrl || ''))) {
        routeHTML += `<div class="tm-note">The last scan started on a different route (<b>${escapeHtml(act.label)}</b>${act.proxyUrl ? ' · ' + escapeHtml(act.proxyUrl) : ''}). The settings above apply from the next scan.</div>`;
    }
    document.getElementById('tmRoute').innerHTML = routeHTML;

    renderMorphEgress(d.egress, d.generation, morphEgressMatches(d));

    // TLS
    const t = d.tls;
    if (t.error) {
        document.getElementById('tmTLS').innerHTML = `<div class="tm-note tm-bad">Could not measure the ClientHello: ${escapeHtml(t.error)}</div>`;
    } else {
        document.getElementById('tmTLS').innerHTML = `
            <div class="tm-kv">
                <div>Stack</div><div>${escapeHtml(t.library)}</div>
                <div>JA4</div><div class="tm-mono">${escapeHtml(t.ja4)}<button class="tm-copy" data-copy="${escapeHtml(t.ja4)}" onclick="morphCopy(this)">COPY</button></div>
                <div>JA3 hash</div><div class="tm-mono">${escapeHtml(t.ja3Hash)}<button class="tm-copy" data-copy="${escapeHtml(t.ja3Hash)}" onclick="morphCopy(this)">COPY</button></div>
                <div>JA3</div><div class="tm-mono" style="color:var(--text-dim)">${escapeHtml(t.ja3)}</div>
                <div>ALPN</div><div>${t.alpn.length ? escapeHtml(t.alpn.join(', ')) : 'none'} · ${escapeHtml(t.httpVersion)}</div>
                <div>Versions</div><div>${escapeHtml(t.versions.join(', '))}</div>
                <div>Ciphers / Ext</div><div>${t.cipherCount} cipher suites · ${t.extensionCount} extensions</div>
                <div>Groups</div><div class="tm-mono">${escapeHtml(t.groups.join(', '))}</div>
            </div>
            <div class="tm-note tm-info">Captured from a real handshake of the scan transport, so this is exactly what a target's WAF fingerprints. It is the same for every request and identity.</div>`;
    }

    // Persona
    const p = d.persona;
    document.getElementById('tmPersonaTag').innerHTML = !d.enabled
        ? morphTag('off')
        : morphTag(p.mode === 'sticky' ? 'sticky' : 'rotating', p.mode === 'sticky' ? 'tm-good' : 'tm-warn');
    const totalUA = p.pool.reduce((a, e) => a + e.count, 0);
    const bars = p.pool.map(e => {
        const pct = totalUA ? (e.count / totalUA * 100) : 0;
        return `<div class="tm-bar-row ${e.ua === p.current ? 'current' : ''}" title="${escapeHtml(e.ua)}">
                    <span class="tm-bar-label">${escapeHtml(e.label)}</span>
                    <div class="tm-bar-track"><div class="tm-bar-fill" style="width:${pct.toFixed(1)}%"></div></div>
                    <span class="tm-bar-count">${e.count}</span>
                </div>`;
    }).join('');
    document.getElementById('tmPersona').innerHTML = `
        <div>
            <div style="font-size:18px; font-weight:700; color:#fff;">${escapeHtml(p.currentLabel || 'No request sent yet')}</div>
            <div class="tm-mono" style="color:var(--text-dim); margin-top:4px;">${escapeHtml(p.current || (p.mode === 'sticky' ? '' : 'A random User-Agent from the pool below is drawn per request.'))}</div>
        </div>
        ${d.enabled ? '' : '<div class="tm-note">Traffic Morph is off: every request sends this one User-Agent and the pool below is not used. Turn MORPH on to rotate personas.</div>'}
        <div style="font-size:11px; color:var(--text-dim); text-transform:uppercase; letter-spacing:1px; font-weight:600;">Pool · requests this scan</div>
        <div style="display:flex; flex-direction:column; gap:8px;">${bars}</div>`;

    // Traffic
    const tr = d.traffic;
    document.getElementById('tmTrafficTag').innerHTML = d.live ? morphTag('live', 'tm-good') : morphTag('idle');
    const pct = tr.total ? Math.round(tr.proxied / tr.total * 100) : 0;
    document.getElementById('tmTraffic').innerHTML = `
        <div class="tm-stats">
            <div class="tm-stat"><div class="tm-stat-num">${tr.total}</div><div class="tm-stat-label">Requests</div></div>
            <div class="tm-stat"><div class="tm-stat-num">${tr.reqPerSec.toFixed(1)}</div><div class="tm-stat-label">Req / s</div></div>
            <div class="tm-stat"><div class="tm-stat-num">${tr.proxied}</div><div class="tm-stat-label">Via proxy (${pct}%)</div></div>
            <div class="tm-stat"><div class="tm-stat-num">${tr.direct}</div><div class="tm-stat-label">Direct</div></div>
            <div class="tm-stat"><div class="tm-stat-num">${tr.hosts}</div><div class="tm-stat-label">Hosts</div></div>
            <div class="tm-stat"><div class="tm-stat-num">${tr.delayMs}<span style="font-size:12px">±${tr.jitterMs}</span></div><div class="tm-stat-label">Delay ms</div></div>
        </div>
        <div style="font-size:12px; color:var(--text-dim);">
            Scan client built ${escapeHtml(morphAgo(tr.scanSince))} · last request ${escapeHtml(morphAgo(tr.lastAt))}.
            Counts every HTTP request on the shared scan transport: plugins, the sitemapper, the tech-profile probe and SCI
            (<span class="tm-mono">models.GetClient()</span> / <span class="tm-mono">models.GetScanTransport()</span>).
        </div>
        <div class="tm-note tm-info">Headless Chrome (DOM crawler, DOM XSS plugin) is not counted here but runs on the same route: it gets
            <span class="tm-mono">--proxy-server</span> and the persona User-Agent. Chrome cannot send SOCKS credentials, so on Tor it uses Tor's default
            circuit, not the NEW IDENTITY one.</div>
        <div class="tm-note tm-bad">Still direct from this machine: raw TCP/TLS probes (port checks, banner grabs, TLS-version and service checks)
            and feed downloads that never touch the target (CVE / KEV / Exploit-DB, prompt-injection corpus, package registries).</div>`;

    // Consistency
    const c = d.consistency;
    document.getElementById('tmConsistencyTag').innerHTML = morphTag(c.verdict, c.verdict === 'CONSISTENT' ? 'tm-good' : c.verdict === 'OFF' ? '' : 'tm-bad');
    document.getElementById('tmConsistency').innerHTML = c.reasons.length
        ? c.reasons.map(r => `<div class="tm-note">${escapeHtml(r)}</div>`).join('')
        : `<div class="tm-note tm-good">User-Agent, TLS and connection behaviour tell the same story.</div>`;
}

function renderMorphEgress(e, generation, sameRoute) {
    const body = document.getElementById('tmEgress');
    const tag = document.getElementById('tmEgressTag');
    const staleNote = (e && !sameRoute)
        ? `<div class="tm-note">This result is from another route (${escapeHtml(e.route)}${e.routeProxyUrl ? ' · ' + escapeHtml(e.routeProxyUrl) : ''}). Check again for the current one.</div>`
        : '';
    if (!e) {
        tag.innerHTML = morphTag('not checked');
        body.innerHTML = `<div style="color:var(--text-dim); font-size:13px;">Not checked for identity #${generation}. <b>CHECK EGRESS</b> sends one request through the configured route to check.torproject.org (and ip-api.com for location) — nothing is sent until you click it.</div>`;
        return;
    }
    if (e.error) {
        tag.innerHTML = morphTag('unreachable', 'tm-bad');
        body.innerHTML = staleNote + `
            <div class="tm-note tm-bad">No egress through <b>${escapeHtml(e.route)}</b>.<br>HTTPS: ${escapeHtml(e.httpsError || '—')}<br>HTTP: ${escapeHtml(e.error)}</div>
            <div style="font-size:12px; color:var(--text-dim);">Checked ${escapeHtml(morphAgo(e.checkedAt))}.</div>`;
        return;
    }
    const tags = [];
    if (e.isTor === true) tags.push(morphTag('Tor exit', 'tm-good'));
    else if (e.isTor === false) tags.push(morphTag('not Tor', 'tm-warn'));
    if (e.hosting) tags.push(morphTag('datacenter IP', 'tm-warn'));
    if (e.proxyFlag) tags.push(morphTag('known proxy/VPN', 'tm-warn'));
    if (e.isTor) tag.innerHTML = morphTag('anonymized', 'tm-good');
    else if (e.routeMode === 'direct' || e.routeMode === 'analyzer' || e.routeMode === 'invalid') tag.innerHTML = morphTag('own IP exposed', 'tm-bad');
    else tag.innerHTML = morphTag('proxied', 'tm-warn');
    const where = [e.city, e.country].filter(Boolean).join(', ');
    body.innerHTML = staleNote + `
        <div class="tm-ip">${escapeHtml(e.ip)}</div>
        <div>${tags.join('')}</div>
        <div class="tm-kv">
            <div>Location</div><div>${escapeHtml(where || '—')}</div>
            <div>ISP</div><div>${escapeHtml(e.isp || '—')}</div>
            <div>ASN</div><div class="tm-mono">${escapeHtml(e.asn || '—')}</div>
            <div>Route</div><div>${escapeHtml(e.route)} · ${e.latencyMs} ms</div>
            <div>Checked</div><div>${escapeHtml(morphAgo(e.checkedAt))} · identity #${e.generation}</div>
        </div>
        ${e.httpsError ? `<div class="tm-note tm-bad">HTTPS through this route failed (${escapeHtml(e.httpsError)}). The IP above is from a plain-HTTP lookup.</div>` : ''}`;
}

async function checkMorphEgress() {
    const btn = document.getElementById('tmEgressBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> CHECKING…';
    try {
        await apiJSON('/api/identity/egress?' + morphRouteQuery(), { method: 'POST' });
        await refreshMorph();
    } catch (e) {
        showToast('Egress check failed: ' + errMsg(e), 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-globe"></i> CHECK EGRESS';
    }
}

async function rotateMorphIdentity() {
    if (morphBusy || (morphLastData && !morphLastData.enabled)) return;
    morphBusy = true;
    const btn = document.getElementById('tmIdentityBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> MORPHING…';
    try {
        const res = await apiJSON('/api/identity/rotate?' + morphRouteQuery(), { method: 'POST' });
        const toneOf = { done: 'tm-good', partial: 'tm-warn', kept: '' };
        const box = document.getElementById('tmRotateResult');
        box.style.display = 'block';
        box.innerHTML = `
            <div class="sm-panel">
                <div class="sm-panel-header"><span><i class="fas fa-user-secret"></i> Identity #${res.generation} — what changed</span></div>
                <div class="tm-card-body tm-actions-list">
                    ${res.actions.map(a => `
                        <div class="tm-action-row">
                            <span>${morphTag(a.status === 'done' ? 'reset' : a.status, toneOf[a.status])}</span>
                            <b>${escapeHtml(a.what)}</b>
                            <span style="color:var(--text-dim)">${escapeHtml(a.detail)}</span>
                        </div>`).join('')}
                </div>
            </div>`;
        showToast(`New identity #${res.generation}`, 'success');
        await refreshMorph();
    } catch (e) {
        showToast('NEW IDENTITY failed: ' + errMsg(e), 'error');
    } finally {
        morphBusy = false;
        btn.disabled = !!(morphLastData && !morphLastData.enabled);
        btn.innerHTML = '<i class="fas fa-user-secret"></i> NEW IDENTITY';
    }
}

// Switches Traffic Morph on or off. It applies from the next request, also
// in the middle of a scan. The backend starts OFF on every launch, so the
// switch always shows the server's state, never a remembered one.
async function setMorphEnabled(on) {
    if (morphToggleBusy) return;
    morphToggleBusy = true;
    const toggle = document.getElementById('tmEnabledToggle');
    toggle.disabled = true;
    try {
        await apiJSON('/api/identity/enabled?on=' + (on ? 'true' : 'false'), { method: 'POST' });
        showToast(on ? 'Traffic Morph on — User-Agent personas active' : 'Traffic Morph off — fixed DORM User-Agent', 'success');
    } catch (e) {
        toggle.checked = !on;
        showToast('Could not switch Traffic Morph: ' + errMsg(e), 'error');
    } finally {
        morphToggleBusy = false;
        toggle.disabled = false;
        await refreshMorph();
    }
}

async function setMorphPersonaMode(mode) {
    try {
        await apiJSON('/api/identity/persona?mode=' + encodeURIComponent(mode), { method: 'POST' });
        await refreshMorph();
    } catch (e) {
        showToast('Could not change persona mode: ' + errMsg(e), 'error');
    }
}

function morphCopy(btn) {
    const text = btn.dataset.copy;
    navigator.clipboard.writeText(text).then(
        () => showToast('Copied', 'success', 1500),
        () => showToast('Clipboard not available', 'error')
    );
}

function initMorphView() {
    stopMorphPolling();
    if (morphLastData) renderMorph(morphLastData);
    refreshMorph();
    morphPollInterval = setInterval(refreshMorph, 2000);
}

function stopMorphPolling() {
    if (morphPollInterval) {
        clearInterval(morphPollInterval);
        morphPollInterval = null;
    }
}

// Sidebar badge + icon: once at load, whenever the proxy settings change, and
// every 4s while a scan stream is open (the view's own 2s poll covers the
// rest when it is visible).
window.addEventListener('load', () => {
    refreshMorph();
    document.getElementById('proxyToggle').addEventListener('change', refreshMorph);
    document.getElementById('proxyUrlInput').addEventListener('change', refreshMorph);
    setInterval(() => {
        const scanning = (typeof scanEventSource !== 'undefined' && scanEventSource) ||
            (typeof tplScanEventSource !== 'undefined' && tplScanEventSource);
        if (morphPollInterval) return;
        if (scanning) {
            refreshMorph();
        } else if (morphLastData && morphLastData.live) {
            refreshMorph(); // one more poll lets the icon settle back to idle
        }
    }, 4000);
});
