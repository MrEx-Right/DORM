// ============================================================
// DOM CRAWLER — Real-Time Event Feed
// ============================================================

let domEventSource = null;
let domEventCount = 0;
let domStats = { navigate: 0, click: 0, xhr: 0, spa_route: 0, error: 0 };
const DOM_MAX_ROWS = 300; // keep feed from growing forever

const domIconMap = {
    navigate:  { icon: 'fa-compass',        cls: 'dom-icon-navigate', label: 'Navigate',  color: '#60A5FA' },
    click:     { icon: 'fa-mouse-pointer',  cls: 'dom-icon-click',    label: 'Click',     color: '#34D399' },
    xhr:       { icon: 'fa-exchange-alt',   cls: 'dom-icon-xhr',      label: 'XHR/Fetch', color: '#FBBF24' },
    spa_route: { icon: 'fa-route',          cls: 'dom-icon-spa_route',label: 'SPA Route', color: '#A78BFA' },
    form:      { icon: 'fa-wpforms',        cls: 'dom-icon-form',     label: 'Form',      color: '#F87171' },
    error:     { icon: 'fa-exclamation-triangle', cls: 'dom-icon-error', label: 'Error', color: '#EF4444' },
    done:      { icon: 'fa-check-circle',   cls: 'dom-icon-done',     label: 'Done',      color: '#10B981' },
};

function initDOMCrawlerFeed() {
    if (domEventSource) return; // already connected

    domEventSource = new EventSource('/dom-events');

    domEventSource.onopen = () => {
        setDOMStatus('CONNECTED', '#10B981', 'rgba(16,185,129,0.15)', 'rgba(16,185,129,0.3)');
    };

    domEventSource.onmessage = (e) => {
        try {
            const ev = JSON.parse(e.data);
            appendDOMEvent(ev);
        } catch (_) {}
    };

    domEventSource.onerror = () => {
        setDOMStatus('IDLE', '#94A3B8', 'rgba(148,163,184,0.1)', 'rgba(148,163,184,0.2)');
    };
}

function setDOMStatus(text, color, bg, border) {
    const badge = document.getElementById('dom-status-badge');
    if (!badge) return;
    badge.textContent = text;
    badge.style.color = color;
    badge.style.background = bg;
    badge.style.borderColor = border;
}

function appendDOMEvent(ev) {
    const feed = document.getElementById('domFeed');
    if (!feed) return;

    // Hide empty state on first event
    const empty = document.getElementById('dom-empty-state');
    if (empty) empty.style.display = 'none';

    // Update status badge
    setDOMStatus('CRAWLING', '#10B981', 'rgba(16,185,129,0.15)', 'rgba(16,185,129,0.3)');

    // Show pulse on nav item
    const pulse = document.getElementById('dom-nav-pulse');
    if (pulse) pulse.style.display = 'inline-block';

    // Update counters
    domEventCount++;
    const countEl = document.getElementById('dom-event-count');
    if (countEl) countEl.textContent = domEventCount + ' event' + (domEventCount !== 1 ? 's' : '');

    if (ev.kind === 'navigate') { domStats.navigate++; updateDOMStat('dom-stat-pages', domStats.navigate); }
    if (ev.kind === 'click')    { domStats.click++;    updateDOMStat('dom-stat-clicks', domStats.click); }
    if (ev.kind === 'xhr')      { domStats.xhr++;      updateDOMStat('dom-stat-xhr', domStats.xhr); }
    if (ev.kind === 'spa_route'){ domStats.spa_route++;updateDOMStat('dom-stat-routes', domStats.spa_route); }
    if (ev.kind === 'error')    { domStats.error++;    updateDOMStat('dom-stat-errors', domStats.error); }

    if (ev.kind === 'done') {
        setDOMStatus('DONE', '#10B981', 'rgba(16,185,129,0.15)', 'rgba(16,185,129,0.3)');
        if (pulse) setTimeout(() => { pulse.style.display = 'none'; }, 2000);
    }

    const meta = domIconMap[ev.kind] || domIconMap['navigate'];
    const timeStr = new Date(ev.timestamp).toLocaleTimeString('en-GB', { hour12: false });
    const urlTrunc = ev.url ? (ev.url.length > 80 ? ev.url.slice(0, 77) + '…' : ev.url) : '';
    const detailText = ev.detail || ev.selector || ev.label || '';

    const row = document.createElement('div');
    row.className = 'dom-event-row new';

    row.innerHTML = `
        <div class="dom-event-icon ${meta.cls}">
            <i class="fas ${meta.icon}"></i>
        </div>
        <div class="dom-event-body">
            <div class="dom-event-label" style="color:${meta.color};">${meta.label}</div>
            ${urlTrunc ? `<div class="dom-event-url">${escapeHtml(urlTrunc)}</div>` : ''}
            ${detailText ? `<div class="dom-event-detail">${escapeHtml(detailText)}</div>` : ''}
        </div>
        <div class="dom-event-time">${timeStr}</div>
    `;

    // Prepend so newest is always at top
    feed.insertBefore(row, feed.firstChild);

    // Remove 'new' class after animation completes (avoids re-trigger on scroll)
    setTimeout(() => row.classList.remove('new'), 900);

    // Trim old rows
    const rows = feed.querySelectorAll('.dom-event-row');
    if (rows.length > DOM_MAX_ROWS) {
        for (let i = DOM_MAX_ROWS; i < rows.length; i++) rows[i].remove();
    }
}

function updateDOMStat(id, val) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val;
    // Brief scale-up animation
    el.style.transform = 'scale(1.3)';
    setTimeout(() => { el.style.transform = 'scale(1)'; el.style.transition = 'transform 0.2s ease'; }, 120);
}

function clearDOMFeed() {
    const feed = document.getElementById('domFeed');
    if (!feed) return;
    feed.innerHTML = `
        <div class="dom-empty" id="dom-empty-state">
            <i class="fas fa-spider"></i>
            <p style="font-size:15px;font-weight:600;color:var(--text-main);margin:0 0 6px;">Feed cleared</p>
            <p style="font-size:13px;margin:0;">New events will appear here as the DOM Crawler runs.</p>
        </div>
    `;
    domEventCount = 0;
    domStats = { navigate: 0, click: 0, xhr: 0, spa_route: 0, error: 0 };
    ['dom-stat-pages','dom-stat-clicks','dom-stat-xhr','dom-stat-routes','dom-stat-errors'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '0';
    });
    const countEl = document.getElementById('dom-event-count');
    if (countEl) countEl.textContent = '0 events';
}

// Auto-start SSE connection when page loads (stays connected in background)
window.addEventListener('load', () => {
    initDOMCrawlerFeed();
    initTargetLineNumbers();
});
