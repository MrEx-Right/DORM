// --- HELPER FUNCTIONS ---
function escapeHtml(text) {
    if (text == null) return '';
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
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

function toggleDetail(detailId, parentId) {
    // If only one arg passed, it's the old scanner logic where id is a number
    if (parentId === undefined) {
        parentId = 'row-' + detailId;
        detailId = 'detail-' + detailId;
    }
    const row = document.getElementById(detailId);
    const parent = document.getElementById(parentId);
    if (row.style.display === 'table-row') {
        row.style.display = 'none';
        parent.classList.remove('open');
    } else {
        row.style.display = 'table-row';
        parent.classList.add('open');
    }
}
