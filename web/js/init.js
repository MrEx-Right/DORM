// --- INITIALIZATION ---
window.addEventListener('load', async () => {
    try {
        // Load Plugins
        const groupedPlugins = await apiJSON('/plugins');
        const grid = document.getElementById('pluginGrid');

        // Build once and assign once — `innerHTML +=` inside the loop re-parsed
        // and rebuilt the whole grid on every plugin (O(n^2) for ~100 plugins).
        const parts = [];
        for (const [category, plugins] of Object.entries(groupedPlugins)) {

            // Add Category Header
            const catClass = category.replace(/\W/g, '');
            parts.push(`
                <div style="grid-column: 1 / -1; margin-top: 10px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 5px; margin-bottom: 5px; display: flex; justify-content: space-between; align-items: center;">
                    <h4 style="margin:0; color: var(--accent); font-size: 13px; text-transform: uppercase; letter-spacing: 1px;">${escapeHtml(category)}</h4>
                    <label style="font-size: 11px; color: var(--text-dim); cursor: pointer; display: flex; align-items: center; gap: 4px;">
                        <input type="checkbox" checked onchange="toggleCategory(this, '${catClass}')" style="margin:0;"> Select/deselect Group
                    </label>
                </div>
            `);

            plugins.forEach(p => {
                const escaped = escapeHtml(p);
                parts.push(`
                    <label class="plugin-item active-plugin category-${catClass}">
                        <div class="plugin-checkbox-wrapper">
                            <input type="checkbox" class="plugin-check custom-checkbox" onchange="this.closest('.plugin-item').classList.toggle('active-plugin', this.checked)" value="${escaped}" checked>
                            <span>${escaped}</span>
                        </div>
                    </label>
                `);
            });
        }
        grid.innerHTML = parts.join('');

        await loadHistory();
    } catch (e) {
        console.error("Initialization error:", e);
        showToast("Dashboard failed to initialize: " + errMsg(e), 'error', 10000);
    } finally {
        // Check if loader has already been shown in this session
        const loader = document.getElementById('dorm-loader');
        const hasBeenShown = sessionStorage.getItem('dorm_loader_shown');

        if (!hasBeenShown && loader) {
            // First time: Wait longer to show off the advanced animation (3.5s)
            setTimeout(() => {
                loader.classList.add('loader-hidden');
                setTimeout(() => {
                    loader.style.display = 'none';
                    sessionStorage.setItem('dorm_loader_shown', 'true');
                }, 1000); // Wait for CSS transition
            }, 10000);
        } else if (loader) {
            // F5/Refresh: Loader is already hidden by inline CSS, just clean up DOM state
            loader.style.display = 'none';
        }
    }
});

window.toggleCategory = function (cb, catClass) {
    document.querySelectorAll('.category-' + catClass + ' .plugin-check').forEach(input => {
        input.checked = cb.checked;
        input.closest('.plugin-item').classList.toggle('active-plugin', cb.checked);
    });
};
