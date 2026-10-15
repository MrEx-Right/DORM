// --- VIEW SWITCHING ---
function switchView(viewName) {
    if (sitemapPollInterval) {
        clearInterval(sitemapPollInterval);
        sitemapPollInterval = null;
    }
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    // Highlight the sidebar item for `viewName` — not whatever element fired
    // the click. switchView() is also called from in-page buttons (history
    // "Back", "View Sitemap") and programmatically; relying on the implicit
    // global `event.currentTarget` highlighted that button instead and left
    // the sidebar with no active item.
    const navItem = document.querySelector(`.nav-item[onclick="switchView('${viewName}')"]`);
    if (navItem) navItem.classList.add('active');
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    document.getElementById('view-' + viewName).classList.add('active');
    document.querySelector('.main-content').scrollTop = 0; // Reset scroll position
    if (viewName === 'history') loadHistory();
    if (viewName === 'cvecenter') loadCVECenter();
    if (viewName === 'sitemap') initSitemapView();
    if (viewName === 'sci') initSCIView();
    if (viewName === 'templates') initTemplatesView();
}
