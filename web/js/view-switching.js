// --- VIEW SWITCHING ---
function switchView(viewName) {
    if (sitemapPollInterval) {
        clearInterval(sitemapPollInterval);
        sitemapPollInterval = null;
    }
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    event.currentTarget.classList.add('active');
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    document.getElementById('view-' + viewName).classList.add('active');
    document.querySelector('.main-content').scrollTop = 0; // Reset scroll position
    if (viewName === 'history') loadHistory();
    if (viewName === 'cvecenter') loadCVECenter();
    if (viewName === 'sitemap') initSitemapView();
    if (viewName === 'sci') initSCIView();
}
