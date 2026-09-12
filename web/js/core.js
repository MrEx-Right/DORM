// --- GLOBAL VARIABLES ---
let timerInterval, timerSeconds = 0, vulnCount = 0, scanResults = [];
let scanEventSource = null; // <--- MADE GLOBAL (To enable stopping)
window.allScanRecords = []; // Store history records for viewing
let detailResults = []; // Store results for the detail view

// --- TARGET FILTER STATE ---
// When a scan (live or historical) covers multiple hosts, results are
// grouped by host so they don't all render as one mixed flat list.
let liveTargetFilter = 'ALL';
let liveTargetCounts = {}; // host -> finding count, in first-seen order
let detailTargetFilter = 'ALL';
let detailTargetCounts = {};

const ctx = document.getElementById('vulnChart').getContext('2d');
const detailCtx = document.getElementById('detailVulnChart').getContext('2d');

// --- CHART CONFIG ---
let vulnChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: ['#EF4444', '#F97316', '#F59E0B', '#3B82F6', '#64748B'], borderWidth: 0 }] },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'right',
                labels: { color: '#8B93A1', font: { family: 'Segoe UI' } },
                onClick: function (e, legendItem, legend) {
                    const index = legendItem.index;
                    const chart = legend.chart;

                    // Manually toggle data visibility in Chart.js 4+
                    chart.toggleDataVisibility(index);
                    chart.update();

                    applyResultFilters('#tableBody', chart, liveTargetFilter);
                }
            }
        }
    }
});

let detailVulnChart = new Chart(detailCtx, {
    type: 'doughnut',
    data: { labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: ['#EF4444', '#F97316', '#F59E0B', '#3B82F6', '#64748B'], borderWidth: 0 }] },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'right',
                labels: { color: '#8B93A1', font: { family: 'Segoe UI' } },
                onClick: function (e, legendItem, legend) {
                    const index = legendItem.index;
                    const chart = legend.chart;

                    chart.toggleDataVisibility(index);
                    chart.update();

                    applyResultFilters('#detailTableBody', chart, detailTargetFilter);
                }
            }
        }
    }
});

// --- CROSS-SECTION SHARED STATE (relocated here during the web/js/ split) ---

// Relocated from the original "VIEW SWITCHING" section.
// Written by Scanner (scanner.js) and Sitemap (sitemap.js); read by
// View Switching (view-switching.js) and Sitemap (sitemap.js).
let sitemapPollInterval = null;

// Relocated from the original "SITEMAP LOGIC" section.
window.currentSitemapScanID = '';

// Previously an implicit global, first created only by assignment inside
// viewScan() (history.js) — there was no declaration anywhere to relocate.
// Made explicit here alongside the other cross-section state for a single,
// discoverable source of truth.
window.currentDetailScanID = null;
