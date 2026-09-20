// --- REPORT HELPERS ---
function getTargetDisplayString() {
    const rawTargets = document.getElementById('targetInput').value;
    const arr = rawTargets.split('\n').map(t => t.trim()).filter(t => t !== '');
    if (arr.length > 3) return arr.slice(0, 3).join(', ') + ` (+${arr.length - 3} more)`;
    return arr.join(', ');
}

// Groups a flat vulnerability list by its Target (IP:Port), preserving the
// order targets first appear in. A multi-target scan mixes every target's
// findings into one undifferentiated table/PDF otherwise, making it
// impossible to tell which host a given row belongs to.
function groupResultsByTarget(results) {
    const groups = [];
    const indexByKey = new Map();

    results.forEach(r => {
        const key = (r.Target && r.Target.IP) ? `${r.Target.IP}:${r.Target.Port}` : 'Unknown Target';
        if (!indexByKey.has(key)) {
            indexByKey.set(key, groups.length);
            groups.push({ label: key, items: [] });
        }
        groups[indexByKey.get(key)].items.push(r);
    });

    return groups;
}

function buildReportHTML(results, title, targetDisplay, date) {
    const groups = groupResultsByTarget(results);
    const multiTarget = groups.length > 1;

    const tableFor = (items) => {
        let t = `<table><thead><tr><th>Sev</th><th>Vuln</th><th>Details</th></tr></thead><tbody>`;
        items.forEach(r => t += `<tr><td class="${r.Severity}">${r.Severity}</td><td>${escapeHtml(r.Name)}</td><td>${escapeHtml(r.Description)}</td></tr>`);
        t += `</tbody></table>`;
        return t;
    };

    let sections = '';
    if (multiTarget) {
        groups.forEach(g => {
            sections += `<h2 style="margin-top:30px; padding-bottom:8px; border-bottom:2px solid #ddd;">Target: ${escapeHtml(g.label)} <span style="font-size:14px; color:#888;">(${g.items.length} finding${g.items.length !== 1 ? 's' : ''})</span></h2>`;
            sections += tableFor(g.items);
        });
    } else {
        sections = tableFor(results);
    }

    return `<html><head><title>${title}</title><style>body{font-family:sans-serif;padding:30px;color:#333}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #ddd;padding:12px;text-align:left}th{background:#f4f4f4}.CRITICAL{color:#d32f2f;font-weight:bold}.HIGH{color:#f57c00;font-weight:bold}</style></head><body>`
        + `<h1>${title}</h1><p>Target(s): ${escapeHtml(targetDisplay)}<br>Date: ${escapeHtml(date)}</p>`
        + sections
        + `</body></html>`;
}

function downloadReport() {
    if (scanResults.length === 0) return alert("No results to export!");
    const html = buildReportHTML(scanResults, 'DORM Security Report', getTargetDisplayString(), new Date().toLocaleString());

    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([html], { type: "text/html" }));
    link.download = `DORM_Report_${Date.now()}.html`;
    link.click();
}

function downloadDetailReport() {
    if (detailResults.length === 0) return alert("No results to export!");
    const targetDisplay = document.getElementById('detailTarget').innerText;
    const date = document.getElementById('detailDate').innerText;
    const html = buildReportHTML(detailResults, 'DORM Security Report (Archived)', targetDisplay, date);

    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([html], { type: "text/html" }));
    link.download = `DORM_Report_Archive_${Date.now()}.html`;
    link.click();
}

// --- PDF GENERATION ---
// Shared by the live and archived reports. Grouping by target (one autoTable
// per target, starting on its own page when there's more than one) keeps a
// multi-target scan legible instead of dumping every host's findings into a
// single interleaved table.

function drawPDFCoverHeader(doc, targetDisplay, date, archived) {
    doc.setFillColor(13, 17, 23);
    doc.rect(0, 0, 210, 40, 'F');
    doc.setFontSize(22); doc.setTextColor(88, 166, 255); doc.text("DORM SECURITY REPORT", 14, 20);
    doc.setFontSize(10); doc.setTextColor(201, 209, 217);
    doc.text(`Target(s): ${targetDisplay}${archived ? ' (Archived)' : ''}`, 14, 30);
    doc.text(`Date: ${date}`, 14, 35);
}

function renderVulnTable(doc, items, startY) {
    const tableRows = items.map(vuln => [
        vuln.Severity, vuln.CVSS.toFixed(1), vuln.Name,
        vuln.Description.replace(/<br>/g, "\n").substring(0, 200) + (vuln.Description.length > 200 ? "..." : "")
    ]);

    doc.autoTable({
        head: [['SEVERITY', 'CVSS', 'VULNERABILITY', 'DETAILS']],
        body: tableRows,
        startY: startY,
        theme: 'grid',
        headStyles: { fillColor: [22, 27, 34], textColor: [255, 255, 255], fontStyle: 'bold' },
        styles: { fontSize: 9, cellPadding: 4, overflow: 'linebreak' },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 25 }, 1: { cellWidth: 15, halign: 'center' }, 2: { cellWidth: 50 }, 3: { cellWidth: 'auto' } },
        didParseCell: function (data) {
            if (data.section === 'body' && data.column.index === 0) {
                const sev = data.cell.raw.toUpperCase();
                if (sev === 'CRITICAL') data.cell.styles.textColor = [255, 123, 114];
                else if (sev === 'HIGH') data.cell.styles.textColor = [255, 155, 94];
                else if (sev === 'MEDIUM') data.cell.styles.textColor = [210, 153, 34];
                else if (sev === 'LOW') data.cell.styles.textColor = [227, 179, 65];
                else data.cell.styles.textColor = [88, 166, 255];
            }
        }
    });
}

function addPDFPageFooters(doc, archived) {
    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8); doc.setTextColor(150);
        doc.text(`Page ${i} of ${pageCount} - Generated by DORM Scanner${archived ? ' (Archived)' : ''}`, 105, 290, null, null, "center");
    }
}

function buildVulnPDF(results, targetDisplay, date, archived) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const groups = groupResultsByTarget(results);
    const multiTarget = groups.length > 1;

    drawPDFCoverHeader(doc, targetDisplay, date, archived);

    let startY = 45;
    groups.forEach((group, i) => {
        if (i > 0) {
            doc.addPage();
            startY = 20;
        }
        if (multiTarget) {
            doc.setFontSize(13); doc.setTextColor(88, 166, 255);
            doc.text(`Target: ${group.label}  (${group.items.length} finding${group.items.length !== 1 ? 's' : ''})`, 14, startY);
            startY += 8;
        }
        renderVulnTable(doc, group.items, startY);
    });

    addPDFPageFooters(doc, archived);
    return doc;
}

function downloadPDF() {
    if (scanResults.length === 0) return alert("No results to export!");
    const doc = buildVulnPDF(scanResults, getTargetDisplayString(), new Date().toLocaleString(), false);
    doc.save(`DORM_Report_${Date.now()}.pdf`);
}

function downloadDetailPDF() {
    if (detailResults.length === 0) return alert("No results to export!");
    const targetDisplay = document.getElementById('detailTarget').innerText;
    const date = document.getElementById('detailDate').innerText;
    const doc = buildVulnPDF(detailResults, targetDisplay, date, true);
    doc.save(`DORM_Report_Archive_${Date.now()}.pdf`);
}

function checkAllPlugins(state) {
    document.querySelectorAll('.plugin-check').forEach(cb => {
        cb.checked = state;
        cb.closest('.plugin-item').classList.toggle('active-plugin', state);
    });
}
