//
// kpi.js
// Security KPI Panel Renderer – OWASP, MITRE, Severity Overview
//

let owaspChart = null;


// -------------------------------------------------------------
// Main Renderer
// -------------------------------------------------------------
function renderKPI(d) {
    if (!d) return;

    const oLabels = d.owasp?.labels || [];
    const oValues = d.owasp?.values || [];
    const mitreArr = d.mitre || [];
    const tenants = d.tenants || [];

    // === Render KPI Cards ===
    renderTopOwasp(oLabels, oValues);
    renderTopMitre(mitreArr);
    renderHighCritical(mitreArr);

    // === OWASP Bar Chart ===
    renderOwaspChart(oLabels, oValues);

    // === MITRE Technique Table ===
    renderMitreTable(mitreArr, tenants);
}



// -------------------------------------------------------------
// KPI #1 – Dominant OWASP Category
// -------------------------------------------------------------
function renderTopOwasp(labels, values) {
    const titleEl = document.getElementById("kpiTopOwasp");
    const textEl = document.getElementById("kpiTopOwaspText");

    if (!(labels.length && values.length)) {
        titleEl.textContent = "-";
        textEl.textContent = "Belum ada distribusi kategori OWASP yang dapat ditampilkan.";
        return;
    }

    const total = values.reduce((a, b) => a + b, 0) || 1;
    const topIdx = 0;
    const topName = labels[topIdx];
    const topVal = values[topIdx];

    titleEl.textContent = topName;
    textEl.textContent = `Kategori ini menyumbang sekitar ${((topVal / total) * 100).toFixed(1)}% dari total serangan.`;
}



// -------------------------------------------------------------
// KPI #2 – Most Used MITRE Technique
// -------------------------------------------------------------
function renderTopMitre(mitreArr) {
    const titleEl = document.getElementById("kpiTopMitre");
    const textEl = document.getElementById("kpiTopMitreText");

    if (!mitreArr.length) {
        titleEl.textContent = "-";
        textEl.textContent = "Belum ada teknik MITRE yang dominan.";
        return;
    }

    const top = [...mitreArr].sort((a,b) => b.count - a.count)[0];
    titleEl.textContent = top.mitre_id;
    textEl.textContent = `${top.category || ""} – ${top.count} events.`;
}



// -------------------------------------------------------------
// KPI #3 – High/Critical Severity Total
// -------------------------------------------------------------
function renderHighCritical(mitreArr) {
    const el = document.getElementById("kpiHighCrit");
    const textEl = document.getElementById("kpiHighCritText");

    let total = 0;

    mitreArr.forEach(m => {
        const sev = (m.severity || "").toUpperCase();
        if (sev === "HIGH" || sev === "CRITICAL") {
            total += m.count || 0;
        }
    });

    animateNumber(el, total);

    textEl.textContent = total > 0
        ? "Total serangan dengan risiko tinggi/kritikal yang perlu menjadi fokus mitigasi."
        : "Belum ada teknik dengan severity High/Critical.";
}



// -------------------------------------------------------------
// OWASP Bar Chart Renderer
// -------------------------------------------------------------
function renderOwaspChart(labels, values) {
    const canvas = document.getElementById("owaspChart");

    if (owaspChart) {
        owaspChart.destroy();
        owaspChart = null;
    }

    if (!(labels.length && values.length)) {
        const ctx = canvas.getContext("2d");
        ctx.clearRect(0,0,canvas.width,canvas.height);
        ctx.fillStyle = "#6b7280";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText("Belum ada data OWASP pada periode ini.", canvas.width/2, canvas.height/2);
        return;
    }

    const colors = labels.map((_, i) => `hsl(${(i * 70) % 360}, 80%, 60%)`);

    owaspChart = new Chart(canvas, {
        type: "bar",
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: colors
            }]
        },
        options: {
            plugins: { 
                legend: { display: false } 
            },
            scales: {
                x: { ticks: { color:"#9ca3af" }, grid: { display:false }},
                y: { ticks: { color:"#9ca3af" }, grid: { color: "rgba(31,41,55,0.8)" }}
            }
        }
    });
}



// -------------------------------------------------------------
// MITRE Table Renderer
// -------------------------------------------------------------
function renderMitreTable(mitreArr, tenants) {
    const tbody = document.querySelector("#attackDetailTable tbody");
    tbody.innerHTML = "";

    const totalTenantEvents = tenants.reduce((a,t)=>a + (t.events || 0), 0) || 1;

    mitreArr
        .slice()
        .sort((a,b)=>b.count - a.count)
        .forEach(row => {
            const tr = document.createElement("tr");

            const sevClass = getSeverityClass(row.severity);

            // Hitung tenant involvement (approx)
            const tenantList = tenants
                .filter(t => t.events > 0)
                .map(t => {
                    const c = Math.round((row.count || 0) * ((t.events || 0) / totalTenantEvents));
                    return { name: t.hostname.replace(".pelindo.co.id",""), count: c };
                })
                .filter(x => x.count > 0)
                .map(x => `${x.name} (${x.count})`)
                .join(", ");

            tr.innerHTML = `
                <td>${row.mitre_id}</td>
                <td>${row.category || "-"}</td>
                <td>${row.owasp || "-"}</td>
                <td><span class="sev-badge ${sevClass}">${row.severity.toUpperCase()}</span></td>
                <td>${row.count}</td>
                <td>${tenantList || "-"}</td>
            `;

            tbody.appendChild(tr);
        });
}



// -------------------------------------------------------------
// Severity Badge Class Mapper
// -------------------------------------------------------------
function getSeverityClass(sev) {
    if (!sev) return "sev-info";

    const s = sev.toUpperCase();

    if (s === "CRITICAL") return "sev-critical";
    if (s === "HIGH") return "sev-high";
    if (s === "MEDIUM") return "sev-medium";
    if (s === "LOW") return "sev-low";

    return "sev-info";
}



// -------------------------------------------------------------
// Export
// -------------------------------------------------------------
window.renderKPI = renderKPI;
