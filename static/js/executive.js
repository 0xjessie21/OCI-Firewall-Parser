//
// executive.js
// Executive Summary Renderer
//

let trendChart = null;


// -------------------------------------------------------------
// Render Executive Summary
// -------------------------------------------------------------
function renderExecutive(d) {
    if (!d) return;

    // =======================
    // KPI: Total Attacks
    // =======================
    const total = d.total_attacks || 0;
    animateNumber(document.getElementById("kpiTotal"), total);

    // =======================
    // KPI: Active Tenants
    // =======================
    const tenants = d.tenants || [];
    animateNumber(document.getElementById("kpiTenantCount"), tenants.length);

    // =======================
    // KPI: Attack Velocity (AI Slot)
    // =======================
    const velocityText = calculateVelocity(d);
    document.getElementById("kpiVelocity").textContent = velocityText;

    // =======================
    // KPI: Peak Time
    // =======================
    const peak = calculatePeakTime(d);
    document.getElementById("kpiPeakTime").textContent = peak;

    // =======================
    // Risk Highlights
    // =======================
    updateRiskHighlights(d);

    // =======================
    // Trend chart
    // =======================
    const labels = d.timeline?.labels || [];
    const values = d.timeline?.values || [];
    renderTrendChart(labels, values);

    // =======================
    // Cyber Map (will be implemented in cyber_map.js)
    // =======================
    if (window.renderCyberMap) {
        renderCyberMap(d);
    }
}



// -------------------------------------------------------------
// Attack Velocity Calculator
// -------------------------------------------------------------
function calculateVelocity(d) {
    const labels = d.timeline?.labels || [];
    const values = d.timeline?.values || [];
    const total = d.total_attacks || 0;

    if (!(values.length > 0 && labels.length === values.length)) {
        return "-";
    }

    const slotInfo = autoDetectSlot(labels);
    const attacksPerSlot = (total / values.length).toFixed(1);

    return `${attacksPerSlot} / ${slotInfo.label}`;
}



// -------------------------------------------------------------
// Peak Time Detection
// -------------------------------------------------------------
function calculatePeakTime(d) {
    const labels = d.timeline?.labels || [];
    const values = d.timeline?.values || [];

    if (!(values.length > 0 && labels.length === values.length)) {
        return "-";
    }

    const maxIdx = values.indexOf(Math.max(...values));
    return labels[maxIdx] || "-";
}



// -------------------------------------------------------------
// Risk Highlights Renderer
// -------------------------------------------------------------
function updateRiskHighlights(d) {
    const total = d.total_attacks || 0;
    const mostOwasp = d.owasp?.labels?.[0] || "–";

    const highLabels = (d.severity?.labels || []).map(x => x.toUpperCase());
    const hasHigh = highLabels.includes("HIGH") || highLabels.includes("CRITICAL");

    const riskEl = document.getElementById("riskHighlights");

    riskEl.innerHTML = `
        <ul class="mb-0">
            <li>Total <strong>${total.toLocaleString("id-ID")}</strong> percobaan serangan pada periode ini.</li>
            <li>Fokus utama serangan mengarah pada kategori <strong>${mostOwasp}</strong>.</li>
            <li>${
                hasHigh
                ? `Terdapat aktivitas dengan tingkat risiko <strong>tinggi/kritikal</strong> yang perlu dimonitor.`
                : `Tidak terlihat lonjakan signifikan, namun pemantauan rutin tetap diperlukan.`
            }</li>
        </ul>
    `;
}



// -------------------------------------------------------------
// Trend Chart Renderer (Chart.js)
// -------------------------------------------------------------
function renderTrendChart(labels, values) {
    const canvas = document.getElementById("trendChart");

    // destroy previous instance
    if (trendChart) {
        trendChart.destroy();
        trendChart = null;
    }

    if (!(labels.length > 0 && labels.length === values.length)) {
        const ctx = canvas.getContext("2d");
        ctx.clearRect(0,0,canvas.width,canvas.height);
        ctx.fillStyle = "#6b7280";
        ctx.font = "12px system-ui";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText("Belum ada data timeline pada periode ini.", canvas.width/2, canvas.height/2);
        return;
    }

    trendChart = new Chart(canvas, {
        type: "line",
        data: {
            labels,
            datasets: [{
                label: "Serangan",
                data: values,
                borderColor: "#22d3ee",
                backgroundColor: "rgba(34,211,238,0.15)",
                borderWidth: 2,
                tension: 0.35,
                pointRadius: 2,
                pointBackgroundColor: "#22d3ee"
            }]
        },
        options: {
            plugins: { legend: { display: false }},
            scales: {
                x: { ticks: { color: "#9ca3af" }, grid: { color: "rgba(55,65,81,0.6)" }},
                y: { ticks: { color: "#9ca3af" }, grid: { color: "rgba(31,41,55,0.8)" }}
            }
        }
    });
}



// -------------------------------------------------------------
// Export to global scope
// -------------------------------------------------------------
window.renderExecutive = renderExecutive;
