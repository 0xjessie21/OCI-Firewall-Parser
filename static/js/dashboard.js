//
// dashboard.js
// Main controller for the dashboard application
//

let lastData = null;
let autoRefreshInterval = null;


// -------------------------------------------------------------
// INITIALIZATION
// -------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {

    setupNavigation();   // sidebar navigation
    loadData();          // initial load

    // Auto-refresh every 60 seconds (opsional)
    autoRefreshInterval = setInterval(loadData, 60000);
});



// -------------------------------------------------------------
// FETCH DATA FROM BACKEND
// -------------------------------------------------------------
async function loadData() {
    try {
        const res = await fetch("/api/data");
        const data = await res.json();
        lastData = data;

        // Update scope header
        updateTenantScope(data);

        // Call all rendering modules
        if (window.renderExecutive) renderExecutive(data);
        if (window.renderTenantWall) renderTenantWall(data);
        if (window.renderKPI) renderKPI(data);
        if (window.renderCyberMap) renderCyberMap(data);

    } catch (err) {
        console.error("Gagal fetch data API:", err);
    }
}



// -------------------------------------------------------------
// UPDATE TENANT SCOPE LABEL
// -------------------------------------------------------------
function updateTenantScope(data) {
    const el = document.getElementById("tenantScope");
    if (!el) return;

    el.textContent = data.identity || data.hostname || "UNKNOWN";
}



// -------------------------------------------------------------
// SIDEBAR NAVIGATION HANDLER
// -------------------------------------------------------------
function setupNavigation() {
    const buttons = document.querySelectorAll(".nav-link");
    const sections = document.querySelectorAll(".view-section");

    buttons.forEach(btn => {
        btn.addEventListener("click", () => {

            // Remove active from all
            buttons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");

            const view = btn.dataset.view;

            sections.forEach(sec => {
                if (sec.id === view) sec.classList.add("active");
                else sec.classList.remove("active");
            });
        });
    });
}



// -------------------------------------------------------------
// Optional: Manual Refresh Trigger
// -------------------------------------------------------------
window.refreshDashboard = () => {
    loadData();
};



// -------------------------------------------------------------
// Optional: Stop Auto Refresh (if needed for debugging)
// -------------------------------------------------------------
window.stopAutoRefresh = () => {
    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
};
