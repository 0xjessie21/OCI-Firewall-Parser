//
// tenants.js
// Tenant Identity Wall Renderer
//

function renderTenantWall(d) {
    const cont = document.getElementById("tenantWallCards");
    if (!cont) return;

    cont.innerHTML = "";

    const tenants = d.tenants || [];
    if (!tenants.length) {
        cont.innerHTML = `<div class="text-muted small">Belum ada data tenant.</div>`;
        return;
    }

    const maxEvents = Math.max(...tenants.map(t => t.events || 0), 1);

    tenants.forEach(t => {
        cont.appendChild(makeTenantCard(t, maxEvents));
    });
}


function makeTenantCard(t, maxEvents) {
    const host = (t.hostname || "").replace(".pelindo.co.id", "");
    const id = t.identity || "";
    const ev = t.events || 0;

    const pct = calculatePct(ev, maxEvents);

    const wrapper = document.createElement("div");
    wrapper.className = "tenant-card mb-2 p-2";
    wrapper.style = `
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(148,163,184,0.25);
        border-radius: 10px;
        cursor: pointer;
    `;

    // Drill-down event
    wrapper.addEventListener("click", () => {
        loadTenantDetails(t.hostname);
    });

    wrapper.innerHTML = `
        <div class="d-flex justify-content-between fw-bold">
            <span>${host}</span>
            <span>${ev}</span>
        </div>
        <div class="small text-muted mb-1">${id}</div>

        <div style="height: 6px; background: rgba(148,163,184,0.15); border-radius: 4px; overflow: hidden;">
            <div style="
                height: 100%;
                width: ${pct}%;
                background: linear-gradient(90deg, #22d3ee, #a855f7);
                border-radius: 4px;
                box-shadow: 0 0 12px rgba(34,211,238,0.6);
                transition: width .6s ease-out;
            "></div>
        </div>
    `;

    return wrapper;
}


function calculatePct(ev, max) {
    if (max <= 0) return 0;
    return Math.round((ev / max) * 100);
}

window.renderTenantWall = renderTenantWall;
