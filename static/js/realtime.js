// realtime.js
// Realtime Attack Feed (polling /api/realtime_feed setiap 60 detik)

async function loadRealtimeOnce() {
    const tableBody = document.querySelector("#rtTable tbody");
    if (!tableBody) {
        return; // view belum ada / tidak aktif
    }

    try {
        const res = await fetch("/api/realtime_feed");
        if (!res.ok) {
            console.error("Realtime feed error:", res.status, await res.text());
            return;
        }

        const data = await res.json();
        const events = data.events || [];

        tableBody.innerHTML = "";

        events.forEach((ev) => {
            const tr = document.createElement("tr");

            const sev = (ev.severity || "INFO").toUpperCase();
            const sevClass = `sev-${sev.toLowerCase()}`;

            tr.innerHTML = `
                <td>${ev.time || "-"}</td>
                <td>${ev.clientIp || "-"}</td>
                <td>${ev.host || "-"}</td>
                <td>${ev.uri || "-"}</td>
                <td>${ev.mitre || "-"}</td>
                <td>${ev.rule || "-"}</td>
                <td><span class="sev-badge ${sevClass}">${sev}</span></td>
            `;

            tableBody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load realtime feed:", err);
    }
}

// Auto-refresh setiap 60 detik
setInterval(loadRealtimeOnce, 60000);

// Load pertama saat halaman selesai
document.addEventListener("DOMContentLoaded", () => {
    loadRealtimeOnce();
});
