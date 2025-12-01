//
// utils.js
// Utility functions for dashboard rendering
//

// -------------------------------------------------------------
// Animate KPI Numbers
// -------------------------------------------------------------
function animateNumber(el, target) {
    if (!el) return;

    const duration = 700;
    const startVal = parseInt(el.textContent.replace(/[^\d]/g, "") || "0", 10);
    const startTime = performance.now();

    function tick(now) {
        const progress = Math.min((now - startTime) / duration, 1);
        const val = Math.floor(startVal + (target - startVal) * progress);
        el.textContent = val.toLocaleString("id-ID");

        if (progress < 1) requestAnimationFrame(tick);
    }

    requestAnimationFrame(tick);
}



// -------------------------------------------------------------
// Time Parsing Helpers (AI Timeline Detection)
// -------------------------------------------------------------

// Flexible timestamp parser
function parseTimeFlexible(label) {
    const d = new Date(label);
    if (!isNaN(d)) return d;

    // yyyy-mm-dd
    const dateOnly = /^\d{4}-\d{2}-\d{2}$/;
    if (dateOnly.test(label)) {
        const d2 = new Date(label + " 00:00:00");
        if (!isNaN(d2)) return d2;
    }

    return null;
}


// Compute deltas between sorted timestamps
function computeSlotDeltas(labels) {
    const times = labels
        .map(parseTimeFlexible)
        .filter(t => t instanceof Date && !isNaN(t));

    if (times.length < 2) return [];

    times.sort((a, b) => a - b);

    const deltas = [];
    for (let i = 1; i < times.length; i++) {
        deltas.push(times[i] - times[i - 1]);
    }

    return deltas;
}


// Convert milliseconds to human-friendly label
function msToReadable(ms) {
    const minutes = ms / 60000;
    const hours = minutes / 60;
    const days = hours / 24;

    if (minutes < 60) return `${minutes.toFixed(0)} minutes`;
    if (hours < 24) return `${hours.toFixed(1)} hours`;
    return `${days.toFixed(1)} days`;
}


// AI Slot Detector
function autoDetectSlot(labels) {
    const deltas = computeSlotDeltas(labels || []);

    if (deltas.length > 0) {
        const avg = deltas.reduce((a, b) => a + b, 0) / deltas.length;
        return {
            mode: "ai",
            slotMs: avg,
            label: msToReadable(avg)
        };
    }

    // fallback – detect hour/day manually
    const hourPattern = /\b([01]?\d|2[0-3]):[0-5]\d\b/;
    const datePattern = /^\d{4}-\d{2}-\d{2}$/;

    const hasHour = (labels || []).some(l => hourPattern.test(l));
    const hasDate = (labels || []).some(l => datePattern.test(l));

    if (hasHour) return { mode: "fallback", label: "hour" };
    if (hasDate) return { mode: "fallback", label: "day" };

    return { mode: "unknown", label: "-" };
}


// -------------------------------------------------------------
// Export to global scope so other modules can use them
// -------------------------------------------------------------
window.animateNumber = animateNumber;
window.autoDetectSlot = autoDetectSlot;
window.parseTimeFlexible = parseTimeFlexible;
window.computeSlotDeltas = computeSlotDeltas;
window.msToReadable = msToReadable;
