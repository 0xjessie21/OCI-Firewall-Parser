//
// cyber_map.js
// Neon Attack Landscape Visualizer
//

// -------------------------------------------------------------
// Main Renderer
// -------------------------------------------------------------
function renderCyberMap(d) {
    const cont = document.getElementById("cyberMap");
    if (!cont) return;

    clearMap(cont);

    const mitre = d.mitre || [];
    if (!mitre.length) {
        cont.innerHTML = `<div class="text-muted small">Belum ada data serangan untuk divisualisasikan.</div>`;
        return;
    }

    // --- Create center node (hub) ---
    const centerName = d.identity || d.hostname || "SYSTEM";
    const centerNode = createNode(centerName, "CENTER");
    centerNode.style.left = "50%";
    centerNode.style.top = "50%";
    centerNode.style.transform = "translate(-50%, -50%)";
    cont.appendChild(centerNode);

    // --- Create MITRE technique nodes around the center ---
    const techniqueNodes = mitre.slice(0, 12).map((item, i) => {
        const node = createNode(item.mitre_id, item.severity);
        cont.appendChild(node);
        return node;
    });

    // --- Position nodes using circular layout ---
    layoutCircular(techniqueNodes, cont);

    // --- Draw connecting neon lines ---
    drawConnections(centerNode, techniqueNodes, cont);
}



// -------------------------------------------------------------
// Clear previous map
// -------------------------------------------------------------
function clearMap(container) {
    container.innerHTML = "";
}



// -------------------------------------------------------------
// Create Glowing Node
// -------------------------------------------------------------
function createNode(name, severity) {
    const node = document.createElement("div");
    node.className = "cyber-node";

    const color = severityColor(severity);

    node.style.position = "absolute";
    node.style.width = "70px";
    node.style.height = "70px";
    node.style.borderRadius = "50%";
    node.style.display = "flex";
    node.style.alignItems = "center";
    node.style.justifyContent = "center";

    node.style.background = `radial-gradient(circle, ${color} 20%, rgba(0,0,0,0.6) 70%)`;
    node.style.boxShadow = `0 0 15px ${color}, 0 0 35px ${color}`;
    node.style.textAlign = "center";
    node.style.fontSize = "0.7rem";
    node.style.padding = "6px";
    node.style.color = "#fff";

    // Animated pulse
    node.style.animation = "pulseGlow 2.3s ease-in-out infinite";

    node.textContent = name;

    return node;
}



// -------------------------------------------------------------
// Severity → Color Mapping
// -------------------------------------------------------------
function severityColor(sev) {
    if (!sev) return "#38bdf8"; // default / center

    const s = sev.toUpperCase();

    if (s === "CRITICAL") return "#f43f5e";
    if (s === "HIGH")     return "#f97316";
    if (s === "MEDIUM")   return "#eab308";
    if (s === "LOW")      return "#22c55e";

    return "#38bdf8";
}



// -------------------------------------------------------------
// Circular Layout for Technique Nodes
// -------------------------------------------------------------
function layoutCircular(nodes, container) {
    const cx = container.offsetWidth / 2;
    const cy = container.offsetHeight / 2;
    const radius = Math.min(cx, cy) - 80;

    const step = (2 * Math.PI) / nodes.length;

    nodes.forEach((node, i) => {
        const angle = step * i - Math.PI / 2; // start top center
        const x = cx + radius * Math.cos(angle);
        const y = cy + radius * Math.sin(angle);

        node.style.left = `${x}px`;
        node.style.top = `${y}px`;
        node.style.transform = "translate(-50%, -50%)";
    });
}



// -------------------------------------------------------------
// Draw glowing neon lines between center and nodes
// -------------------------------------------------------------
function drawConnections(centerNode, nodes, container) {
    const rectCenter = centerNode.getBoundingClientRect();
    const cx = rectCenter.left + rectCenter.width / 2;
    const cy = rectCenter.top + rectCenter.height / 2;

    nodes.forEach(node => {
        const rect = node.getBoundingClientRect();
        const nx = rect.left + rect.width / 2;
        const ny = rect.top + rect.height / 2;

        const line = document.createElement("div");
        line.className = "cyber-line";

        // Line length and angle
        const dx = nx - cx;
        const dy = ny - cy;
        const distance = Math.sqrt(dx * dx + dy * dy);
        const angle = Math.atan2(dy, dx) * (180 / Math.PI);

        line.style.position = "absolute";
        line.style.width = `${distance}px`;
        line.style.height = "3px";
        line.style.left = `${cx}px`;
        line.style.top = `${cy}px`;
        line.style.transformOrigin = "0 50%";
        line.style.transform = `rotate(${angle}deg)`;
        line.style.background = "linear-gradient(90deg, rgba(34,211,238,0.7), rgba(168,85,247,0.8))";
        line.style.boxShadow = "0 0 10px rgba(34,211,238,0.7)";
        line.style.borderRadius = "999px";
        line.style.opacity = "0.8";

        container.appendChild(line);
    });
}



// -------------------------------------------------------------
// Export
// -------------------------------------------------------------
window.renderCyberMap = renderCyberMap;
