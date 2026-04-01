/**
 * NexShield — SOC script.js (Mission Control Premium Edition v2)
 * Real-time intelligence, toast notifications, keyboard shortcuts,
 * canvas radar/timeline, live system clock.
 */

let lastTimelineData = {};
let lastTrendData = {};
let currentThreats = [];
let currentFilteredThreats = [];
let donutAnimationFrame = null;
let resizeTimeout;

// ── App Initialization ───────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    console.log("NEXSHIELD :: MISSION_CONTROL :: ONLINE");

    // Fade-in effect
    document.body.style.opacity = 0;
    setTimeout(() => {
        document.body.style.transition = "opacity 0.8s ease";
        document.body.style.opacity = 1;
    }, 100);

    // Start live clock
    updateSystemClock();
    setInterval(updateSystemClock, 1000);

    // Initial Dashboard Sync
    syncIntelligence();

    // Mission Control Pulse (Polling)
    setInterval(syncIntelligence, 30000);

    setupKeyboardShortcuts();

    window.addEventListener("resize", debounce(() => {
        if (lastTimelineData.days && lastTimelineData.timeline) {
            drawTimeline(lastTimelineData.days, lastTimelineData.timeline);
        }
        if (lastTrendData.severity_distribution) {
            drawDonut(lastTrendData.severity_distribution);
        }
    }, 150));

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            closeModal();
        }
    });
});

// ── Live System Clock ───────────────────────────────────────────
function updateSystemClock() {
    const el = document.getElementById("systemClock");
    if (!el) return;
    const now = new Date();
    const h = String(now.getUTCHours()).padStart(2, "0");
    const m = String(now.getUTCMinutes()).padStart(2, "0");
    const s = String(now.getUTCSeconds()).padStart(2, "0");
    el.textContent = `${h}:${m}:${s} UTC`;
}

// ── Socket.IO Real-time Connection ──────────────────────────────
const socket = io({
    auth: async (cb) => {
        try {
            const res = await fetch("/api/auth/token");
            const data = await res.json();
            cb({ token: data.token });
        } catch (e) {
            console.error("Auth token fetch failed", e);
            cb({});
        }
    }
});

socket.on("connect", () => {
    updateSystemStatus("ONLINE", "status-dot--online");
    showToast("System Link established with Central Intelligence.", "success");
});

socket.on("disconnect", () => {
    updateSystemStatus("OFFLINE", "");
    showToast("System Link severed. Attempting reconnection...", "error");
});

socket.on("scan_complete", (data) => {
    stopRadar();
    showToast(data.message, data.status);
    syncIntelligence();
});

socket.on("analysis_complete", (data) => {
    showToast(data.message, data.status);
    syncIntelligence();
});

socket.on("training_complete", (data) => {
    showToast(data.message, data.status);
    syncIntelligence();
});

socket.on("data_reset", (data) => {
    const resetButton = document.getElementById("btnReset");
    if (!resetButton || !resetButton.disabled) {
        showToast(data.message, data.status || "success");
    }
    closeModal();
    stopRadar();
    syncIntelligence();
});

socket.on("quarantine_complete", (data) => {
    showToast(data.message, data.status);
    syncIntelligence();
});

/**
 * Unified Intelligence Synchronizer.
 */
function syncIntelligence() {
    fetchStats();
    fetchThreats();
    fetchTimeline();
    fetchThreatTrends();
    fetchRiskScores();
    fetchActivity();
}

/**
 * Update the Top Header Status
 */
function updateSystemStatus(text, dotClass) {
    const dot = document.getElementById("statusDot");
    const label = document.getElementById("statusText");
    if (dot && label) {
        dot.className = "status-dot " + dotClass;
        label.innerText = `SYS_LINK: ${text}`;
    }
}

async function fetchJson(url, options = {}) {
    const response = await fetch(url, {
        headers: {
            Accept: "application/json",
            ...(options.headers || {}),
        },
        ...options,
    });

    const data = await response.json();

    if (response.status === 401) {
        window.location.href = "/login";
        throw new Error("Session expired. Please sign in again.");
    }

    if (!response.ok) {
        throw new Error(data.message || `Request failed (${response.status})`);
    }

    return data;
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function formatTimestamp(value) {
    if (!value) return "Unknown";
    const parsed = value.$date ? new Date(value.$date) : new Date(value);
    return Number.isNaN(parsed.getTime()) ? "Unknown" : parsed.toLocaleString();
}

function severityClass(severity) {
    switch ((severity || "").toLowerCase()) {
    case "critical": return "sev-critical";
    case "high": return "sev-high";
    case "medium": return "sev-medium";
    case "low": return "sev-low";
    default: return "sev-medium";
    }
}

function consoleSeverityClass(type) {
    switch ((type || "").toLowerCase()) {
    case "error":
    case "critical":
    case "high":
        return "sev-critical";
    case "warning":
    case "medium":
        return "sev-medium";
    case "success":
    case "low":
        return "sev-low";
    default:
        return "sev-high";
    }
}

function debounce(callback, wait) {
    return (...args) => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => callback(...args), wait);
    };
}

// ── Tactical Helpers ─────────────────────────────────────────────
function startLoadingState(btnId, loadingText = "TRANSMITTING...") {
    const btn = document.querySelector(`#${btnId} .btn-manual`) || document.getElementById(btnId);
    if (btn) {
        btn.dataset.originalText = btn.innerText;
        btn.innerText = loadingText;
        btn.disabled = true;
        btn.style.opacity = "0.7";
        btn.style.cursor = "wait";
    }
}

function stopLoadingState(btnId) {
    const btn = document.querySelector(`#${btnId} .btn-manual`) || document.getElementById(btnId);
    if (btn) {
        btn.innerText = btn.dataset.originalText || "EXEC_SCAN";
        btn.disabled = false;
        btn.style.opacity = "1";
        btn.style.cursor = "pointer";
    }
}

function renderSkeletonMap() {
    const grid = document.getElementById("riskScoresGrid");
    if (!grid) return;
    grid.innerHTML = "";
    for (let i = 0; i < 12; i++) {
        const skeleton = document.createElement("div");
        skeleton.className = "risk-dot skeleton";
        grid.appendChild(skeleton);
    }
}

// ── Stats ────────────────────────────────────────────────────────
async function fetchStats() {
    try {
        const data = await fetchJson("/api/stats");

        animateCount("totalThreats", data.total_threats);
        animateCount("criticalCount", data.critical);
        animateCount("highCount", data.high);
        animateCount("mediumCount", (data.medium || 0) + (data.low || 0));
        animateCount("scanCount", data.total_scans || 0);

        updateTrend("trendTotal", data.total_threats, "ACTIVE_NODES");
        updateTrend("trendCritical", data.critical, "FLAGGED");
        updateTrend("trendHigh", data.high, "FLAGGED");
        updateTrend("trendMedium", (data.medium || 0) + (data.low || 0), "TRACKED");
        updateTrend("trendScans", data.total_scans || 0, "COMPLETED");
    } catch (err) {
        console.error("Stats fail:", err);
    }
}

function animateCount(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    const startValue = parseInt(el.innerText) || 0;
    const duration = 1000;
    const startTime = performance.now();

    function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Ease-out curve
        const eased = 1 - Math.pow(1 - progress, 3);
        const currentCount = Math.floor(eased * (value - startValue) + startValue);
        el.innerText = currentCount;
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

function updateTrend(id, value, label = "ACTIVE_NODES") {
    const el = document.getElementById(id);
    if (el) el.innerHTML = `<span style="opacity: 0.5">${label}:</span> ${value}`;
}

// ── Threats List ──────────────────────────────────────────────────
async function fetchThreats() {
    try {
        const data = await fetchJson("/api/threats?limit=100");
        currentThreats = Array.isArray(data.threats) ? data.threats : [];
        applyFilters();
    } catch (err) {
        console.error("Threats fail:", err);
        renderThreats([]);
    }
}

function renderThreats(threats) {
    const body = document.getElementById("threatsBody");
    if (!body) return;

    if (!threats || threats.length === 0) {
        body.innerHTML = '<tr><td colspan="5" class="empty-row">NO_THREATS_DETECTED — Run a scan to begin.</td></tr>';
        return;
    }

    currentFilteredThreats = threats;
    body.innerHTML = threats.map((t, index) => `
        <tr onclick="openModalByIndex(${index})" class="row-clickable">
            <td><span class="${severityClass(t.severity)}">${escapeHtml((t.severity || "unknown").toUpperCase())}</span></td>
            <td class="font-mono" style="font-size: 0.8rem">${escapeHtml(t.name || "Unknown threat")}</td>
            <td class="font-mono">${escapeHtml(t.host || "Unknown host")}</td>
            <td><code>${escapeHtml(t.cve_id || "-")}</code></td>
            <td style="opacity: 0.6; font-size: 0.75rem">${escapeHtml(t.source || "Unknown engine")}</td>
        </tr>
    `).join("");
}

function openModalByIndex(index) {
    if (index >= 0 && index < currentFilteredThreats.length) {
        openModal(currentFilteredThreats[index]);
    }
}

function applyFilters() {
    const search = (document.getElementById("filterSearch")?.value || "").trim().toLowerCase();
    const severity = (document.getElementById("filterSeverity")?.value || "").trim().toLowerCase();

    const filtered = currentThreats.filter((threat) => {
        const haystack = [
            threat.name,
            threat.host,
            threat.cve_id,
            threat.source,
            threat.detail,
        ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();

        const matchesSearch = !search || haystack.includes(search);
        const matchesSeverity = !severity || threat.severity === severity;
        return matchesSearch && matchesSeverity;
    });

    renderThreats(filtered);
}

async function fetchThreatTrends() {
    try {
        const data = await fetchJson("/api/threat-trends");
        lastTrendData = data;
        drawDonut(data.severity_distribution);
    } catch (err) { console.error("Trend fail:", err); }
}

function drawDonut(dist) {
    const canvas = document.getElementById("donutChart");
    const legend = document.getElementById("donutLegend");
    if (!canvas || !legend) return;

    const critical = dist.critical || 0;
    const high = dist.high || 0;
    const medlow = (dist.medium || 0) + (dist.low || 0);

    const data = {
        labels: ["Critical", "High", "Medium/Low"],
        datasets: [{
            data: [critical, high, medlow],
            backgroundColor: ["#ff3860", "#ff8c00", "#ffd600"],
            borderWidth: 0,
            hoverOffset: 15
        }]
    };

    renderDonutCanvas(canvas, data);

    legend.innerHTML = `
        <div class="hud-item">
            <span class="hud-label">CRITICAL_VULN</span>
            <span class="hud-value hud-value--critical">${critical}</span>
        </div>
        <div class="hud-item">
            <span class="hud-label">HIGH_RISK</span>
            <span class="hud-value hud-value--high">${high}</span>
        </div>
        <div class="hud-item">
            <span class="hud-label">MED_LOW</span>
            <span class="hud-value hud-value--medlow">${medlow}</span>
        </div>
    `;
}

async function fetchTimeline() {
    try {
        const data = await fetchJson("/api/timeline?days=7");
        lastTimelineData = data;
        drawTimeline(data.days, data.timeline);
    } catch (err) { console.error("Timeline fail:", err); }
}

// ── Host Risk Heatmap ──────────────────────────────────────────────
async function fetchRiskScores() {
    try {
        const grid = document.getElementById("riskScoresGrid");
        if (grid && grid.children.length === 0) renderSkeletonMap();

        const data = await fetchJson("/api/risk-scores");
        renderRiskHeatmap(data.scores);
    } catch (err) { console.error("Risk fail:", err); }
}

function renderRiskHeatmap(scores) {
    const grid = document.getElementById("riskScoresGrid");
    if (!grid) return;

    if (!scores || scores.length === 0) {
        grid.innerHTML = '<p style="font-size: 0.7rem; opacity: 0.5; font-family: var(--font-mono); letter-spacing: 1px">RUN_ANALYSIS_FOR_MAP</p>';
        return;
    }

    const orderedScores = [...scores].sort((left, right) => (right.score || 0) - (left.score || 0));
    grid.innerHTML = orderedScores.map((score) => {
        let color = "rgba(136, 146, 164, 0.5)";
        if (score.risk_level === "critical") color = "var(--red)";
        else if (score.risk_level === "high") color = "var(--orange)";
        else if (score.risk_level === "medium") color = "var(--yellow)";
        else if (score.risk_level === "low") color = "var(--green)";

        return `<div class="risk-dot"
                     style="border-left: 3px solid ${color}; box-shadow: -5px 0 10px ${color}22"
                     title="NODE::${escapeHtml(score.host)} | SCORE::${escapeHtml(String(score.score || 0))} | ENGINES::${escapeHtml(String(score.engines_flagged || 0))}"
                     onclick="showHostReport('${escapeHtml(score.host || "")}')">
                     <span class="risk-node-ip">${escapeHtml(score.host || "unknown")}</span>
                </div>`;
    }).join("");
}

async function fetchActivity() {
    try {
        const data = await fetchJson("/api/activity");
        const list = document.getElementById("activityList");
        if (!list) return;

        const events = Array.isArray(data.events) ? data.events : [];
        if (events.length === 0) {
            list.innerHTML = '<div style="opacity: 0.5; font-family: var(--font-mono)">[WAITING] No recorded activity.</div>';
            return;
        }

        list.innerHTML = events.slice(0, 25).map((event) => `
            <div style="margin-bottom: 4px">
                <span style="opacity: 0.4">[${escapeHtml(formatTimestamp(event.timestamp))}]</span>
                <span class="${consoleSeverityClass(event.severity)}">${escapeHtml(event.message || "No message")}</span>
            </div>
        `).join("");
    } catch (err) {
        console.error("Activity fail:", err);
    }
}

// ── Action Handlers ──────────────────────────────────────────────
function triggerScan() {
    const target = document.getElementById("scanTarget")?.value.trim() || "";
    const ports = document.getElementById("scanPorts")?.value.trim() || "";
    if (!target) {
        showToast("Enter a real target IP, CIDR, or hostname first.", "error");
        document.getElementById("scanTarget")?.focus();
        return;
    }

    startLoadingState("btnScan", "SCANNING...");
    startRadar();
    showToast("Initiating live target scan...", "info");

    const payload = { target };
    if (ports) payload.ports = ports;

    fetchJson("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    })
        .then((data) => showToast(data.message, data.status || "success"))
        .catch((error) => {
            stopRadar();
            showToast(error.message, "error");
        })
        .finally(() => stopLoadingState("btnScan"));
}

function triggerAnalysis() {
    startLoadingState("btnAnalyze", "ANALYZING...");
    showToast("Launching AI analysis pipeline...", "info");
    fetchJson("/api/analyze", { method: "POST" })
        .then((data) => showToast(data.message, data.status || "success"))
        .catch((error) => showToast(error.message, "error"))
        .finally(() => stopLoadingState("btnAnalyze"));
}

function triggerTraining() {
    startLoadingState("btnTrain", "TRAINING...");
    showToast("Optimizing AI multi-models...", "info");
    fetchJson("/api/train", { method: "POST" })
        .then((data) => showToast(data.message, data.status || "success"))
        .catch((error) => showToast(error.message, "error"))
        .finally(() => stopLoadingState("btnTrain"));
}

function triggerResetData() {
    const approved = window.confirm(
        "Reset old threats, scan history, and activity logs? User accounts stay intact."
    );
    if (!approved) return;

    startLoadingState("btnReset", "RESETTING...");
    showToast("Resetting old operational data...", "warning");
    fetchJson("/api/reset-data", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ include_cache: false })
    }).then((data) => {
        currentThreats = [];
        currentFilteredThreats = [];
        showToast(data.message, data.status || "success");
        closeModal();
        syncIntelligence();
    }).catch((error) => {
        showToast(error.message, "error");
    }).finally(() => stopLoadingState("btnReset"));
}

function triggerManualScan() {
    const target = document.getElementById("scanTarget").value.trim();
    const ports = document.getElementById("scanPorts").value.trim();
    if (!target) return showToast("Enter an IP range or host.", "error");

    startLoadingState("execScanBtn", "SCANNING...");
    const payload = { target };
    if (ports) payload.ports = ports;

    fetchJson("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    }).then((data) => {
        showToast(data.message, data.status || "success");
        if (data.status === "accepted") startRadar();
    }).catch((error) => {
        stopRadar();
        showToast(error.message, "error");
    }).finally(() => stopLoadingState("execScanBtn"));
}

function quarantineHost(host) {
    const approved = window.confirm(`Isolate node [${host}] and remediate its active threats?`);
    if (!approved) return;

    showToast(`Initializing ZERO-TRUST isolation protocols for ${host}...`, "warning");
    fetchJson("/api/quarantine", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host })
    }).then((data) => {
        showToast(data.message, data.status || "success");
        closeModal();
    }).catch((error) => {
        showToast(error.message, "error");
    });
}

function exportReport(format, filters = {}) {
    const params = new URLSearchParams({ format });
    const severity = document.getElementById("filterSeverity")?.value;

    if (filters.host) params.set("host", filters.host);
    if (filters.severity) {
        params.set("severity", filters.severity);
    } else if (severity) {
        params.set("severity", severity);
    }

    showToast(`Preparing ${format.toUpperCase()} export...`, "success");
    window.location.href = `/api/export?${params.toString()}`;
}

function lookupCVE(cveId) {
    const input = (cveId || document.getElementById("cveInput")?.value || "").trim().toUpperCase();
    const resultBox = document.getElementById("cveResult");
    if (!input) {
        showToast("Enter a CVE identifier first.", "error");
        return;
    }

    if (resultBox) {
        resultBox.innerHTML = '<div style="opacity: 0.65; margin-top: 0.75rem; font-family: var(--font-mono)">QUERYING_INTEL_CACHE...</div>';
    }

    fetchJson(`/api/cve/${encodeURIComponent(input)}`)
        .then((data) => {
            if (!resultBox) return;
            const references = (data.references || []).slice(0, 5).map((reference) => `
                <li style="margin-bottom: 0.35rem"><a href="${escapeHtml(reference)}" target="_blank" rel="noreferrer" style="color: var(--cyan)">${escapeHtml(reference)}</a></li>
            `).join("") || '<li style="opacity: 0.6">No reference links returned.</li>';

            resultBox.innerHTML = `
                <div style="margin-top: 0.9rem; font-size: 0.8rem; line-height: 1.55; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 0.9rem">
                    <div style="margin-bottom: 0.5rem">
                        <strong>${escapeHtml(data.cve_id || input)}</strong>
                        <span class="${severityClass(data.severity)}" style="margin-left: 0.5rem">${escapeHtml((data.severity || "unknown").toUpperCase())}</span>
                    </div>
                    <div style="margin-bottom: 0.5rem; opacity: 0.85">${escapeHtml(data.description || "No description available.")}</div>
                    <div style="display: grid; grid-template-columns: 96px 1fr; gap: 6px; margin-bottom: 0.7rem; font-family: var(--font-mono)">
                        <span style="opacity: 0.5">CVSS</span><span>${escapeHtml(String(data.score ?? "n/a"))}</span>
                        <span style="opacity: 0.5">Published</span><span>${escapeHtml(data.published || "Unknown")}</span>
                        <span style="opacity: 0.5">Modified</span><span>${escapeHtml(data.modified || "Unknown")}</span>
                        <span style="opacity: 0.5">Cache</span><span>${data.cached ? "Hit" : "Live fetch"}</span>
                    </div>
                    <ul style="padding-left: 1rem">${references}</ul>
                </div>
            `;
            showToast(`Loaded ${input} intelligence.`, "success");
        })
        .catch((error) => {
            if (resultBox) {
                resultBox.innerHTML = `<div class="sev-critical" style="margin-top: 0.75rem; font-family: var(--font-mono)">${escapeHtml(error.message)}</div>`;
            }
            showToast(error.message, "error");
        });
}

function targetScanHost(host) {
    closeModal();
    const targetInput = document.getElementById("scanTarget");
    if (targetInput) targetInput.value = host;
    triggerManualScan();
}

async function showHostReport(host) {
    const overlay = document.getElementById("modalOverlay");
    const title = document.getElementById("modalTitle");
    const body = document.getElementById("modalBody");
    if (!overlay || !title || !body) return;
    
    title.innerText = `IP_PROFILING::${host}`;
    body.innerHTML = `<div style="opacity: 0.6; font-family: var(--font-mono); font-size: 0.85rem">FETCHING_NODE_TELEMETRY...</div>`;
    overlay.classList.add("modal--active");

    const hostThreats = currentThreats.filter((threat) => threat.host === host);
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    hostThreats.forEach((threat) => {
        if (summary[threat.severity] !== undefined) summary[threat.severity] += 1;
    });

    try {
        const data = await fetchJson(`/api/host/${encodeURIComponent(host)}`);
        
        let portsTable = `<div style="margin-top: 1.5rem; color: #8892a4; font-size: 0.8rem; font-family: var(--font-mono)">[!] NO_SCAN_FOOTPRINT_FOUND</div>`;
        
        if (data.footprint && data.footprint.protocols) {
            let rows = "";
            let openCount = 0;
            data.footprint.protocols.forEach(proto => {
                if(proto.ports) {
                    proto.ports.forEach(p => {
                        if (p.state === "open" || p.state === "filtered") {
                            openCount++;
                            rows += `
                                <tr>
                                    <td><span class="${p.state === 'open' ? 'sev-low' : 'sev-medium'}">${escapeHtml(p.state).toUpperCase()}</span></td>
                                    <td>${escapeHtml(String(p.port))}/${escapeHtml(proto.protocol)}</td>
                                    <td>${escapeHtml(p.service)}</td>
                                    <td style="opacity: 0.6">${escapeHtml(p.version || p.product || "-")}</td>
                                </tr>
                            `;
                        }
                    });
                }
            });
            
            if (openCount > 0) {
                portsTable = `
                    <div style="margin-top: 1.5rem; border-top: 1px solid #1a2433; padding-top: 1rem;">
                        <div style="margin-bottom: 0.8rem; color: var(--cyan); letter-spacing: 1px; font-size: 0.8rem; font-family: var(--font-mono)">[✓] ${openCount} OPEN_PORTS_DETECTED</div>
                        <table class="data-table" style="margin-top: 0;">
                            <thead><tr><th>STATE</th><th>PORT</th><th>SERVICE</th><th>VERSION</th></tr></thead>
                            <tbody>${rows}</tbody>
                        </table>
                    </div>
                `;
            }
        }

        body.innerHTML = `
            <div style="font-family: var(--font-mono); font-size: 0.85rem;">
                <div style="display: grid; grid-template-columns: 120px 1fr; gap: 10px; padding-bottom: 1rem;">
                    <span style="opacity: 0.5">CRITICAL</span> <span class="sev-critical">${summary.critical}</span>
                    <span style="opacity: 0.5">HIGH</span> <span class="sev-high">${summary.high}</span>
                    <span style="opacity: 0.5">MEDIUM</span> <span class="sev-medium">${summary.medium}</span>
                    <span style="opacity: 0.5">LOW</span> <span class="sev-low">${summary.low}</span>
                </div>
                ${portsTable}
                <div style="margin-top: 1.5rem; display: flex; flex-wrap: wrap; gap: 10px;">
                    <button class="btn-console" style="border-color: var(--red); color: var(--red);" onclick="quarantineHost('${escapeHtml(host)}')">⚡ QUARANTINE_NODE</button>
                    <button class="btn-console" style="color: var(--orange); border-color: var(--orange);" onclick="targetScanHost('${escapeHtml(host)}')">⚡ TARGETED_SCAN</button>
                    <button class="btn-console" onclick="exportReport('csv', { host: '${escapeHtml(host)}' })">EXPORT_THREATS_CSV</button>
                    ${data.footprint ? `<button class="btn-console" onclick="window.location.href='/api/export-scan?host=${encodeURIComponent(host)}'">EXPORT_FOOTPRINT_JSON</button>` : ''}
                </div>
            </div>
        `;
    } catch (err) {
        body.innerHTML = `<div class="sev-critical" style="font-family: var(--font-mono)">[!] FAILED_TO_RETRIEVE_NODE_TELEMETRY:<br>${escapeHtml(err.message)}</div>`;
    }
}

// ── Radar Visualization ──────────────────────────────────────────
function startRadar() {
    const radar = document.getElementById("radarPing");
    if (radar) radar.classList.add("radar-active");
}

function stopRadar() {
    const radar = document.getElementById("radarPing");
    if (radar) radar.classList.remove("radar-active");
}

// ── Modal Handling ────────────────────────────────────────────────
function openModal(threat) {
    const overlay = document.getElementById("modalOverlay");
    const title = document.getElementById("modalTitle");
    const body = document.getElementById("modalBody");
    if (!overlay || !title || !body || !threat) return;

    title.innerText = `THREAT::${(threat.name || "Unknown").toUpperCase()}`;
    body.innerHTML = `
        <div style="font-family: var(--font-mono); font-size: 0.85rem;">
            <p style="margin-bottom: 1rem; color: #8892a4;">[SUMMARY]: ${escapeHtml(threat.detail || "No summary available.")}</p>
            <div style="display: grid; grid-template-columns: 120px 1fr; gap: 10px; border-top: 1px solid #1a2433; padding-top: 1rem;">
                <span style="opacity: 0.5">IP_NODE</span> <span>${escapeHtml(threat.host || "Unknown")}</span>
                <span style="opacity: 0.5">RISK_LEVEL</span> <span class="${severityClass(threat.severity)}">${escapeHtml((threat.severity || "unknown").toUpperCase())}</span>
                <span style="opacity: 0.5">CVE_LINK</span> <code>${escapeHtml(threat.cve_id || "LOCAL")}</code>
                <span style="opacity: 0.5">ENGINE</span> <span>${escapeHtml(threat.source || "Unknown")}</span>
                <span style="opacity: 0.5">TIMESTAMP</span> <span>${escapeHtml(formatTimestamp(threat.detected_at))}</span>
            </div>
            <div style="margin-top: 2rem; display: flex; flex-wrap: wrap; gap: 10px;">
                <button class="btn-console" onclick="exportReport('csv', { host: '${threat.host || ""}' })">EXPORT_CSV</button>
                <button class="btn-console" onclick="lookupCVE('${threat.cve_id || ""}')">LOOKUP_CVE</button>
                <button class="btn-console" style="border-color: var(--red); color: var(--red);" onclick="quarantineHost('${escapeHtml(threat.host || "")}')">QUARANTINE</button>
            </div>
        </div>
    `;
    overlay.classList.add("modal--active");
}

function closeModal() {
    const overlay = document.getElementById("modalOverlay");
    if (overlay) overlay.classList.remove("modal--active");
}

// ── Toast Notification System ────────────────────────────────────
function showToast(msg, type = "info", duration = 4000) {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const iconMap = {
        error: "🔴",
        warning: "🟡",
        success: "🟢",
        accepted: "🔵",
        info: "🔵",
        complete: "🟢",
    };

    const toast = document.createElement("div");
    const tone = (type || "info").toLowerCase();
    toast.className = `toast toast--${tone}`;
    toast.innerHTML = `
        <span class="toast__icon">${iconMap[tone] || "🔵"}</span>
        <span class="toast__message">${escapeHtml(msg)}</span>
        <div class="toast__progress" style="animation-duration: ${duration}ms"></div>
    `;

    container.appendChild(toast);

    // Also update legacy feedback bar
    const fb = document.getElementById("actionFeedback");
    if (fb) {
        fb.innerText = `[${new Date().toLocaleTimeString()}] ${msg}`;
        const colorMap = {
            error: "var(--red)", warning: "var(--yellow)", success: "var(--green)",
            accepted: "var(--cyan)", info: "var(--cyan)", complete: "var(--green)",
        };
        fb.style.color = colorMap[tone] || "var(--cyan)";
    }

    _logToConsole(msg, type);

    // Auto-dismiss
    setTimeout(() => {
        toast.classList.add("toast--exit");
        setTimeout(() => toast.remove(), 300);
    }, duration);

    // Limit visible toasts
    while (container.children.length > 5) {
        container.firstChild.remove();
    }
}

// Legacy feedback bridge
function showFeedback(msg, type) {
    showToast(msg, type);
}

function _logToConsole(msg, type) {
    const list = document.getElementById("activityList");
    if (!list) return;
    const div = document.createElement("div");
    div.style.marginBottom = "4px";
    div.innerHTML = `<span style="opacity: 0.4">[${escapeHtml(new Date().toLocaleTimeString())}]</span> <span class="${consoleSeverityClass(type)}">${escapeHtml(msg)}</span>`;
    list.prepend(div);
}

// ── Sidebar Navigation ───────────────────────────────────────────
function setupSidebarNav() {
    document.querySelectorAll(".sidebar__link").forEach(link => {
        link.onclick = (e) => {
            document.querySelectorAll(".sidebar__link").forEach(l => l.classList.remove("active"));
            link.classList.add("active");
        };
    });
}

// ── Keyboard Shortcuts ───────────────────────────────────────────
function setupKeyboardShortcuts() {
    document.addEventListener("keydown", (e) => {
        // Don't trigger while typing in inputs
        if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA" || e.target.tagName === "SELECT") return;

        switch (e.key.toLowerCase()) {
        case "s":
            e.preventDefault();
            document.getElementById("scanTarget")?.focus();
            break;
        case "a":
            e.preventDefault();
            triggerAnalysis();
            break;
        case "t":
            e.preventDefault();
            triggerTraining();
            break;
        case "r":
            if (e.ctrlKey || e.metaKey) return; // Don't intercept browser refresh
            e.preventDefault();
            syncIntelligence();
            showToast("Dashboard refreshed.", "info");
            break;
        case "?":
            e.preventDefault();
            showShortcutsHelp();
            break;
        }
    });
}

function showShortcutsHelp() {
    const overlay = document.getElementById("modalOverlay");
    const title = document.getElementById("modalTitle");
    const body = document.getElementById("modalBody");
    if (!overlay || !title || !body) return;

    title.innerText = "KEYBOARD::SHORTCUTS";
    body.innerHTML = `
        <div class="shortcuts-grid">
            <kbd>S</kbd> <span>Focus scan target input</span>
            <kbd>A</kbd> <span>Run AI analysis pipeline</span>
            <kbd>T</kbd> <span>Train / optimize AI model</span>
            <kbd>R</kbd> <span>Refresh all dashboard data</span>
            <kbd>?</kbd> <span>Show this shortcuts panel</span>
            <kbd>Esc</kbd> <span>Close modal / dismiss</span>
        </div>
    `;
    overlay.classList.add("modal--active");
}

// ── Advanced Canvas Rendering (Neon SOC Edition) ──────────────────
let radarAngle = 0;

function renderDonutCanvas(canvas, data) {
    if (!canvas) return;
    if (donutAnimationFrame) {
        cancelAnimationFrame(donutAnimationFrame);
        donutAnimationFrame = null;
    }
    const dpr = window.devicePixelRatio || 1;
    const parent = canvas.parentElement;
    const rect = parent.getBoundingClientRect();

    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    canvas.style.width = `${rect.width}px`;
    canvas.style.height = `${rect.height}px`;

    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;
    const centerX = w / 2;
    const centerY = h / 2;
    const radius = Math.min(w, h) * 0.35;
    const total = data.datasets[0].data.reduce((a, b) => a + b, 0);

    let angle = 0;
    function draw() {
        if (!canvas.isConnected) return;
        ctx.clearRect(0, 0, w, h);

        // 1. Radar Sweep
        ctx.save();
        ctx.translate(centerX, centerY);
        ctx.rotate(angle);
        const grad = ctx.createRadialGradient(0, 0, 0, 0, 0, radius + 20);
        grad.addColorStop(0, "transparent");
        grad.addColorStop(1, "rgba(0, 240, 255, 0.15)");
        ctx.fillStyle = grad;
        ctx.beginPath(); ctx.moveTo(0, 0); ctx.arc(0, 0, radius + 20, -0.4, 0); ctx.fill();
        ctx.restore();

        // 2. Data Segments
        let startAngle = -Math.PI / 2;
        data.datasets[0].data.forEach((val, i) => {
            if (val <= 0) return;
            const sliceAngle = total > 0 ? (val / total) * (Math.PI * 2) : 0;
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
            ctx.strokeStyle = data.datasets[0].backgroundColor[i];
            ctx.lineWidth = 14;
            ctx.lineCap = "round";
            ctx.stroke();

            // Glow effect
            ctx.save();
            ctx.shadowBlur = 15;
            ctx.shadowColor = data.datasets[0].backgroundColor[i];
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
            ctx.strokeStyle = data.datasets[0].backgroundColor[i] + "40";
            ctx.lineWidth = 20;
            ctx.stroke();
            ctx.restore();

            startAngle += sliceAngle;
        });

        // 3. Center Ring
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius - 20, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(0, 240, 255, 0.05)";
        ctx.lineWidth = 1;
        ctx.stroke();

        // 4. Center Text
        if (total > 0) {
            ctx.fillStyle = "rgba(0, 240, 255, 0.6)";
            ctx.font = `bold ${Math.min(w, h) * 0.08}px 'Share Tech Mono'`;
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillText(total.toString(), centerX, centerY - 5);
            ctx.fillStyle = "rgba(136, 146, 164, 0.6)";
            ctx.font = `${Math.min(w, h) * 0.035}px 'Share Tech Mono'`;
            ctx.fillText("TOTAL", centerX, centerY + 15);
        }

        angle += 0.015;
        donutAnimationFrame = requestAnimationFrame(draw);
    }
    draw();
}

function drawTimeline(days, timeline) {
    const canvas = document.getElementById("timelineChart");
    if (!canvas) return;

    const dpr = window.devicePixelRatio || 1;
    const parent = canvas.parentElement;
    const rect = parent.getBoundingClientRect();

    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    canvas.style.width = `${rect.width}px`;
    canvas.style.height = `${rect.height}px`;

    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;
    const margin = 50;
    const bottomPadding = 40;
    const chartH = h - bottomPadding - 30;
    const chartW = w - (margin * 2);

    ctx.clearRect(0, 0, w, h);

    // 1. Grid lines
    ctx.strokeStyle = "rgba(0, 240, 255, 0.05)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const py = 20 + (chartH / 4) * i;
        ctx.beginPath();
        ctx.moveTo(margin, py);
        ctx.lineTo(w - margin, py);
        ctx.stroke();
    }

    // 2. Bars
    const maxVal = Math.max(...Object.values(timeline).map(v => Object.values(v).reduce((a, b) => a + b, 0)), 5);
    const barW = Math.min(35, (chartW / days.length) * 0.5);
    const spacing = (chartW - (days.length * barW)) / (days.length + 1);

    days.forEach((day, i) => {
        const counts = timeline[day] || {};
        const px = margin + spacing + (i * (barW + spacing));
        let currentY = h - bottomPadding;

        ['low', 'medium', 'high', 'critical'].forEach(sev => {
            const val = counts[sev] || 0;
            if (val > 0) {
                const segH = (val / maxVal) * chartH;
                const py = currentY - segH;

                ctx.save();
                const colors = {
                    critical: ["#ff3860", "#660000"],
                    high: ["#ff9500", "#663300"],
                    medium: ["#ffd600", "#665500"],
                    low: ["#00f0ff", "#003344"]
                };

                const grad = ctx.createLinearGradient(px, py, px, currentY);
                grad.addColorStop(0, colors[sev][0]);
                grad.addColorStop(1, colors[sev][1]);

                // Bar with rounded top
                ctx.fillStyle = grad;
                ctx.shadowBlur = 10;
                ctx.shadowColor = colors[sev][0];
                ctx.beginPath();
                const r = Math.min(3, barW / 2);
                ctx.moveTo(px, currentY);
                ctx.lineTo(px, py + r);
                ctx.quadraticCurveTo(px, py, px + r, py);
                ctx.lineTo(px + barW - r, py);
                ctx.quadraticCurveTo(px + barW, py, px + barW, py + r);
                ctx.lineTo(px + barW, currentY);
                ctx.fill();
                ctx.restore();

                currentY = py;
            }
        });

        // Date label
        ctx.fillStyle = "rgba(136, 146, 164, 0.8)";
        ctx.font = "10px 'Share Tech Mono'";
        ctx.textAlign = "center";
        ctx.fillText(day.split("-").pop(), px + barW / 2, h - 15);
    });
}
