/**
 * script.js — NexShield Advanced Dashboard Logic
 * Features: Live polling, Timeline Chart, Threat Modal, Search/Filter,
 *           Export, Scan History, CVE Lookup, Activity Log.
 */

// ═══════════════════════════════════════════════════════════════════
//  DOM References
// ═══════════════════════════════════════════════════════════════════

const threatsBody    = document.getElementById("threatsBody");
const totalThreats   = document.getElementById("totalThreats");
const criticalCount  = document.getElementById("criticalCount");
const highCount      = document.getElementById("highCount");
const mediumCount    = document.getElementById("mediumCount");
const totalScans     = document.getElementById("totalScans");
const statusDot      = document.getElementById("statusDot");
const statusText     = document.getElementById("statusText");
const actionFeedback = document.getElementById("actionFeedback");


// ═══════════════════════════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════════════════════════

let allThreats = [];  // Stores full threat list for filtering


// ═══════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_COLORS = {
    critical: "#ff3860",
    high: "#ff8c00",
    medium: "#ffd600",
    low: "#00ff88",
};

function severityBadge(level) {
    const cls = (level || "info").toLowerCase();
    return `<span class="badge badge--${cls}">${cls.toUpperCase()}</span>`;
}

function formatDate(dateStr) {
    if (!dateStr) return "—";
    try {
        const d = new Date(dateStr["$date"] || dateStr);
        return d.toLocaleString("en-IN", {
            day: "2-digit", month: "short", year: "numeric",
            hour: "2-digit", minute: "2-digit", second: "2-digit",
            hour12: false,
        });
    } catch {
        return dateStr;
    }
}

function shortDate(dateStr) {
    if (!dateStr) return "—";
    try {
        const d = new Date(dateStr["$date"] || dateStr);
        return d.toLocaleString("en-IN", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false });
    } catch {
        return dateStr;
    }
}

function setOnline(online) {
    statusDot.classList.toggle("status-dot--online", online);
    statusDot.classList.toggle("status-dot--offline", !online);
    statusText.textContent = online ? "System Online" : "Database Offline";
}

function showFeedback(msg, type = "info") {
    actionFeedback.textContent = msg;
    actionFeedback.className = `action-panel__feedback feedback--${type} feedback--visible`;
    setTimeout(() => {
        actionFeedback.classList.remove("feedback--visible");
    }, 4000);
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

function animateValue(el, newVal) {
    const current = parseInt(el.textContent) || 0;
    if (current === newVal) return;
    el.textContent = newVal;
    el.classList.add("value-flash");
    setTimeout(() => el.classList.remove("value-flash"), 600);
}


// ═══════════════════════════════════════════════════════════════════
//  Fetch Threats
// ═══════════════════════════════════════════════════════════════════

async function fetchThreats() {
    try {
        const res = await fetch("/api/threats?limit=50");
        const data = await res.json();

        if (!res.ok) { setOnline(false); return; }

        setOnline(true);
        allThreats = data.threats || [];
        applyFilters();
    } catch (err) {
        console.error("[NexShield] Fetch threats failed:", err);
        setOnline(false);
    }
}

function renderThreats(list) {
    if (list.length === 0) {
        threatsBody.innerHTML = `<tr class="empty-row"><td colspan="6">No threats match your filters.</td></tr>`;
        return;
    }

    threatsBody.innerHTML = list.map((t, i) => `
        <tr class="threat-row threat-row--${(t.severity || "info").toLowerCase()}" 
            style="animation-delay:${i * 0.03}s" onclick='openModal(${JSON.stringify(t).replace(/'/g, "&#39;")})'>
            <td>${severityBadge(t.severity)}</td>
            <td class="cell--name">${escapeHtml(t.name || "Unknown")}</td>
            <td class="cell--host"><code>${escapeHtml(t.host || "—")}</code></td>
            <td class="cell--cve"><code>${escapeHtml(t.cve_id || "—")}</code></td>
            <td class="cell--source">${escapeHtml(t.source || "—")}</td>
            <td class="cell--date">${formatDate(t.detected_at)}</td>
        </tr>
    `).join("");
}


// ═══════════════════════════════════════════════════════════════════
//  Search & Filter
// ═══════════════════════════════════════════════════════════════════

function applyFilters() {
    const search = (document.getElementById("filterSearch").value || "").toLowerCase();
    const severity = document.getElementById("filterSeverity").value;

    let filtered = allThreats;

    if (severity) {
        filtered = filtered.filter(t => (t.severity || "").toLowerCase() === severity);
    }

    if (search) {
        filtered = filtered.filter(t =>
            (t.name || "").toLowerCase().includes(search) ||
            (t.host || "").toLowerCase().includes(search) ||
            (t.cve_id || "").toLowerCase().includes(search) ||
            (t.source || "").toLowerCase().includes(search)
        );
    }

    renderThreats(filtered);
}


// ═══════════════════════════════════════════════════════════════════
//  Fetch Stats
// ═══════════════════════════════════════════════════════════════════

async function fetchStats() {
    try {
        const res = await fetch("/api/stats");
        const data = await res.json();

        setOnline(data.db_online !== false);

        animateValue(totalThreats, data.total_threats ?? 0);
        animateValue(criticalCount, data.critical ?? 0);
        animateValue(highCount, data.high ?? 0);
        animateValue(mediumCount, (data.medium ?? 0) + (data.low ?? 0));
    } catch (err) {
        console.error("[NexShield] Fetch stats failed:", err);
        setOnline(false);
    }
}


// ═══════════════════════════════════════════════════════════════════
//  Timeline Chart (Pure Canvas)
// ═══════════════════════════════════════════════════════════════════

async function fetchTimeline() {
    try {
        const res = await fetch("/api/timeline");
        const data = await res.json();
        if (data.status === "complete") {
            drawTimeline(data.days, data.timeline);
        }
    } catch (err) {
        console.error("[NexShield] Timeline fetch failed:", err);
    }
}

function drawTimeline(days, timeline) {
    const canvas = document.getElementById("timelineChart");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;

    // Resize canvas for sharp rendering
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = 220 * dpr;
    canvas.style.width = rect.width + "px";
    canvas.style.height = "220px";
    ctx.scale(dpr, dpr);

    const W = rect.width;
    const H = 220;
    const padL = 50, padR = 20, padT = 20, padB = 40;
    const chartW = W - padL - padR;
    const chartH = H - padT - padB;

    ctx.clearRect(0, 0, W, H);

    // Calculate max value
    let maxVal = 1;
    for (const day of days) {
        const d = timeline[day] || {};
        const total = (d.critical || 0) + (d.high || 0) + (d.medium || 0) + (d.low || 0);
        if (total > maxVal) maxVal = total;
    }

    const barW = Math.min(chartW / days.length * 0.6, 40);
    const gap = chartW / days.length;

    // Draw grid lines
    ctx.strokeStyle = "rgba(0, 240, 255, 0.06)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = padT + chartH - (chartH / 4) * i;
        ctx.beginPath();
        ctx.moveTo(padL, y);
        ctx.lineTo(W - padR, y);
        ctx.stroke();

        // Y-axis labels
        ctx.fillStyle = "#8892a4";
        ctx.font = "11px 'Share Tech Mono', monospace";
        ctx.textAlign = "right";
        ctx.fillText(Math.round(maxVal / 4 * i), padL - 8, y + 4);
    }

    // Draw stacked bars for each day
    const sevOrder = ["low", "medium", "high", "critical"];

    days.forEach((day, i) => {
        const d = timeline[day] || {};
        const x = padL + gap * i + (gap - barW) / 2;
        let yOffset = 0;

        for (const sev of sevOrder) {
            const val = d[sev] || 0;
            const h = (val / maxVal) * chartH;

            ctx.fillStyle = SEV_COLORS[sev] || "#555";
            ctx.globalAlpha = 0.85;
            const radius = 3;
            const bx = x, by = padT + chartH - yOffset - h, bw = barW, bh = h;

            if (bh > 0) {
                ctx.beginPath();
                ctx.moveTo(bx + radius, by);
                ctx.lineTo(bx + bw - radius, by);
                ctx.quadraticCurveTo(bx + bw, by, bx + bw, by + radius);
                ctx.lineTo(bx + bw, by + bh);
                ctx.lineTo(bx, by + bh);
                ctx.lineTo(bx, by + radius);
                ctx.quadraticCurveTo(bx, by, bx + radius, by);
                ctx.closePath();
                ctx.fill();
            }
            yOffset += h;
        }
        ctx.globalAlpha = 1;

        // X-axis label
        ctx.fillStyle = "#8892a4";
        ctx.font = "10px 'Share Tech Mono', monospace";
        ctx.textAlign = "center";
        const label = day.substring(5); // "MM-DD"
        ctx.fillText(label, x + barW / 2, H - 10);
    });

    // Legend
    const legendX = padL + 5;
    const legendY = padT + 5;
    ctx.font = "10px 'Inter', sans-serif";
    let lx = legendX;
    for (const sev of ["critical", "high", "medium", "low"]) {
        ctx.fillStyle = SEV_COLORS[sev];
        ctx.fillRect(lx, legendY, 10, 10);
        ctx.fillStyle = "#e2e8f0";
        ctx.textAlign = "left";
        ctx.fillText(sev.charAt(0).toUpperCase() + sev.slice(1), lx + 14, legendY + 9);
        lx += ctx.measureText(sev).width + 30;
    }
}


// ═══════════════════════════════════════════════════════════════════
//  Threat Detail Modal
// ═══════════════════════════════════════════════════════════════════

function openModal(threat) {
    const overlay = document.getElementById("modalOverlay");
    const title = document.getElementById("modalTitle");
    const body = document.getElementById("modalBody");

    title.textContent = threat.name || "Threat Details";
    body.innerHTML = `
        <div class="modal-field">
            <span class="modal-label">Severity</span>
            ${severityBadge(threat.severity)}
        </div>
        <div class="modal-field">
            <span class="modal-label">Affected Host</span>
            <code>${escapeHtml(threat.host || "—")}</code>
        </div>
        <div class="modal-field">
            <span class="modal-label">CVE / ID</span>
            <code>${escapeHtml(threat.cve_id || "—")}</code>
        </div>
        <div class="modal-field">
            <span class="modal-label">Source Engine</span>
            <span>${escapeHtml(threat.source || "—")}</span>
        </div>
        <div class="modal-field">
            <span class="modal-label">Detail</span>
            <p class="modal-detail">${escapeHtml(threat.detail || "No additional details.")}</p>
        </div>
        <div class="modal-field">
            <span class="modal-label">Detected At</span>
            <span>${formatDate(threat.detected_at)}</span>
        </div>
        ${threat.merged_count ? `
        <div class="modal-field">
            <span class="modal-label">Merged Count</span>
            <span>${threat.merged_count} duplicate(s) merged by ${escapeHtml(threat.merged_by || "—")}</span>
        </div>` : ""}
    `;

    overlay.classList.add("modal--active");
    document.body.style.overflow = "hidden";
}

function closeModal() {
    document.getElementById("modalOverlay").classList.remove("modal--active");
    document.body.style.overflow = "";
}

// Close modal on Escape key
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
});


// ═══════════════════════════════════════════════════════════════════
//  Export Reports
// ═══════════════════════════════════════════════════════════════════

function exportReport(format) {
    showFeedback(`Downloading ${format.toUpperCase()} report…`, "info");
    window.location.href = `/api/export?format=${format}`;
}


// ═══════════════════════════════════════════════════════════════════
//  CVE Lookup
// ═══════════════════════════════════════════════════════════════════

async function lookupCVE() {
    const input = document.getElementById("cveInput");
    const resultDiv = document.getElementById("cveResult");
    const cveId = input.value.trim();

    if (!cveId) {
        input.classList.add("input-group__input--error");
        setTimeout(() => input.classList.remove("input-group__input--error"), 2000);
        return;
    }

    resultDiv.innerHTML = `<p class="cve-loading">Looking up ${escapeHtml(cveId)}…</p>`;

    try {
        const res = await fetch(`/api/cve/${encodeURIComponent(cveId)}`);
        const data = await res.json();

        if (data.status === "error") {
            resultDiv.innerHTML = `<p class="cve-error">❌ ${escapeHtml(data.message)}</p>`;
            return;
        }

        resultDiv.innerHTML = `
            <div class="cve-card">
                <div class="cve-card__header">
                    <strong>${escapeHtml(data.cve_id)}</strong>
                    <span class="badge badge--${(data.severity || "info").toLowerCase()}">${(data.severity || "UNKNOWN").toUpperCase()}</span>
                    <span class="cve-score">Score: ${data.score || "N/A"}</span>
                </div>
                <p class="cve-desc">${escapeHtml(data.description || "No description.")}</p>
                <div class="cve-meta">
                    <span>Published: ${data.published ? data.published.substring(0, 10) : "—"}</span>
                    <span>Modified: ${data.modified ? data.modified.substring(0, 10) : "—"}</span>
                    ${data.cached ? '<span class="cve-cached">📦 Cached</span>' : '<span class="cve-live">🌐 Live</span>'}
                </div>
                ${data.references && data.references.length ? `
                <div class="cve-refs">
                    <strong>References:</strong>
                    ${data.references.map(r => `<a href="${r}" target="_blank" rel="noopener">${r.substring(0, 60)}…</a>`).join("")}
                </div>` : ""}
            </div>
        `;
    } catch (err) {
        resultDiv.innerHTML = `<p class="cve-error">❌ Failed to look up CVE.</p>`;
        console.error(err);
    }
}


// ═══════════════════════════════════════════════════════════════════
//  Scan History
// ═══════════════════════════════════════════════════════════════════

async function fetchScanHistory() {
    try {
        const res = await fetch("/api/scan-history");
        const data = await res.json();
        const list = document.getElementById("scanHistoryList");

        if (data.status !== "complete" || !data.scans || data.scans.length === 0) {
            list.innerHTML = `<p class="scan-history__empty">No scans recorded yet.</p>`;
            return;
        }

        list.innerHTML = data.scans.map(s => `
            <div class="scan-history__item">
                <div class="scan-history__icon">📡</div>
                <div class="scan-history__info">
                    <span class="scan-history__target">${escapeHtml(s.target || s._id || "Unknown target")}</span>
                    <span class="scan-history__meta">${s.host_count} host(s) • ${shortDate(s.scanned_at)}</span>
                </div>
            </div>
        `).join("");
    } catch (err) {
        console.error("[NexShield] Scan history failed:", err);
    }
}


// ═══════════════════════════════════════════════════════════════════
//  Activity Log
// ═══════════════════════════════════════════════════════════════════

const ACTIVITY_ICONS = {
    scan_start: "⚡",
    scan_complete: "✅",
    scan_error: "❌",
    analysis_start: "🧠",
    analysis_complete: "✅",
    analysis_error: "❌",
    export: "📥",
    system: "🖥️",
};

async function fetchActivity() {
    try {
        const res = await fetch("/api/activity");
        const data = await res.json();
        const list = document.getElementById("activityList");

        if (data.status !== "complete" || !data.events || data.events.length === 0) {
            list.innerHTML = `<p class="activity-feed__empty">No activity yet.</p>`;
            return;
        }

        list.innerHTML = data.events.slice(0, 30).map(e => `
            <div class="activity-item activity-item--${e.severity || "info"}">
                <span class="activity-item__icon">${ACTIVITY_ICONS[e.type] || "📌"}</span>
                <span class="activity-item__msg">${escapeHtml(e.message || "")}</span>
                <span class="activity-item__time">${shortDate(e.timestamp)}</span>
            </div>
        `).join("");
    } catch (err) {
        console.error("[NexShield] Activity log failed:", err);
    }
}


// ═══════════════════════════════════════════════════════════════════
//  Actions — Generalized Handler
// ═══════════════════════════════════════════════════════════════════

async function apiAction({ btnId, url, method = "POST", body = null, loadingMsg, successMsg, errorPrefix }) {
    const btn = document.getElementById(btnId);
    if (!btn) return;

    btn.disabled = true;
    btn.classList.add("btn--loading");
    showFeedback(loadingMsg, "info");

    try {
        const options = { method };
        if (body) {
            options.headers = { "Content-Type": "application/json" };
            options.body = JSON.stringify(body);
        }

        const res = await fetch(url, options);
        const data = await res.json();

        if (data.status === "complete") {
            const msg = typeof successMsg === "function" ? successMsg(data) : successMsg;
            showFeedback(msg, "success");
        } else {
            showFeedback(`${errorPrefix}: ${data.message || "Unknown error"}`, "error");
        }
    } catch (err) {
        showFeedback(`${errorPrefix} failed — check console.`, "error");
        console.error(`[NexShield] Action failed (${url}):`, err);
    } finally {
        btn.disabled = false;
        btn.classList.remove("btn--loading");
        refreshAll();
    }
}


// ═══════════════════════════════════════════════════════════════════
//  Action Wrappers
// ═══════════════════════════════════════════════════════════════════

function triggerScan() {
    apiAction({
        btnId: "btnScan",
        url: "/api/scan",
        loadingMsg: "Launching quick scan…",
        successMsg: (d) => `Quick scan done — ${d.hosts_found} host(s) found.`,
        errorPrefix: "Scan error"
    });
}

function triggerAnalysis() {
    apiAction({
        btnId: "btnAnalyze",
        url: "/api/analyze",
        loadingMsg: "Running 7-engine AI pipeline…",
        successMsg: (d) => `Pipeline done — ${d.threats_created} threats, ${d.hosts_scored || 0} hosts scored, ${d.duplicates_removed} deduped (${(d.engines_used || []).length} engines).`,
        errorPrefix: "Analysis error"
    });
}

function triggerManualScan() {
    const targetInput = document.getElementById("scanTarget");
    const portsInput = document.getElementById("scanPorts");
    const target = targetInput.value.trim();
    const ports = portsInput.value.trim();

    if (!target) {
        showFeedback("Please enter a target IP or range.", "error");
        targetInput.focus();
        targetInput.classList.add("input-group__input--error");
        setTimeout(() => targetInput.classList.remove("input-group__input--error"), 2000);
        return;
    }

    apiAction({
        btnId: "btnManualScan",
        url: "/api/scan",
        body: { target, ports: ports || undefined },
        loadingMsg: `Scanning ${target}…`,
        successMsg: (d) => `Manual scan complete — ${d.hosts_found} host(s) found on ${d.target}.`,
        errorPrefix: "Manual scan error"
    });
}


// ═══════════════════════════════════════════════════════════════════
//  Refresh All & Init
// ═══════════════════════════════════════════════════════════════════

function refreshAll() {
    fetchThreats();
    fetchStats();
    fetchTimeline();
    fetchScanHistory();
    fetchActivity();
}

document.addEventListener("DOMContentLoaded", () => {
    refreshAll();

    // Live polling
    setInterval(fetchThreats, 5000);
    setInterval(fetchStats, 10000);
    setInterval(fetchTimeline, 15000);
    setInterval(fetchScanHistory, 20000);
    setInterval(fetchActivity, 8000);

    // Resize chart on window resize
    window.addEventListener("resize", fetchTimeline);
});
