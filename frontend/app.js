/* ============================================================
   CIRIP v2.0 — AI-Powered Cyber Threat Fusion & Intelligence Platform
   Frontend JavaScript
   ============================================================ */

const API_BASE = "http://127.0.0.1:8000";

// ── State ──────────────────────────────────────────────────────────────────
let currentIncidentId = null;
let currentStoryline  = null;
let charts = {};        // Chart.js instances keyed by canvas id
let graphNetworks = {}; // vis-network instances keyed by container id
let sidebarCollapsed = false;

// ── Toast Notification System ───────────────────────────────────────────────
function showNotification(message, type = "info", duration = 4500) {
  const container = document.getElementById("toastContainer");
  if (!container) {
    console.log(`[${type.toUpperCase()}] ${message}`);
    return;
  }

  const icons = {
    success: "✓",
    error:   "✕",
    warning: "⚠",
    info:    "ℹ",
  };

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <div class="toast-content">
      <span class="toast-icon">${icons[type] || "ℹ"}</span>
      <span>${escHtml(message)}</span>
    </div>
    <button class="toast-close" aria-label="Close">✕</button>
  `;

  const closeToast = () => {
    toast.classList.add("toast-hide");
    setTimeout(() => toast.remove(), 320);
  };

  toast.querySelector(".toast-close")?.addEventListener("click", closeToast);
  container.appendChild(toast);

  if (duration > 0) {
    setTimeout(closeToast, duration);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// SIDEBAR NAVIGATION
// ═══════════════════════════════════════════════════════════════════════════

const BREADCRUMBS = {
  command:    "Threat Command Center",
  dashboard:  "Intelligence Dashboard",
  analyze:    "Analyze Threat",
  graph:      "Threat Graph",
  storyline:  "Attack Storyline",
  campaigns:  "Threat Campaigns",
  history:    "Incident History",
  reports:    "Intelligence Reports",
  evaluation: "Model Performance & Evaluation",
  settings:   "System Settings",
};

function navigateTo(viewId) {
  // Hide all views
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  // Show target view
  const view = document.getElementById(`view-${viewId}`);
  if (view) view.classList.add("active");

  const navItem = document.getElementById(`nav-${viewId}`);
  if (navItem) navItem.classList.add("active");

  const bc = document.getElementById("topbarBreadcrumb");
  if (bc) bc.textContent = BREADCRUMBS[viewId] || viewId;

  // Load view-specific data
  if (viewId === "command")    loadCommandCenter();
  if (viewId === "dashboard")  loadDashboard();
  if (viewId === "history")    loadHistory();
  if (viewId === "campaigns")  loadCampaigns();
  if (viewId === "graph")      loadGraphView();
  if (viewId === "reports")    loadReportsList();
  if (viewId === "evaluation") loadEvaluation();
  if (viewId === "settings")   loadSettings();
}

document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", () => navigateTo(item.dataset.view));
});

// Sidebar toggle
document.getElementById("sidebarToggle").addEventListener("click", () => {
  sidebarCollapsed = !sidebarCollapsed;
  const sidebar      = document.getElementById("sidebar");
  const mainContent  = document.getElementById("mainContent");
  sidebar.classList.toggle("collapsed", sidebarCollapsed);
  mainContent.classList.toggle("sidebar-collapsed", sidebarCollapsed);
});

// Mobile topbar menu
const topbarMenuBtn = document.getElementById("topbarMenuBtn");
if (topbarMenuBtn) {
  topbarMenuBtn.addEventListener("click", () => {
    const sidebar = document.getElementById("sidebar");
    sidebar.classList.toggle("collapsed");
  });
}

// Source tabs (Analyze view)
document.querySelectorAll(".source-tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".source-tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    // Update placeholder text
    const placeholders = {
      paste:   "Paste your incident report, SOC notes, SIEM alert, or threat feed here…",
      email:   "Paste the email content here (headers + body)…",
      message: "Paste the chat or message content here…",
      report:  "Paste the security report or threat intelligence report here…",
    };
    document.getElementById("incidentText").placeholder = placeholders[tab.dataset.source] || "";
  });
});

// ── Live clock ─────────────────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById("topbarTime");
  if (el) el.textContent = new Date().toLocaleTimeString("en-US", { hour12: false });
}
updateClock();
setInterval(updateClock, 1000);

// ═══════════════════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════════════════

async function checkHealth() {
  const dot   = document.getElementById("statusDot");
  const label = document.getElementById("statusLabel");
  const sub   = document.getElementById("statusSub");
  try {
    const res  = await fetch(`${API_BASE}/api/health`);
    const data = await res.json();
    const ok   = data.models_loaded;
    if (dot)   { dot.className = "status-dot " + (ok ? "ok" : "error"); }
    if (label) { label.textContent = ok ? "System Online" : "Models Not Trained"; }
    if (sub)   { sub.textContent = `${data.storage_backend || "—"} · v${data.version || "2.0"}`; }
    const badge = document.getElementById("systemBadge");
    if (badge) badge.textContent = ok ? "● SYSTEM MONITORING ACTIVE" : "● BACKEND OFFLINE";
    return data;
  } catch {
    if (dot)   { dot.className = "status-dot error"; }
    if (label) { label.textContent = "Backend Unreachable"; }
    const badge = document.getElementById("systemBadge");
    if (badge) badge.textContent = "● BACKEND OFFLINE";
    return null;
  }
}
checkHealth();
setInterval(checkHealth, 15000);

// ═══════════════════════════════════════════════════════════════════════════
// COMMAND CENTER
// ═══════════════════════════════════════════════════════════════════════════

async function loadCommandCenter() {
  try {
    const res  = await fetch(`${API_BASE}/api/dashboard`);
    const data = await res.json();

    animateCounter("cmdTotalIncidents",  data.total_incidents      || 0);
    animateCounter("cmdActiveCampaigns", data.active_campaigns     || 0);
    animateCounter("cmdCriticalThreats", data.critical_incidents   || 0);
    animateCounter("cmdHighRiskIocs",    data.high_risk_iocs       || 0);
    animateCounter("cmdAvgScore",        data.avg_threat_score     || 0);

    renderActivityFeed(data.timeline || []);
    renderSmallChart("cmdSeverityChart", data.severity_distribution || {}, "doughnut");
  } catch(e) {
    console.error("Command center error:", e);
  }
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = 0;
  const duration = 1200;
  const startTime = performance.now();
  function update(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = Math.round(start + (target - start) * eased);
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

function renderActivityFeed(timeline) {
  const container = document.getElementById("recentActivity");
  if (!container) return;
  container.innerHTML = "";

  const recent = [...timeline].reverse().slice(0, 8);
  if (recent.length === 0) {
    container.innerHTML = '<div class="empty-note">No incidents yet. Analyze your first report.</div>';
    return;
  }

  recent.forEach(item => {
    const div  = document.createElement("div");
    div.className = "activity-item";
    div.onclick   = () => item._id && openIncidentFromHistory(item._id);

    const time   = item.created_at ? new Date(item.created_at).toLocaleTimeString("en-US", {hour:"2-digit", minute:"2-digit"}) : "—";
    const date   = item.created_at ? new Date(item.created_at).toLocaleDateString("en-US", {month:"short",day:"numeric"}) : "";
    const sev    = item.severity    || "—";
    const score  = item.threat_score != null ? `${item.threat_score}` : "—";
    const type   = item.incident_type || "Unknown";

    div.innerHTML = `
      <span class="activity-time">${date}<br>${time}</span>
      <span class="activity-type">${escHtml(type)}</span>
      <span class="activity-title">${escHtml(item.title || "Untitled")}</span>
      <span class="badge sev-${escHtml(sev)}">${escHtml(sev)}</span>
      <span class="activity-score">${score}</span>
    `;
    container.appendChild(div);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════

async function loadDashboard() {
  try {
    const res  = await fetch(`${API_BASE}/api/dashboard`);
    const data = await res.json();

    renderBarChart("typeChart",     data.incident_type_distribution || {}, "typeChart");
    renderBarChart("severityChart", data.severity_distribution      || {}, "severityChart");
    renderScoreDistChart("scoreDistChart", data.threat_score_distribution || {});
    renderDashTimeline(data.timeline || []);
    renderGraph("dashGraphContainer", data.combined_knowledge_graph);

    // Fit button
    document.getElementById("dashGraphFit")?.addEventListener("click", () => {
      graphNetworks["dashGraphContainer"]?.fit({ animation: { duration: 600, easingFunction: "easeInOutQuad" } });
    });
    document.getElementById("dashGraphFullscreen")?.addEventListener("click", () => {
      openFullscreenGraph("dashGraphContainer", data.combined_knowledge_graph, "Combined Threat Graph");
    });
  } catch(e) { console.error("Dashboard error:", e); }
}

function renderBarChart(canvasId, distribution, key) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx    = canvas.getContext("2d");
  const labels = Object.keys(distribution);
  const values = Object.values(distribution);
  const palette = ["#3B82F6","#22D3EE","#8B5CF6","#22C55E","#F97316","#EF4444","#FACC15"];

  if (charts[key]) { charts[key].destroy(); }

  charts[key] = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: labels.map((_, i) => palette[i % palette.length] + "CC"),
        borderColor:     labels.map((_, i) => palette[i % palette.length]),
        borderWidth: 1,
        borderRadius: 5,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#8A96A6", font: { family: "JetBrains Mono", size: 10 } }, grid: { color: "#1E2D45" } },
        y: { ticks: { color: "#8A96A6", precision: 0 }, grid: { color: "#1E2D45" }, beginAtZero: true },
      },
      animation: { duration: 800, easing: "easeOutQuart" },
    },
  });
}

function renderScoreDistChart(canvasId, distribution) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx    = canvas.getContext("2d");
  const labels = ["Low Risk", "Moderate Risk", "High Risk", "Critical Risk"];
  const colors = ["#22C55E", "#FACC15", "#F97316", "#EF4444"];
  const values = labels.map(l => distribution[l] || 0);

  if (charts[canvasId]) { charts[canvasId].destroy(); }

  charts[canvasId] = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: colors.map(c => c + "BB"),
        borderColor:     colors,
        borderWidth: 1.5,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: "bottom", labels: { color: "#8A96A6", font: { size: 10, family: "JetBrains Mono" }, padding: 12 } },
      },
      animation: { duration: 900, easing: "easeOutQuart" },
    },
  });
}

function renderSmallChart(canvasId, distribution, type = "doughnut") {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx    = canvas.getContext("2d");
  const labels = Object.keys(distribution);
  const values = Object.values(distribution);
  const palette = ["#3B82F6","#22D3EE","#8B5CF6","#22C55E","#F97316","#EF4444","#FACC15"];

  if (charts[canvasId]) { charts[canvasId].destroy(); }

  charts[canvasId] = new Chart(ctx, {
    type,
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: labels.map((_, i) => palette[i % palette.length] + "BB"), borderWidth: 1 }],
    },
    options: {
      responsive: true,
      plugins: { legend: { position: "bottom", labels: { color: "#8A96A6", font: { size: 10, family: "JetBrains Mono" } } } },
      animation: { duration: 800 },
    },
  });
}

function renderDashTimeline(timeline) {
  const container = document.getElementById("dashTimeline");
  if (!container) return;
  container.innerHTML = "";
  if (!timeline.length) {
    container.innerHTML = '<div class="empty-note">No incidents yet.</div>';
    return;
  }
  const SEV_COLORS = { Critical: "#EF4444", High: "#F97316", Medium: "#FACC15", Low: "#22C55E" };
  [...timeline].reverse().slice(0, 20).forEach(item => {
    const div = document.createElement("div");
    div.className = "timeline-item";
    div.style.cursor = item._id ? "pointer" : "default";
    if (item._id) div.onclick = () => openIncidentFromHistory(item._id);
    const time   = item.created_at ? new Date(item.created_at).toLocaleString() : "—";
    const color  = SEV_COLORS[item.severity] || "#5B6B82";
    const score  = item.threat_score != null ? item.threat_score : "—";
    div.innerHTML = `
      <div class="timeline-dot" style="background:${color};box-shadow:0 0 6px ${color}"></div>
      <div class="timeline-time">${time}</div>
      <div class="timeline-content">
        <div class="timeline-type">${escHtml(item.incident_type || "Unknown")} — ${escHtml(item.title || "Untitled")}</div>
        <div class="timeline-sev">${escHtml(item.severity || "—")} ${item.campaign_name ? `· ${escHtml(item.campaign_name)}` : ""}</div>
      </div>
      <div class="timeline-score" style="color:${color}">${score}</div>
    `;
    container.appendChild(div);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// ANALYZE — PIPELINE ANIMATION
// ═══════════════════════════════════════════════════════════════════════════

function resetTrace() {
  document.querySelectorAll(".trace-step").forEach(el => {
    el.classList.remove("active", "done");
  });
}

async function animateTrace() {
  const steps = document.querySelectorAll(".trace-step");
  for (let i = 0; i < steps.length; i++) {
    steps[i].classList.add("active");
    await delay(120);
    steps[i].classList.remove("active");
    steps[i].classList.add("done");
  }
}

const delay = ms => new Promise(r => setTimeout(r, ms));

// ═══════════════════════════════════════════════════════════════════════════
// ANALYZE — SUBMIT
// ═══════════════════════════════════════════════════════════════════════════

document.getElementById("analyzeBtn").addEventListener("click", analyzeIncident);

async function analyzeIncident() {
  const text   = document.getElementById("incidentText").value.trim();
  const title  = document.getElementById("incidentTitle").value.trim();
  const useLlm = document.getElementById("useLlm").checked;

  if (!text) { alert("Please paste an incident report to analyze."); return; }

  const btn = document.getElementById("analyzeBtn");
  btn.disabled = true;
  btn.textContent = "Analyzing…";
  document.getElementById("resultsArea").classList.add("hidden");
  resetTrace();
  const traceAnim = animateTrace();

  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, text, use_llm: useLlm }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Request failed (${res.status})`);
    }
    const data = await res.json();
    await traceAnim;
    renderResults(data);
    loadSimilar(data._id);
    // Navigate to analyze view to show results
    navigateTo("analyze");
  } catch (e) {
    await traceAnim;
    alert("Analysis failed: " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyze Threat";
    btn.innerHTML = '<span class="btn-icon">⚡</span> Analyze Threat';
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// RENDER RESULTS
// ═══════════════════════════════════════════════════════════════════════════

function renderResults(data) {
  currentIncidentId = data._id;
  currentStoryline  = data.attack_storyline || null;

  document.getElementById("resultsArea").classList.remove("hidden");

  // Incident type
  document.getElementById("typeValue").textContent = data.incident_type.label;
  document.getElementById("typeConf").textContent  = `${(data.incident_type.confidence * 100).toFixed(1)}% confidence`;

  // Severity
  const sevEl = document.getElementById("sevValue");
  sevEl.textContent  = data.severity.label;
  sevEl.className    = "metric-value sev-" + data.severity.label;
  document.getElementById("sevConf").textContent = `${(data.severity.confidence * 100).toFixed(1)}% confidence`;

  // Campaign status
  const campEl  = document.getElementById("campaignStatus");
  const campSub = document.getElementById("campaignStatusSub");
  if (data.campaign_name) {
    campEl.textContent  = `⚠ ${data.campaign_name}`;
    campEl.style.color  = "var(--high)";
    campSub.textContent = "Potentially related campaign detected";
  } else {
    campEl.textContent  = "No Campaign";
    campEl.style.color  = "var(--muted)";
    campSub.textContent = "Insufficient cross-incident links";
  }

  // Threat score gauge
  renderThreatScoreGauge(data.threat_score);

  // Summary
  document.getElementById("summaryText").textContent = data.summary.text;
  const srcTag = document.getElementById("summarySrc");
  srcTag.textContent = data.summary.source.startsWith("llm") ? "LLM-generated" : "Extractive (TF-IDF + TextRank)";
  srcTag.className   = "src-tag " + (data.summary.source.startsWith("llm") ? "llm" : "rule");

  renderIocs(data.iocs);
  renderEntities(data.entities);
  renderCorrelations(data.correlations || []);
  renderXai(data.explainable_ai.incident_type_top_features);
  renderMitigation(data.mitigation);
  renderGraph("graphContainer", data.knowledge_graph);

  // Update storyline view with this incident's data
  if (data.attack_storyline) {
    renderStoryline(data.attack_storyline, data.title || "Current Incident");
  }

  // Graph controls
  document.getElementById("graphFit")?.addEventListener("click", () => {
    graphNetworks["graphContainer"]?.fit({ animation: { duration: 600, easingFunction: "easeInOutQuad" } });
  });
  document.getElementById("graphFullscreen")?.addEventListener("click", () => {
    openFullscreenGraph("graphContainer", data.knowledge_graph, data.title || "Incident Graph");
  });

  // Scroll to results
  document.getElementById("resultsArea").scrollIntoView({ behavior: "smooth", block: "start" });
}

// ═══════════════════════════════════════════════════════════════════════════
// THREAT SCORE GAUGE
// ═══════════════════════════════════════════════════════════════════════════

function renderThreatScoreGauge(ts) {
  if (!ts) return;
  const score  = ts.score || 0;
  const cls    = ts.classification || "Low Risk";

  const CIRCUMFERENCE = 2 * Math.PI * 80; // r=80 → 502.65
  const offset = CIRCUMFERENCE * (1 - score / 100);

  const fill  = document.getElementById("gaugeFill");
  const gScore = document.getElementById("gaugeScore");
  const gLabel = document.getElementById("gaugeLabel");

  const COLORS = {
    "Low Risk":      "#22C55E",
    "Moderate Risk": "#FACC15",
    "High Risk":     "#F97316",
    "Critical Risk": "#EF4444",
  };
  const color = COLORS[cls] || "#3B82F6";

  if (fill)  {
    fill.style.strokeDashoffset = CIRCUMFERENCE;
    fill.style.stroke = color;
    fill.style.filter = `drop-shadow(0 0 8px ${color})`;
    setTimeout(() => { fill.style.strokeDashoffset = offset; }, 100);
  }
  if (gScore) {
    gScore.style.color = color;
    animateCounterEl(gScore, 0, score, 1200);
  }
  if (gLabel) gLabel.textContent = cls;

  // Score breakdown
  renderScoreBreakdown(ts.breakdown || []);

  // Why score button
  const btn = document.getElementById("whyScoreBtn");
  const bd  = document.getElementById("scoreBreakdown");
  if (btn && bd) {
    btn.onclick = () => {
      bd.classList.toggle("hidden");
      btn.textContent = bd.classList.contains("hidden") ? "Why this score? ▼" : "Hide breakdown ▲";
    };
  }
}

function animateCounterEl(el, from, to, duration) {
  const start = performance.now();
  function update(now) {
    const p = Math.min((now - start) / duration, 1);
    const e = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (to - from) * e);
    if (p < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

function renderScoreBreakdown(breakdown) {
  const container = document.getElementById("scoreBreakdown");
  if (!container) return;
  container.innerHTML = "";
  if (!breakdown || breakdown.length === 0) {
    container.innerHTML = '<div class="empty-note">No score breakdown available.</div>';
    return;
  }
  breakdown.forEach(b => {
    const div = document.createElement("div");
    div.className = "breakdown-item";
    div.innerHTML = `
      <span class="breakdown-reason">${escHtml(b.reason)}</span>
      <span class="breakdown-pts">+${b.points} pts</span>
    `;
    container.appendChild(div);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// IOC RENDERING — Cards
// ═══════════════════════════════════════════════════════════════════════════

const IOC_META = {
  ipv4_addresses: { icon: "🖥",  label: "IPv4 Addresses" },
  ipv6_addresses: { icon: "🖥",  label: "IPv6 Addresses" },
  domains:        { icon: "🌐",  label: "Domains" },
  urls:           { icon: "🔗",  label: "URLs" },
  emails:         { icon: "📧",  label: "Emails" },
  cves:           { icon: "🛡",  label: "CVEs" },
};

function renderIocs(iocs) {
  const container = document.getElementById("iocList");
  if (!container) return;
  container.innerHTML = "";

  // Main IoC types
  Object.entries(IOC_META).forEach(([key, meta]) => {
    const values = iocs[key] || [];
    const card   = buildIocCard(meta.icon, meta.label, values);
    container.appendChild(card);
  });

  // File hashes
  const fh = iocs.file_hashes || {};
  ["md5", "sha1", "sha256"].forEach(ht => {
    const values = fh[ht] || [];
    if (values.length === 0 && Object.values(fh).every(v => !v?.length)) return;
    const card = buildIocCard("🔒", `${ht.toUpperCase()} Hashes`, values);
    container.appendChild(card);
  });
}

function buildIocCard(icon, label, values) {
  const card = document.createElement("div");
  card.className = "ioc-card";
  const valHtml = values.length
    ? values.slice(0, 6).map(v => `<span class="ioc-value-chip">${escHtml(String(v))}</span>`).join("") +
      (values.length > 6 ? `<span class="ioc-value-chip">+${values.length - 6} more</span>` : "")
    : `<span class="ioc-empty">none found</span>`;
  card.innerHTML = `
    <span class="ioc-type-icon">${icon}</span>
    <div class="ioc-values">
      <div class="ioc-type-label">${escHtml(label)}</div>
      <div>${valHtml}</div>
    </div>
  `;
  return card;
}

// ═══════════════════════════════════════════════════════════════════════════
// ENTITY RENDERING
// ═══════════════════════════════════════════════════════════════════════════

function chipRow(title, items) {
  const row   = document.createElement("div");
  const label = document.createElement("div");
  label.className = "chip-group-title";
  label.textContent = title;
  row.appendChild(label);
  const chips = document.createElement("div");
  chips.className = "chip-row";
  if (!items || items.length === 0) {
    const c = document.createElement("span");
    c.className = "chip empty";
    c.textContent = "none found";
    chips.appendChild(c);
  } else {
    items.forEach(i => {
      const c = document.createElement("span");
      c.className = "chip";
      c.textContent = i;
      chips.appendChild(c);
    });
  }
  row.appendChild(chips);
  return row;
}

function renderEntities(entities) {
  const container = document.getElementById("entityList");
  if (!container) return;
  container.innerHTML = "";
  container.appendChild(chipRow("Malware Families", entities.malware_families));
  container.appendChild(chipRow("Attack Keywords",  entities.attack_keywords));
  container.appendChild(chipRow("Users",            entities.users));
  container.appendChild(chipRow("Organizations",    entities.organizations));
}

// ═══════════════════════════════════════════════════════════════════════════
// CORRELATIONS
// ═══════════════════════════════════════════════════════════════════════════

function renderCorrelations(correlations) {
  const container = document.getElementById("correlationList");
  if (!container) return;
  container.innerHTML = "";

  if (!correlations || correlations.length === 0) {
    container.innerHTML = '<div class="empty-note">No cross-incident correlations detected yet. Analyze more incidents to build the correlation database.</div>';
    return;
  }

  const STRENGTH_CLASS = {
    "Strongly Related":   "strength-strong",
    "Potentially Related":"strength-potential",
    "Weakly Related":     "strength-weak",
  };

  correlations.forEach(corr => {
    const card = document.createElement("div");
    card.className = "correlation-card";
    const cls = STRENGTH_CLASS[corr.relationship_strength] || "strength-weak";
    const reasons = (corr.reasons || []).map(r => `<span class="correlation-reason">${escHtml(r)}</span>`).join("");
    card.innerHTML = `
      <div class="correlation-head">
        <span class="correlation-title">${escHtml(corr.incident_title || "Unknown Incident")}</span>
        <span class="correlation-strength ${cls}">${escHtml(corr.relationship_strength)}</span>
        <span class="badge sev-${escHtml(corr.severity || "")}">${escHtml(corr.severity || "—")}</span>
      </div>
      <div class="correlation-conf-bar">
        <div class="correlation-conf-fill" style="width:0%"
             data-target="${corr.confidence}%"></div>
      </div>
      <div style="font-size:10px;color:var(--muted);margin-bottom:6px;">
        Relationship Confidence: <strong style="color:var(--text)">${corr.confidence}%</strong>
      </div>
      <div class="correlation-reasons">${reasons}</div>
    `;
    container.appendChild(card);
    // Animate bar
    const fill = card.querySelector(".correlation-conf-fill");
    setTimeout(() => { if (fill) fill.style.width = fill.dataset.target; }, 100);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// SIMILAR INCIDENTS (enhanced)
// ═══════════════════════════════════════════════════════════════════════════

async function loadSimilar(id) {
  const container = document.getElementById("similarList");
  if (!container) return;
  container.innerHTML = '<div class="empty-note">Searching for similar incidents…</div>';
  try {
    const res  = await fetch(`${API_BASE}/api/similar/${id}`);
    const data = await res.json();
    container.innerHTML = "";
    if (!data.similar_incidents || data.similar_incidents.length === 0) {
      container.innerHTML = '<div class="empty-note">No similar past incidents yet — analyze more reports to build history.</div>';
      return;
    }
    data.similar_incidents.forEach(s => {
      const div = document.createElement("div");
      div.className = "similar-item";
      const reasons = (s.reasons || []).slice(0, 3)
        .map(r => `<span class="similar-reason-tag">✓ ${escHtml(r)}</span>`).join("");
      const strength = s.relationship_strength
        ? `<span class="correlation-strength ${s.relationship_strength === "Strongly Related" ? "strength-strong" : s.relationship_strength === "Potentially Related" ? "strength-potential" : "strength-weak"}">${escHtml(s.relationship_strength)}</span>`
        : "";
      div.innerHTML = `
        <div class="similar-title">
          ${escHtml(s.title || "Untitled")}
          ${strength}
        </div>
        <div>
          <span class="badge sev-${escHtml(s.severity || "")}">${escHtml(s.incident_type || "—")}</span>
          ${reasons ? `<div class="similar-reasons">${reasons}</div>` : ""}
        </div>
        <span class="sim-score">${(s.similarity_score * 100).toFixed(1)}%</span>
      `;
      container.appendChild(div);
    });
  } catch {
    container.innerHTML = '<div class="empty-note">Could not load similar incidents.</div>';
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// XAI BARS
// ═══════════════════════════════════════════════════════════════════════════

function renderXai(features) {
  const container = document.getElementById("xaiBars");
  if (!container) return;
  container.innerHTML = "";
  if (!features || features.length === 0) {
    container.innerHTML = '<div class="empty-note">No contributing features found.</div>';
    return;
  }
  const maxAbs = Math.max(...features.map(f => Math.abs(f.contribution)), 0.0001);
  features.forEach(f => {
    const row  = document.createElement("div");
    row.className = "xai-bar-row";
    const pct  = Math.min(100, Math.abs(f.contribution) / maxAbs * 100);
    row.innerHTML = `
      <div class="xai-word">${escHtml(f.feature)}</div>
      <div class="xai-track"><div class="xai-fill" style="width:0%" data-target="${pct}%"></div></div>
      <div class="xai-val">${f.contribution.toFixed(3)}</div>
    `;
    container.appendChild(row);
    const fill = row.querySelector(".xai-fill");
    setTimeout(() => { if (fill) fill.style.width = fill.dataset.target; }, 100);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// MITIGATION
// ═══════════════════════════════════════════════════════════════════════════

function mitList(title, items) {
  const col = document.createElement("div");
  col.className = "mit-col";
  const h = document.createElement("div");
  h.className = "mit-col-title";
  h.textContent = title;
  col.appendChild(h);
  const ul = document.createElement("ul");
  (items || []).forEach(i => {
    const li = document.createElement("li");
    li.textContent = i;
    ul.appendChild(li);
  });
  col.appendChild(ul);
  return col;
}

function renderMitigation(mitigation) {
  const container = document.getElementById("mitigationBody");
  if (!container) return;
  container.innerHTML = "";
  const rb = mitigation.rule_based;
  container.appendChild(mitList("Immediate Response", rb.immediate_response));
  container.appendChild(mitList("Containment",        rb.containment));
  container.appendChild(mitList("Recovery",           rb.recovery));
  container.appendChild(mitList("Prevention",         rb.prevention));
  if (rb.severity_guidance) {
    const note = document.createElement("div");
    note.className = "severity-note";
    note.textContent = "Severity guidance: " + rb.severity_guidance;
    container.appendChild(note);
  }
  const llmBox = document.getElementById("llmNarrative");
  if (mitigation.llm_narrative) {
    document.getElementById("llmNarrativeText").textContent = mitigation.llm_narrative;
    llmBox?.classList.remove("hidden");
  } else {
    llmBox?.classList.add("hidden");
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// KNOWLEDGE GRAPH (vis-network)
// ═══════════════════════════════════════════════════════════════════════════

const COLOR_BY_TYPE = {
  incident:     { background: "#3B82F6", border: "#93C5FD" },
  malware:      { background: "#EF4444", border: "#FCA5A5" },
  organization: { background: "#FACC15", border: "#FDE68A" },
  user:         { background: "#8B5CF6", border: "#C4B5FD" },
  ip:           { background: "#22C55E", border: "#86EFAC" },
  domain:       { background: "#F97316", border: "#FED7AA" },
  cve:          { background: "#F472B6", border: "#FBCFE8" },
  hash:         { background: "#22D3EE", border: "#A5F3FC" },
};

function renderGraph(containerId, graphData) {
  const el = document.getElementById(containerId);
  if (!el) return;

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    el.innerHTML = '<div class="empty-note" style="padding:16px;">No graph data yet.</div>';
    return;
  }

  const nodes = graphData.nodes.map((n, idx) => {
    const type   = n.type || "unknown";
    const colors = COLOR_BY_TYPE[type] || { background: "#5B6B82", border: "#A8B3C4" };
    let shape = "dot", size = 16;
    if (type === "incident")     { shape = "diamond"; size = 28; }
    else if (type === "malware") { shape = "hexagon"; size = 22; }
    else if (type === "cve")     { shape = "triangle"; size = 20; }

    return {
      id:    n.id !== undefined ? n.id : idx,
      label: n.label || String(n.id),
      title: `<div style="padding:8px;font-family:monospace;background:#111827;color:#E7ECF2;border:1px solid #3B82F6;border-radius:6px;font-size:11px;"><b>${type.toUpperCase()}</b><br>${n.label || n.id}</div>`,
      shape, size,
      color: { background: colors.background, border: colors.border, highlight: { background: colors.background, border: "#fff" }, hover: { background: colors.background, border: "#fff" } },
      borderWidth: 2,
      shadow: { enabled: true, color: "rgba(59,130,246,0.35)", size: 12, x: 0, y: 0 },
      font:  { color: "#E7ECF2", size: type === "incident" ? 13 : 11, face: "JetBrains Mono", strokeWidth: 3, strokeColor: "#080B12" },
    };
  });

  const links = graphData.links || graphData.edges || [];
  const edges = links.map((l, i) => ({
    id:     `e${i}`,
    from:   l.source !== undefined ? l.source : l.from,
    to:     l.target !== undefined ? l.target : l.to,
    label:  l.relation || l.label || "",
    color:  { color: "#3B82F6", highlight: "#fff", hover: "#93C5FD", inherit: false },
    width: 1.5, selectionWidth: 3,
    smooth: { enabled: true, type: "dynamic", roundness: 0.25 },
    font:   { color: "#93C5FD", size: 9, face: "JetBrains Mono", strokeWidth: 2, strokeColor: "#080B12", align: "middle" },
    shadow: { enabled: true, color: "rgba(59,130,246,0.3)", size: 6 },
  }));

  const data    = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
  const options = {
    autoResize: true,
    nodes: { borderWidth: 2, borderWidthSelected: 4, chosen: true },
    edges: { arrows: { to: { enabled: true, scaleFactor: 0.65 } }, width: 1.5, smooth: { type: "dynamic" } },
    physics: {
      solver: "forceAtlas2Based",
      forceAtlas2Based: { gravitationalConstant: -55, centralGravity: 0.015, springLength: 180, springConstant: 0.035, damping: 0.45, avoidOverlap: 1.2 },
      stabilization: { enabled: true, iterations: 250, updateInterval: 25, fit: true },
    },
    interaction: { hover: true, tooltipDelay: 100, navigationButtons: true, keyboard: true, zoomView: true, dragView: true, dragNodes: true, multiselect: true },
    manipulation: { enabled: false },
  };

  el.innerHTML = "";
  const network = new vis.Network(el, data, options);
  graphNetworks[containerId] = network;

  network.on("hoverNode",  () => { el.style.cursor = "pointer"; });
  network.on("blurNode",   () => { el.style.cursor = "default"; });
  network.on("doubleClick", params => {
    if (params.nodes.length) {
      network.focus(params.nodes[0], { scale: 1.4, animation: { duration: 600, easingFunction: "easeInOutQuad" } });
    }
  });
  network.once("stabilizationIterationsDone", () => {
    network.fit({ animation: { duration: 700, easingFunction: "easeInOutQuad" } });
  });
  el._network = network;
}

// ── Graph view (dedicated page) ───────────────────────────────────────────
async function loadGraphView() {
  try {
    const res  = await fetch(`${API_BASE}/api/dashboard`);
    const data = await res.json();
    renderGraph("graphViewContainer", data.combined_knowledge_graph);

    document.getElementById("graphViewFit")?.addEventListener("click", () => {
      graphNetworks["graphViewContainer"]?.fit({ animation: { duration: 600, easingFunction: "easeInOutQuad" } });
    });
    document.getElementById("graphViewFullscreen")?.addEventListener("click", () => {
      openFullscreenGraph("graphViewContainer", data.combined_knowledge_graph, "Threat Knowledge Graph");
    });
  } catch(e) { console.error("Graph view error:", e); }
}

// ── Fullscreen graph ──────────────────────────────────────────────────────
function openFullscreenGraph(sourceContainerId, graphData, title) {
  const overlay  = document.getElementById("fullscreenOverlay");
  const container = document.getElementById("fullscreenGraph");
  const titleEl  = document.getElementById("fullscreenTitle");
  if (!overlay || !container) return;
  overlay.classList.remove("hidden");
  if (titleEl) titleEl.textContent = title || "Graph";
  container.innerHTML = "";
  renderGraph("fullscreenGraph", graphData);
}

document.getElementById("fullscreenClose")?.addEventListener("click", () => {
  document.getElementById("fullscreenOverlay")?.classList.add("hidden");
});

// ═══════════════════════════════════════════════════════════════════════════
// ATTACK STORYLINE
// ═══════════════════════════════════════════════════════════════════════════

function renderStoryline(storyline, incidentTitle) {
  const container = document.getElementById("storylineContainer");
  const titleEl   = document.getElementById("storylineIncidentTitle");
  if (!container) return;
  if (titleEl) titleEl.textContent = incidentTitle || "Current Incident";

  if (!storyline || !storyline.stages || storyline.stages.length === 0) {
    container.innerHTML = `
      <div class="storyline-empty">
        <div class="empty-icon">⚡</div>
        <div class="empty-title">Insufficient Evidence for Storyline</div>
        <div class="empty-sub">${escHtml(storyline?.summary || "No attack stages could be inferred from this report.")}</div>
      </div>`;
    return;
  }

  const chain = document.createElement("div");
  chain.className = "storyline-chain";

  // Summary + note
  if (storyline.summary) {
    const sum = document.createElement("div");
    sum.className = "storyline-summary";
    sum.textContent = storyline.summary;
    chain.appendChild(sum);
  }
  if (storyline.note) {
    const note = document.createElement("div");
    note.className = "storyline-note";
    note.textContent = storyline.note;
    chain.appendChild(note);
  }

  storyline.stages.forEach((stage, idx) => {
    // Stage card
    const card = document.createElement("div");
    card.className = `stage-card ${stage.evidence_label}`;
    card.style.animationDelay = `${idx * 0.08}s`;

    const evidenceHtml = (stage.evidence || []).slice(0, 4)
      .map(e => `<div class="stage-evidence-item">${escHtml(e)}</div>`).join("");
    const iocHtml = (stage.iocs || []).slice(0, 5)
      .map(i => `<span class="stage-ioc-tag">${escHtml(i)}</span>`).join("");
    const lblClass = { confirmed: "label-confirmed", inferred: "label-inferred", possible: "label-possible" }[stage.evidence_label] || "label-possible";

    card.innerHTML = `
      <div class="stage-head">
        <div class="stage-name">${escHtml(stage.name)}</div>
        <div style="display:flex;gap:6px;align-items:center;">
          <span class="stage-mitre">${escHtml(stage.mitre_tactic)}</span>
          <span class="stage-evidence-label ${lblClass}">${escHtml(stage.evidence_label)}</span>
        </div>
      </div>
      <div class="stage-evidence">${evidenceHtml}</div>
      ${iocHtml ? `<div class="stage-iocs">${iocHtml}</div>` : ""}
      ${stage.note ? `<div class="stage-note">${escHtml(stage.note)}</div>` : ""}
      <div class="stage-conf-bar">
        <div class="stage-conf-fill" style="width:0%" data-target="${stage.confidence}%"></div>
      </div>
    `;
    chain.appendChild(card);

    // Animate confidence bar
    const fill = card.querySelector(".stage-conf-fill");
    setTimeout(() => { if (fill) fill.style.width = fill.dataset.target; }, 200 + idx * 80);

    // Arrow (not after last)
    if (idx < storyline.stages.length - 1) {
      const arrow = document.createElement("div");
      arrow.className = "storyline-arrow";
      arrow.innerHTML = '<div class="storyline-arrow-line"></div><div class="storyline-arrow-head"></div>';
      chain.appendChild(arrow);
    }
  });

  container.innerHTML = "";
  container.appendChild(chain);
}

// ═══════════════════════════════════════════════════════════════════════════
// THREAT CAMPAIGNS
// ═══════════════════════════════════════════════════════════════════════════

async function loadCampaigns() {
  const container = document.getElementById("campaignsList");
  if (!container) return;
  container.innerHTML = '<div class="panel" style="grid-column:1/-1;"><div class="empty-note">Loading campaigns…</div></div>';

  try {
    const res  = await fetch(`${API_BASE}/api/campaigns`);
    const data = await res.json();
    container.innerHTML = "";

    if (!data.campaigns || data.campaigns.length === 0) {
      container.innerHTML = `
        <div class="panel" style="grid-column:1/-1;">
          <div class="storyline-empty">
            <div class="empty-icon">🎯</div>
            <div class="empty-title">No Campaigns Detected Yet</div>
            <div class="empty-sub">Campaigns are detected when multiple incidents share common IoCs, malware families, or CVEs. Analyze at least 2 related incidents to trigger campaign detection.</div>
          </div>
        </div>`;
      return;
    }

    data.campaigns.forEach(camp => renderCampaignCard(camp, container));
  } catch(e) {
    container.innerHTML = '<div class="panel" style="grid-column:1/-1;"><div class="empty-note">Could not load campaigns.</div></div>';
  }
}

function renderCampaignCard(camp, container) {
  const card = document.createElement("div");
  card.className = `campaign-card level-${camp.threat_level || "Unknown"}`;

  const common = camp.common_iocs || {};
  const iocPreview = [
    ...((common.domains || []).slice(0, 2)),
    ...((common.malware_families || []).slice(0, 2)),
    ...((common.ip_addresses || []).slice(0, 1)),
  ].slice(0, 5);

  const iocHtml  = iocPreview.map(v => `<span class="ioc-value-chip">${escHtml(v)}</span>`).join("") || '<span class="ioc-empty">No common IoCs</span>';
  const firstDet = camp.first_detected ? new Date(camp.first_detected).toLocaleDateString() : "—";
  const lastAct  = camp.last_activity  ? new Date(camp.last_activity).toLocaleDateString()  : "—";

  card.innerHTML = `
    <div class="campaign-name">${escHtml(camp.name)}</div>
    <div class="campaign-level-badge">${escHtml(camp.threat_level || "Unknown")} Risk</div>
    <div class="campaign-stats">
      <div class="campaign-stat">
        <div class="campaign-stat-val">${camp.incident_count || 0}</div>
        <div class="campaign-stat-lbl">Incidents</div>
      </div>
      <div class="campaign-stat">
        <div class="campaign-stat-val">${iocPreview.length}</div>
        <div class="campaign-stat-lbl">Common IoCs</div>
      </div>
    </div>
    <div class="campaign-ioc-preview">${iocHtml}</div>
    <div class="campaign-dates">First: ${firstDet} · Last: ${lastAct}</div>
    <button class="btn-primary btn-sm" style="width:100%">View Campaign →</button>
  `;
  card.querySelector("button").addEventListener("click", (e) => {
    e.stopPropagation();
    openCampaignModal(camp.campaign_id);
  });
  container.appendChild(card);
}

async function openCampaignModal(campaignId) {
  const overlay = document.getElementById("campaignModal");
  const nameEl  = document.getElementById("modalCampaignName");
  const subEl   = document.getElementById("modalCampaignSub");
  const body    = document.getElementById("campaignModalBody");
  if (!overlay) return;

  overlay.classList.remove("hidden");
  if (body) body.innerHTML = '<div class="empty-note">Loading…</div>';

  try {
    const res  = await fetch(`${API_BASE}/api/campaign/${campaignId}`);
    const camp = await res.json();

    if (nameEl) nameEl.textContent = camp.name || "—";
    if (subEl)  subEl.textContent  = `${camp.threat_level || "—"} Risk · ${camp.incident_count || 0} Incidents`;

    const common = camp.common_iocs || {};
    const membersHtml = (camp.members || []).map(m => `
      <div class="timeline-item">
        <div class="timeline-time">${m.created_at ? new Date(m.created_at).toLocaleDateString() : "—"}</div>
        <div class="timeline-content">
          <div class="timeline-type">${escHtml(m.incident_type || "—")}</div>
          <div class="timeline-sev">${escHtml(m.title || "Untitled")}</div>
        </div>
        <span class="badge sev-${escHtml(m.severity || "")}">${escHtml(m.severity || "—")}</span>
        ${m.threat_score != null ? `<span class="sim-score">${m.threat_score}</span>` : ""}
      </div>`).join("") || '<div class="empty-note">No member incidents found.</div>';

    const iocHtml = Object.entries(common)
      .filter(([,v]) => v && v.length > 0)
      .map(([k,v]) => `
        <div style="margin-bottom:8px;">
          <div class="ioc-type-label" style="margin-bottom:4px;">${escHtml(k.replace(/_/g," ").toUpperCase())}</div>
          <div>${v.map(i => `<span class="ioc-value-chip">${escHtml(i)}</span>`).join("")}</div>
        </div>`).join("") || '<div class="empty-note">No shared IoCs found.</div>';

    if (body) body.innerHTML = `
      <h4 style="font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;">Member Incidents</h4>
      <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:20px;">${membersHtml}</div>
      <h4 style="font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;">Common Indicators</h4>
      <div>${iocHtml}</div>
    `;
  } catch(e) {
    if (body) body.innerHTML = '<div class="empty-note">Failed to load campaign details.</div>';
  }
}

document.getElementById("campaignModalClose")?.addEventListener("click", () => {
  document.getElementById("campaignModal")?.classList.add("hidden");
});

// ═══════════════════════════════════════════════════════════════════════════
// HISTORY
// ═══════════════════════════════════════════════════════════════════════════

document.getElementById("refreshHistory")?.addEventListener("click", loadHistory);

async function loadHistory() {
  const tbody = document.getElementById("historyBody");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7" class="empty-note">Loading…</td></tr>';

  try {
    const res  = await fetch(`${API_BASE}/api/history`);
    if (!res.ok) throw new Error(`${res.status}`);
    const data = await res.json();

    if (!Array.isArray(data) || data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-note">No incidents analyzed yet.</td></tr>';
      return;
    }

    data.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
    tbody.innerHTML = "";

    data.forEach(item => {
      const tr  = document.createElement("tr");
      const date = item.created_at ? new Date(item.created_at).toLocaleString() : "—";
      const conf = item.confidence != null ? `${(item.confidence * 100).toFixed(1)}%` : "—";
      const score = item.threat_score != null ? item.threat_score : "—";
      tr.innerHTML = `
        <td>${escHtml(item.title || "Untitled")}</td>
        <td><span class="badge">${escHtml(item.incident_type || "Unknown")}</span></td>
        <td><span class="badge sev-${escHtml(item.severity || "")}">${escHtml(item.severity || "Unknown")}</span></td>
        <td style="font-family:var(--font-mono);font-size:11px;">${score}</td>
        <td>${item.campaign_name ? `<span style="font-size:10px;color:var(--high);">${escHtml(item.campaign_name)}</span>` : "—"}</td>
        <td style="font-size:11px;color:var(--muted);">${date}</td>
        <td><button class="link-btn" data-id="${escHtml(item.id)}">View</button></td>
      `;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll(".link-btn").forEach(btn => {
      btn.addEventListener("click", () => openIncidentFromHistory(btn.dataset.id));
    });
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-note">Could not load history: ${e.message}</td></tr>`;
  }
}

async function openIncidentFromHistory(id) {
  try {
    const res  = await fetch(`${API_BASE}/api/incident/${id}`);
    const data = await res.json();
    navigateTo("analyze");
    document.getElementById("incidentTitle").value = data.title || "";
    document.getElementById("incidentText").value  = data.text  || "";
    renderResults(data);
    loadSimilar(id);
    document.getElementById("resultsArea").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch {
    alert("Could not load that incident.");
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// REPORTS LIST
// ═══════════════════════════════════════════════════════════════════════════

async function loadReportsList() {
  const container = document.getElementById("reportsList");
  if (!container) return;
  container.innerHTML = '<div class="empty-note">Loading reports…</div>';

  try {
    const res  = await fetch(`${API_BASE}/api/history`);
    const data = await res.json();

    if (!Array.isArray(data) || data.length === 0) {
      container.innerHTML = '<div class="empty-note">No incidents analyzed yet. Reports will appear here after analysis.</div>';
      return;
    }

    container.innerHTML = "";
    data.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
    data.forEach(item => {
      const row = document.createElement("div");
      row.className = "report-row";
      const date = item.created_at ? new Date(item.created_at).toLocaleDateString() : "—";
      const score = item.threat_score != null ? `Score: ${item.threat_score}` : "";
      row.innerHTML = `
        <div class="report-row-icon">📄</div>
        <div class="report-row-body">
          <div class="report-row-title">${escHtml(item.title || "Untitled Incident")}</div>
          <div class="report-row-sub">${escHtml(item.incident_type || "—")} · ${escHtml(item.severity || "—")} ${score ? `· ${score}` : ""} · ${date}</div>
        </div>
        <div class="report-actions">
          <button class="btn-secondary btn-sm view-report-btn" data-id="${escHtml(item.id)}">View</button>
          <button class="btn-primary btn-sm download-report-btn" data-id="${escHtml(item.id)}">⬇ PDF</button>
        </div>
      `;
      row.querySelector(".view-report-btn")?.addEventListener("click", () => openIncidentFromHistory(item.id));
      row.querySelector(".download-report-btn")?.addEventListener("click", async (e) => {
        const dBtn = e.currentTarget;
        const originalText = dBtn.innerHTML;
        dBtn.disabled = true;
        dBtn.innerHTML = '<span class="btn-spinner"></span>';
        try {
          await downloadPdf(item.id);
        } finally {
          dBtn.disabled = false;
          dBtn.innerHTML = originalText;
        }
      });
      container.appendChild(row);
    });
  } catch {
    container.innerHTML = '<div class="empty-note">Could not load reports list.</div>';
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════════════════

async function loadSettings() {
  const container = document.getElementById("settingsStatus");
  if (!container) return;
  container.innerHTML = '<div class="empty-note">Loading…</div>';
  try {
    const data = await checkHealth();
    if (!data) throw new Error("offline");
    const items = [
      ["Backend Status",    data.status === "ok" ? "Online" : "Offline"],
      ["Platform Version",  data.version || "2.0.0"],
      ["Storage Backend",   data.storage_backend || "—"],
      ["Models Loaded",     data.models_loaded ? "Yes" : "No — run train_models.py"],
      ["LLM Available",     data.llm_available ? "Yes" : "No (optional)"],
    ];
    container.innerHTML = items.map(([label, val]) => `
      <div class="settings-status-item">
        <span class="settings-status-label">${escHtml(label)}</span>
        <span class="settings-status-val">${escHtml(val)}</span>
      </div>`).join("");
  } catch {
    container.innerHTML = '<div class="empty-note">Could not load system status.</div>';
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// FINAL REPORT + PDF
// ═══════════════════════════════════════════════════════════════════════════

document.getElementById("generateReportBtn")?.addEventListener("click", generateFinalReport);
document.getElementById("downloadPdfBtn")?.addEventListener("click",    () => downloadPdf());

async function generateFinalReport() {
  if (!currentIncidentId) {
    showNotification("Please analyze an incident first.", "warning");
    return;
  }
  const btn = document.getElementById("generateReportBtn");
  btn.textContent = "Generating…";
  btn.disabled = true;
  try {
    const res    = await fetch(`${API_BASE}/api/report/${currentIncidentId}`);
    if (!res.ok) throw new Error(`${res.status}`);
    const report = await res.json();
    renderFinalReport(report);
    showNotification("Intelligence report generated successfully.", "success");
  } catch(e) {
    showNotification("Report generation error: " + e.message, "error");
  } finally {
    btn.textContent = "Generate Report";
    btn.disabled = false;
  }
}

async function downloadPdf(targetIncidentId = null) {
  const incId = (typeof targetIncidentId === "string" && targetIncidentId) ? targetIncidentId : currentIncidentId;

  if (!incId) {
    showNotification("Please analyze or select an incident first before downloading the PDF report.", "warning");
    return;
  }

  const btn = document.getElementById("downloadPdfBtn");
  const isMainButton = btn && (!targetIncidentId || targetIncidentId === currentIncidentId);

  if (isMainButton) {
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-spinner"></span> Generating PDF Report…';
  }

  try {
    const res = await fetch(`${API_BASE}/api/report/${encodeURIComponent(incId)}/pdf`);
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Server returned ${res.status}`);
    }

    const blob = await res.blob();
    if (!blob || blob.size === 0) {
      throw new Error("Received an empty or corrupted PDF from server.");
    }

    // Extract filename from Content-Disposition if present
    let filename = `CIRIP_Report_${incId.slice(0, 8)}.pdf`;
    const disp = res.headers.get("Content-Disposition");
    if (disp) {
      const match = disp.match(/filename=["']?([^"']+)["']?/);
      if (match && match[1]) {
        filename = match[1];
      }
    }

    // Trigger cross-browser download
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.style.display = "none";
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();

    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 250);

    showNotification(`PDF Report downloaded successfully: ${filename}`, "success");
  } catch(e) {
    console.error("PDF download failure:", e);
    showNotification(`PDF download failed: ${e.message}`, "error");
  } finally {
    if (isMainButton) {
      btn.disabled = false;
      btn.innerHTML = '⬇ Download PDF Report';
    }
  }
}

function renderFinalReport(report) {
  const body = document.getElementById("finalReportBody");
  if (!body) return;
  body.classList.remove("hidden");

  document.getElementById("reportTitle").textContent         = report.title || "Untitled Incident";
  document.getElementById("reportIncidentId").textContent    = report.incident_id || "—";
  document.getElementById("reportIncidentType").textContent  = report.incident_type?.label || "—";
  document.getElementById("reportIncidentConfidence").textContent =
    report.incident_type?.confidence != null ? `${(report.incident_type.confidence * 100).toFixed(1)}% confidence` : "";
  document.getElementById("reportSeverity").textContent      = report.severity?.label || "—";
  document.getElementById("reportSeverityConfidence").textContent =
    report.severity?.confidence != null ? `${(report.severity.confidence * 100).toFixed(1)}% confidence` : "";
  document.getElementById("reportSummary").textContent       = report.summary?.text || "—";

  // Threat score in report
  const ts = report.threat_score;
  if (ts) {
    const scoreEl = document.getElementById("reportThreatScore");
    const clsEl   = document.getElementById("reportThreatClass");
    if (scoreEl) scoreEl.textContent = `${ts.score}/100`;
    if (clsEl)   clsEl.textContent   = ts.classification || "";
  }

  renderReportIocs(report.iocs || {});
  renderReportEntities(report.entities || {});
  renderRootCause(report.root_cause_hints || []);
  renderReportMitigation(report.mitigation || {});
  renderReportXai(report.explainable_ai || {});

  body.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderReportIocs(iocs) {
  const container = document.getElementById("reportIocs");
  if (!container) return;
  container.innerHTML = "";
  Object.entries(iocs).forEach(([type, values]) => {
    if (type === "extraction_method" || type === "file_hashes") return;
    if (!Array.isArray(values) || values.length === 0) return;
    container.appendChild(chipRow(type.replace(/_/g, " "), values));
  });
  const fh = iocs.file_hashes || {};
  Object.entries(fh).forEach(([ht, hashes]) => {
    if (hashes && hashes.length > 0) container.appendChild(chipRow(`${ht.toUpperCase()} Hashes`, hashes));
  });
}

function renderReportEntities(entities) {
  const container = document.getElementById("reportEntities");
  if (!container) return;
  container.innerHTML = "";
  Object.entries(entities).forEach(([key, values]) => {
    if (key === "extraction_method" || !Array.isArray(values) || values.length === 0) return;
    container.appendChild(chipRow(key.replace(/_/g, " "), values));
  });
}

function renderRootCause(hints) {
  const ul = document.getElementById("reportRootCause");
  if (!ul) return;
  ul.innerHTML = hints.map(h => `<li>${escHtml(h)}</li>`).join("") || "<li>No root cause hints available.</li>";
}

function renderReportMitigation(mitigation) {
  const container = document.getElementById("reportMitigation");
  if (!container) return;
  container.innerHTML = "";
  const rb = mitigation.rule_based || {};
  container.appendChild(mitList("Immediate Response", rb.immediate_response));
  container.appendChild(mitList("Containment",        rb.containment));
  container.appendChild(mitList("Recovery",           rb.recovery));
  container.appendChild(mitList("Prevention",         rb.prevention));
}

function renderReportXai(xai) {
  const container = document.getElementById("reportXai");
  if (!container) return;
  const features = xai.incident_type_top_features || [];
  if (!features.length) { container.innerHTML = '<div class="empty-note">No XAI features.</div>'; return; }
  const maxAbs = Math.max(...features.map(f => Math.abs(f.contribution)), 0.0001);
  container.innerHTML = "";
  features.forEach(f => {
    const row = document.createElement("div");
    row.className = "xai-bar-row";
    const pct = Math.min(100, Math.abs(f.contribution) / maxAbs * 100);
    row.innerHTML = `
      <div class="xai-word">${escHtml(f.feature)}</div>
      <div class="xai-track"><div class="xai-fill" style="width:${pct}%"></div></div>
      <div class="xai-val">${f.contribution.toFixed(3)}</div>
    `;
    container.appendChild(row);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// MODEL PERFORMANCE & EVALUATION
// ═══════════════════════════════════════════════════════════════════════════

async function loadEvaluation() {
  try {
    let evalData = null;
    try {
      const res = await fetch(`${API_BASE}/api/model-evaluation`);
      if (res.ok) {
        evalData = await res.json();
      }
    } catch (netErr) {
      console.warn("Backend evaluation endpoint unreachable, using verified reported metrics:", netErr);
    }

    // Populate comparison table if data is returned from API
    if (evalData && evalData.comparison_table) {
      renderEvaluationTable(evalData.comparison_table);
    }

    // Render Visual Comparison Charts (Logistic Regression)
    renderEvaluationCharts();
  } catch (err) {
    console.error("Evaluation view error:", err);
  }
}

function renderEvaluationTable(tableRows) {
  const tbody = document.getElementById("evalComparisonTableBody");
  if (!tbody || !tableRows || !tableRows.length) return;

  tbody.innerHTML = "";
  tableRows.forEach(row => {
    const tr = document.createElement("tr");

    const isEvaluated = row.status && row.status.toLowerCase().includes("evaluated") && !row.status.toLowerCase().startsWith("not");

    const holdoutBadge = row.holdout_accuracy === "100%"
      ? `<span class="eval-score-highlight green">${escHtml(row.holdout_accuracy)}</span>`
      : (row.holdout_accuracy === "Not evaluated"
          ? `<span class="badge badge-muted">Not evaluated</span>`
          : `<span class="eval-score-highlight">${escHtml(row.holdout_accuracy)}</span>`);

    let indepAccBadge = `<span class="badge badge-muted">Not evaluated</span>`;
    if (row.independent_accuracy !== "Not evaluated") {
      const cls = String(row.independent_accuracy).startsWith("72") ? "cyan" : "orange";
      indepAccBadge = `<span class="eval-score-highlight ${cls}">${escHtml(row.independent_accuracy)}</span>`;
    }

    let indepF1Badge = `<span class="badge badge-muted">Not evaluated</span>`;
    if (row.independent_macro_f1 !== "Not evaluated") {
      const cls = String(row.independent_macro_f1).startsWith("0.7") ? "purple" : "red";
      indepF1Badge = `<span class="eval-score-highlight ${cls}">${escHtml(row.independent_macro_f1)}</span>`;
    }

    const statusBadge = isEvaluated
      ? `<span class="badge">Active &amp; Evaluated</span>`
      : `<span class="badge badge-muted">Not evaluated</span>`;

    const titleHtml = isEvaluated
      ? `<strong>${escHtml(row.model_task)}</strong>`
      : `${escHtml(row.model_task)}`;

    tr.innerHTML = `
      <td>${titleHtml}</td>
      <td>${holdoutBadge}</td>
      <td>${indepAccBadge}</td>
      <td>${indepF1Badge}</td>
      <td>${statusBadge}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderEvaluationCharts() {
  // Chart A: Holdout vs. Independent Accuracy
  const canvasA = document.getElementById("evalHoldoutVsIndependentChart");
  if (canvasA) {
    const ctxA = canvasA.getContext("2d");
    if (charts["evalHoldout"]) {
      charts["evalHoldout"].destroy();
    }

    charts["evalHoldout"] = new Chart(ctxA, {
      type: "bar",
      data: {
        labels: ["Incident Classification", "Severity Prediction"],
        datasets: [
          {
            label: "Holdout Accuracy (80/20 Test)",
            data: [100.0, 100.0],
            backgroundColor: "rgba(59, 130, 246, 0.8)",
            borderColor: "#3B82F6",
            borderWidth: 1.5,
            borderRadius: 6,
          },
          {
            label: "Independent Benchmark (18 Reports)",
            data: [72.22, 33.33],
            backgroundColor: "rgba(34, 211, 238, 0.8)",
            borderColor: "#22D3EE",
            borderWidth: 1.5,
            borderRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: true,
            position: "top",
            labels: {
              color: "#A8B3C4",
              font: { family: "Inter", size: 11 },
              boxWidth: 12,
              padding: 12,
            },
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                return ` ${context.dataset.label}: ${context.parsed.y.toFixed(2)}%`;
              },
            },
          },
        },
        scales: {
          x: {
            ticks: {
              color: "#A8B3C4",
              font: { family: "Inter", size: 11, weight: 600 },
            },
            grid: { color: "#1E2D45" },
          },
          y: {
            min: 0,
            max: 100,
            ticks: {
              color: "#8A96A6",
              font: { family: "JetBrains Mono", size: 10 },
              stepSize: 20,
              callback: function(value) { return value + "%"; },
            },
            grid: { color: "#1E2D45" },
          },
        },
        animation: { duration: 800, easing: "easeOutQuart" },
      },
    });
  }

  // Chart B: Independent Macro F1: Classification vs Severity
  const canvasB = document.getElementById("evalMacroF1Chart");
  if (canvasB) {
    const ctxB = canvasB.getContext("2d");
    if (charts["evalMacroF1"]) {
      charts["evalMacroF1"].destroy();
    }

    charts["evalMacroF1"] = new Chart(ctxB, {
      type: "bar",
      data: {
        labels: ["Incident Classification", "Severity Prediction"],
        datasets: [
          {
            label: "Independent Macro F1-Score (18 Reports)",
            data: [0.71, 0.20],
            backgroundColor: [
              "rgba(139, 92, 246, 0.8)",
              "rgba(249, 115, 22, 0.8)",
            ],
            borderColor: [
              "#8B5CF6",
              "#F97316",
            ],
            borderWidth: 1.5,
            borderRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: true,
            position: "top",
            labels: {
              color: "#A8B3C4",
              font: { family: "Inter", size: 11 },
              boxWidth: 12,
              padding: 12,
            },
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                return ` ${context.dataset.label}: ${context.parsed.y.toFixed(2)}`;
              },
            },
          },
        },
        scales: {
          x: {
            ticks: {
              color: "#A8B3C4",
              font: { family: "Inter", size: 11, weight: 600 },
            },
            grid: { color: "#1E2D45" },
          },
          y: {
            min: 0,
            max: 1.0,
            ticks: {
              color: "#8A96A6",
              font: { family: "JetBrains Mono", size: 10 },
              stepSize: 0.2,
              callback: function(value) { return value.toFixed(2); },
            },
            grid: { color: "#1E2D45" },
          },
        },
        animation: { duration: 800, easing: "easeOutQuart" },
      },
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY
// ═══════════════════════════════════════════════════════════════════════════

function escHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ═══════════════════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════════════════

// Load command center on startup
loadCommandCenter();