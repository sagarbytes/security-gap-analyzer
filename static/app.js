/* ═══════════════════════════════════════════════════════════════
   Security Control Gap Analysis — app.js
   ═══════════════════════════════════════════════════════════════ */

const CONTROL_AREAS = [
  "Authorization",
  "Authentication",
  "Logging & Monitoring",
  "Certification & Compliance",
  "Application Patching",
  "System Hardening",
  "Session Management",
];

const MAX_CHARS = 3000;

const LOADING_QUOTES = [
  "Security is not a product, but a process.",
  "Hackers don't break in, they log in.",
  "The quieter you become, the more you can hear.",
  "Cybersecurity is much more than a matter of IT.",
  "Trust, but verify—especially for access control and authentication.",
  "Least privilege: give users exactly what they need, nothing more.",
  "Defense in depth: no single control has to carry the whole load.",
  "Your policy is the source of truth; we're matching your story to it.",
];

const PROGRESS_STEPS = [
  "Analyzing controls…",
  "Retrieving policy excerpts…",
  "Validating against policy…",
  "Running rule-based checks…",
  "Generating assessment…",
];

/* ── Helpers ── */

function shuffleArray(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function getDescriptions() {
  const descriptions = {};
  for (const area of CONTROL_AREAS) {
    const el = document.getElementById(area);
    descriptions[area] = (el?.value || "").trim();
  }
  return descriptions;
}

function statusPillClass(status) {
  if (status === "Compliant") return "ok";
  if (status === "Partially Implemented") return "warn";
  return "bad";
}

function statusBorderClass(status) {
  if (status === "Compliant") return "result-card--ok";
  if (status === "Partially Implemented") return "result-card--warn";
  return "result-card--bad";
}

/* ── Character counters ── */

function initCharCounters() {
  for (const area of CONTROL_AREAS) {
    const ta = document.getElementById(area);
    const counter = document.querySelector(`.char-count[data-for="${area}"]`);
    if (!ta || !counter) continue;

    const update = () => {
      const len = ta.value.length;
      counter.textContent = `${len} / ${MAX_CHARS}`;
      counter.classList.toggle("char-count--warn", len > MAX_CHARS * 0.85);
      counter.classList.toggle("char-count--over", len >= MAX_CHARS);
    };

    ta.addEventListener("input", update);
    update();
  }
}

/* ── Loading overlay ── */

function showLoading() {
  const overlay = document.getElementById("loadingOverlay");
  const resultsSection = document.getElementById("resultsSection");
  overlay.classList.remove("loading-overlay--hidden");
  overlay.setAttribute("aria-hidden", "false");
  overlay.setAttribute("aria-busy", "true");
  if (resultsSection) resultsSection.classList.add("results--loading");
}

function hideLoading() {
  const overlay = document.getElementById("loadingOverlay");
  const resultsSection = document.getElementById("resultsSection");
  overlay.classList.add("loading-overlay--hidden");
  overlay.setAttribute("aria-hidden", "true");
  overlay.setAttribute("aria-busy", "false");
  if (resultsSection) resultsSection.classList.remove("results--loading");
}

function startLoadingContent(quoteEl, progressEl, quoteMs = 2600, progressMs = 3200) {
  const quoteOrder = shuffleArray(LOADING_QUOTES);
  let qi = 0;
  quoteEl.textContent = quoteOrder[0] || "";
  const quoteInterval = window.setInterval(() => {
    qi += 1;
    quoteEl.textContent = quoteOrder[qi % quoteOrder.length];
  }, quoteMs);

  let pi = 0;
  if (progressEl) progressEl.textContent = PROGRESS_STEPS[0];
  const progressInterval = window.setInterval(() => {
    pi += 1;
    if (progressEl) progressEl.textContent = PROGRESS_STEPS[pi % PROGRESS_STEPS.length];
  }, progressMs);

  return { quoteInterval, progressInterval };
}

function stopLoadingContent(ids) {
  if (ids.quoteInterval != null) window.clearInterval(ids.quoteInterval);
  if (ids.progressInterval != null) window.clearInterval(ids.progressInterval);
}

/* ── Compliance summary ── */

let _lastResults = null; // stored for export

function renderSummary(summary) {
  const section = document.getElementById("summarySection");
  section.classList.remove("summary-section--hidden");

  document.getElementById("countCompliant").textContent = summary.compliant;
  document.getElementById("countPartial").textContent = summary.partially_implemented;
  document.getElementById("countGap").textContent = summary.gap_identified;

  const score = summary.compliance_score;
  document.getElementById("scoreValue").textContent = score;

  // Animate the arc
  const arc = document.getElementById("scoreArc");
  const circumference = 2 * Math.PI * 52; // r=52
  const offset = circumference - (circumference * score) / 100;
  arc.style.transition = "stroke-dashoffset 1.2s ease";
  requestAnimationFrame(() => {
    arc.style.strokeDashoffset = offset;
  });

  // Color the arc based on score
  if (score >= 80) {
    arc.style.stroke = "var(--ok)";
  } else if (score >= 50) {
    arc.style.stroke = "var(--warn)";
  } else {
    arc.style.stroke = "var(--bad)";
  }
}

/* ── Results rendering ── */

function renderResults(results) {
  const grid = document.getElementById("resultsGrid");
  const resultsSection = document.getElementById("resultsSection");
  grid.innerHTML = "";
  grid.classList.remove("results-grid--fade-in");
  resultsSection.classList.remove("results--hidden");

  for (const area of CONTROL_AREAS) {
    const r = results[area] || {
      control_area: area,
      status: "Gap Identified",
      summary: "",
      gap_detail: "No result returned for this control area.",
      policy_reference: [],
    };

    const card = document.createElement("div");
    card.className = `result-card ${statusBorderClass(r.status)}`;

    const top = document.createElement("div");
    top.className = "result-top";

    const title = document.createElement("h3");
    title.textContent = r.control_area || area;

    const pill = document.createElement("span");
    pill.className = `pill ${statusPillClass(r.status)}`;
    pill.textContent = r.status;

    top.appendChild(title);
    top.appendChild(pill);
    card.appendChild(top);

    // Summary
    const summary = document.createElement("div");
    summary.className = "field";
    summary.innerHTML = `<div class="label">Summary</div><div class="value"></div>`;
    summary.querySelector(".value").textContent = r.summary || "";
    card.appendChild(summary);

    // Gap detail (only for non-compliant)
    if (r.status !== "Compliant") {
      const gap = document.createElement("div");
      gap.className = "field";
      gap.innerHTML = `<div class="label">Gap detail</div><div class="value"></div>`;
      gap.querySelector(".value").textContent = r.gap_detail || "";
      card.appendChild(gap);
    }

    // Policy reference
    const pref = document.createElement("div");
    pref.className = "field";
    pref.innerHTML = `<div class="label">Policy reference</div><div class="mono"></div>`;
    const refText = Array.isArray(r.policy_reference)
      ? r.policy_reference.join("\n")
      : r.policy_reference || "";
    pref.querySelector(".mono").textContent = refText || "—";
    card.appendChild(pref);

    // Error (if any)
    if (r.error) {
      const err = document.createElement("div");
      err.className = "field field--error";
      err.innerHTML = `<div class="label">Error</div><div class="value"></div>`;
      err.querySelector(".value").textContent = r.error;
      card.appendChild(err);
    }

    grid.appendChild(card);
  }

  requestAnimationFrame(() => {
    grid.classList.add("results-grid--fade-in");
  });
}

/* ── Export ── */

function exportResults() {
  if (!_lastResults) return;
  const blob = new Blob([JSON.stringify(_lastResults, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `security-gap-analysis-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ── Main assessment flow ── */

async function runAssessment() {
  const btn = document.getElementById("submitBtn");
  const status = document.getElementById("status");
  const loadingQuote = document.getElementById("loadingQuote");
  const loadingProgress = document.getElementById("loadingProgress");
  btn.disabled = true;
  status.textContent = "";
  let timers = { quoteInterval: null, progressInterval: null };

  try {
    const descriptions = getDescriptions();
    const missing = Object.entries(descriptions)
      .filter(([_, v]) => !v || v.trim().length === 0)
      .map(([k]) => k);
    if (missing.length > 0) {
      status.textContent =
        `All seven fields are required. Missing: ${missing.join(", ")}. ` +
        "Blank fields will be treated as gaps, but you must still submit text in each field.";
      btn.disabled = false;
      return;
    }

    showLoading();
    timers = startLoadingContent(loadingQuote, loadingProgress);

    const res = await fetch("/assess", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ descriptions }),
    });
    const raw = await res.text();
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    let data = null;
    const trimmed = raw.trim();
    const looksJson = trimmed.startsWith("{") || trimmed.startsWith("[");
    if (ct.includes("application/json") || looksJson) {
      try {
        data = JSON.parse(raw);
      } catch {
        data = null;
      }
    }
    if (data == null) {
      const preview = raw.replace(/\s+/g, " ").trim().slice(0, 160);
      throw new Error(
        `Server returned non-JSON (${res.status}). ` +
          (preview ? `Response starts with: ${preview}…` : "Empty response.") +
          " If you see HTML, the app may have crashed—check the terminal running Flask."
      );
    }
    if (!res.ok) {
      throw new Error(data?.error || data?.message || `Request failed: ${res.status}`);
    }

    stopLoadingContent(timers);
    timers = { quoteInterval: null, progressInterval: null };
    hideLoading();

    _lastResults = data;

    // Render compliance summary
    if (data.summary) {
      renderSummary(data.summary);
    }

    renderResults(data.results || {});
    const anyErrors = Object.values(data.results || {}).some((r) => r && r.error);
    status.textContent = anyErrors
      ? "Done (some control areas returned errors—see cards)."
      : "Done.";
  } catch (e) {
    stopLoadingContent(timers);
    hideLoading();
    status.textContent = `Error: ${e.message}`;
  } finally {
    btn.disabled = false;
  }
}

/* ── Init ── */

document.addEventListener("DOMContentLoaded", () => {
  initCharCounters();
  document.getElementById("submitBtn").addEventListener("click", runAssessment);
  document.getElementById("exportBtn").addEventListener("click", exportResults);
});
