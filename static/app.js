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

/* ── Wizard Navigation ── */

let currentStep = 1;

function goToStep(step) {
  // Hide all steps
  document.querySelectorAll(".step").forEach((el) => el.classList.add("hidden"));
  
  // Show target step
  const targetEl = document.getElementById(`step${step}`);
  if (targetEl) targetEl.classList.remove("hidden");
  
  // Update stepper UI
  document.querySelectorAll(".step-indicator").forEach((el) => {
    const s = parseInt(el.getAttribute("data-step"));
    el.classList.toggle("step-indicator--active", s === step);
    el.classList.toggle("step-indicator--completed", s < step);
  });
  
  currentStep = step;
  window.scrollTo({ top: 0, behavior: "smooth" });
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
  
  const updateQuote = () => {
    quoteEl.style.opacity = 0;
    setTimeout(() => {
      quoteEl.textContent = quoteOrder[qi];
      quoteEl.style.opacity = 1;
      qi = (qi + 1) % quoteOrder.length;
      // Re-shuffle when we finish the list to keep it fresh but non-repeating
      if (qi === 0) {
        // We could re-shuffle here if we wanted
      }
    }, 200);
  };

  updateQuote();
  const quoteInterval = window.setInterval(updateQuote, quoteMs);

  let pi = 0;
  if (progressEl) progressEl.textContent = PROGRESS_STEPS[0];
  const progressInterval = window.setInterval(() => {
    pi = (pi + 1) % PROGRESS_STEPS.length;
    if (progressEl) progressEl.textContent = PROGRESS_STEPS[pi];
  }, progressMs);

  return { quoteInterval, progressInterval };
}

function stopLoadingContent(ids) {
  if (ids.quoteInterval != null) window.clearInterval(ids.quoteInterval);
  if (ids.progressInterval != null) window.clearInterval(ids.progressInterval);
}

/* ── Compliance summary ── */

let _lastResults = null; // stored for export
let _lastSummary = null; // stored for hover calcs

function renderSummary(summary) {
  _lastSummary = summary;
  const section = document.getElementById("summarySection");
  section.classList.remove("summary-section--hidden");

  document.getElementById("countCompliant").textContent = summary.compliant;
  document.getElementById("countPartial").textContent = summary.partially_implemented;
  document.getElementById("countGap").textContent = summary.gap_identified;

  const score = summary.compliance_score;
  document.getElementById("scoreValue").textContent = score;

  // Animate the three arcs
  const circumference = 2 * Math.PI * 52; // r=52 (~326.73)
  const total = 7;
  
  const arcCompliant = document.getElementById("arcCompliant");
  const arcPartial = document.getElementById("arcPartial");
  const arcGap = document.getElementById("arcGap");
  
  // Ratios
  const rCompliant = summary.compliant / total;
  const rPartial = summary.partially_implemented / total;
  const rGap = summary.gap_identified / total;
  
  // Set stroke-dashoffset (circumference minus the segment length)
  const offCompliant = circumference - (circumference * rCompliant);
  const offPartial = circumference - (circumference * rPartial);
  const offGap = circumference - (circumference * rGap);
  
  // Set starting rotation for each segment
  // The first segment starts at 0 rotation 
  // partial starts where compliant ends
  const rotPartial = rCompliant * 360; 
  // gap starts where partial ends
  const rotGap = rotPartial + (rPartial * 360);
  
  // Apply rotation using transform origin center
  arcCompliant.style.transformOrigin = "50% 50%";
  arcPartial.style.transformOrigin = "50% 50%";
  arcGap.style.transformOrigin = "50% 50%";
  
  arcCompliant.style.transform = `rotate(0deg)`;
  arcPartial.style.transform = `rotate(${rotPartial}deg)`;
  arcGap.style.transform = `rotate(${rotGap}deg)`;
  
  requestAnimationFrame(() => {
    arcCompliant.style.strokeDashoffset = offCompliant;
    arcPartial.style.strokeDashoffset = offPartial;
    arcGap.style.strokeDashoffset = offGap;
  });
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
    
    // Build collapsible policy wrapper
    const prefWrapper = document.createElement("div");
    prefWrapper.className = "policy-wrapper";
    
    const prefLabel = document.createElement("div");
    prefLabel.className = "label";
    prefLabel.textContent = "Policy Reference";
    pref.appendChild(prefLabel);

    let refText = Array.isArray(r.policy_reference)
      ? r.policy_reference.join("\n")
      : r.policy_reference || "";
      
    // Formatting: Ensure bullet points strictly start on a new line for better hierarchy
    if (refText && refText !== "—") {
      // Replace bullet char with newline + bullet, and cleanup extra whitespace
      refText = refText.replace(/[•●]\s*/g, "\n• ").trim();
      // Ensure specific policy section headers (e.g. [4.1 ...]) also start on a new line if joined
      refText = refText.replace(/(\[\d+\.\d+\s+.*?\])/g, "\n$1").trim();
      // Clean up multiple newlines
      refText = refText.replace(/\n\s*\n/g, "\n").trim();
    }
      
    const prefContent = document.createElement("div");
    prefContent.className = "mono policy-content";
    prefContent.textContent = refText || "—";
    
    prefWrapper.appendChild(prefContent);

    // Only add toggle if text is long (roughly > 140 chars or has multiple lines)
    if (refText && (refText.length > 140 || refText.includes("\n"))) {
      const toggle = document.createElement("button");
      toggle.className = "btn-toggle-policy";
      toggle.textContent = "View Full Policy";
      toggle.onclick = () => {
        const isExpanded = prefContent.classList.toggle("expanded");
        toggle.textContent = isExpanded ? "Show Less" : "View Full Policy";
      };
      prefWrapper.appendChild(toggle);
    }

    pref.appendChild(prefWrapper);
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

function exportJson() {
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

function exportPdf() {
  if (!_lastResults || !_lastResults.results) return;
  
  const results = _lastResults.results;
  const summary = _lastResults.summary;
  const dateStr = new Date().toLocaleDateString();
  
  // 1. Create a well-structured print wrapper
  const printWrapper = document.createElement("div");
  printWrapper.style.padding = "40px";
  printWrapper.style.background = "#ffffff";
  printWrapper.style.color = "#111827";
  printWrapper.style.fontFamily = "'Inter', sans-serif";
  printWrapper.style.lineHeight = "1.5";
  
  // Header
  const header = document.createElement("div");
  header.style.borderBottom = "2px solid #6366F1";
  header.style.marginBottom = "30px";
  header.style.paddingBottom = "10px";
  header.innerHTML = `
    <h1 style="margin:0; font-size:24px; color:#111827;">Security Gap Analysis Report</h1>
    <p style="margin:5px 0 0; color:#6B7280; font-size:14px;">Generated on ${dateStr}</p>
  `;
  printWrapper.appendChild(header);

  // Summary Card
  if (summary) {
    const sumCard = document.createElement("div");
    sumCard.style.background = "#F8FAFC";
    sumCard.style.padding = "20px";
    sumCard.style.borderRadius = "12px";
    sumCard.style.marginBottom = "40px";
    sumCard.style.border = "1px solid #E5E7EB";
    sumCard.innerHTML = `
      <h2 style="margin:0 0 15px; font-size:18px;">Executive Summary</h2>
      <div style="display:flex; gap:40px;">
        <div>
          <div style="font-size:12px; color:#6B7280; text-transform:uppercase;">Overall Score</div>
          <div style="font-size:28px; font-weight:700; color:#6366F1;">${summary.compliance_score}%</div>
        </div>
        <div>
          <div style="font-size:12px; color:#6B7280; text-transform:uppercase;">Statuses</div>
          <div style="font-size:14px; margin-top:5px;">
            <span style="color:#059669;">●</span> ${summary.compliant} Compliant &nbsp;&nbsp;
            <span style="color:#D97706;">●</span> ${summary.partially_implemented} Partial &nbsp;&nbsp;
            <span style="color:#DC2626;">●</span> ${summary.gap_identified} Gaps
          </div>
        </div>
      </div>
    `;
    printWrapper.appendChild(sumCard);
  }

  // Findings List
  const findingsHeader = document.createElement("h2");
  findingsHeader.textContent = "Detailed Findings";
  findingsHeader.style.fontSize = "18px";
  findingsHeader.style.marginBottom = "20px";
  printWrapper.appendChild(findingsHeader);

  for (const area of CONTROL_AREAS) {
    const data = results[area];
    if (!data) continue;

    const areaSection = document.createElement("div");
    areaSection.style.marginBottom = "30px";
    areaSection.style.paddingBottom = "20px";
    areaSection.style.borderBottom = "1px solid #F1F5F9";
    
    const statusColor = data.status === "Compliant" ? "#059669" : (data.status === "Partially Implemented" ? "#D97706" : "#DC2626");
    
    areaSection.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h3 style="margin:0; font-size:16px;">${area}</h3>
        <span style="font-size:12px; font-weight:600; padding:4px 10px; border-radius:100px; background:${statusColor}15; color:${statusColor}; border:1px solid ${statusColor}30;">
          ${data.status}
        </span>
      </div>
      <div style="margin-bottom:12px;">
        <div style="font-size:12px; font-weight:600; color:#6B7280; margin-bottom:4px;">SUMMARY</div>
        <div style="font-size:14px; color:#374151;">${data.summary || "No summary provided."}</div>
      </div>
      ${data.status !== "Compliant" ? `
      <div style="margin-bottom:12px;">
        <div style="font-size:12px; font-weight:600; color:#6B7280; margin-bottom:4px;">GAP DETAIL</div>
        <div style="font-size:14px; color:#374151;">${data.gap_detail || "No details provided."}</div>
      </div>` : ""}
      <div>
        <div style="font-size:12px; font-weight:600; color:#6B7280; margin-bottom:4px;">POLICY REFERENCE</div>
        <div style="font-size:13px; color:#4B5563; white-space:pre-wrap; background:#F8FAFC; padding:10px; border-radius:6px; border:1px solid #F1F5F9; font-family:monospace;">${
          Array.isArray(data.policy_reference) ? data.policy_reference.join("\n") : (data.policy_reference || "—")
        }</div>
      </div>
    `;
    printWrapper.appendChild(areaSection);
  }

  // Final footer
  const footer = document.createElement("div");
  footer.style.marginTop = "40px";
  footer.style.textAlign = "center";
  footer.style.fontSize = "12px";
  footer.style.color = "#94A3B8";
  footer.textContent = "Strict Security Assessment Protocol - Automated Gap Analysis";
  printWrapper.appendChild(footer);

  // 2. Render and Download
  printWrapper.style.position = "fixed";
  printWrapper.style.left = "0";
  printWrapper.style.top = "0";
  printWrapper.style.width = "800px";
  printWrapper.style.visibility = "hidden";
  printWrapper.style.pointerEvents = "none";
  printWrapper.style.zIndex = "-9999";
  document.body.appendChild(printWrapper);
  
  const opt = {
    margin:       10,
    filename:     `Security_Compliance_Report_${new Date().toISOString().slice(0, 10)}.pdf`,
    image:        { type: 'jpeg', quality: 0.98 },
    html2canvas:  { 
      scale: 2, 
      useCORS: true, 
      logging: false,
      scrollY: -window.scrollY // Fixes potential capture offset
    },
    jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
  };
  
  // Use a slight timeout to ensure visibility:hidden doesn't interfere with first paint calculation
  setTimeout(() => {
    html2pdf().set(opt).from(printWrapper).save().then(() => {
      document.body.removeChild(printWrapper);
    });
  }, 150);
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

    const formData = new FormData();
    formData.append("descriptions", JSON.stringify(descriptions));
    
    const fileInput = document.getElementById("policyFile");
    if (fileInput && fileInput.files.length > 0) {
      formData.append("policy_file", fileInput.files[0]);
    }

    const res = await fetch("/assess", {
      method: "POST",
      body: formData,
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
    
    // Switch to step 3
    goToStep(3);

    const anyErrors = Object.values(data.results || {}).some((r) => r && r.error);
    status.textContent = anyErrors
      ? "Done (some control areas returned errors)."
      : "Assessment complete.";
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
  
  // Navigation
  document.getElementById("startBtn").addEventListener("click", () => goToStep(2));
  document.getElementById("backToStep1").addEventListener("click", () => goToStep(1));
  document.getElementById("backToStep2").addEventListener("click", () => goToStep(2));
  document.getElementById("restartBtn").addEventListener("click", () => {
    // Clear and restart
    if (confirm("This will clear your current assessment. Continue?")) {
      for (const area of CONTROL_AREAS) {
        const el = document.getElementById(area);
        if (el) el.value = "";
      }
      initCharCounters(); // reset counts
      goToStep(1);
    }
  });

  // Assessment
  document.getElementById("submitBtn").addEventListener("click", runAssessment);
  
  // Export Dropdown Toggle
  const exportBtn = document.getElementById("exportBtn");
  const exportDropdown = document.getElementById("exportDropdown");
  
  if (exportBtn && exportDropdown) {
    exportBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      exportDropdown.classList.toggle("show");
      exportBtn.classList.toggle("active");
    });

    // Close on any click outside
    document.addEventListener("click", (e) => {
      if (!exportDropdown.contains(e.target) && !exportBtn.contains(e.target)) {
        exportDropdown.classList.remove("show");
        exportBtn.classList.remove("active");
      }
    });
  }
  
  const btnJson = document.getElementById("exportBtnJson");
  const btnPdf = document.getElementById("exportBtnPdf");
  if(btnJson) btnJson.addEventListener("click", exportJson);
  if(btnPdf) btnPdf.addEventListener("click", exportPdf);
  
  const fileInput = document.getElementById("policyFile");
  const fileDisplay = document.getElementById("fileDisplay");
  const nameSpan = document.getElementById("policyFileName");
  const removeBtn = document.getElementById("removeFileBtn");

  if (fileInput && fileDisplay && nameSpan && removeBtn) {
    fileInput.addEventListener("change", (e) => {
      if (e.target.files.length > 0) {
        nameSpan.textContent = e.target.files[0].name;
        fileDisplay.classList.remove("hidden");
      } else {
        fileDisplay.classList.add("hidden");
      }
    });

    removeBtn.addEventListener("click", (e) => {
      e.preventDefault();
      fileInput.value = "";
      fileDisplay.classList.add("hidden");
      nameSpan.textContent = "";
    });

    nameSpan.addEventListener("click", (e) => {
      if (fileInput.files.length > 0) {
        e.preventDefault();
        e.stopPropagation();
        const objUrl = URL.createObjectURL(fileInput.files[0]);
        window.open(objUrl, "_blank");
      }
    });
  }

  // Compliance Ring Hover
  const arcs = {
    arcGap: "Gap Identified",
    arcPartial: "Partially Implemented",
    arcCompliant: "Compliant"
  };

  const scoreLabel = document.getElementById("scoreValue");
  const scoreUnit = document.querySelector(".score-ring__unit");
  let originalScore = "";

  Object.entries(arcs).forEach(([id, label]) => {
    const el = document.getElementById(id);
    if (!el) return;

    el.addEventListener("mouseenter", () => {
      originalScore = scoreLabel.textContent;
      scoreLabel.textContent = label;
      scoreLabel.style.fontSize = "14px";
      scoreLabel.style.fontWeight = "600";
      if (scoreUnit) scoreUnit.style.display = "none";
    });

    el.addEventListener("mouseleave", () => {
      scoreLabel.textContent = originalScore;
      scoreLabel.style.fontSize = "";
      scoreLabel.style.fontWeight = "";
      if (scoreUnit) scoreUnit.style.display = "inline";
    });
  });
});
