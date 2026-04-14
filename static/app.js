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

// Badge labels paired with each progress step
const BADGE_LABELS = [
  "Analyzing",
  "Retrieving",
  "Validating",
  "Checking",
  "Finalizing",
];

function startLoadingContent(quoteEl, progressEl, intervalMs = 3200) {
  const quoteOrder = shuffleArray(LOADING_QUOTES);
  let tick = 0;

  const badgeEl = document.getElementById("loadingBadge");

  // Set initial state immediately (no wait)
  const applyTick = () => {
    const stepIdx  = tick % PROGRESS_STEPS.length;
    const badgeIdx = tick % BADGE_LABELS.length;
    const quoteIdx = tick % quoteOrder.length;

    // Fade everything out together
    if (progressEl) progressEl.style.opacity = "0";
    if (quoteEl)    quoteEl.style.opacity    = "0";
    if (badgeEl)    badgeEl.style.opacity    = "0";

    setTimeout(() => {
      if (progressEl) progressEl.textContent = PROGRESS_STEPS[stepIdx];
      if (quoteEl)    quoteEl.textContent    = quoteOrder[quoteIdx];
      if (badgeEl)    badgeEl.textContent    = BADGE_LABELS[badgeIdx] + "…";

      // Fade everything back in together
      if (progressEl) progressEl.style.opacity = "1";
      if (quoteEl)    quoteEl.style.opacity    = "1";
      if (badgeEl)    badgeEl.style.opacity    = "1";
    }, 300);

    tick++;
  };

  applyTick(); // fire immediately on show
  const handle = window.setInterval(applyTick, intervalMs);
  return { handle };
}

function stopLoadingContent(ids) {
  if (ids && ids.handle != null) window.clearInterval(ids.handle);
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
  const dateStr = new Date().toLocaleDateString(undefined, {
    year: "numeric", month: "long", day: "numeric",
  });

  // ── Use jsPDF directly (bundled inside html2pdf.bundle.min.js) ──
  // This avoids html2canvas entirely — no DOM rendering issues.
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: "mm", format: "a4", orientation: "portrait" });

  const pageW = doc.internal.pageSize.getWidth();   // 210
  const pageH = doc.internal.pageSize.getHeight();   // 297
  const marginL = 20;
  const marginR = 20;
  const contentW = pageW - marginL - marginR;        // 170
  let y = 20; // current vertical cursor

  // ── Helpers ──
  function checkPage(needed) {
    if (y + needed > pageH - 25) {
      doc.addPage();
      y = 20;
      return true;
    }
    return false;
  }

  function wrapText(text, maxWidth, fontSize) {
    doc.setFontSize(fontSize);
    return doc.splitTextToSize(text || "", maxWidth);
  }

  // ── Colors ──
  const COLORS = {
    primary:  [99, 102, 241],   // #6366F1
    black:    [17, 24, 39],     // #111827
    dark:     [55, 65, 81],     // #374151
    muted:    [107, 114, 128],  // #6B7280
    light:    [148, 163, 184],  // #94A3B8
    ok:       [5, 150, 105],    // #059669
    warn:     [217, 119, 6],    // #D97706
    bad:      [220, 38, 38],    // #DC2626
    bgLight:  [248, 250, 252],  // #F8FAFC
    border:   [226, 232, 240],  // #E2E8F0
  };

  function setColor(c) { doc.setTextColor(c[0], c[1], c[2]); }
  function setDrawColor(c) { doc.setDrawColor(c[0], c[1], c[2]); }
  function setFillColor(c) { doc.setFillColor(c[0], c[1], c[2]); }

  // ══════════════════════════════════════════════════
  // PAGE 1: HEADER
  // ══════════════════════════════════════════════════

  // Title
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  setColor(COLORS.black);
  doc.text("Security Compliance Report", marginL, y);
  y += 8;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  setColor(COLORS.muted);
  doc.text("Policy-Grounded Gap Assessment", marginL, y);

  // Right-aligned date & confidential
  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  setColor(COLORS.dark);
  doc.text("CONFIDENTIAL", pageW - marginR, y - 8, { align: "right" });
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  setColor(COLORS.muted);
  doc.text(dateStr, pageW - marginR, y, { align: "right" });
  y += 4;

  // Header divider line
  setDrawColor(COLORS.primary);
  doc.setLineWidth(0.6);
  doc.line(marginL, y, pageW - marginR, y);
  y += 12;

  // ══════════════════════════════════════════════════
  // EXECUTIVE SUMMARY BOX
  // ══════════════════════════════════════════════════

  const sumBoxH = 42;
  setFillColor(COLORS.bgLight);
  setDrawColor(COLORS.border);
  doc.setLineWidth(0.3);
  doc.roundedRect(marginL, y, contentW, sumBoxH, 3, 3, "FD");

  // Score
  const scoreX = marginL + 30;
  doc.setFont("helvetica", "bold");
  doc.setFontSize(36);
  setColor(COLORS.primary);
  doc.text(`${summary.compliance_score}%`, scoreX, y + 22, { align: "center" });

  doc.setFontSize(8);
  setColor(COLORS.muted);
  doc.text("COMPLIANCE SCORE", scoreX, y + 28, { align: "center" });

  // Vertical divider
  setDrawColor(COLORS.border);
  doc.line(marginL + 60, y + 6, marginL + 60, y + sumBoxH - 6);

  // Breakdown
  const bx = marginL + 70;
  let by = y + 12;

  doc.setFontSize(10);
  doc.setFont("helvetica", "bold");
  setColor(COLORS.dark);
  doc.text("Assessment Breakdown", bx, by);
  by += 8;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);

  // Compliant
  setFillColor(COLORS.ok);
  doc.circle(bx + 2, by - 1.2, 1.5, "F");
  setColor(COLORS.dark);
  doc.text(`Compliant`, bx + 7, by);
  doc.text(`${summary.compliant} / 7`, bx + contentW - 80, by);
  by += 7;

  // Partial
  setFillColor(COLORS.warn);
  doc.circle(bx + 2, by - 1.2, 1.5, "F");
  setColor(COLORS.dark);
  doc.text(`Partially Implemented`, bx + 7, by);
  doc.text(`${summary.partially_implemented} / 7`, bx + contentW - 80, by);
  by += 7;

  // Gap
  setFillColor(COLORS.bad);
  doc.circle(bx + 2, by - 1.2, 1.5, "F");
  setColor(COLORS.dark);
  doc.text(`Gap Identified`, bx + 7, by);
  doc.text(`${summary.gap_identified} / 7`, bx + contentW - 80, by);

  y += sumBoxH + 14;

  // ══════════════════════════════════════════════════
  // DETAILED FINDINGS HEADER
  // ══════════════════════════════════════════════════

  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  setColor(COLORS.black);
  doc.text("Detailed Findings", marginL, y);
  y += 3;
  setDrawColor(COLORS.border);
  doc.setLineWidth(0.2);
  doc.line(marginL, y, pageW - marginR, y);
  y += 8;

  // ══════════════════════════════════════════════════
  // EACH CONTROL AREA
  // ══════════════════════════════════════════════════

  for (let i = 0; i < CONTROL_AREAS.length; i++) {
    const area = CONTROL_AREAS[i];
    const data = results[area];
    if (!data) continue;

    // Pre-calculate wrapped text to estimate card height
    const summaryLines = wrapText(data.summary || "No summary provided.", contentW - 10, 10);
    const gapLines = (data.status !== "Compliant")
      ? wrapText(data.gap_detail || "No specific gaps recorded.", contentW - 10, 10)
      : [];
    const policyText = Array.isArray(data.policy_reference)
      ? data.policy_reference.join("\n")
      : (data.policy_reference || "No policy references found.");
    const policyLines = wrapText(policyText, contentW - 16, 9);

    const cardH = 18                           // header + status row
      + (summaryLines.length * 4.5) + 10       // summary section
      + (gapLines.length > 0 ? (gapLines.length * 4.5) + 10 : 0)
      + (policyLines.length * 3.8) + 14        // policy section
      + 6;                                     // padding bottom

    checkPage(Math.min(cardH, 80)); // Make sure at least the header fits

    // ── Card border ──
    const statusColor = data.status === "Compliant" ? COLORS.ok
      : data.status === "Partially Implemented" ? COLORS.warn : COLORS.bad;

    setDrawColor(COLORS.border);
    doc.setLineWidth(0.2);
    // Left accent bar
    setFillColor(statusColor);
    doc.rect(marginL, y, 1.5, Math.min(cardH, pageH - y - 25), "F");

    // ── Area title & status badge ──
    const cardLeft = marginL + 5;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    setColor(COLORS.black);
    doc.text(`${i + 1}. ${area}`, cardLeft, y + 5);

    // Status badge (right-aligned)
    const badgeText = data.status.toUpperCase();
    doc.setFontSize(8);
    const badgeW = doc.getTextWidth(badgeText) + 8;
    const badgeX = pageW - marginR - badgeW;
    setFillColor(statusColor);
    doc.roundedRect(badgeX, y + 0.5, badgeW, 6, 1.5, 1.5, "F");
    doc.setTextColor(255, 255, 255);
    doc.text(badgeText, badgeX + 4, y + 4.5);

    y += 10;

    // Thin divider under header
    setDrawColor(COLORS.border);
    doc.line(cardLeft, y, pageW - marginR, y);
    y += 5;

    // ── SUMMARY section ──
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    setColor(COLORS.muted);
    doc.text("SUMMARY", cardLeft, y);
    y += 4;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    setColor(COLORS.dark);
    for (const line of summaryLines) {
      checkPage(6);
      doc.text(line, cardLeft, y);
      y += 4.5;
    }
    y += 3;

    // ── GAP DETAIL section (non-compliant only) ──
    if (gapLines.length > 0) {
      checkPage(10);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      setColor(COLORS.muted);
      doc.text("GAP ANALYSIS DETAIL", cardLeft, y);
      y += 4;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      setColor(COLORS.dark);
      for (const line of gapLines) {
        checkPage(6);
        doc.text(line, cardLeft, y);
        y += 4.5;
      }
      y += 3;
    }

    // ── POLICY REFERENCE section ──
    checkPage(12);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    setColor(COLORS.muted);
    doc.text("POLICY EVIDENCE & REFERENCES", cardLeft, y);
    y += 4;

    // Policy box background
    const policyBoxH = (policyLines.length * 3.8) + 6;
    checkPage(policyBoxH + 4);
    setFillColor(COLORS.bgLight);
    setDrawColor(COLORS.border);
    doc.setLineWidth(0.15);
    doc.roundedRect(cardLeft, y - 1, contentW - 5, policyBoxH, 1.5, 1.5, "FD");

    doc.setFont("courier", "normal");
    doc.setFontSize(9);
    setColor(COLORS.dark);
    let py = y + 3;
    for (const line of policyLines) {
      checkPage(5);
      doc.text(line, cardLeft + 3, py);
      py += 3.8;
    }
    y = py + 4;

    // Bottom spacing between cards
    y += 6;

    // Separator between cards (not after the last)
    if (i < CONTROL_AREAS.length - 1) {
      checkPage(4);
      setDrawColor(COLORS.border);
      doc.setLineWidth(0.1);
      doc.line(marginL, y, pageW - marginR, y);
      y += 8;
    }
  }

  // ══════════════════════════════════════════════════
  // FOOTER
  // ══════════════════════════════════════════════════

  checkPage(20);
  y += 6;
  setDrawColor(COLORS.border);
  doc.setLineWidth(0.2);
  doc.line(marginL, y, pageW - marginR, y);
  y += 6;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  setColor(COLORS.light);
  doc.text(
    `This report was automatically generated on ${dateStr} by the Security Gap Analyzer.`,
    pageW / 2, y, { align: "center" }
  );
  y += 4;
  doc.text(
    `© ${new Date().getFullYear()} Security Compliance Labs — Proprietary & Confidential`,
    pageW / 2, y, { align: "center" }
  );

  // ── Page numbers on every page ──
  const totalPages = doc.internal.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text(`Page ${p} of ${totalPages}`, pageW / 2, pageH - 10, { align: "center" });
  }

  // ── Save ──
  doc.save(`Security_Gap_Report_${new Date().toISOString().slice(0, 10)}.pdf`);
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
