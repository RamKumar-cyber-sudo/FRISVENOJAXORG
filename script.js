
"use strict";

const $ = id => document.getElementById(id);

const API_BASE = ""; // Set your deployed backend URL here if hosted separately.

let latestScan = null;
let scanHistory = [];

const toast = message => {
  const el = $("toast");
  if (!el) {
    console.log(message);
    return;
  }

  el.textContent = message;
  el.classList.add("show");

  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => {
    el.classList.remove("show");
  }, 3200);
};

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  const contentType = response.headers.get("content-type") || "";

  const result = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    throw new Error(
      typeof result === "object" && result.error
        ? result.error
        : `Request failed (${response.status})`
    );
  }

  return result;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function showText(id, value) {
  const element = $(id);
  if (element) element.textContent = value;
}

function downloadText(filename, content, type = "text/plain") {
  const blob = new Blob([content], { type: `${type};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderScanResult(result) {
  latestScan = result;

  showText(
    "fileDetails",
    `Scanned: ${result.filename} · ${formatBytes(result.size_bytes)} · ` +
    `Risk: ${result.risk_level} (${result.risk_score}/100)`
  );

  showText(
    "hashOutput",
    `SHA-256\n${result.sha256}\n\n` +
    `Assessment ID: ${result.scan_id}\n` +
    `Risk level: ${result.risk_level}\n` +
    `Risk score: ${result.risk_score}/100\n\n` +
    `Findings:\n${result.findings.map(item => "• " + item).join("\n")}\n\n` +
    `Note: Preliminary pattern checks only. This is not verified CVE analysis.`
  );

  renderHistoryItem(result);
}

function renderHistoryItem(scan) {
  const container = $("scanHistory");
  if (!container) return;

  const item = document.createElement("div");
  item.className = "scan-history-item";

  const heading = document.createElement("strong");
  heading.textContent = `#${scan.id ?? scan.scan_id} — ${scan.filename}`;

  const details = document.createElement("p");
  details.textContent =
    `Risk: ${scan.risk_level} (${scan.risk_score}/100) · ` +
    `${scan.created_at || new Date().toISOString()}`;

  item.append(heading, details);
  container.prepend(item);
}

async function loadScanHistory() {
  try {
    const results = await apiRequest("/api/scans");
    scanHistory = Array.isArray(results) ? results : [];

    const container = $("scanHistory");
    if (!container) return;

    container.replaceChildren();

    if (scanHistory.length === 0) {
      container.textContent = "No completed scans yet.";
      return;
    }

    scanHistory.forEach(scan => {
      const item = document.createElement("div");
      item.className = "scan-history-item";

      const heading = document.createElement("strong");
      heading.textContent = `#${scan.id} — ${scan.filename}`;

      const details = document.createElement("p");
      details.textContent =
        `Risk: ${scan.risk_level} (${scan.risk_score}/100) · ` +
        `${scan.created_at}`;

      const reportButton = document.createElement("button");
      reportButton.type = "button";
      reportButton.textContent = "Download report";
      reportButton.addEventListener("click", () => {
        window.location.href =
          `${API_BASE}/api/reports/${encodeURIComponent(scan.id)}`;
      });

      item.append(heading, details, reportButton);
      container.appendChild(item);
    });
  } catch (error) {
    console.warn("Could not load scan history:", error.message);
  }
}

// Sidebar navigation
document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach(item => {
      item.classList.remove("active");
    });

    link.classList.add("active");

    const label = link.textContent.trim().replace(/\s+\d+$/, "");
    showText("pageName", label);
  });
});

// Dismiss demo banner
const dismissBanner = $("dismissBanner");
if (dismissBanner) {
  dismissBanner.addEventListener("click", () => {
    const banner = document.querySelector(".demo-banner");
    if (banner) banner.style.display = "none";
  });
}

// Firmware selection
const firmwareInput = $("firmwareFile");

if (firmwareInput) {
  firmwareInput.addEventListener("change", event => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;

    showText(
      "fileDetails",
      `Selected: ${file.name} · ${formatBytes(file.size)} · Not scanned yet.`
    );

    toast("File selected. Start assessment to upload it to the backend.");
  });
}

// Real backend assessment
const startButton = $("startAssessment");

if (startButton) {
  startButton.addEventListener("click", async () => {
    const file = firmwareInput?.files?.[0];

    if (!file) {
      toast("Choose a firmware file first.");
      firmwareInput?.focus();
      return;
    }

    const originalText = startButton.textContent;

    startButton.disabled = true;
    startButton.textContent = "Scanning...";

    showText("fileDetails", `Uploading ${file.name}...`);

    try {
      const formData = new FormData();
      formData.append("firmware", file);

      const result = await apiRequest("/api/scan", {
        method: "POST",
        body: formData
      });

      renderScanResult(result);
      toast(`Assessment #${result.scan_id} completed.`);
      await loadScanHistory();
    } catch (error) {
      showText(
        "fileDetails",
        "Could not scan the file. Check the backend URL and server status."
      );

      toast(error.message || "Backend connection failed.");
    } finally {
      startButton.disabled = false;
      startButton.textContent = originalText;
    }
  });
}

// Generate a demo hash only when no real scan is available
async function demoHash() {
  const output = $("hashOutput");
  if (!output) return;

  if (latestScan?.sha256) {
    output.textContent =
      `SHA-256 of uploaded firmware\n${latestScan.sha256}\n\n` +
      "This hash identifies the uploaded file. It does not prove the file is safe.";
    toast("Showing the latest firmware hash.");
    return;
  }

  const label = "FRIS demo audit record v1 | no firmware data";

  try {
    if (!crypto.subtle) {
      throw new Error("Secure browser context required.");
    }

    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(label)
    );

    const hash = [...new Uint8Array(digest)]
      .map(n => n.toString(16).padStart(2, "0"))
      .join("");

    output.textContent =
      `SHA-256 · DEMO LABEL ONLY\n${hash}\n\n` +
      "No firmware was hashed and no blockchain transaction was made.";

    toast("Demo hash generated locally.");
  } catch {
    output.textContent =
      "Hash API unavailable. Open the site over HTTPS and try again.";
  }
}

const generateHashButton = $("generateHash");
if (generateHashButton) {
  generateHashButton.addEventListener("click", demoHash);
}

// Download the latest real report, or a clearly labelled demo report
const downloadButton = $("downloadReport");

if (downloadButton) {
  downloadButton.addEventListener("click", async () => {
    if (latestScan?.scan_id) {
      window.location.href =
        `${API_BASE}/api/reports/${encodeURIComponent(latestScan.scan_id)}`;
      return;
    }

    const report = {
      project: "FRIS — Firmware Risk Intelligence System",
      status: "Frontend demonstration only",
      sample_data: true,
      message: "No firmware was scanned; this is not a real assessment.",
      planned_features: [
        "Firmware component identification",
        "Verified vulnerability database matching",
        "AI-assisted analysis",
        "Blockchain audit verification"
      ]
    };

    downloadText(
      "FRIS-demo-report.json",
      JSON.stringify(report, null, 2),
      "application/json"
    );

    toast("Demo report downloaded; it contains no scan results.");
  });
}

const exportButton = $("exportBtn");
if (exportButton && downloadButton) {
  exportButton.addEventListener("click", () => downloadButton.click());
}

const notifyButton = $("notifyBtn");
if (notifyButton) {
  notifyButton.addEventListener("click", () => {
    toast("Notifications are not connected to a live notification service yet.");
  });
}

const testNotification = $("testNotification");
if (testNotification) {
  testNotification.addEventListener("click", () => {
    toast("FRIS workspace is ready to explore.");
  });
}

// Motion preference
const motionToggle = $("motionToggle");
if (motionToggle) {
  motionToggle.addEventListener("change", event => {
    document.body.classList.toggle(
      "reduce-motion",
      event.target.checked
    );

    toast(
      event.target.checked
        ? "Decorative motion disabled."
        : "Decorative motion enabled."
    );
  });
}

// Dashboard period selector
const periodSelect = $("periodSelect");
if (periodSelect) {
  periodSelect.addEventListener("change", event => {
    toast(
      `${event.target.value} selected. ` +
      "Historical dashboard charts may still contain sample data."
    );
  });
}

// Search table rows
const searchInput = $("searchInput");
if (searchInput) {
  searchInput.addEventListener("input", event => {
    const query = event.target.value.trim().toLowerCase();

    document.querySelectorAll(".component-panel tbody tr").forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(query)
        ? ""
        : "none";
    });
  });
}

// Keyboard shortcut: Ctrl+K / Cmd+K
document.addEventListener("keydown", event => {
  if (
    (event.metaKey || event.ctrlKey) &&
    event.key.toLowerCase() === "k"
  ) {
    event.preventDefault();
    searchInput?.focus();
  }
});

// Check backend and load history when the page opens
async function initializeFRIS() {
  try {
    const health = await apiRequest("/api/health");
    console.info("FRIS backend status:", health);
    await loadScanHistory();
  } catch (error) {
    console.info(
      "FRIS backend is not connected yet:",
      error.message
    );
  }
}

initializeFRIS();
