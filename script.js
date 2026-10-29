const $ = id => document.getElementById(id);
const toast = message => {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
};

document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach(item => item.classList.remove("active"));
    link.classList.add("active");
    const label = link.textContent.trim().replace(/\s+\d+$/, "");
    $("pageName").textContent = label;
  });
});

$("dismissBanner").addEventListener("click", () => {
  document.querySelector(".demo-banner").style.display = "none";
});

$("firmwareFile").addEventListener("change", event => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  $("fileDetails").textContent =
    `Selected: ${file.name} · ${(file.size / 1024).toFixed(2)} KB · Local browser only; file contents have not been scanned.`;
  toast("File selected for the FRIS workflow preview.");
});

$("startAssessment").addEventListener("click", () => {
  const file = $("firmwareFile").files[0];
  if (!file) {
    toast("Choose a firmware file first to preview the workflow.");
    $("firmwareFile").focus();
    return;
  }
  toast("Demo workflow prepared. Real extraction and vulnerability scanning require a backend.");
});

async function demoHash() {
  const output = $("hashOutput");
  const label = "FRIS demo audit record v1 | no firmware data";
  try {
    if (!crypto.subtle) throw new Error("secure context required");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(label));
    const hash = [...new Uint8Array(digest)].map(n => n.toString(16).padStart(2, "0")).join("");
    output.textContent = "SHA-256 · DEMO LABEL ONLY\n" + hash;
    toast("Demo hash generated locally. No blockchain transaction was made.");
  } catch (e) {
    output.textContent = "Hash API unavailable in this context. Open the deployed HTTPS website and try again.";
  }
}
$("generateHash").addEventListener("click", demoHash);

$("downloadReport").addEventListener("click", () => {
  const text = [
    "FRIS — Firmware Risk Intelligence System",
    "Sample Assessment Summary",
    "Status: Frontend demonstration only",
    "",
    "Sample metrics (not scan results):",
    "Assets tracked: 120",
    "Total findings: 1,284",
    "Critical findings: 24",
    "",
    "Proposed workflow:",
    "1. Upload firmware for controlled analysis.",
    "2. Extract and identify software components and versions.",
    "3. Match verified components against trusted vulnerability data such as the NVD.",
    "4. Prioritize findings and prepare an assessment report.",
    "5. Hash selected audit artifacts for later integrity verification.",
    "",
    "Planned AI agent roles: Vulnerability Agent, Threat Intelligence Agent, Verification Agent.",
    "Blockchain: Not connected in this prototype.",
    "Important: No firmware was scanned; all dashboard metrics are illustrative sample data."
  ].join("\n");
  const blob = new Blob([text], {type: "text/plain;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "FRIS-demo-assessment.txt";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("Sample FRIS report downloaded.");
});

$("exportBtn").addEventListener("click", () => {
  $("downloadReport").click();
});
$("notifyBtn").addEventListener("click", () => toast("You’re all caught up. Notifications are sample data."));
$("testNotification").addEventListener("click", () => toast("FRIS demo notification: workspace is ready to explore."));
$("motionToggle").addEventListener("change", event => {
  document.body.classList.toggle("reduce-motion", event.target.checked);
  toast(event.target.checked ? "Decorative motion disabled." : "Decorative motion enabled.");
});
$("periodSelect").addEventListener("change", event => {
  toast(`${event.target.value} selected. Metrics remain sample data in this prototype.`);
});

$("searchInput").addEventListener("input", event => {
  const query = event.target.value.trim().toLowerCase();
  document.querySelectorAll(".component-panel tbody tr").forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(query) ? "" : "none";
  });
});
document.addEventListener("keydown", event => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    $("searchInput").focus();
  }
});
