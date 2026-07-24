const cDemoArtifactGroups = [
  ["source_files", "source files"],
  ["c_code_context", "static C context"],
  ["stage_01_intent", "01 intent facts"],
  ["stage_02_functions", "02 function facts"],
  ["stage_03_state", "03 state facts"],
  ["stage_04_environment", "04 environment facts"],
  ["stage_05_crypto", "05 crypto facts"],
  ["stage_06_messages", "06 message facts"],
  ["stage_07_checks_events", "07 checks/events"],
  ["stage_08_lifecycle", "08 lifecycle facts"],
  ["stage_09_claims", "09 claim facts"],
  ["stage_10_protocol_ir", "10 ProtocolIR output"],
  ["protocol_ir", "ProtocolIR"],
  ["reviewed_ir", "reviewed IR"],
  ["validation", "IR validation"],
  ["proof_context", "proof context"],
  ["review_decisions", "review decisions"],
  ["modeling_contract_json", "contract JSON"],
  ["modeling_contract_reviewed_json", "reviewed contract JSON"],
  ["modeling_contract_reviewed_md", "reviewed contract MD"],
  ["initial_model", "initial model"],
  ["repaired_model_1", "repaired model 1"],
  ["repaired_model_2", "repaired model 2"],
  ["repaired_model_3", "repaired model 3"],
  ["msr_model", "final MSR model"],
  ["compile_initial", "compile result"],
  ["repair_loop", "repair loop"],
  ["proof_lint", "proof lint"],
  ["lemma_coverage", "lemma coverage"],
  ["proof_spec", "proof spec"],
  ["proof_result", "proof result"],
  ["proof_result_repaired", "repaired proof result"],
  ["summary", "summary"],
];

document.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("cFileInput");
  if (fileInput) fileInput.addEventListener("change", previewCFile);
  document.addEventListener("click", (event) => {
    const button = event.target && event.target.closest ? event.target.closest("[data-c-artifact-key]") : null;
    if (!button) return;
    loadCArtifact(button.dataset.cArtifactKey);
  });
  hydrateCCodeDemoInput();
});

async function hydrateCCodeDemoInput() {
  const { response, data } = await cDemoApiJson("/api/c_code_demo");
  if (!response.ok) {
    setCSourceSummary(data.error || "Failed to load C-code artifacts.");
    return;
  }
  const summary = data.source_summary || {};
  const files = Array.isArray(data.source_files) ? data.source_files : [];
  setCSourceSummary(
    [
      files.length ? `Recorded source: ${files.join(", ")}` : "No recorded source file metadata.",
      summary.line_count ? `${summary.line_count} lines` : "",
      summary.function_count ? `${summary.function_count} detected functions` : "",
      summary.crypto_call_count ? `${summary.crypto_call_count} crypto-related calls` : "",
    ].filter(Boolean).join(" · ")
  );
  renderCArtifactButtons(data.artifacts || []);
}

function renderCArtifactButtons(artifacts) {
  const root = document.getElementById("cArtifactButtons");
  if (!root) return;
  const byKey = Object.fromEntries(artifacts.map((item) => [item.key, item]));
  root.innerHTML = cDemoArtifactGroups.map(([key, label]) => {
    const artifact = byKey[key] || {};
    const size = artifact.bytes ? ` · ${formatCBytes(artifact.bytes)}` : "";
    return `<button data-c-artifact-key="${escapeCHtml(key)}" ${artifact.exists ? "" : "disabled"}>${escapeCHtml(label)}${escapeCHtml(size)}</button>`;
  }).join("");
}

async function previewCFile(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  setCSourceSummary(`Selected source file: ${file.name} · ${file.size} bytes. Loaded artifacts below use the current C-to-IR run directory.`);
}

async function loadCArtifact(key) {
  const viewer = document.getElementById("cArtifactViewer");
  if (!viewer) return;
  viewer.textContent = `Loading ${key}...`;
  const { response, data } = await cDemoApiJson(`/api/c_code_demo/artifact?key=${encodeURIComponent(key)}`);
  if (!response.ok) {
    viewer.textContent = data.error || `Failed to load ${key}.`;
    return;
  }
  viewer.textContent = data.content || "";
}

function setCSourceSummary(message) {
  const root = document.getElementById("cSourceSummary");
  if (root) root.textContent = message || "";
}

async function cDemoApiJson(url, options = {}) {
  const response = await fetch(url, options);
  let data = {};
  try {
    data = await response.json();
  } catch (_) {
    data = {};
  }
  return { response, data };
}

function escapeCHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatCBytes(value) {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
