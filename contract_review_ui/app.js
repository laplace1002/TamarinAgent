const state = {
  original: null,
  contract: null,
  sourcePath: "",
  reviewedPath: "",
  pendingPatch: null,
  workflow: null,
  workflowLibrary: null,
  abstractionHintsInitialized: false,
};

const sectionGroups = [
  {
    title: "Start",
    items: [
      ["nl_input", "NL Input"],
    ],
  },
  {
    title: "Review",
    items: [
      ["fresh", "Fresh Values"],
      ["setup", "Setup State"],
      ["messages", "Messages"],
      ["checks", "Checks"],
      ["events", "Events"],
      ["proof_targets", "Proof Targets"],
      ["attack_surface", "Attack Surface"],
    ],
  },
  {
    title: "Generate",
    items: [
      ["sapic", "Sapic+"],
      ["tamarin", "Tamarin"],
    ],
  },
];

const sections = sectionGroups.flatMap((group) => group.items);
const workflowNavSteps = [
  { id: "nl_input", label: "NL", section: "nl_input", done: (exists) => exists.case },
  { id: "sapic_generation", label: "Sapic+", section: "sapic", done: (exists) => exists.sapic },
  { id: "verify", label: "Verify", section: "tamarin", done: (exists) => exists.repair_verify || exists.verify },
  { id: "tamarin_prove", label: "Prove", section: "tamarin", done: (exists) => exists.proof },
];
const messageUserFields = ["label", "step", "from", "to", "protection", "term", "meaning"];
const messageVisibleReviewFields = ["label", "from", "to", "protection", "term", "meaning"];
const messageDerivedFields = ["sender_knows", "receiver_can_decrypt", "receiver_must_treat_as_opaque", "checks", "events_after"];
const messageDerivedMetadataFields = ["derived_fields_signature"];
const messageProtectionOptions = [
  ["plain", "Public / visible"],
  ["asymmetric-encryption", "Encrypted to receiver"],
  ["symmetric-encryption", "Encrypted with shared key"],
  ["signing", "Signed"],
  ["mac", "MAC / keyed tag"],
  ["hashing", "Hash / commitment"],
  ["unknown", "Not sure"],
];
const reviewFieldsBySection = {
  fresh: ["name", "owner", "purpose"],
  setup: ["name", "owner", "public_term", "policy"],
  messages: messageVisibleReviewFields,
  checks: ["role", "condition", "source_message", "action"],
  events: ["name", "role", "when", "arguments"],
  proof_targets: ["name", "goal_type", "trace_kind", "expected_state", "required_events"],
  expected_attack_surface: ["target", "policy"],
};
const reviewVisibleSections = new Set([
  "fresh",
  "setup",
  "messages",
  "checks",
  "events",
  "proof_targets",
  "attack_surface",
  "expected_attack_surface",
]);
const reviewNavSections = ["fresh", "setup", "messages", "checks", "events", "proof_targets", "attack_surface"];
const reviewHiddenMessageFragments = [
  ".sender_knows",
  ".receiver_can_decrypt",
  ".receiver_must_treat_as_opaque",
  ".checks",
  ".events_after",
  ".derived_fields_signature",
  ".derived_fields_status",
];

document.addEventListener("DOMContentLoaded", () => {
  buildNav();
  bindGlobalActions();
  bindReviewEditInvalidation();
  loadContract({ clearTransient: true });
});

function buildNav() {
  const nav = document.getElementById("sectionNav");
  nav.innerHTML = sectionGroups.map((group) => `
    <div class="nav-group">
      <div class="nav-group-title">${escapeHtml(group.title)}</div>
      <div class="nav-group-items">
        ${group.items.map(([id, label]) => `
          <button data-nav-section="${escapeHtml(id)}">
            <span class="nav-label">${escapeHtml(label)}</span>
            <span class="nav-status" hidden></span>
            <small class="nav-review-count" hidden></small>
          </button>
        `).join("")}
      </div>
    </div>
  `).join("");
  nav.querySelectorAll("[data-nav-section]").forEach((button, index) => {
    if (index === 0) button.classList.add("active");
    button.addEventListener("click", () => {
      const section = button.dataset.navSection;
      scrollToSection(section);
      if (section === "tamarin" && workflowHasTamarinResult(state.workflow) && tamarinResultIsEmpty()) {
        loadExistingTamarinResult({ quiet: true });
      }
    });
  });
}

function scrollToSection(id) {
  const target = document.querySelector(`[data-section="${cssEscape(id)}"]`);
  if (!target) return;
  target.scrollIntoView({ behavior: "smooth", block: "start" });
  setActiveNav(id);
}

function setActiveNav(id) {
  const nav = document.getElementById("sectionNav");
  if (!nav) return;
  nav.querySelectorAll("[data-nav-section]").forEach((button) => {
    button.classList.toggle("active", button.dataset.navSection === id);
  });
}

function bindGlobalActions() {
  document.getElementById("workflowBtn").addEventListener("click", loadWorkflow);
  document.getElementById("reloadBtn").addEventListener("click", () => loadContract({ clearTransient: true }));
  document.getElementById("saveBtn").addEventListener("click", saveReviewed);
  document.getElementById("loadWorkflowLibraryBtn").addEventListener("click", loadWorkflowLibrary);
  document.getElementById("importWorkflowBtn").addEventListener("click", importWorkflow);
  document.getElementById("workflowLibrarySelect").addEventListener("change", updateActionState);
  document.getElementById("startFromNlBtn").addEventListener("click", startFromNl);
  document.getElementById("proposePatchBtn").addEventListener("click", proposePatch);
  document.getElementById("applyPatchBtn").addEventListener("click", applyPendingPatch);
  document.getElementById("generateSapicBtn").addEventListener("click", generateSapic);
  document.getElementById("abstractionHintsToggle").addEventListener("change", updateActionState);
  document.getElementById("repairVerifyBtn").addEventListener("click", repairVerifySapic);
  document.getElementById("proveBtn").addEventListener("click", proveSapic);
  document.querySelectorAll("[data-add-row]").forEach((button) => {
    button.addEventListener("click", () => addRow(button.dataset.addRow));
  });
  document.querySelectorAll("[data-add-attack-surface]").forEach((button) => {
    button.addEventListener("click", addAttackSurfaceItem);
  });
}

function bindReviewEditInvalidation() {
  document.addEventListener("focusin", (event) => {
    const input = event.target && event.target.closest ? event.target.closest("[data-bind]") : null;
    if (!input) return;
    input.dataset.beforeEditValue = String(input.value ?? "");
  });
  document.addEventListener("change", (event) => maybeInvalidateEditedField(event.target));
  document.addEventListener("change", (event) => applyProtectionShortcut(event.target));
  document.addEventListener("blur", (event) => maybeInvalidateEditedField(event.target), true);
}

function maybeInvalidateEditedField(target) {
  const input = target && target.closest ? target.closest("[data-bind]") : null;
  if (!input || !state.contract) return;
  const before = input.dataset.beforeEditValue;
  if (before == null) {
    input.dataset.beforeEditValue = String(input.value ?? "");
    return;
  }
  const after = String(input.value ?? "");
  if (before === after) return;
  input.dataset.beforeEditValue = after;
  invalidateDependentFieldReviews(input.dataset.bind, { render: false, referenceValue: before });
  syncAllInputs();
  invalidateDependentFieldReviews(input.dataset.bind, { render: false, referenceValue: after });
  renderAll();
}

async function loadContract(options = {}) {
  if (options.clearTransient) {
    clearTransientOutputs();
  }
  setStatus("Loading contract...");
  const { response, data } = await apiJson("/api/contract");
  if (!response.ok) {
    setStatus(data.error || "Failed to load contract", true);
    await loadWorkflow({ quiet: true });
    await loadWorkflowLibrary({ quiet: true });
    renderAll();
    return;
  }
  const contract = isNonEmptyObject(data.contract) ? data.contract : null;
  state.original = contract ? deepClone(contract) : null;
  state.contract = contract ? deepClone(contract) : null;
  state.sourcePath = data.source_path || "";
  state.reviewedPath = data.reviewed_path || "";
  state.pendingPatch = null;
  document.getElementById("runDir").textContent = "";
  hydrateNlInput(data.case_input);
  await loadWorkflow({ quiet: true });
  await loadWorkflowLibrary({ quiet: true });
  renderAll();
  const renderedTamarin = renderExistingTamarinResult(data.tamarin_result);
  setStatus(
    contract
      ? renderedTamarin ? "Contract loaded with existing Tamarin results." : "Contract loaded."
      : "No contract yet. Start from Natural Language Input.",
    false,
    true,
  );
}

function renderExistingTamarinResult(result) {
  if (!result || typeof result !== "object") return false;
  const data = result.data && typeof result.data === "object" ? result.data : null;
  if (!data) return false;
  renderTamarinSummary(result.kind || "compile", data, true);
  return true;
}

async function loadExistingTamarinResult(options = {}) {
  const quiet = Boolean(options.quiet);
  const { response, data } = await apiJson("/api/contract");
  if (!response.ok) {
    if (!quiet) setStatus(data.error || "Failed to load Tamarin result", true);
    return false;
  }
  return renderExistingTamarinResult(data.tamarin_result);
}

function workflowHasTamarinResult(workflow) {
  const exists = workflow && workflow.exists ? workflow.exists : {};
  return Boolean(exists.proof || exists.repair_verify || exists.verify);
}

function tamarinResultIsEmpty() {
  const root = document.getElementById("tamarinResult");
  return !root || !String(root.textContent || "").trim();
}

async function loadWorkflowLibrary(options = {}) {
  const quiet = Boolean(options.quiet);
  if (!quiet) setStatus("Loading prepared workflow library...");
  const { response, data } = await apiJson("/api/workflow_library");
  if (!response.ok) {
    state.workflowLibrary = {
      error: data.error || "Failed to load workflow library",
      cases: [],
    };
    renderWorkflowLibrary();
    updateActionState();
    if (!quiet) setStatus(data.error || "Failed to load workflow library", true);
    return;
  }
  state.workflowLibrary = data;
  renderWorkflowLibrary();
  updateActionState();
  if (!quiet) setStatus(`Loaded ${data.case_count || 0} prepared workflow(s).`, false, true);
}

async function importWorkflow() {
  const select = document.getElementById("workflowLibrarySelect");
  const caseId = select ? select.value : "";
  if (!caseId) {
    setStatus("Select a prepared workflow first.", true);
    return;
  }
  setBusy(["importWorkflowBtn"], true);
  setStatus("Importing prepared workflow...");
  const { response, data } = await apiJson("/api/import_workflow", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_id: caseId }),
  });
  setBusy(["importWorkflowBtn"], false);
  if (!response.ok) {
    setStatus(data.error || "Workflow import failed", true);
    return;
  }
  state.original = deepClone(data.contract);
  state.contract = deepClone(data.contract);
  state.sourcePath = data.workflow && data.workflow.artifacts ? data.workflow.artifacts.reviewed_contract || "" : "";
  state.reviewedPath = state.sourcePath;
  state.workflow = data.workflow || state.workflow;
  state.pendingPatch = null;
  hydrateNlInput(data.case_input);
  clearTransientOutputs();
  renderAll();
  setStatus(`Imported ${data.case}.`, false, true);
}

async function saveReviewed() {
  if (!state.contract) {
    setStatus("No contract to save. Generate IR / Contract first.", true);
    return;
  }
  syncAllInputs();
  setStatus("Saving reviewed contract...");
  const { response, data } = await apiJson("/api/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contract: state.contract }),
  });
  if (!response.ok) {
    setStatus(data.error || "Save failed", true);
    return;
  }
  state.contract = data.contract;
  state.reviewedPath = data.json_path || state.reviewedPath;
  await loadWorkflow({ quiet: true });
  renderAll();
  setStatus("Reviewed contract saved.", false, true);
}

async function proposePatch() {
  if (!state.contract) {
    setStatus("Generate a contract before requesting a revision.", true);
    return;
  }
  syncAllInputs();
  const instruction = document.getElementById("patchInstruction").value.trim();
  const section = document.getElementById("patchSection").value;
  if (!instruction) {
    setStatus("Enter a natural-language instruction first.", true);
    return;
  }
  setStatus("Requesting local patch proposal...");
  document.getElementById("applyPatchBtn").disabled = true;
  const { response, data } = await apiJson("/api/propose_patch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contract: state.contract, instruction, section }),
  });
  if (!response.ok) {
    setStatus(formatPatchFailure(data), true);
    document.getElementById("patchSummary").textContent = JSON.stringify(data, null, 2);
    return;
  }
  state.pendingPatch = data;
  document.getElementById("patchSummary").textContent = JSON.stringify(data, null, 2);
  const ok = data.validation && data.validation.ok && Array.isArray(data.patches) && data.patches.length > 0;
  document.getElementById("applyPatchBtn").disabled = !ok;
  setStatus(ok ? "Patch proposal ready for review." : "Patch proposal has no applicable changes or validation issues.", !ok);
}

async function applyPendingPatch() {
  if (!state.contract) {
    setStatus("No contract to patch.", true);
    return;
  }
  if (!state.pendingPatch || !Array.isArray(state.pendingPatch.patches)) {
    setStatus("No pending patch to apply.", true);
    return;
  }
  setStatus("Applying patch...");
  const { response, data } = await apiJson("/api/apply_patch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contract: state.contract, patches: state.pendingPatch.patches }),
  });
  if (!response.ok) {
    setStatus(data.error || "Patch apply failed", true);
    document.getElementById("patchSummary").textContent = JSON.stringify(data, null, 2);
    return;
  }
  state.contract = data.contract;
  state.pendingPatch = null;
  document.getElementById("applyPatchBtn").disabled = true;
  renderAll();
  setStatus("Patch applied locally. Save reviewed contract when ready.", false, true);
}

async function startFromNl() {
  const payload = {
    name: document.getElementById("nlName").value.trim(),
    difficulty: document.getElementById("nlDifficulty").value,
    description: document.getElementById("nlDescription").value.trim(),
    assumptions: document.getElementById("nlAssumptions").value,
    goals: document.getElementById("nlGoals").value,
  };
  if (!payload.description) {
    setStatus("Natural-language description is required.", true);
    return;
  }
  setBusy(["startFromNlBtn"], true);
  setStatus("Generating IR and modeling contract from natural language...");
  const { response, data } = await apiJson("/api/start_from_nl", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  setBusy(["startFromNlBtn"], false);
  if (!response.ok) {
    setStatus(formatNlFailure(data), true);
    renderSapicSummary({
      ok: false,
      title: "Contract generation failed",
      message: data.error || "The natural-language workflow stopped before producing a contract.",
      details: compactFailureDetails(data),
    });
    await loadWorkflow({ quiet: true });
    renderAll();
    return;
  }
  state.original = deepClone(data.contract);
  state.contract = deepClone(data.contract);
  state.sourcePath = data.contract_path || "";
  state.reviewedPath = "";
  state.pendingPatch = null;
  state.workflow = data.workflow || state.workflow;
  clearTransientOutputs();
  renderSapicSummary({
    ok: true,
    title: "Contract ready",
    message: "IR and modeling contract are ready for review.",
    details: {
      case: data.case || "Protocol",
      ir: data.ir_bundle && data.ir_bundle.validation && data.ir_bundle.validation.ok ? "valid" : "needs attention",
      errors: data.ir_bundle && data.ir_bundle.validation ? data.ir_bundle.validation.errors || [] : [],
    },
  });
  renderAll();
  setStatus("IR and modeling contract are ready for review.", false, true);
}

async function generateSapic() {
  if (!state.contract) {
    setStatus("No contract is available.", true);
    return;
  }
  syncAllInputs();
  setBusy(["generateSapicBtn"], true);
  const useAbstractionHints = abstractionHintsEnabled();
  setStatus(useAbstractionHints ? "Generating Sapic+ with abstraction hints..." : "Generating Sapic+ from the current contract...");
  const { response, data } = await apiJson("/api/generate_sapic", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contract: state.contract, abstraction_hints: useAbstractionHints }),
  });
  setBusy(["generateSapicBtn"], false);
  state.workflow = data.workflow || state.workflow;
  if (!response.ok) {
    renderSapicSummary({
      ok: false,
      title: "Sapic+ generation failed",
      message: data.error || "The model was not generated.",
      details: compactFailureDetails(data),
    });
    renderAll();
    setStatus(formatSapicFailure(data), true);
    return;
  }
  renderSapicSummary({
    ok: true,
    title: "Sapic+ generated",
    message: "Compile check is running automatically.",
    details: {
      warnings: data.lint_issues || [],
      model: "final/model.spthy",
      abstraction_hints: data.abstraction_hints_enabled ? "enabled" : "disabled",
      retrieved_hints: abstractionHintCount(data.abstraction_hints),
    },
  });
  renderAll();
  setStatus("Sapic+ generated. Running compile check...", false, true);
  await compileSapic({ auto: true });
}

async function compileSapic(options = {}) {
  const busyIds = options.auto ? ["generateSapicBtn"] : [];
  setBusy(busyIds, true);
  if (!options.quiet) setStatus("Running Tamarin compile check...");
  syncAllInputs();
  const { response, data } = await apiJson("/api/compile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contract: state.contract || null }),
  });
  setBusy(busyIds, false);
  state.workflow = data.workflow || state.workflow;
  renderTamarinSummary("compile", data, response.ok);
  renderAll();
  setStatus(response.ok && data.ok ? "Tamarin compile check completed." : data.error || "Tamarin compile check failed.", !(response.ok && data.ok), response.ok && data.ok);
}

async function repairVerifySapic() {
  setBusy(["repairVerifyBtn"], true);
  const useAbstractionHints = abstractionHintsEnabled();
  setStatus(useAbstractionHints ? "Running repair & verify loop with abstraction hints..." : "Running repair & verify loop...");
  syncAllInputs();
  const { response, data } = await apiJson("/api/repair_verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contract: state.contract || null, abstraction_hints: useAbstractionHints }),
  });
  setBusy(["repairVerifyBtn"], false);
  state.workflow = data.workflow || state.workflow;
  renderTamarinSummary("repair", data, response.ok);
  renderAll();
  const ok = response.ok && data.ok;
  setStatus(ok ? "Repair & verify loop reached a clean compile." : data.error || "Repair & verify loop stopped before a clean compile.", !ok, ok);
}

async function proveSapic() {
  setBusy(["proveBtn"], true);
  setStatus("Running Tamarin proof...");
  syncAllInputs();
  const { response, data } = await apiJson("/api/prove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contract: state.contract || null }),
  });
  setBusy(["proveBtn"], false);
  state.workflow = data.workflow || state.workflow;
  renderTamarinSummary("proof", data, response.ok);
  renderAll();
  setStatus(response.ok && data.ok ? "Tamarin proof completed." : data.error || "Tamarin proof failed or mismatched expectations.", !(response.ok && data.ok), response.ok && data.ok);
}

async function loadWorkflow(options = {}) {
  const quiet = Boolean(options.quiet);
  if (!quiet) setStatus("Refreshing workflow status...");
  const { response, data } = await apiJson("/api/workflow");
  if (!response.ok) {
    if (!quiet) setStatus(data.error || "Workflow refresh failed", true);
    return;
  }
  state.workflow = data;
  renderWorkflow();
  updateActionState();
  if (workflowHasTamarinResult(data) && tamarinResultIsEmpty()) {
    await loadExistingTamarinResult({ quiet: true });
  }
  if (!quiet) setStatus("Workflow status refreshed.", false, true);
}

function renderAll() {
  renderWorkflow();
  renderHeader();
  syncAbstractionHintToggle();
  updateActionState();
  if (!state.contract) {
    renderEmptyContract();
    return;
  }
  updateReviewNavigation(sortedFieldReviews());
  renderFresh();
  renderSetup();
  renderMessages();
  renderChecks();
  renderEvents();
  renderProofTargets();
  renderAttackSurface();
  renderRaw();
}

function renderHeader() {
  if (!state.contract) {
    document.getElementById("caseName").textContent = "New workflow";
    return;
  }
  const caseInfo = state.contract.case || {};
  document.getElementById("caseName").textContent = caseInfo.name || "Protocol";
}

function renderEmptyContract() {
  ["freshTable", "setupTable", "checksTable", "eventsTable", "proofTargetsTable"].forEach((id) => {
    document.getElementById(id).innerHTML = `<div class="muted">No contract loaded.</div>`;
  });
  document.getElementById("messagesList").innerHTML = `<div class="muted">No contract loaded.</div>`;
  document.getElementById("attackSurfaceList").innerHTML = `<div class="muted">No contract loaded.</div>`;
  document.getElementById("originalJson").textContent = "";
  document.getElementById("currentJson").textContent = "";
}

function renderFresh() {
  renderEditableTable("freshTable", state.contract.fresh || [], [
    ["name", "Name"],
    ["owner", "Owner"],
    ["purpose", "Purpose"],
  ], "fresh");
}

function renderSetup() {
  renderEditableTable("setupTable", state.contract.setup || [], [
    ["name", "Name"],
    ["owner", "Owner"],
    ["public_term", "Public Term"],
    ["policy", "Policy"],
  ], "setup");
}

function renderChecks() {
  renderEditableTable("checksTable", state.contract.checks || [], [
    ["role", "Role"],
    ["condition", "Condition"],
    ["source_message", "Source Message"],
    ["action", "Action"],
  ], "checks");
}

function renderEvents() {
  renderEditableTable("eventsTable", state.contract.events || [], [
    ["name", "Name"],
    ["role", "Role"],
    ["when", "When"],
    ["arguments", "Arguments"],
  ], "events");
}

function renderProofTargets() {
  renderEditableTable("proofTargetsTable", state.contract.proof_targets || [], [
    ["name", "Name"],
    ["goal_type", "Goal Type"],
    ["trace_kind", "Trace Kind"],
    ["expected_state", "Expected State"],
    ["required_events", "Required Events"],
  ], "proof_targets");
}

function renderAttackSurface() {
  const root = document.getElementById("attackSurfaceList");
  const items = Array.isArray(state.contract.expected_attack_surface) ? state.contract.expected_attack_surface : [];
  if (!items.length) {
    root.innerHTML = `<div class="muted">No expected attack surface recorded.</div>`;
    return;
  }
  root.innerHTML = items.map((item, index) => `
    <div class="attack-row" data-attack-surface-row="${index}">
      <div class="attack-editor">
        ${attackSurfaceFields(item, index)}
      </div>
      <button class="icon-btn" data-delete-attack-surface="${index}" title="Delete">x</button>
    </div>
  `).join("");
  root.querySelectorAll("[data-delete-attack-surface]").forEach((button) => {
    button.addEventListener("click", () => deleteAttackSurfaceItem(Number(button.dataset.deleteAttackSurface)));
  });
  bindFieldReviewActions(root);
}

function attackSurfaceFields(item, index) {
  if (item && typeof item === "object" && !Array.isArray(item)) {
    return `
      <div class="attack-fields">
        ${inputHtml(`expected_attack_surface.${index}.target`, "Target", item.target || "")}
        ${textareaHtml(`expected_attack_surface.${index}.policy`, "Policy", item.policy || "", 3)}
        ${Object.entries(item)
          .filter(([key]) => !["target", "policy"].includes(key))
          .map(([key, value]) => textareaHtml(`expected_attack_surface.${index}.${key}`, titleCase(key), formatEditableValue(value), 2))
          .join("")}
      </div>
    `;
  }
  return textareaHtml(`expected_attack_surface.${index}`, "Policy", formatEditableValue(item), 3);
}

function renderMessages() {
  const root = document.getElementById("messagesList");
  const messages = state.contract.messages || [];
  if (!messages.length) {
    root.innerHTML = `<div class="muted">No messages recorded.</div>`;
    return;
  }
  root.innerHTML = messages.map((message, index) => `
    <div class="message-card" data-message-index="${index}">
      <div class="message-head">
        ${inputHtml(`messages.${index}.label`, "Label", message.label)}
        ${inputHtml(`messages.${index}.from`, "From", message.from)}
        ${inputHtml(`messages.${index}.to`, "To", message.to)}
        ${messageProtectionHtml(`messages.${index}.protection`, "Protection", message.protection || "plain")}
      </div>
      ${textareaHtml(`messages.${index}.term`, "Term", message.term, 2)}
      ${textareaHtml(`messages.${index}.meaning`, "Meaning", message.meaning, 2)}
    </div>
  `).join("");
  bindFieldReviewActions(root);
}

function renderOpenQuestions() {
  const root = document.getElementById("openQuestionsList");
  if (!root) return;
  const questions = state.contract.open_questions || [];
  if (!questions.length) {
    root.innerHTML = `<div class="muted">No open questions.</div>`;
    return;
  }
  root.innerHTML = questions.map((item, index) => {
    if (typeof item === "string") {
      return `
        <div class="question-card">
          <div class="question-head">
            <strong>question_${index}</strong>
            ${reviewStatusSelect(`open_questions.${index}.review_status`, "needs_review")}
          </div>
          <p>${escapeHtml(item)}</p>
          ${proposalBlock("", "", "", [])}
          ${textareaHtml(`open_questions.${index}.answer`, "Answer", "", 3)}
          ${textareaHtml(`open_questions.${index}.resolution`, "Resolution / modeling decision", "", 2)}
        </div>
      `;
    }
    const signals = Array.isArray(item.signals) ? item.signals : [];
    const riskNotes = Array.isArray(item.proposal_risk_notes) ? item.proposal_risk_notes : [];
    const status = item.review_status || "needs_review";
    const accepted = status === "accepted";
    return `
      <div class="question-card">
        <div class="question-head">
          <strong>${escapeHtml(item.id || `question_${index}`)}</strong>
          <div class="question-status">
            ${item.severity ? `<span class="badge ${escapeHtml(String(item.severity).toLowerCase())}">${escapeHtml(item.severity)}</span>` : ""}
            ${reviewStatusSelect(`open_questions.${index}.review_status`, status)}
          </div>
        </div>
        <p>${escapeHtml(item.question || item.answer || JSON.stringify(item))}</p>
        ${item.why ? `<p class="muted">${escapeHtml(item.why)}</p>` : ""}
        ${signals.length ? `<div class="chips">${signals.map((signal) => `<span class="chip">${escapeHtml(signal)}</span>`).join("")}</div>` : ""}
        ${item.default_if_unanswered ? `<p class="muted"><strong>Default:</strong> ${escapeHtml(item.default_if_unanswered)}</p>` : ""}
        ${proposalBlock(item.proposed_answer || "", item.proposed_resolution || "", item.proposal_confidence || "", riskNotes)}
        <div class="button-row compact">
          <button data-accept-open-question="${index}" ${accepted ? "disabled" : ""}>${accepted ? "Accepted" : "Accept Proposed"}</button>
          <button data-mark-open-question-edited="${index}">Mark Edited</button>
        </div>
        ${textareaHtml(`open_questions.${index}.answer`, "Answer", item.answer || "", 3)}
        ${textareaHtml(`open_questions.${index}.resolution`, "Resolution / modeling decision", item.resolution || "", 2)}
      </div>
    `;
  }).join("");
  root.querySelectorAll("[data-accept-open-question]").forEach((button) => {
    button.addEventListener("click", () => acceptOpenQuestionProposal(Number(button.dataset.acceptOpenQuestion)));
  });
  root.querySelectorAll("[data-mark-open-question-edited]").forEach((button) => {
    button.addEventListener("click", () => markOpenQuestionEdited(Number(button.dataset.markOpenQuestionEdited)));
  });
}

function reviewStatusSelect(bind, value) {
  return selectHtml(bind, value || "needs_review", [
    "needs_review",
    "accepted",
    "edited",
    "rejected",
  ]);
}

function proposalBlock(answer, resolution, confidence, riskNotes) {
  const hasProposal = answer || resolution || confidence || riskNotes.length;
  if (!hasProposal) {
    return `<div class="proposal empty">No LLM proposal yet.</div>`;
  }
  return `
    <div class="proposal">
      <div class="proposal-head">
        <strong>LLM Proposed Resolution</strong>
        ${confidence ? `<span class="chip">confidence: ${escapeHtml(confidence)}</span>` : ""}
      </div>
      ${answer ? `<label>Proposed answer</label><p>${escapeHtml(answer)}</p>` : ""}
      ${resolution ? `<label>Proposed modeling decision</label><p>${escapeHtml(resolution)}</p>` : ""}
      ${riskNotes.length ? `<label>Risk notes</label><ul>${riskNotes.map((note) => `<li>${escapeHtml(note)}</li>`).join("")}</ul>` : ""}
    </div>
  `;
}

function renderRaw() {
  document.getElementById("originalJson").textContent = JSON.stringify(state.original, null, 2);
  document.getElementById("currentJson").textContent = JSON.stringify(state.contract, null, 2);
}

function renderEditableTable(rootId, rows, columns, section, options = {}) {
  const root = document.getElementById(rootId);
  if (!Array.isArray(rows)) rows = [];
  const allowDelete = options.allowDelete !== false;
  root.innerHTML = `
    <div class="table-wrap">
      <table data-section-table="${section}">
        <thead>
          <tr>${columns.map(([, label]) => `<th>${escapeHtml(label)}</th>`).join("")}${allowDelete ? "<th></th>" : ""}</tr>
        </thead>
        <tbody>
          ${rows.map((row, rowIndex) => `
            <tr data-row="${rowIndex}">
              ${columns.map(([key]) => `<td>${cellInput(section, rowIndex, key, row ? row[key] : "")}</td>`).join("")}
              ${allowDelete ? `<td class="ops"><button class="icon-btn" data-delete-row="${section}:${rowIndex}" title="Delete">x</button></td>` : ""}
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
  root.querySelectorAll("[data-delete-row]").forEach((button) => {
    button.addEventListener("click", () => {
      const [targetSection, rawIndex] = button.dataset.deleteRow.split(":");
      deleteRow(targetSection, Number(rawIndex));
    });
  });
  bindFieldReviewActions(root);
}

function cellInput(section, rowIndex, key, value) {
  const normalized = formatEditableValue(value);
  const attr = `${section}.${rowIndex}.${key}`;
  if (section === "proof_targets" && key === "expected_state") {
    return fieldReviewWrapper(attr, selectHtml(attr, String(normalized || "ProvedSatisfying"), [
      "ProvedSatisfying",
      "CounterexampleFound",
      "MissingProofResult",
      "ProofTimeout",
      "Unknown",
    ]));
  }
  if (section === "proof_targets" && key === "trace_kind") {
    return fieldReviewWrapper(attr, selectHtml(attr, String(normalized || "all-traces"), [
      "all-traces",
      "exists-trace",
      "unknown",
    ]));
  }
  if (section === "proof_targets" && key === "goal_type") {
    return fieldReviewWrapper(attr, selectHtml(attr, String(normalized), [
      "",
      "secrecy",
      "authentication",
      "reachability",
      "executability",
      "property",
      "source",
    ]));
  }
  const multiline = String(normalized).length > 80 || ["policy", "intent", "preservation_policy", "condition", "required_events"].includes(key);
  if (multiline) {
    return fieldReviewWrapper(attr, `<textarea rows="2" data-bind="${escapeHtml(attr)}">${escapeHtml(String(normalized))}</textarea>`);
  }
  return fieldReviewWrapper(attr, `<input data-bind="${escapeHtml(attr)}" value="${escapeHtml(String(normalized))}">`);
}

function inputHtml(bind, label, value) {
  return fieldEditorHtml(bind, label, `<input data-bind="${escapeHtml(bind)}" value="${escapeHtml(value ?? "")}">`);
}

function messageProtectionHtml(bind, label, value) {
  const displayValue = messageProtectionDisplayValue(value);
  return fieldEditorHtml(bind, label, `
    <div class="protection-picker">
      <select data-protection-shortcut="${escapeHtml(bind)}">
        <option value="">Choose preset...</option>
        ${messageProtectionOptions.map(([optionValue, optionLabel]) => `<option value="${escapeHtml(optionValue)}">${escapeHtml(optionLabel)}</option>`).join("")}
      </select>
      <input data-bind="${escapeHtml(bind)}" value="${escapeHtml(displayValue)}">
    </div>
  `);
}

function textareaHtml(bind, label, value, rows) {
  return fieldEditorHtml(bind, label, `<textarea rows="${rows}" data-bind="${escapeHtml(bind)}">${escapeHtml(value ?? "")}</textarea>`);
}

function messageProtectionDisplayValue(value) {
  const text = String(value ?? "").trim();
  const option = messageProtectionOptions.find(([optionValue]) => optionValue === text);
  return option ? option[1] : text;
}

function normalizeMessageProtectionValue(value) {
  const text = String(value ?? "").trim();
  const normalized = text.toLowerCase();
  const option = messageProtectionOptions.find(([optionValue, optionLabel]) => (
    optionValue.toLowerCase() === normalized || optionLabel.toLowerCase() === normalized
  ));
  return option ? option[0] : text;
}

function applyProtectionShortcut(target) {
  const select = target && target.closest ? target.closest("[data-protection-shortcut]") : null;
  if (!select || !select.value) return;
  const bind = select.dataset.protectionShortcut;
  const input = document.querySelector(`[data-bind="${cssEscape(bind)}"]`);
  const label = messageProtectionDisplayValue(select.value);
  if (input) {
    input.dataset.beforeEditValue = String(input.value ?? "");
    input.value = label;
    maybeInvalidateEditedField(input);
  }
  select.value = "";
}

function fieldEditorHtml(bind, label, controlHtml) {
  const reviews = visibleFieldReviewItems(bind);
  const status = reviews.length ? reviewStatus(reviews[0]) : "";
  const reviewClass = reviews.length ? ` has-review review-status-${escapeHtml(status)}` : "";
  return `
    <div class="field-editor${reviewClass}" data-field-path="${escapeHtml(bind)}">
      <label>${escapeHtml(label)}</label>
      ${controlHtml}
      ${fieldReviewDetailsHtml(reviews)}
    </div>
  `;
}

function fieldReviewWrapper(bind, controlHtml) {
  const reviews = visibleFieldReviewItems(bind);
  if (!reviews.length) {
    return `<div data-field-path="${escapeHtml(bind)}">${controlHtml}</div>`;
  }
  const status = reviewStatus(reviews[0]);
  return `
    <div class="field-review-wrap has-review review-status-${escapeHtml(status)}" data-field-path="${escapeHtml(bind)}">
      ${controlHtml}
      ${fieldReviewDetailsHtml(reviews)}
    </div>
  `;
}

function fieldReviewItems(bind) {
  const path = String(bind || "");
  if (!state.contract || !Array.isArray(state.contract.field_reviews)) return [];
  return state.contract.field_reviews.filter((item) => String(item.field_path || "") === path);
}

function visibleFieldReviewItems(bind) {
  const path = String(bind || "");
  if (!isReviewFieldVisible(path)) return [];
  return fieldReviewItems(path);
}

function isReviewFieldVisible(fieldPath) {
  const path = String(fieldPath || "");
  const section = fieldPathSection(path);
  if (!reviewVisibleSections.has(section)) return false;
  if (section === "messages" && reviewHiddenMessageFragments.some((fragment) => path.includes(fragment))) return false;
  const field = path.split(".").slice(2).join(".");
  const visibleFields = reviewFieldsBySection[section];
  if (Array.isArray(visibleFields) && (!field || !visibleFields.includes(field))) return false;
  return true;
}

function sortedFieldReviews() {
  if (!state.contract || !Array.isArray(state.contract.field_reviews)) return [];
  return [...state.contract.field_reviews].sort((a, b) => {
    const pa = Number(a.priority_score || 0);
    const pb = Number(b.priority_score || 0);
    if (pb !== pa) return pb - pa;
    return String(a.field_path || "").localeCompare(String(b.field_path || ""));
  });
}

function reviewStatus(item) {
  return String((item && item.review_status) || "needs_review");
}

function isReviewComplete() {
  if (!state.contract || !Array.isArray(state.contract.field_reviews) || !state.contract.field_reviews.length) {
    return false;
  }
  return unresolvedReviewItems(state.contract.field_reviews).length === 0;
}

function reviewSectionStatus(section) {
  if (!state.contract || !Array.isArray(state.contract.field_reviews) || !state.contract.field_reviews.length) {
    return "pending";
  }
  const items = state.contract.field_reviews.filter((item) => navSectionOwnsField(section, item.field_path) && isReviewFieldVisible(item.field_path));
  if (!items.length) return "done";
  return unresolvedReviewItems(items).length ? "pending" : "done";
}

function unresolvedReviewItems(items) {
  return (Array.isArray(items) ? items : []).filter((item) => (
    ["must_review", "needs_review"].includes(reviewStatus(item)) && isReviewFieldVisible(item.field_path)
  ));
}

function priorityDetailText(item) {
  return scorePercentText(item.priority_score);
}

function reviewMetricText(item, keys) {
  for (const key of keys) {
    if (item[key] != null && item[key] !== "") {
      const scoreText = scorePercentText(item[key]);
      return scoreText === "-" ? "Error: invalid score" : scoreText;
    }
  }
  return "Error: missing score";
}

function scorePercentText(raw) {
  const score = normalizedReviewScore(raw);
  if (score == null) return "-";
  return `${Math.round(score * 100)}%`;
}

function normalizedReviewScore(raw) {
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return normalizeScoreNumber(raw);
  }
  const text = String(raw ?? "").trim().toLowerCase();
  if (!text) return null;
  if (text.endsWith("%")) {
    const percent = Number(text.slice(0, -1));
    return Number.isFinite(percent) ? normalizeScoreNumber(percent) : null;
  }
  const numeric = Number(text);
  if (Number.isFinite(numeric)) return normalizeScoreNumber(numeric);
  return null;
}

function normalizeScoreNumber(value) {
  const normalized = value > 1 ? value / 100 : value;
  return Math.max(0, Math.min(1, normalized));
}

function updateReviewNavigation(items) {
  const nav = document.getElementById("sectionNav");
  if (!nav) return;
  nav.querySelectorAll("[data-nav-section]").forEach((button) => {
    const section = button.dataset.navSection;
    const count = unresolvedReviewItems(items).filter((item) => navSectionOwnsField(section, item.field_path)).length;
    const badge = button.querySelector(".nav-review-count");
    if (!badge) return;
    badge.hidden = count === 0;
    badge.textContent = count ? String(count) : "";
  });
}

function navSectionOwnsField(section, fieldPath) {
  const owner = fieldPathSection(fieldPath);
  if (owner === "expected_attack_surface") return section === "attack_surface";
  return owner === section;
}

function fieldPathSection(fieldPath) {
  return String(fieldPath || "").split(".", 1)[0];
}

function reviewMetadataHtml(item) {
  return `
    <div class="review-metadata">
      <div><span>Priority</span><strong>${escapeHtml(priorityDetailText(item))}</strong></div>
      <div><span>Evidence</span><strong>${escapeHtml(reviewMetricText(item, ["evidence_confidence_score", "evidence_score"]))}</strong></div>
      <div><span>Consistency</span><strong>${escapeHtml(reviewMetricText(item, ["consistency_confidence_score", "consistency_score"]))}</strong></div>
      <div><span>Impact</span><strong>${escapeHtml(reviewMetricText(item, ["semantic_impact_score", "impact_score"]))}</strong></div>
    </div>
  `;
}

function fieldReviewDetailsHtml(reviews) {
  if (!reviews.length) return "";
  return reviews.map((item) => `
    <details class="field-review-details">
      <summary>Review details</summary>
      ${reviewMetadataHtml(item)}
      ${diagnosticHtml(item)}
      ${evidenceHtml(item)}
      <div class="button-row compact">
        <button data-field-review-action="user_confirmed:${escapeHtml(item.field_path || "")}">Confirm</button>
        <button data-field-review-action="system_assumption:${escapeHtml(item.field_path || "")}">Assumed</button>
      </div>
    </details>
  `).join("");
}

function diagnosticHtml(item) {
  const diagnostics = Array.isArray(item.diagnostics) ? item.diagnostics : [];
  const suggested = item.suggested_action || "";
  if (!diagnostics.length && !suggested) return "";
  return `
    <div class="diagnostics">
      ${diagnostics.map((text) => `<div>${escapeHtml(text)}</div>`).join("")}
      ${suggested ? `<div><strong>Action:</strong> ${escapeHtml(suggested)}</div>` : ""}
    </div>
  `;
}

function evidenceHtml(item) {
  const evidence = Array.isArray(item.source_evidence) ? item.source_evidence : [];
  if (!evidence.length) return "";
  return `
    <div class="evidence-list">
      ${evidence.map((ev) => `
        <div class="evidence-item">
          <span>${escapeHtml(ev.kind || "evidence")}</span>
          ${ev.quote ? `<q>${escapeHtml(ev.quote)}</q>` : `<em>No direct source span</em>`}
        </div>
      `).join("")}
    </div>
  `;
}

function bindFieldReviewActions(root = document) {
  root.querySelectorAll("[data-field-review-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const [status, ...pathParts] = button.dataset.fieldReviewAction.split(":");
      updateFieldReviewStatus(pathParts.join(":"), status);
    });
  });
}

function formatEditableValue(value) {
  if (Array.isArray(value)) return value.join(", ");
  if (value && typeof value === "object") return JSON.stringify(value, null, 2);
  return value ?? "";
}

function titleCase(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function selectHtml(bind, value, options) {
  return `<select data-bind="${escapeHtml(bind)}">
    ${options.map((option) => `<option value="${escapeHtml(option)}" ${option === value ? "selected" : ""}>${escapeHtml(option || "-")}</option>`).join("")}
  </select>`;
}

function addRow(section) {
  if (!state.contract) {
    setStatus("Generate a contract before adding rows.", true);
    return;
  }
  syncAllInputs();
  if (!Array.isArray(state.contract[section])) state.contract[section] = [];
  const templates = {
    fresh: { name: "", owner: "", purpose: "" },
    setup: { name: "", owner: "", public_term: "", policy: "Treat as setup/state knowledge owned by the role; do not learn it from the adversarial network." },
    checks: { role: "", condition: "", source_message: "", action: "" },
    events: { name: "", role: "", when: "", arguments: [] },
    proof_targets: {
      name: "",
      goal_type: "",
      trace_kind: "all-traces",
      expected_state: "ProvedSatisfying",
      intent: "",
      required_events: [],
      preservation_policy: "",
    },
  };
  state.contract[section].push(deepClone(templates[section] || {}));
  renderAll();
}

function addAttackSurfaceItem() {
  if (!state.contract) {
    setStatus("Generate a contract before adding attack-surface notes.", true);
    return;
  }
  syncAllInputs();
  if (!Array.isArray(state.contract.expected_attack_surface)) {
    state.contract.expected_attack_surface = [];
  }
  state.contract.expected_attack_surface.push("");
  renderAll();
}

function deleteAttackSurfaceItem(index) {
  if (!state.contract) return;
  syncAllInputs();
  if (!Array.isArray(state.contract.expected_attack_surface)) return;
  state.contract.expected_attack_surface.splice(index, 1);
  renderAll();
}

function deleteRow(section, index) {
  if (!state.contract) return;
  syncAllInputs();
  if (!Array.isArray(state.contract[section])) return;
  state.contract[section].splice(index, 1);
  renderAll();
}

function updateFieldReviewStatus(fieldPath, status) {
  if (!state.contract || !Array.isArray(state.contract.field_reviews)) return;
  syncAllInputs();
  state.contract.field_reviews.forEach((item) => {
    if (String(item.field_path || "") === String(fieldPath || "")) {
      item.review_status = status;
      item.review_decision = status;
      item.reviewed_at = new Date().toISOString();
    }
  });
  renderAll();
  setStatus(`Marked ${fieldPath} as ${statusLabel(status)}. Save reviewed contract when ready.`, false, true);
}

function statusLabel(status) {
  const labels = {
    user_confirmed: "confirmed",
    system_assumption: "assumed",
    needs_review: "needs review",
    must_review: "must review",
    high_confidence: "high confidence",
  };
  return labels[status] || String(status || "").replace(/_/g, " ");
}

function scrollToField(fieldPath) {
  const selector = `[data-field-path="${cssEscape(fieldPath)}"]`;
  const element = document.querySelector(selector);
  if (!element) {
    setStatus(`Field ${fieldPath} is not visible in the current view.`, true);
    return;
  }
  element.scrollIntoView({ behavior: "smooth", block: "center" });
  element.classList.add("review-highlight");
  setTimeout(() => element.classList.remove("review-highlight"), 1800);
}

function reviewStatusCounts(items) {
  const statuses = ["must_review", "needs_review", "system_assumption", "user_confirmed", "high_confidence"];
  return statuses.reduce((acc, status) => {
    acc[status] = items.filter((item) => reviewStatus(item) === status).length;
    return acc;
  }, {});
}

function acceptOpenQuestionProposal(index) {
  if (!state.contract || !Array.isArray(state.contract.open_questions)) return;
  syncAllInputs();
  const question = state.contract.open_questions[index];
  if (!question || typeof question !== "object") return;
  question.answer = question.proposed_answer || question.answer || "";
  question.resolution = question.proposed_resolution || question.resolution || "";
  question.review_status = "accepted";
  renderAll();
  setStatus(`Accepted ${question.id || `open_question_${index + 1}`}`, false, true);
}

function markOpenQuestionEdited(index) {
  if (!state.contract || !Array.isArray(state.contract.open_questions)) return;
  syncAllInputs();
  const question = state.contract.open_questions[index];
  if (!question || typeof question !== "object") return;
  question.review_status = "edited";
  renderAll();
  setStatus(`Marked ${question.id || `open_question_${index + 1}`} as edited`, false, true);
}

function syncAllInputs() {
  if (!state.contract) return;
  normalizeStringOpenQuestions();
  const beforeMessages = Array.isArray(state.contract.messages) ? deepClone(state.contract.messages) : [];
  document.querySelectorAll("[data-bind]").forEach((input) => {
    setByPath(state.contract, input.dataset.bind.split("."), input.value);
  });
  invalidateDerivedMessageFields(beforeMessages);
}

function invalidateDerivedMessageFields(beforeMessages) {
  if (!Array.isArray(state.contract.messages)) return;
  const staleIndexes = [];
  state.contract.messages.forEach((message, index) => {
    if (!message || typeof message !== "object") return;
    const before = beforeMessages[index];
    const userChanged = !before || messageUserFields.some((field) => {
      return JSON.stringify(before[field] ?? "") !== JSON.stringify(message[field] ?? "");
    });
    if (!userChanged) return;
    [...messageDerivedFields, ...messageDerivedMetadataFields].forEach((field) => {
      delete message[field];
    });
    message.derived_fields_status = "stale_after_user_edit";
    staleIndexes.push(index);
    invalidateDependentFieldReviews(`messages.${index}.__row__`, { render: false });
  });
  removeStaleMessageFieldReviews(staleIndexes);
}

function invalidateDependentFieldReviews(changedPath, options = {}) {
  if (!state.contract || !Array.isArray(state.contract.field_reviews)) return;
  const changed = parseFieldPath(changedPath);
  if (!changed) return;
  const stalePaths = dependentFieldReviewPaths(changed);
  if (!stalePaths.size) return;
  const reason = `This field may be stale because ${changed.displayPath} changed.`;
  const now = new Date().toISOString();
  state.contract.field_reviews.forEach((item) => {
    if (!item || typeof item !== "object") return;
    const path = String(item.field_path || "");
    if (!stalePaths.has(path)) return;
    markReviewItemStale(item, reason, now);
  });
  if (options.render !== false) {
    renderAll();
  }
}

function markReviewItemStale(item, reason, timestamp) {
  item.review_status = "needs_review";
  item.review_decision = "stale_after_user_edit";
  item.stale_after_user_edit = true;
  item.stale_reason = reason;
  item.stale_at = timestamp;
  item.consistency_confidence = "low";
  item.consistency_confidence_score = 0;
  // Intentional UX override beyond the paper's priority formula: fields
  // invalidated by a user edit are floored at 0.7 so they are always re-reviewed.
  item.priority_score = Math.max(normalizedReviewScore(item.priority_score) ?? 0, 0.7);
  item.priority_level = "high";
  if (!item.priority_source || item.priority_source === "formula") {
    item.priority_source = "stale";
  }
  const diagnostics = Array.isArray(item.diagnostics) ? item.diagnostics : [];
  if (!diagnostics.includes(reason)) diagnostics.unshift(reason);
  item.diagnostics = diagnostics;
  item.suggested_action = "Re-check this field after the related edit, then edit or confirm it.";
}

function parseFieldPath(path) {
  const parts = String(path || "").split(".");
  if (parts.length < 3) return null;
  const section = parts[0];
  const rowIndex = Number(parts[1]);
  if (!Number.isInteger(rowIndex)) return null;
  return {
    section,
    rowIndex,
    field: parts.slice(2).join("."),
    displayPath: `${section}.${rowIndex}.${parts.slice(2).join(".")}`,
  };
}

function dependentFieldReviewPaths(changed) {
  const paths = new Set();
  const add = (section, index, field) => {
    if (index == null || index < 0 || !field) return;
    paths.add(`${section}.${index}.${field}`);
  };
  if (changed.section === "messages") {
    const fields = reviewFieldsBySection.messages || [];
    fields.forEach((field) => add("messages", changed.rowIndex, field));
    messageDerivedFields.forEach((field) => add("messages", changed.rowIndex, field));
    if (changed.field === "label") {
      addMessageLabelDependents(changed, paths);
    }
  } else if (changed.section === "checks") {
    (reviewFieldsBySection.checks || []).forEach((field) => add("checks", changed.rowIndex, field));
    addEventAndTargetDependentsForCheck(changed, paths);
  } else if (changed.section === "events") {
    (reviewFieldsBySection.events || []).forEach((field) => add("events", changed.rowIndex, field));
    addProofTargetDependentsForEvent(changed, paths);
  } else if (changed.section === "proof_targets") {
    (reviewFieldsBySection.proof_targets || []).forEach((field) => add("proof_targets", changed.rowIndex, field));
  } else if (changed.section === "fresh" || changed.section === "setup") {
    (reviewFieldsBySection[changed.section] || []).forEach((field) => add(changed.section, changed.rowIndex, field));
    addValueReferenceDependents(changed, paths);
  }
  return paths;
}

function addMessageLabelDependents(changed, paths) {
  const message = state.contract.messages && state.contract.messages[changed.rowIndex];
  const label = String(message && message.label || "").trim();
  if (!label) return;
  (state.contract.checks || []).forEach((check, index) => {
    if (String(check && check.source_message || "").trim() === label) {
      (reviewFieldsBySection.checks || []).forEach((field) => paths.add(`checks.${index}.${field}`));
    }
  });
  (state.contract.events || []).forEach((event, index) => {
    const text = JSON.stringify(event || {});
    if (text.includes(label)) {
      (reviewFieldsBySection.events || []).forEach((field) => paths.add(`events.${index}.${field}`));
    }
  });
  (state.contract.proof_targets || []).forEach((target, index) => {
    const text = JSON.stringify(target || {});
    if (text.includes(label)) {
      (reviewFieldsBySection.proof_targets || []).forEach((field) => paths.add(`proof_targets.${index}.${field}`));
    }
  });
}

function addEventAndTargetDependentsForCheck(changed, paths) {
  const check = state.contract.checks && state.contract.checks[changed.rowIndex];
  const source = String(check && check.source_message || "").trim();
  if (!source) return;
  (state.contract.events || []).forEach((event, index) => {
    if (JSON.stringify(event || {}).includes(source)) {
      (reviewFieldsBySection.events || []).forEach((field) => paths.add(`events.${index}.${field}`));
    }
  });
}

function addProofTargetDependentsForEvent(changed, paths) {
  const event = state.contract.events && state.contract.events[changed.rowIndex];
  const eventName = String(event && event.name || "").trim();
  if (!eventName) return;
  (state.contract.proof_targets || []).forEach((target, index) => {
    if (JSON.stringify(target || {}).includes(eventName)) {
      (reviewFieldsBySection.proof_targets || []).forEach((field) => paths.add(`proof_targets.${index}.${field}`));
    }
  });
}

function addValueReferenceDependents(changed, paths) {
  const rows = state.contract[changed.section] || [];
  const row = rows[changed.rowIndex];
  const value = String(row && row.name || "").trim();
  if (!value) return;
  for (const section of ["messages", "checks", "events", "proof_targets"]) {
    (state.contract[section] || []).forEach((rowItem, index) => {
      if (JSON.stringify(rowItem || {}).includes(value)) {
        (reviewFieldsBySection[section] || []).forEach((field) => paths.add(`${section}.${index}.${field}`));
      }
    });
  }
}

function removeStaleMessageFieldReviews(indexes) {
  if (!indexes.length || !Array.isArray(state.contract.field_reviews)) return;
  const stalePaths = new Set();
  indexes.forEach((index) => {
    messageDerivedFields.forEach((field) => {
      stalePaths.add(`messages.${index}.${field}`);
    });
  });
  state.contract.field_reviews = state.contract.field_reviews.filter((item) => {
    return !stalePaths.has(String(item && item.field_path || ""));
  });
}

function normalizeStringOpenQuestions() {
  if (!Array.isArray(state.contract.open_questions)) return;
  state.contract.open_questions = state.contract.open_questions.map((item, index) => {
    if (typeof item !== "string") return item;
    return {
      id: `question_${index}`,
      question: item,
      proposed_answer: "",
      proposed_resolution: "",
      answer: "",
      resolution: "",
      review_status: "needs_review",
      proposal_source: "legacy_string",
    };
  });
}

function setByPath(root, parts, value) {
  let current = root;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const raw = parts[i];
    const key = /^\d+$/.test(raw) ? Number(raw) : raw;
    if (current[key] == null) current[key] = {};
    current = current[key];
  }
  const lastRaw = parts[parts.length - 1];
  const last = /^\d+$/.test(lastRaw) ? Number(lastRaw) : lastRaw;
  const oldValue = current[last];
  if (parts[0] === "messages" && last === "protection") {
    current[last] = normalizeMessageProtectionValue(value);
  } else if (Array.isArray(oldValue)) {
    current[last] = splitTopLevelCsv(value);
  } else if (typeof oldValue === "boolean") {
    current[last] = ["true", "yes", "1"].includes(String(value).toLowerCase());
  } else {
    current[last] = value;
  }
}

function splitTopLevelCsv(value) {
  const text = String(value ?? "");
  const items = [];
  let current = "";
  let angleDepth = 0;
  let parenDepth = 0;
  let quote = "";
  for (const char of text) {
    if (quote) {
      current += char;
      if (char === quote) quote = "";
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      current += char;
      continue;
    }
    if (char === "<") {
      angleDepth += 1;
      current += char;
      continue;
    }
    if (char === ">") {
      angleDepth = Math.max(0, angleDepth - 1);
      current += char;
      continue;
    }
    if (char === "(") {
      parenDepth += 1;
      current += char;
      continue;
    }
    if (char === ")") {
      parenDepth = Math.max(0, parenDepth - 1);
      current += char;
      continue;
    }
    if (char === "," && angleDepth === 0 && parenDepth === 0) {
      const item = current.trim();
      if (item) items.push(item);
      current = "";
      continue;
    }
    current += char;
  }
  const tail = current.trim();
  if (tail) items.push(tail);
  return items;
}

function renderList(title, items) {
  if (!items || !items.length) return "";
  return `<div class="message-card"><strong>${escapeHtml(title)}</strong><div class="chips">${items.map((item) => `<span class="chip">${escapeHtml(item)}</span>`).join("")}</div></div>`;
}

function renderSapicSummary(result) {
  const root = document.getElementById("sapicResult");
  if (!root) return;
  const details = result.details || {};
  const warnings = Array.isArray(details.warnings) ? details.warnings : [];
  const errors = Array.isArray(details.errors) ? details.errors : [];
  root.innerHTML = `
    <div class="result-card ${result.ok ? "ok" : "error"}">
      <div class="result-head">
        <strong>${escapeHtml(result.title || "Sapic+ status")}</strong>
        <span class="result-pill">${escapeHtml(result.ok ? "OK" : "Needs attention")}</span>
      </div>
      ${result.message ? `<p>${escapeHtml(result.message)}</p>` : ""}
      <div class="result-grid">
        ${details.case ? resultMetric("Case", details.case) : ""}
        ${details.ir ? resultMetric("IR", details.ir) : ""}
        ${details.model ? resultMetric("Model artifact", details.model) : ""}
        ${details.abstraction_hints ? resultMetric("Abstraction hints", details.abstraction_hints) : ""}
        ${details.retrieved_hints !== undefined ? resultMetric("Retrieved hints", details.retrieved_hints) : ""}
        ${resultMetric("Warnings", warnings.length)}
        ${errors.length ? resultMetric("Errors", errors.length) : ""}
      </div>
      ${renderIssueList("Warnings", warnings)}
      ${renderIssueList("Errors", errors)}
      ${renderDetailRows(details)}
    </div>
  `;
}

function renderTamarinSummary(kind, data, responseOk) {
  const root = document.getElementById("tamarinResult");
  if (!root) return;
  const payload = data || {};
  const ok = Boolean(responseOk && payload.ok);
  const warnings = Array.isArray(payload.warnings) ? payload.warnings : [];
  const lintIssues = Array.isArray(payload.lint_issues) ? payload.lint_issues : [];
  const title = {
    compile: "Compile Check",
    repair: "Repair & Verify",
    proof: "Proof",
  }[kind] || "Tamarin Result";
  const processHtml = `
    ${payload.error ? `<p class="error-text">${escapeHtml(payload.error)}</p>` : ""}
    <div class="result-grid">
      ${resultMetric("Status", payload.status || (responseOk ? "completed" : "failed"))}
      ${resultMetric("Return code", payload.returncode ?? "-")}
      ${resultMetric("Warnings", warnings.length)}
      ${resultMetric("Lint issues", lintIssues.length)}
      ${payload.abstraction_hints_enabled !== undefined ? resultMetric("Abstraction hints", payload.abstraction_hints_enabled ? "enabled" : "disabled") : ""}
      ${payload.abstraction_hints ? resultMetric("Retrieved hints", abstractionHintCount(payload.abstraction_hints)) : ""}
      ${kind === "repair" ? resultMetric("Repair rounds", repairRoundText(payload)) : ""}
      ${kind === "proof" ? resultMetric("Lemma results", lemmaResultText(payload)) : ""}
    </div>
    ${renderIssueList("Warnings", warnings)}
    ${renderIssueList("Lint Issues", lintIssues)}
    ${kind === "repair" ? renderRepairAttempts(payload.attempts || []) : ""}
    ${kind === "proof" ? renderLemmaTable(payload) : ""}
    ${renderDiagnosticLog(payload)}
  `;
  root.innerHTML = `
    <div class="result-card ${ok ? "ok" : "error"}">
      <div class="result-head">
        <strong>${escapeHtml(title)}</strong>
        <span class="result-pill">${escapeHtml(ok ? "Passed" : "Needs attention")}</span>
      </div>
      ${renderResultTabs(`tamarin-result-${kind}`, processHtml, renderTamarinCodeArtifacts(payload))}
    </div>
  `;
  bindResultTabs(root);
}

function renderResultTabs(tabName, processHtml, codeHtml) {
  const processId = `${tabName}-process-panel`;
  const codeId = `${tabName}-code-panel`;
  return `
    <div class="result-tabs" data-result-tabs="${escapeHtml(tabName)}">
      <div class="result-tab-controls" role="tablist">
        <button type="button" class="result-tab-label active" data-result-tab="process" aria-controls="${escapeHtml(processId)}" aria-selected="true">Process</button>
        <button type="button" class="result-tab-label" data-result-tab="code" aria-controls="${escapeHtml(codeId)}" aria-selected="false">Tamarin Code</button>
      </div>
      <div id="${escapeHtml(processId)}" class="tab-panel process-panel active" data-result-panel="process">${processHtml}</div>
      <div id="${escapeHtml(codeId)}" class="tab-panel code-panel" data-result-panel="code" hidden>${codeHtml}</div>
    </div>
  `;
}

function bindResultTabs(root) {
  root.querySelectorAll("[data-result-tabs]").forEach((tabs) => {
    const buttons = Array.from(tabs.querySelectorAll("[data-result-tab]"));
    const panels = Array.from(tabs.querySelectorAll("[data-result-panel]"));
    buttons.forEach((button) => {
      button.addEventListener("click", () => {
        const target = button.dataset.resultTab;
        buttons.forEach((item) => {
          const selected = item === button;
          item.classList.toggle("active", selected);
          item.setAttribute("aria-selected", selected ? "true" : "false");
        });
        panels.forEach((panel) => {
          const selected = panel.dataset.resultPanel === target;
          panel.hidden = !selected;
          panel.classList.toggle("active", selected);
        });
      });
    });
  });
}

function renderTamarinCodeArtifacts(data) {
  const artifacts = normalizeModelArtifacts(data);
  if (!artifacts.length) {
    return `<p class="muted">No Tamarin model artifact is available yet.</p>`;
  }
  const successful = artifacts.filter((artifact) => artifact.ok === true || artifact.accepted === true);
  const finalArtifact = artifacts.find((artifact) => artifact.path === "final/model.spthy");
  const primary = successful.length ? successful : finalArtifact ? [finalArtifact] : [artifacts[0]];
  const primaryKeys = new Set(primary.map((artifact) => artifact.path || artifact.label || ""));
  const secondary = artifacts.filter((artifact) => !primaryKeys.has(artifact.path || artifact.label || ""));
  return `
    <div class="result-grid">
      ${resultMetric("Model artifacts", artifacts.length)}
      ${resultMetric(successful.length ? "Successful models" : "Current models", primary.length)}
    </div>
    <div class="result-section code-artifact-group">
      <h3>${escapeHtml(successful.length ? "Successful Tamarin Code" : "Current Tamarin Code")}</h3>
      ${primary.map((artifact, index) => renderCodeArtifact(artifact, { open: index === 0 })).join("")}
    </div>
    ${secondary.length ? `
      <div class="result-section code-artifact-group">
        <h3>Generated Candidates</h3>
        ${secondary.map((artifact) => renderCodeArtifact(artifact)).join("")}
      </div>
    ` : ""}
  `;
}

function normalizeModelArtifacts(data) {
  const rawArtifacts = Array.isArray(data.model_artifacts) ? data.model_artifacts : [];
  const artifacts = rawArtifacts
    .filter((artifact) => artifact && String(artifact.code || "").trim())
    .map((artifact) => ({
      label: String(artifact.label || artifact.path || "Tamarin model"),
      path: String(artifact.path || ""),
      code: String(artifact.code || ""),
      ok: artifact.ok,
      accepted: artifact.accepted,
      status: String(artifact.status || ""),
      warning_count: Number(artifact.warning_count || 0),
      lint_issue_count: Number(artifact.lint_issue_count || 0),
    }));
  if (!artifacts.length && String(data.sapic_plus || "").trim()) {
    artifacts.push({
      label: "Current model",
      path: String(data.model_path || "final/model.spthy"),
      code: String(data.sapic_plus || ""),
      ok: data.ok,
      accepted: data.ok,
      status: String(data.status || ""),
      warning_count: Array.isArray(data.warnings) ? data.warnings.length : 0,
      lint_issue_count: Array.isArray(data.lint_issues) ? data.lint_issues.length : 0,
    });
  }
  const seen = new Set();
  return artifacts.filter((artifact) => {
    const key = artifact.path || artifact.label;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderCodeArtifact(artifact, options = {}) {
  const openAttr = options.open ? " open" : "";
  const meta = [
    artifact.path,
    artifact.status ? `status: ${artifact.status}` : "",
    artifact.ok === true ? "tamarin ok" : artifact.ok === false ? "needs attention" : "",
    artifact.accepted === true ? "accepted/current" : "",
    artifact.warning_count ? `${artifact.warning_count} warning(s)` : "",
    artifact.lint_issue_count ? `${artifact.lint_issue_count} lint issue(s)` : "",
  ].filter(Boolean);
  return `
    <details class="result-section code-artifact"${openAttr}>
      <summary>
        <span>${escapeHtml(artifact.label)}</span>
        <span class="artifact-status">${escapeHtml(modelArtifactStatus(artifact))}</span>
      </summary>
      ${meta.length ? `<div class="artifact-meta">${meta.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>` : ""}
      <pre class="codebox tamarin-code">${escapeHtml(artifact.code)}</pre>
    </details>
  `;
}

function modelArtifactStatus(artifact) {
  if (artifact.path === "final/model.spthy") return artifact.ok === true ? "current / clean" : "current";
  if (artifact.accepted === true && artifact.ok === true) return "accepted / clean";
  if (artifact.accepted === true) return "accepted";
  if (artifact.ok === true) return "clean";
  if (artifact.ok === false) return "needs attention";
  return artifact.status || "generated";
}

function renderDiagnosticLog(data) {
  const stderr = String(data.stderr_tail || "").trim();
  const stdout = String(data.stdout_tail || "").trim();
  const parts = [];
  if (stderr) parts.push(`stderr\n${stderr}`);
  if (stdout) parts.push(`stdout\n${stdout}`);
  return renderOutputSnippet("Diagnostic log", parts.join("\n\n"));
}

function resultMetric(label, value) {
  return `
    <div class="result-metric">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(String(value ?? "-"))}</strong>
    </div>
  `;
}

function renderIssueList(title, items) {
  if (!Array.isArray(items) || !items.length) return "";
  return `
    <div class="result-section">
      <h3>${escapeHtml(title)}</h3>
      <ul>${items.slice(0, 12).map((item) => `<li>${escapeHtml(formatIssue(item))}</li>`).join("")}</ul>
      ${items.length > 12 ? `<p class="muted">${escapeHtml(`${items.length - 12} more item(s) saved in artifacts.`)}</p>` : ""}
    </div>
  `;
}

function renderDetailRows(details) {
  const hiddenKeys = new Set(["case", "ir", "model", "abstraction_hints", "retrieved_hints", "warnings", "errors"]);
  const rows = Object.entries(details || {}).filter(([key, value]) => !hiddenKeys.has(key) && value);
  if (!rows.length) return "";
  return `
    <div class="result-section">
      ${rows.map(([key, value]) => `
        <div class="detail-row">
          <span>${escapeHtml(titleCase(key))}</span>
          <strong>${escapeHtml(formatIssue(value))}</strong>
        </div>
      `).join("")}
    </div>
  `;
}

function renderRepairAttempts(attempts) {
  if (!Array.isArray(attempts) || !attempts.length) return "";
  return `
    <div class="result-section">
      <h3>Attempts</h3>
      <table class="compact-table">
        <thead><tr><th>Round</th><th>Status</th><th>Accepted</th><th>Issues</th></tr></thead>
        <tbody>
          ${attempts.map((attempt) => `
            <tr>
              <td>${escapeHtml(attempt.round ?? "-")}</td>
              <td>${escapeHtml(attempt.status || "-")}</td>
              <td>${escapeHtml(attempt.accepted ? "yes" : "no")}</td>
              <td>${escapeHtml((attempt.lint_issue_count || 0) + (attempt.warning_count || 0))}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderLemmaTable(data) {
  const states = data.lemma_actual_states || {};
  const expected = data.lemma_expected_states || {};
  const matches = data.lemma_matches || {};
  const names = Object.keys(states);
  if (!names.length) return "";
  return `
    <div class="result-section">
      <h3>Lemmas</h3>
      <table class="compact-table">
        <thead><tr><th>Lemma</th><th>Actual</th><th>Expected</th><th>Match</th></tr></thead>
        <tbody>
          ${names.map((name) => `
            <tr>
              <td>${escapeHtml(name)}</td>
              <td>${escapeHtml(states[name] || "-")}</td>
              <td>${escapeHtml(expected[name] || "-")}</td>
              <td>${escapeHtml(matches[name] ? "yes" : "no")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderOutputSnippet(title, text) {
  const trimmed = String(text || "").trim();
  if (!trimmed) return "";
  return `
    <details class="result-section output-snippet">
      <summary>${escapeHtml(title)}</summary>
      <pre>${escapeHtml(trimmed.slice(-1600))}</pre>
    </details>
  `;
}

function repairRoundText(data) {
  if (!data) return "-";
  const attempts = Array.isArray(data.attempts) ? data.attempts.length : 0;
  const maxRounds = data.max_rounds ?? "-";
  return `${attempts} attempt(s), max ${maxRounds}`;
}

function lemmaResultText(data) {
  const states = data && data.lemma_actual_states ? Object.keys(data.lemma_actual_states).length : 0;
  const mismatched = data && data.mismatched_results ? data.mismatched_results.length : 0;
  return `${states} checked, ${mismatched} mismatch(es)`;
}

function compactFailureDetails(data) {
  return {
    stage: data.stage || data.type || "",
    reason: data.reason || "",
    attempts: data.json_attempts || data.planner_attempts || "",
    message: data.error || "",
  };
}

function formatIssue(item) {
  if (item == null) return "";
  if (typeof item === "string") return item;
  if (Array.isArray(item)) return item.map(formatIssue).join(", ");
  if (typeof item === "object") {
    return Object.entries(item)
      .map(([key, value]) => `${titleCase(key)}: ${formatIssue(value)}`)
      .join("; ");
  }
  return String(item);
}

function renderWorkflow() {
  const workflow = state.workflow || {};
  renderWorkflowNavStatus(workflow);
}

function syncAbstractionHintToggle() {
  const toggle = document.getElementById("abstractionHintsToggle");
  if (!toggle || state.abstractionHintsInitialized) return;
  const settings = state.workflow && state.workflow.settings ? state.workflow.settings : {};
  toggle.checked = Boolean(settings.abstraction_hints_enabled);
  state.abstractionHintsInitialized = true;
}

function abstractionHintsEnabled() {
  const toggle = document.getElementById("abstractionHintsToggle");
  return Boolean(toggle && toggle.checked);
}

function abstractionHintCount(hints) {
  if (!hints || typeof hints !== "object") return 0;
  return Array.isArray(hints.selected) ? hints.selected.length : 0;
}

function renderWorkflowNavStatus(workflow) {
  const nav = document.getElementById("sectionNav");
  if (!nav) return;
  const exists = workflow.exists || {};
  const current = workflow.current_step || {};
  const currentGroupName = workflowGroup(current.step || "");
  const statusBySection = {};
  workflowNavSteps.forEach((step) => {
    const done = Boolean(step.done(exists));
    const isCurrent = currentGroupName === step.id && isActiveWorkflowEvent(current);
    const status = isCurrent ? "current" : done ? "done" : "pending";
    const previous = statusBySection[step.section];
    if (!previous || statusPriority(status) > statusPriority(previous)) {
      statusBySection[step.section] = status;
    }
  });
  Object.entries(reviewWorkflowStatusBySection(workflow)).forEach(([section, status]) => {
    statusBySection[section] = status;
  });
  nav.querySelectorAll("[data-nav-section]").forEach((button) => {
    const badge = button.querySelector(".nav-status");
    if (!badge) return;
    const status = statusBySection[button.dataset.navSection] || "";
    button.dataset.workflowStatus = status;
    badge.hidden = !status;
    badge.textContent = status;
  });
}

function statusPriority(status) {
  return { current: 3, pending: 2, done: 1 }[status] || 0;
}

function reviewWorkflowStatusBySection(workflow) {
  if (state.contract && Array.isArray(state.contract.field_reviews)) {
    return reviewNavSections.reduce((acc, section) => {
      if (reviewSectionStatus(section) === "done") {
        acc[section] = "done";
      }
      return acc;
    }, {});
  }
  const sections = workflow && workflow.review && workflow.review.sections;
  if (!sections || typeof sections !== "object") return {};
  return reviewNavSections.reduce((acc, section) => {
    const status = sections[section] && sections[section].status ? String(sections[section].status) : "";
    if (status === "done") {
      acc[section] = status;
    }
    return acc;
  }, {});
}

function renderWorkflowLibrary() {
  const select = document.getElementById("workflowLibrarySelect");
  if (!select) return;
  const meta = document.getElementById("workflowLibraryMeta");
  const library = state.workflowLibrary || {};
  const cases = Array.isArray(library.cases) ? library.cases : [];
  if (library.error) {
    select.innerHTML = `<option value="">Failed to load prepared workflows</option>`;
    if (meta) {
      meta.textContent = library.error;
      meta.className = "field-note error";
    }
    return;
  }
  if (!cases.length) {
    select.innerHTML = `<option value="">No prepared workflows found</option>`;
    if (meta) {
      meta.textContent = "No prepared workflows found.";
      meta.className = "field-note";
    }
    return;
  }
  const currentValue = select.value;
  select.innerHTML = `<option value="">Select prepared workflow...</option>${cases.map((item) => {
    const label = `${item.difficulty || "-"} / ${item.name || item.id}${item.reviewed ? "" : " (no review)"}`;
    return `<option value="${escapeHtml(item.id || item.name || "")}">${escapeHtml(label)}</option>`;
  }).join("")}`;
  if (currentValue && cases.some((item) => item.id === currentValue)) {
    select.value = currentValue;
  }
  if (meta) {
    const counts = cases.reduce((acc, item) => {
      const key = item.difficulty || "unspecified";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
    const countText = Object.entries(counts)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, count]) => `${key}: ${count}`)
      .join(", ");
    meta.textContent = `${cases.length} prepared workflows${countText ? ` (${countText})` : ""}`;
    meta.className = "field-note";
  }
}

function workflowGroup(step) {
  if (["planner", "ir"].includes(step)) return "ir";
  if (["contract", "review", "review_patch"].includes(step)) return "contract";
  if (step === "sapic_generation") return "sapic_generation";
  if (["repair_verify", "tamarin_compile"].includes(step)) return "verify";
  if (step === "tamarin_prove") return "tamarin_prove";
  return step || "";
}

function isActiveWorkflowEvent(event) {
  const status = event && event.status ? String(event.status) : "";
  return ["start", "llm_start", "retry_start", "attempt_created"].includes(status);
}

function updateActionState() {
  const hasContract = Boolean(state.contract);
  const exists = state.workflow && state.workflow.exists ? state.workflow.exists : {};
  const libraryCases = state.workflowLibrary && Array.isArray(state.workflowLibrary.cases) ? state.workflowLibrary.cases : [];
  const librarySelect = document.getElementById("workflowLibrarySelect");
  const hasLibrarySelection = Boolean(librarySelect && librarySelect.value);
  const patchReady = hasContract
    && state.pendingPatch
    && state.pendingPatch.validation
    && state.pendingPatch.validation.ok
    && Array.isArray(state.pendingPatch.patches)
    && state.pendingPatch.patches.length > 0;
  document.getElementById("saveBtn").disabled = !hasContract;
  document.getElementById("importWorkflowBtn").disabled = !libraryCases.length || !hasLibrarySelection;
  document.getElementById("proposePatchBtn").disabled = !hasContract;
  document.getElementById("applyPatchBtn").disabled = !patchReady;
  document.getElementById("generateSapicBtn").disabled = !hasContract;
  document.getElementById("repairVerifyBtn").disabled = !exists.sapic;
  document.getElementById("proveBtn").disabled = !exists.sapic;
  document.querySelectorAll("[data-add-row]").forEach((button) => {
    button.disabled = !hasContract;
  });
}

function setBusy(ids, busy) {
  ids.forEach((id) => {
    const element = document.getElementById(id);
    if (element) element.disabled = busy;
  });
  if (!busy) updateActionState();
}

async function apiJson(path, options = {}) {
  const response = await fetch(path, options);
  let data = {};
  try {
    data = await response.json();
  } catch (error) {
    data = { error: `Invalid JSON response: ${error.message}` };
  }
  return { response, data };
}

function isNonEmptyObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length > 0;
}

function setStatus(message, isError = false, isOk = false) {
  const status = document.getElementById("status");
  status.textContent = message || "";
  status.className = `status ${isError ? "error" : isOk ? "ok" : ""}`;
}

function hydrateNlInput(caseInput) {
  if (!caseInput || typeof caseInput !== "object") return;
  document.getElementById("nlName").value = caseInput.name || "";
  document.getElementById("nlDifficulty").value = caseInput.difficulty || "";
  document.getElementById("nlDescription").value = caseInput.description || "";
  document.getElementById("nlAssumptions").value = Array.isArray(caseInput.assumptions)
    ? caseInput.assumptions.join("\n")
    : "";
  document.getElementById("nlGoals").value = Array.isArray(caseInput.goals)
    ? caseInput.goals.map(formatGoalInput).join("\n")
    : "";
}

function formatGoalInput(goal) {
  if (typeof goal === "string") return goal;
  if (!goal || typeof goal !== "object") return "";
  const name = goal.name || "";
  const type = goal.type || "";
  const traceKind = goal.trace_kind || "";
  const expectedResult = goal.expected_result || goal.expected_state || "";
  if (type || traceKind || expectedResult) {
    return [name, type, traceKind, expectedResult].join("; ").trim();
  }
  const description = goal.description ? `: ${goal.description}` : "";
  return `${name}${description}`.trim();
}

function clearTransientOutputs() {
  state.pendingPatch = null;
  ["patchSummary", "sapicResult", "tamarinResult"].forEach((id) => {
    const element = document.getElementById(id);
    if (element) element.innerHTML = "";
  });
}

function formatNlFailure(data) {
  const parts = [data.error || "NL workflow failed"];
  if (data.reason) parts.push(`Reason: ${data.reason}.`);
  parts.push("Current active artifacts were not overwritten.");
  return parts.join(" ");
}

function formatPatchFailure(data) {
  const parts = [data.error || "Patch proposal failed"];
  if (data.reason) parts.push(`Reason: ${data.reason}.`);
  return parts.join(" ");
}

function formatSapicFailure(data) {
  const parts = [data.error || "Sapic+ generation failed"];
  if (data.reason) parts.push(`Reason: ${data.reason}.`);
  return parts.join(" ");
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function cssEscape(value) {
  if (window.CSS && typeof window.CSS.escape === "function") {
    return window.CSS.escape(String(value || ""));
  }
  return String(value || "").replace(/["\\]/g, "\\$&");
}
