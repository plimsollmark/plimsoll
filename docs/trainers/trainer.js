"use strict";

const dataNode = document.getElementById("trainerData");
if (!dataNode) throw new Error("trainerData is missing");
const TRAINER = JSON.parse(dataNode.textContent);
const knownKinds = new Set(["scenario", "quiz", "pipeline", "matrix", "budget", "checklist", "sim"]);
if (!Array.isArray(TRAINER.chapters) || !TRAINER.chapters.length) throw new Error("trainer has no chapters");
for (const chapter of TRAINER.chapters) {
  if (!knownKinds.has(chapter.kind)) throw new Error(`unknown trainer chapter kind: ${chapter.kind}`);
}

const $ = (id) => document.getElementById(id);
const els = {
  title: $("trainerTitle"), tagline: $("trainerTagline"), chapters: $("chapters"),
  kicker: $("chapterKicker"), chapterTitle: $("chapterTitle"), lede: $("chapterLede"),
  stats: $("headStats"), stage: $("stage"), controls: $("lessonControls"),
  explainer: $("explainer"), prev: $("prevChapter"), next: $("nextChapter"), dots: $("progressDots"),
};

const referenceLinks = [
  { kind: "internal", label: "Plain English", note: "Start here for the vocabulary.", href: "plain-english.html" },
  { kind: "internal", label: "Architecture", note: "Follow the request and authority path.", href: "architecture.html" },
  { kind: "internal", label: "API Broker", note: "See route checks, tokens, and budgets.", href: "brokering.html" },
  { kind: "internal", label: "Private API Lab", note: "Follow one call from the model to a private API.", href: "private-api.html" },
  { kind: "external", label: "Hono documentation", note: "The Node web framework used by the gateway.", href: "https://hono.dev/docs" },
  { kind: "external", label: "MCP transports", note: "Official Streamable HTTP and stdio specification.", href: "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports" },
  { kind: "external", label: "JSON-RPC 2.0", note: "The request and response envelope used by MCP.", href: "https://www.jsonrpc.org/specification" },
  { kind: "external", label: "Connect RPC", note: "Typed protobuf RPC over HTTP.", href: "https://connectrpc.com/" },
  { kind: "external", label: "gRPC core concepts", note: "How .proto services become RPC calls.", href: "https://grpc.io/docs/what-is-grpc/core-concepts/" },
  { kind: "external", label: "Protocol Buffers", note: "The schema and serialization layer for typed RPC.", href: "https://protobuf.dev/overview/" },
  { kind: "external", label: "Docker overview", note: "Containers, images, and the Docker daemon.", href: "https://docs.docker.com/get-started/docker-overview" },
  { kind: "external", label: "gVisor documentation", note: "The runsc application-kernel boundary.", href: "https://gvisor.dev/docs/" },
  { kind: "external", label: "WebAssembly guide", note: "The runtime format behind the WASM provider.", href: "https://developer.mozilla.org/en-US/docs/WebAssembly" },
  { kind: "external", label: "wazero documentation", note: "The Go WebAssembly runtime used here.", href: "https://wazero.io/docs/" },
  { kind: "external", label: "E2B documentation", note: "The Firecracker-backed cloud runtime option.", href: "https://e2b.dev/docs" },
  { kind: "external", label: "Docker Cloud Sandboxes", note: "The Docker-managed microVM runtime option.", href: "https://docs.docker.com/ai/sandboxes/cloud/" },
];

// Internal reference hrefs above are written relative to this directory, because that
// is where trainer pages normally live. A page hosted elsewhere sets
// data-trainer-base on <html> (for example "../trainers/") and every internal link
// is resolved against it. External links are absolute and never rewritten. Pages in
// this directory set nothing and get "", so the default path is unchanged.
const trainerBase = document.documentElement.dataset.trainerBase || "";
const internalHref = (href) => trainerBase + href;

function renderReferenceShelf() {
  const rail = document.querySelector(".trainer-rail");
  if (!rail || document.getElementById("referenceShelf")) return;
  const shelf = document.createElement("details");
  shelf.id = "referenceShelf";
  shelf.className = "reference-shelf";
  shelf.innerHTML = `<summary>Definitions and references <span>links are labeled</span></summary>
    <div class="reference-list">${referenceLinks.map((link) => `
      <a class="reference-link ${link.kind}" href="${link.kind === "external" ? link.href : internalHref(link.href)}"${link.kind === "external" ? ' target="_blank" rel="noopener"' : ""}>
        <span class="reference-kind">${link.kind === "external" ? "EXTERNAL · official docs ↗" : "INTERNAL · trainer site →"}</span>
        <strong>${link.label}</strong><small>${link.note}</small>
      </a>`).join("")}</div>`;
  const note = rail.querySelector(".rail-note");
  if (note) note.insertAdjacentElement("afterend", shelf);
  else rail.appendChild(shelf);
}

const storageKey = `plimsoll-trainer:${TRAINER.id}`;
let completed = new Set(readStored().completed || []);
let chapterIndex = initialChapterIndex();
let state = freshState(TRAINER.chapters[chapterIndex]);
let playTimer = null;
let activeSimulatorCleanup = null;

function readStored() {
  try { return JSON.parse(localStorage.getItem(storageKey) || "{}"); } catch { return {}; }
}
function writeStored() {
  try { localStorage.setItem(storageKey, JSON.stringify({ chapter: TRAINER.chapters[chapterIndex].id, completed: [...completed] })); } catch { /* storage is optional */ }
}
function initialChapterIndex() {
  const fromHash = location.hash.slice(1);
  const saved = readStored().chapter;
  const id = fromHash || saved;
  const found = TRAINER.chapters.findIndex((chapter) => chapter.id === id);
  return found >= 0 ? found : 0;
}
function freshState(chapter) {
  return {
    selected: null,
    pipelineStep: 0,
    checks: new Set(),
    budget: { ...(chapter.defaults || {}) },
  };
}
function stopPlaying() {
  if (playTimer) clearInterval(playTimer);
  playTimer = null;
}
function setChapter(index) {
  if (index < 0 || index >= TRAINER.chapters.length) return;
  stopPlaying();
  chapterIndex = index;
  state = freshState(TRAINER.chapters[index]);
  history.replaceState(null, "", `#${TRAINER.chapters[index].id}`);
  writeStored();
  render();
}
function markInteracted() {
  completed.add(TRAINER.chapters[chapterIndex].id);
  writeStored();
}

function render() {
  const chapter = TRAINER.chapters[chapterIndex];
  document.title = `${chapter.title} · ${TRAINER.title}`;
  els.title.textContent = TRAINER.title;
  els.tagline.textContent = TRAINER.tagline;
  els.kicker.textContent = `Chapter ${chapterIndex + 1} of ${TRAINER.chapters.length}`;
  els.chapterTitle.textContent = chapter.title;
  els.lede.textContent = chapter.lede;
  renderRail();
  renderStats(chapter);
  renderStage(chapter);
  renderLesson(chapter);
  renderFooter();
}

function renderRail() {
  els.chapters.innerHTML = TRAINER.chapters.map((chapter, index) => `
    <li><button class="chapter-button ${index === chapterIndex ? "active" : ""} ${completed.has(chapter.id) ? "done" : ""}"
      data-chapter="${index}" ${index === chapterIndex ? 'aria-current="step"' : ""}>
      <span class="chapter-number">${completed.has(chapter.id) && index !== chapterIndex ? "✓" : index + 1}</span>
      <span class="chapter-label">${escapeHTML(chapter.label)}</span>
    </button></li>`).join("");
}

function renderStats(chapter) {
  const stats = typeof chapter.stats === "function" ? chapter.stats(state) : (chapter.stats || []);
  els.stats.innerHTML = stats.map((stat) => `
    <div class="stat ${stat.tone || ""}"><span>${escapeHTML(stat.label)}</span><strong>${escapeHTML(String(stat.value))}</strong></div>`).join("");
}

function renderStage(chapter) {
  if (activeSimulatorCleanup) {
    activeSimulatorCleanup();
    activeSimulatorCleanup = null;
  }
  switch (chapter.kind) {
    case "scenario":
    case "quiz": renderScenario(chapter); break;
    case "pipeline": renderPipeline(chapter); break;
    case "matrix": renderMatrix(chapter); break;
    case "budget": renderBudget(chapter); break;
    case "checklist": renderChecklist(chapter); break;
    case "sim": renderSimulator(chapter); break;
  }
}

function renderSimulator(chapter) {
  const registry = window.plimsollTrainerSimulators || {};
  const simulator = registry[chapter.simulator || chapter.id];
  if (!simulator || typeof simulator.mount !== "function") {
    els.stage.innerHTML = '<div class="result-card bad"><h3>Simulator unavailable</h3><p>This trainer references a simulator that was not loaded.</p></div>';
    return;
  }
  const cleanup = simulator.mount(els.stage, chapter, { markInteracted });
  activeSimulatorCleanup = typeof cleanup === "function" ? cleanup : null;
}

function renderScenario(chapter) {
  const selected = state.selected === null ? null : chapter.options[state.selected];
  els.stage.innerHTML = `
    <p class="stage-title">${escapeHTML(chapter.promptLabel || (chapter.kind === "quiz" ? "Make the call" : "Choose a configuration"))}</p>
    <p class="stage-intro">${chapter.prompt}</p>
    <div class="option-grid">${chapter.options.map((option, index) => `
      <button class="option-card ${state.selected === index ? "selected" : ""}" data-option="${index}">
        <strong>${escapeHTML(option.label)}</strong><small>${option.note}</small>
      </button>`).join("")}</div>
    ${selected ? resultHTML(selected) : '<div class="result-card"><h3>Pick one</h3><p>The stage will show the boundary, outcome, and operator-visible signal.</p></div>'}`;
}

function resultHTML(option) {
  const correct = option.correct;
  const tone = correct === true ? "good" : correct === false ? "bad" : (option.tone || "neutral");
  const heading = correct === true ? `Correct — ${option.result}` : correct === false ? `Not quite — ${option.result}` : option.result;
  return `<div class="result-card ${tone}"><h3>${heading}</h3><p>${option.detail}</p>
    ${option.facts?.length ? `<div class="result-facts">${option.facts.map((fact) => `<span class="fact">${fact}</span>`).join("")}</div>` : ""}</div>`;
}

function renderPipeline(chapter) {
  const active = Math.min(state.pipelineStep, chapter.steps.length - 1);
  const step = chapter.steps[active];
  els.stage.innerHTML = `
    <p class="stage-title">Request path</p><p class="stage-intro">${chapter.prompt}</p>
    <div class="pipeline">${chapter.steps.map((item, index) => `
      <div class="pipe-step ${index < active ? "done" : ""} ${index === active ? "active" : ""}">
        <span class="pipe-layer">${escapeHTML(item.layer)}</span><strong>${escapeHTML(item.name)}</strong><small>${item.short}</small>
      </div>`).join("")}</div>
    <div class="result-card ${step.tone || "neutral"} pipeline-event"><h3>${escapeHTML(step.name)}</h3><p>${step.detail}</p></div>
    <div class="inline-controls">
      <button class="control-button" data-action="pipeline-reset" ${active === 0 ? "disabled" : ""}>Reset</button>
      <button class="control-button primary" data-action="pipeline-step" ${active >= chapter.steps.length - 1 ? "disabled" : ""}>Step request →</button>
      <button class="control-button" data-action="pipeline-play">${playTimer ? "Pause" : "Play path"}</button>
    </div>`;
}

function renderMatrix(chapter) {
  els.stage.innerHTML = `
    <p class="stage-title">${escapeHTML(chapter.promptLabel || "Compare exact contracts")}</p><p class="stage-intro">${chapter.prompt}</p>
    <div class="matrix-wrap"><table class="matrix"><thead><tr><th>${escapeHTML(chapter.rowLabel || "Component")}</th>
      ${chapter.columns.map((column) => `<th>${escapeHTML(column)}</th>`).join("")}</tr></thead><tbody>
      ${chapter.rows.map((row) => `<tr><th>${escapeHTML(row.label)}</th>${row.cells.map((cell) => `
        <td><span class="cell-badge ${cell.tone || "neutral"}">${cell.tone === "good" ? "✓" : cell.tone === "bad" ? "×" : "•"} ${escapeHTML(cell.text)}</span>${cell.note ? `<span class="cell-note">${cell.note}</span>` : ""}</td>`).join("")}</tr>`).join("")}
    </tbody></table></div>`;
}

function renderBudget(chapter) {
  const b = state.budget;
  const memoryFit = Math.floor(b.totalMemory / b.perRunMemory);
  const capacity = Math.max(0, Math.min(b.maxConcurrent, memoryFit));
  const accepted = Math.min(b.offered, capacity);
  const shed = Math.max(0, b.offered - accepted);
  const slots = Array.from({ length: b.offered }, (_, index) => `<div class="run-slot ${index < accepted ? "accepted" : "shed"}">${index < accepted ? `run ${index + 1}` : "shed"}</div>`).join("");
  els.stage.innerHTML = `
    <p class="stage-title">Admission laboratory</p><p class="stage-intro">${chapter.prompt}</p>
    <div class="budget-grid"><div class="budget-controls">
      ${rangeHTML("maxConcurrent", "Max concurrent", b.maxConcurrent, 1, 12, 1, "runs")}
      ${rangeHTML("totalMemory", "Aggregate memory", b.totalMemory, 128, 2048, 128, "MiB")}
      ${rangeHTML("perRunMemory", "Per-run memory", b.perRunMemory, 64, 512, 64, "MiB")}
      ${rangeHTML("offered", "Runs arriving together", b.offered, 1, 16, 1, "runs")}
    </div><div class="budget-result">
      <p class="budget-equation">memory slots = floor(${b.totalMemory} / ${b.perRunMemory}) = ${memoryFit}<br>effective capacity = min(${b.maxConcurrent}, ${memoryFit}) = ${capacity}</p>
      <div class="run-slots">${slots}</div>
      <div class="budget-summary"><div><strong>${accepted}</strong><span>accepted</span></div><div><strong>${shed}</strong><span>shed now</span></div></div>
    </div></div>`;
  els.stats.innerHTML = [
    { label: "memory slots", value: memoryFit },
    { label: "capacity", value: capacity, tone: capacity ? "good" : "bad" },
    { label: "shed", value: shed, tone: shed ? "warn" : "good" },
  ].map((stat) => `<div class="stat ${stat.tone || ""}"><span>${stat.label}</span><strong>${stat.value}</strong></div>`).join("");
}

function rangeHTML(key, label, value, min, max, step, unit) {
  return `<div class="range-row"><label for="range-${key}">${label}</label><output>${value} ${unit}</output>
    <input id="range-${key}" data-range="${key}" type="range" min="${min}" max="${max}" step="${step}" value="${value}"></div>`;
}

function renderChecklist(chapter) {
  const requiredIndexes = chapter.items
    .map((item, index) => item.required === false ? -1 : index)
    .filter((index) => index >= 0);
  const requiredChecked = requiredIndexes.filter((index) => state.checks.has(index)).length;
  const ready = requiredChecked === requiredIndexes.length;
  els.stage.innerHTML = `
    <p class="stage-title">Readiness gate</p><p class="stage-intro">${chapter.prompt}</p>
    <div class="checklist">${chapter.items.map((item, index) => `
      <button class="check-item ${state.checks.has(index) ? "checked" : ""}" data-check="${index}">
        <span class="check-box">${state.checks.has(index) ? "✓" : ""}</span>
        <span class="check-copy"><strong>${escapeHTML(item.label)}</strong><small>${item.why}</small></span>
        <span class="required-tag">${item.required === false ? "recommended" : "required"}</span>
      </button>`).join("")}</div>
    <div class="result-card ${ready ? "good" : "warn"}"><h3>${ready ? "Ready to evaluate hostile code" : "Fail closed"}</h3><p>${ready ? chapter.ready : chapter.notReady}</p></div>`;
  els.stats.innerHTML = `<div class="stat ${ready ? "good" : "warn"}"><span>required checks</span><strong>${requiredChecked}/${requiredIndexes.length}</strong></div>`;
}

// Both side panels are optional. They used to be mandatory because this function
// dereferenced them, which turned a rendering detail into an editorial rule: every
// chapter had to carry a "try this" and a "what to keep" whether the chapter wanted
// them or not. A chapter that says its point once now can.
function renderLesson(chapter) {
  const explainer = chapter.explainer || {};
  els.controls.innerHTML = explainer.try ? `<h2>Try this</h2><p>${explainer.try}</p>` : "";
  els.controls.hidden = !explainer.try;
  els.explainer.innerHTML = explainer.idea
    ? `<h2>What to keep</h2><p class="idea">${explainer.idea}</p>
    ${explainer.points?.length ? `<ul>${explainer.points.map((point) => `<li>${point}</li>`).join("")}</ul>` : ""}`
    : "";
  els.explainer.hidden = !explainer.idea;
}

function renderFooter() {
  const last = chapterIndex === TRAINER.chapters.length - 1;
  const currentComplete = completed.has(TRAINER.chapters[chapterIndex].id);
  els.prev.disabled = chapterIndex === 0;
  els.next.disabled = last && currentComplete;
  els.next.textContent = last ? (currentComplete ? "Completed ✓" : "Mark complete ✓") : "Next idea →";
  els.dots.innerHTML = TRAINER.chapters.map((chapter, index) => `<button class="progress-dot ${index === chapterIndex ? "active" : ""}" data-chapter="${index}" aria-label="Go to ${escapeHTML(chapter.label)}"></button>`).join("");
}

document.addEventListener("click", (event) => {
  const chapterButton = event.target.closest("[data-chapter]");
  if (chapterButton) return setChapter(Number(chapterButton.dataset.chapter));
  const option = event.target.closest("[data-option]");
  if (option) {
    state.selected = Number(option.dataset.option);
    markInteracted();
    render();
    return;
  }
  const check = event.target.closest("[data-check]");
  if (check) {
    const index = Number(check.dataset.check);
    state.checks.has(index) ? state.checks.delete(index) : state.checks.add(index);
    markInteracted();
    render();
    return;
  }
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (action === "pipeline-step") {
    state.pipelineStep = Math.min(state.pipelineStep + 1, TRAINER.chapters[chapterIndex].steps.length - 1);
    markInteracted(); render();
  } else if (action === "pipeline-reset") {
    stopPlaying(); state.pipelineStep = 0; render();
  } else if (action === "pipeline-play") {
    if (playTimer) { stopPlaying(); render(); return; }
    const steps = TRAINER.chapters[chapterIndex].steps;
    if (state.pipelineStep >= steps.length - 1) state.pipelineStep = 0;
    playTimer = setInterval(() => {
      state.pipelineStep++;
      if (state.pipelineStep >= steps.length - 1) { markInteracted(); stopPlaying(); }
      render();
    }, 900);
    render();
  }
});

document.addEventListener("input", (event) => {
  const key = event.target.dataset.range;
  if (key) {
    state.budget[key] = Number(event.target.value);
    markInteracted();
    renderStage(TRAINER.chapters[chapterIndex]);
  }
});

els.prev.addEventListener("click", () => setChapter(chapterIndex - 1));
els.next.addEventListener("click", () => {
  markInteracted();
  if (chapterIndex === TRAINER.chapters.length - 1) render();
  else setChapter(chapterIndex + 1);
});
window.addEventListener("hashchange", () => {
  const index = TRAINER.chapters.findIndex((chapter) => chapter.id === location.hash.slice(1));
  if (index >= 0 && index !== chapterIndex) setChapter(index);
});
window.addEventListener("keydown", (event) => {
  if (event.target.matches("input, textarea, select, [contenteditable=true]")) return;
  if (event.key === "ArrowLeft") setChapter(chapterIndex - 1);
  if (event.key === "ArrowRight") setChapter(chapterIndex + 1);
});

function escapeHTML(value) {
  return String(value).replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
}

renderReferenceShelf();
render();
