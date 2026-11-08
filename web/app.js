// Airlock single-page client. No framework, no third-party code.
// Every string that came from the server (agent text, tool output, diff) is
// rendered with textContent, never as HTML.
"use strict";

const API = "/api/v1";
const POLL_MS = 1000;
const HISTORY_KEY = "airlock.tasks";
const TERMINAL = new Set(["finished", "cancelled", "interrupted"]);

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

class ApiError extends Error {
  constructor(status, code, message, retryAfter) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

async function api(method, path, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") {
    opts.headers["X-Airlock"] = "1";
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
  }
  const res = await fetch(API + path, opts);
  let data = null;
  try { data = await res.json(); } catch (_) { data = null; }
  if (!res.ok) {
    const err = (data && data.error) || {};
    throw new ApiError(res.status, err.code || "http_" + res.status,
      err.message || "Request failed (" + res.status + ").", res.headers.get("Retry-After"));
  }
  return data;
}

function errorText(e) {
  if (!(e instanceof ApiError)) return "Network error. Check your connection and try again.";
  let t = e.message;
  if (e.retryAfter && /^\d+$/.test(e.retryAfter)) {
    const s = Number(e.retryAfter);
    t += s >= 120 ? " Try again in about " + Math.ceil(s / 60) + " min." : " Try again in " + s + " s.";
  }
  return t;
}

// ---------------------------------------------------------------- session

const state = { manifest: null, taskId: null, afterSeq: 0, polling: false, events: 0, reviewLoaded: false };

async function ensureSession() {
  try {
    return await api("GET", "/session");
  } catch (e) {
    if (!(e instanceof ApiError) || e.status !== 401) throw e;
    await api("POST", "/sessions");
    return await api("GET", "/session");
  }
}

function renderQuota(s) {
  const q = s.quota, v = s.service, box = $("quota");
  box.textContent = "";
  const parts = [
    "Tasks today: " + q.tasks_used + " / " + q.tasks_limit,
    "Tokens today: " + q.tokens_used.toLocaleString() + " / " + q.tokens_limit.toLocaleString(),
    "Queue: " + v.queued + " waiting, " + v.running + " running",
  ];
  box.append(el("span", null, parts.join(" · ")));
  if (!v.accepting_tasks) {
    const why = { daily_limit: "the daily limit is reached", spend_limit: "the spend limit is reached",
                  maintenance: "maintenance" }[v.pause_reason] || "it is paused";
    box.append(el("div", "msg err", "New tasks are not being accepted right now: " + why + "."));
  }
  return v.accepting_tasks && q.tasks_remaining > 0;
}

async function refreshQuota() {
  try {
    const s = await api("GET", "/session");
    setStartEnabled(renderQuota(s));
  } catch (_) { /* quota display is best effort */ }
}

// ---------------------------------------------------------------- start

function setStartEnabled(on) {
  document.querySelectorAll("#start button").forEach((b) => { b.disabled = !on; });
}

function startMsg(text, isErr) {
  const m = $("start-msg");
  m.textContent = text || "";
  m.className = "msg" + (isErr ? " err" : "");
}

function currentSample() {
  const id = $("sample").value;
  return state.manifest.samples.find((s) => s.id === id);
}

function renderSample() {
  const s = currentSample();
  $("sample-desc").textContent = s ? s.description : "";
  const box = $("presets");
  box.textContent = "";
  if (!s) return;
  for (const p of s.presets) {
    const b = el("button", "preset");
    b.type = "button";
    b.setAttribute("role", "listitem");
    b.append(el("b", null, p.title), el("span", null, p.description));
    b.addEventListener("click", () => submitTask({ sample_id: s.id, preset_id: p.id }, p.instruction));
    box.append(b);
  }
}

async function loadSamples() {
  state.manifest = await api("GET", "/samples");
  const sel = $("sample");
  sel.textContent = "";
  for (const s of state.manifest.samples) {
    const o = el("option", null, s.title);
    o.value = s.id;
    sel.append(o);
  }
  sel.addEventListener("change", renderSample);
  renderSample();
}

async function submitTask(body, instructionText) {
  setStartEnabled(false);
  startMsg("Starting…");
  try {
    const r = await api("POST", "/tasks", body);
    startMsg("");
    rememberTask(r.task.id, body.sample_id, instructionText);
    openTask(r.task.id);
  } catch (e) {
    startMsg(errorText(e), true);
  } finally {
    refreshQuota();
  }
}

// ---------------------------------------------------------------- history

function loadHistory() {
  try {
    const v = JSON.parse(sessionStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(v) ? v.filter((t) => t && typeof t.id === "string") : [];
  } catch (_) { return []; }
}

function rememberTask(id, sampleId, instruction) {
  const h = loadHistory().filter((t) => t.id !== id);
  h.unshift({ id, sample: sampleId, text: String(instruction || "").slice(0, 120) });
  sessionStorage.setItem(HISTORY_KEY, JSON.stringify(h.slice(0, 10)));
  renderHistory();
}

function renderHistory() {
  const h = loadHistory(), list = $("history-list");
  list.textContent = "";
  $("history").hidden = h.length === 0;
  for (const t of h) {
    const li = el("li");
    const b = el("button", null, t.sample + ": " + (t.text || t.id));
    b.type = "button";
    b.addEventListener("click", () => openTask(t.id));
    li.append(b);
    list.append(li);
  }
}

// ---------------------------------------------------------------- task view

const STATUS_PILL = { queued: "run", running: "run", finished: "ok", cancelled: "bad", interrupted: "bad" };

function setStatus(task) {
  const p = $("status");
  let label = task.status;
  if (task.status === "queued" && task.queue_position) label += " (#" + task.queue_position + ")";
  if (task.end_reason) label += " · " + task.end_reason.replace(/_/g, " ");
  p.textContent = label;
  let cls = STATUS_PILL[task.status] || "";
  if (task.status === "finished" && task.end_reason !== "agent_finished") cls = "warn";
  p.className = "pill " + cls;
}

function openTask(id) {
  state.taskId = id;
  state.afterSeq = 0;
  state.events = 0;
  state.reviewLoaded = false;
  $("timeline").textContent = "";
  $("task-instruction").textContent = "";
  $("task").hidden = false;
  $("report").hidden = true;
  $("review").hidden = true;
  $("task").scrollIntoView({ behavior: "smooth", block: "start" });
  if (!state.polling) poll();
}

async function poll() {
  state.polling = true;
  const id = state.taskId;
  try {
    const t = (await api("GET", "/tasks/" + encodeURIComponent(id))).task;
    if (id !== state.taskId) return;
    $("task-instruction").textContent = t.instruction;
    setStatus(t);
    let more = true;
    let terminal = false;
    while (more && id === state.taskId) {
      const r = await api("GET", "/tasks/" + encodeURIComponent(id) + "/events?after_seq=" + state.afterSeq + "&limit=200");
      for (const e of r.events) addEvent(e);
      state.afterSeq = r.next_after_seq;
      more = r.has_more;
      terminal = r.terminal;
    }
    if (id !== state.taskId) return;
    if (TERMINAL.has(t.status) && terminal) {
      renderReport(t);
      if (!state.reviewLoaded) { state.reviewLoaded = true; loadDiff(t); }
      refreshQuota();
      state.polling = false;
      return;
    }
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 401)) {
      addNote("This task is not available (it may have expired).", "bad");
      state.polling = false;
      return;
    }
    // transient: keep polling
  }
  setTimeout(() => {
    if (state.taskId) poll(); else state.polling = false;
  }, POLL_MS);
}

function addNote(text, cls) {
  const li = el("li", "ev " + (cls || ""));
  li.append(el("div", "b", text));
  $("timeline").append(li);
}

function fmtBytes(n) {
  if (n === null || n === undefined) return "n/a";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB";
  return (n / 1024 / 1024).toFixed(1) + " MiB";
}

function argsText(args) {
  if (!args || typeof args !== "object") return "";
  if (typeof args.command === "string") return "$ " + args.command;
  if (typeof args.path === "string" && typeof args.content === "string") return args.path + "\n" + args.content;
  if (typeof args.path === "string") return args.path;
  return JSON.stringify(args, null, 2);
}

function addEvent(wrap) {
  const ev = wrap.event || {};
  state.events++;
  const li = el("li", "ev");
  const head = el("div", "h");
  const body = el("div", "b");
  li.append(head, body);
  const step = ev.step !== undefined ? "step " + ev.step + " · " : "";
  switch (ev.type) {
    case "sandbox_created": {
      head.textContent = "sandbox created";
      const l = ev.limits || {};
      body.textContent = "memory " + fmtBytes(l.memory_bytes) + " · " + l.cpus + " CPU · " + l.pids +
        " processes · " + l.command_timeout_s + " s per command · no network";
      li.classList.add("good");
      break;
    }
    case "llm_call":
      head.textContent = step + "model call · " + ev.status + " · " + ev.tokens_in + " in / " + ev.tokens_out + " out · " + ev.duration_ms + " ms";
      if (ev.assistant_text) {
        // The tool call is shown as its own event; keep only the model's prose here.
        const prose = ev.assistant_text.replace(/```[a-z]*\n?[\s\S]*?(```|$)/g, "").trim();
        if (prose) body.textContent = prose + (ev.truncated ? " …" : "");
      }
      if (ev.status !== "ok") li.classList.add("bad");
      break;
    case "tool_call":
      head.textContent = step + "agent calls " + ev.tool;
      li.classList.add("tool");
      { const pre = el("pre", null, argsText(ev.args) + (ev.args_truncated ? "\n…" : "")); body.append(pre); }
      break;
    case "tool_result": {
      let h = step + ev.tool + " → " + (ev.ok ? "ok" : "failed");
      if (ev.exit_code !== null && ev.exit_code !== undefined) h += " · exit " + ev.exit_code;
      h += " · " + ev.duration_ms + " ms";
      if (ev.limit_hit) { h += " · LIMIT HIT: " + ev.limit_hit; li.classList.add("limit"); }
      head.textContent = h;
      if (ev.output_excerpt) body.append(el("pre", null, ev.output_excerpt + (ev.truncated ? "\n… (" + fmtBytes(ev.output_bytes) + " total)" : "")));
      break;
    }
    case "action_blocked":
      head.textContent = step + "BLOCKED · " + ev.tool;
      body.textContent = "Reason: " + String(ev.blocked_reason).replace(/_/g, " ") + " (by " + ev.source.replace(/_/g, " ") + ")";
      li.classList.add("blocked");
      break;
    case "budget_stop":
      head.textContent = step + "stopped by budget";
      body.textContent = String(ev.reason).replace(/_/g, " ");
      li.classList.add("bad");
      break;
    case "resource_peak":
      head.textContent = "resource use (sampled)";
      body.textContent = "memory " + fmtBytes(ev.memory_bytes) + " · processes " + (ev.pids ?? "n/a") + " · CPU " + (ev.cpu_ms ?? "n/a") + " ms";
      break;
    case "artifact_collected":
      head.textContent = "diff collected";
      body.textContent = ev.state === "ok" ? (ev.files || []).length + " file(s), " + fmtBytes(ev.size_bytes) : String(ev.state).replace(/_/g, " ");
      break;
    case "sandbox_destroyed":
      head.textContent = "sandbox destroyed";
      body.textContent = "container " + ev.container_ref + (ev.verified ? " · verified gone" : " · not verified");
      li.classList.add(ev.verified ? "good" : "bad");
      break;
    case "sandbox_destroy_failed":
      head.textContent = "sandbox destroy FAILED";
      body.textContent = "container " + ev.container_ref + " · " + (ev.error_class || "unknown error");
      li.classList.add("bad");
      break;
    case "task_finished":
      head.textContent = "task finished · " + String(ev.reason).replace(/_/g, " ") + " · " + ev.steps_used + " steps";
      if (ev.summary) body.textContent = ev.summary;
      li.classList.add(ev.reason === "agent_finished" ? "good" : "bad");
      break;
    default:
      head.textContent = String(ev.type || wrap.type || "event");
  }
  $("timeline").append(li);
}

// ---------------------------------------------------------------- report

function stat(k, v) {
  const d = el("div", "stat");
  d.append(el("div", "k", k), el("div", "v", v));
  return d;
}

function renderReport(t) {
  const r = t.report;
  const box = $("report-body");
  box.textContent = "";
  $("report").hidden = false;
  if (!r) {
    box.append(el("p", "muted", t.status === "finished" ? "No report was recorded." :
      "The task did not run (" + String(t.end_reason || t.status).replace(/_/g, " ") + ")."));
    return;
  }
  const v = el("p", "verdict " + (r.contained ? "ok" : "bad"),
    r.contained ? "Contained: the sandbox was destroyed and verified gone. " +
                  (r.diff.state === "ok" ? "Nothing left the sandbox except the diff below." : "Nothing left the sandbox.")
                : r.sandbox === "destroy_failed" ? "Warning: the sandbox could not be verified as destroyed."
                : "No sandbox was created.");
  box.append(v);
  const g = el("div", "grid");
  const tools = Object.entries(r.tools_used).filter(([, n]) => n > 0).map(([k, n]) => k + " ×" + n).join(", ") || "none";
  const blocked = r.blocked_actions.reduce((a, b) => a + b.count, 0);
  const limits = r.limit_hits.map((h) => h.limit.replace(/_/g, " ") + (h.count > 1 ? " ×" + h.count : "")).join(", ") || "none";
  g.append(
    stat("End reason", String(r.end_reason).replace(/_/g, " ")),
    stat("Steps", String(r.steps_used)),
    stat("Tokens", r.tokens_in.toLocaleString() + " in / " + r.tokens_out.toLocaleString() + " out"),
    stat("Cost", "$" + (r.cost_usd_micros / 1e6).toFixed(4)),
    stat("Tool calls", tools),
    stat("Blocked actions", String(blocked)),
    stat("Limits hit", limits),
    stat("Peak memory (sampled)", fmtBytes(r.resource_peak.memory_bytes)),
    stat("Network", "none (no interface)"),
    stat("Secrets in sandbox", "none passed in"),
    stat("Diff", r.diff.state === "ok" ? r.diff.files.length + " file(s), " + fmtBytes(r.diff.size_bytes) : r.diff.state.replace(/_/g, " ")),
  );
  box.append(g);
  if (r.blocked_actions.length) {
    const ul = el("ul");
    for (const b of r.blocked_actions) ul.append(el("li", null, b.reason.replace(/_/g, " ") + " ×" + b.count + " (by " + b.source.replace(/_/g, " ") + ")"));
    box.append(el("p", "muted", "Blocked:"), ul);
  }
  if (!r.events_complete) box.append(el("p", "muted small", "Some events could not be recorded; the counts above come from the events that were."));
}

// ---------------------------------------------------------------- diff + review

function renderDiffText(text) {
  const pre = $("diff");
  pre.textContent = "";
  for (const line of text.split("\n")) {
    let cls = "";
    if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff ") || line.startsWith("index ")) cls = "meta";
    else if (line.startsWith("+")) cls = "add";
    else if (line.startsWith("-")) cls = "del";
    else if (line.startsWith("@@")) cls = "hunk";
    pre.append(el("span", cls, line));
  }
}

function setReviewState(rs) {
  const id = state.taskId;
  const p = $("review-state");
  p.textContent = rs;
  p.className = "pill " + ({ approved: "ok", rejected: "bad", pending: "warn" }[rs] || "");
  const pending = rs === "pending";
  $("approve").hidden = !pending;
  $("reject").hidden = !pending;
  const dl = $("download");
  dl.hidden = rs !== "approved";
  if (rs === "approved") {
    dl.href = API + "/tasks/" + encodeURIComponent(id) + "/patch";
    dl.setAttribute("download", "airlock-" + id + ".patch");
  } else {
    dl.removeAttribute("href");
  }
}

async function loadDiff(t) {
  if (!t.report || t.report.diff.state !== "ok") return;
  try {
    const d = (await api("GET", "/tasks/" + encodeURIComponent(t.id) + "/diff")).diff;
    $("review").hidden = false;
    $("diff-meta").textContent = d.files.map((f) => f.path + " (+" + f.lines_added + " −" + f.lines_removed + ")").join(" · ") +
      " · sha256 " + String(d.sha256).slice(0, 16) + "…";
    renderDiffText(d.text);
    setReviewState(d.review_state);
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) addNote(errorText(e), "bad");
  }
}

async function review(decision) {
  $("approve").disabled = true;
  $("reject").disabled = true;
  try {
    const r = await api("POST", "/tasks/" + encodeURIComponent(state.taskId) + "/review", { decision });
    setReviewState(r.review_state);
  } catch (e) {
    addNote(errorText(e), "bad");
  } finally {
    $("approve").disabled = false;
    $("reject").disabled = false;
  }
}

// ---------------------------------------------------------------- boot

async function boot() {
  const ta = $("instruction");
  ta.addEventListener("input", () => { $("count").textContent = ta.value.length + " / 2000"; });
  $("run-custom").addEventListener("click", () => {
    const text = ta.value.trim();
    const s = currentSample();
    if (!s || !text) { startMsg("Write an instruction first.", true); return; }
    submitTask({ sample_id: s.id, instruction: text }, text);
  });
  $("approve").addEventListener("click", () => review("approve"));
  $("reject").addEventListener("click", () => review("reject"));
  renderHistory();
  try {
    const s = await ensureSession();
    await loadSamples();
    setStartEnabled(renderQuota(s));
  } catch (e) {
    setStartEnabled(false);
    startMsg(errorText(e), true);
  }
  setInterval(refreshQuota, 15000);
}

boot();
