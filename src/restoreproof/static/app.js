/* RestoreProof dashboard: dependency-free, hash-routed. All API data is HTML-escaped before rendering. */
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const view = $("#view");
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const badge = (s) => s ? `<span class="badge b-${esc(s)}">${esc(String(s).replace("_", " "))}</span>` : `<span class="muted">—</span>`;
const short = (id, n = 8) => id ? esc(String(id).slice(0, n)) : "—";
const bytes = (n) => { if (n == null) return "—"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };
const ms = (v) => v == null ? "—" : v >= 60000 ? `${(v / 60000).toFixed(1)} min` : v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${v} ms`;
function ago(t) {
  if (!t) return "never";
  const s = (Date.now() - new Date(t).getTime()) / 1000, f = Math.abs(s), fut = s < 0;
  const txt = f < 60 ? `${Math.round(f)}s` : f < 3600 ? `${Math.round(f / 60)} min` : f < 86400 ? `${(f / 3600).toFixed(1)} h` : `${(f / 86400).toFixed(1)} days`;
  return fut ? `in ${txt}` : `${txt} ago`;
}
const when = (t) => t ? `<span title="${esc(new Date(t).toLocaleString())}">${esc(ago(t))}</span>` : `<span class="muted">never</span>`;

function toast(msg) {
  const el = document.createElement("div"); el.className = "t"; el.textContent = msg;
  $("#toast").appendChild(el); setTimeout(() => el.remove(), 5000);
}

// ---------------------------------------------------------------- API
const store = { get token() { try { return sessionStorage.getItem("rp_token"); } catch { return null; } },
  set token(v) { try { v ? sessionStorage.setItem("rp_token", v) : sessionStorage.removeItem("rp_token"); } catch { /* ignore */ } } };
let me = null;

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (store.token) headers.Authorization = `Bearer ${store.token}`;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api/v1${path}`, { ...opts, headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
  if (res.status === 401 && !path.startsWith("/auth/login")) { store.token = null; me = null; location.hash = "#/login"; throw new Error("Please sign in"); }
  if (res.status === 204) return null;
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("json") ? await res.json() : await res.text();
  if (!res.ok) {
    const e = data && data.error ? data.error : { message: String(data) };
    const err = new Error(e.message || "request failed"); err.code = e.code; err.details = e.details; throw err;
  }
  return data;
}
const errText = (e) => esc(e.message) + (Array.isArray(e.details) ? "\n" + e.details.map((d) => `• ${esc(d.loc)}: ${esc(d.msg)}`).join("\n") : "");

async function openAuthed(path, download) {
  const res = await fetch(`/api/v1${path}`, { headers: { Authorization: `Bearer ${store.token}` } });
  if (!res.ok) { toast("Report not available"); return; }
  const url = URL.createObjectURL(await res.blob());
  if (download) { const a = document.createElement("a"); a.href = url; a.download = download; a.click(); }
  else window.open(url, "_blank", "noopener");
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

// ---------------------------------------------------------------- Router
const routes = [];
const route = (re, fn) => routes.push([re, fn]);
let refreshTimer = null;

// Renders are serialized: a hash change during an in-flight render re-runs it afterwards, so a slow,
// stale render can never overwrite a newer page.
let rendering = false, renderAgain = false;
async function render() {
  if (rendering) { renderAgain = true; return; }
  rendering = true;
  try { await renderNow(); } finally {
    rendering = false;
    if (renderAgain) { renderAgain = false; render(); }
  }
}

async function renderNow() {
  clearTimeout(refreshTimer);
  const hash = location.hash.slice(1) || "/";
  if (!store.token && !["/login", "/setup"].includes(hash)) {
    const st = await fetch("/api/v1/setup").then((r) => r.json()).catch(() => ({}));
    const target = st.needs_setup ? "#/setup" : "#/login";
    if (location.hash !== target) { location.hash = target; return; }
  }
  if (store.token && !me) { try { me = await api("/auth/me"); } catch { return; } }
  $("#nav").hidden = !me;
  $("#who").innerHTML = me ? `${esc(me.email)} · ${esc(me.role)} · <a href="#/logout">sign out</a>` : "";
  document.querySelectorAll("nav a").forEach((a) => {
    const h = a.getAttribute("href").slice(1);
    a.classList.toggle("active", h === "/" ? hash === "/" : hash.startsWith(h));
  });
  for (const [re, fn] of routes) {
    const m = hash.match(re);
    if (m) {
      try { await fn(...m.slice(1)); } catch (e) { if (e.message !== "Please sign in") view.innerHTML = `<div class="notice bad">${errText(e)}</div>`; }
      return;
    }
  }
  view.innerHTML = `<p>Not found.</p>`;
}
window.addEventListener("hashchange", render);
const can = (role) => me && ["viewer", "operator", "admin"].indexOf(me.role) >= ["viewer", "operator", "admin"].indexOf(role);
const autoRefresh = (fn, secs = 5) => { refreshTimer = setTimeout(() => { if (!document.hidden) fn(); else autoRefresh(fn, secs); }, secs * 1000); };

// ---------------------------------------------------------------- Auth pages
route(/^\/setup$/, () => {
  view.innerHTML = `<div class="narrow card"><h1>Welcome to RestoreProof</h1>
    <p class="muted">Create the administrator account. This form only works while no users exist.</p>
    <form id="f"><label>Email</label><input name="email" type="email" required autocomplete="username">
    <label>Password (min. 12 characters)</label><input name="password" type="password" minlength="12" required autocomplete="new-password">
    <div class="actions"><button class="primary">Create administrator</button></div><p class="err" id="e"></p></form></div>`;
  $("#f").onsubmit = async (ev) => {
    ev.preventDefault(); const f = new FormData(ev.target);
    try { const r = await api("/setup", { method: "POST", body: { email: f.get("email"), password: f.get("password") } });
      store.token = r.token; me = r.user; location.hash = "#/"; } catch (e) { $("#e").innerHTML = errText(e); }
  };
});
route(/^\/login$/, () => {
  view.innerHTML = `<div class="narrow card"><h1>Sign in</h1>
    <form id="f"><label>Email</label><input name="email" type="email" required autocomplete="username">
    <label>Password</label><input name="password" type="password" required autocomplete="current-password">
    <div class="actions"><button class="primary">Sign in</button></div><p class="err" id="e"></p></form></div>`;
  $("#f").onsubmit = async (ev) => {
    ev.preventDefault(); const f = new FormData(ev.target);
    try { const r = await api("/auth/login", { method: "POST", body: { email: f.get("email"), password: f.get("password") } });
      store.token = r.token; me = r.user; location.hash = "#/"; } catch (e) { $("#e").innerHTML = errText(e); }
  };
});
route(/^\/logout$/, async () => { try { await api("/auth/logout", { method: "POST" }); } catch { /* ignore */ } store.token = null; me = null; location.hash = "#/login"; });

// ---------------------------------------------------------------- Overview
function appCard(a) {
  const latest = a.latest_job || {}, lp = a.last_passed_job;
  const cls = a.freshness === "overdue" ? "overdue" : (latest.status || "untested");
  return `<a class="card app-card ${esc(cls)}" href="#/apps/${esc(a.id)}">
    <div class="row spread"><span class="name">${esc(a.name)}</span>${badge(latest.status || "untested")}</div>
    <dl class="facts">
      <dt>Last test</dt><dd>${when(latest.created_at)}${latest.cleanup_status === "cleanup_failed" ? ` ${badge("cleanup_failed")}` : ""}</dd>
      <dt>Last pass</dt><dd>${lp ? when(lp.finished_at) : `<span class="muted">no successful test yet</span>`}</dd>
      <dt>Freshness</dt><dd>${badge(a.freshness)}</dd>
      <dt>Recovery point</dt><dd class="mono">${short((latest.summary || {}).recovery_point, 12)}</dd>
      <dt>Schedule</dt><dd>${a.policy && a.policy.enabled ? `${esc(a.policy.schedule)} · next ${when(a.policy.next_run_at)}` : `<span class="muted">manual only</span>`}</dd>
      <dt>Test depth</dt><dd>${typeof depthLine === "function" ? depthLine(a.layers_configured) : ""}</dd>
    </dl></a>`;
}

route(/^\/$/, async () => {
  const [o, sources] = await Promise.all([api("/overview"), api("/sources")]);
  const c = o.counts;
  const passedRecently = o.apps.filter((a) => a.freshness === "fresh").length;
  const onboarding = !sources.length || !o.apps.length || !o.recent_jobs.length;
  if (!sources.length && !o.apps.length && can("admin")) { location.hash = "#/welcome"; return; }
  view.innerHTML = `
    <div class="row spread"><div><h1>Recovery readiness</h1><p class="muted">Is each protected application recoverable from a recent, tested backup?</p></div>
    ${can("admin") ? `<a class="btn" href="#/apps/new">+ Protect an application</a>` : ""}</div>
    ${onboarding ? `<div class="card hero"><div><h2 style="margin:0">Set up your first recovery test</h2>
      <p class="muted" style="margin:4px 0 0">Connect a backup, pick an app template, and see whether it really restores. About five minutes.</p></div>
      <a class="btn primary" href="#/welcome">Start guided setup →</a></div>` : ""}
    ${o.cleanup_warnings ? `<div class="notice bad"><b>${o.cleanup_warnings} temporary resource(s) could not be cleaned up.</b> Open the affected runs to see what needs manual removal.</div>` : ""}
    ${o.workers.total && !o.workers.online ? `<div class="notice bad"><b>No worker is online.</b> Queued tests will not run. Start <code>restoreproof worker</code>.</div>` : ""}
    ${!o.workers.total ? `<div class="notice">No worker has registered yet. Tests are queued until <code>restoreproof worker</code> runs.</div>` : ""}
    <div class="stats">
      <div class="card stat"><div class="n">${c.apps}</div><div class="l">Protected apps</div></div>
      <div class="card stat"><div class="n">${passedRecently} / ${c.apps}</div><div class="l">Recently passed</div></div>
      <div class="card stat"><div class="n">${c.failing}</div><div class="l">Failing / unknown</div></div>
      <div class="card stat"><div class="n">${c.overdue}</div><div class="l">Overdue</div></div>
      <div class="card stat"><div class="n">${c.untested}</div><div class="l">Untested</div></div>
      <div class="card stat"><div class="n">${c.running}</div><div class="l">Running now</div></div>
    </div>
    <div class="grid">${o.apps.map(appCard).join("") || `<p class="muted">No applications yet.</p>`}</div>
    <div class="grid" style="margin-top:20px">
      <div><h2>Recent runs</h2><div class="table-wrap"><table><tr><th>Application</th><th>Result</th><th>Cleanup</th><th>When</th></tr>
        ${o.recent_jobs.map((j) => { const a = o.apps.find((x) => x.id === j.app_id); return `<tr><td><a href="#/jobs/${esc(j.id)}">${esc(a ? a.name : short(j.app_id))}</a> <span class="muted small">${esc(j.trigger)}</span></td><td>${badge(j.status)}</td><td>${badge(j.cleanup_status)}</td><td>${when(j.created_at)}</td></tr>`; }).join("") || `<tr><td colspan="4" class="muted">No runs yet</td></tr>`}</table></div></div>
      <div><h2>Upcoming</h2><div class="table-wrap"><table><tr><th>Application</th><th>Next run</th></tr>
        ${o.upcoming.map((u) => `<tr><td><a href="#/apps/${esc(u.app_id)}">${esc(u.app_name)}</a></td><td>${when(u.next_run_at)}</td></tr>`).join("") || `<tr><td colspan="2" class="muted">Nothing scheduled</td></tr>`}</table></div>
        <h2>Infrastructure</h2><dl class="facts card">
          <dt>Workers online</dt><dd>${o.workers.online} / ${o.workers.total}</dd>
          <dt>Temporary storage</dt><dd>${bytes(o.temporary_storage.bytes)} in use (${o.temporary_storage.files} files)</dd>
          <dt>Free disk</dt><dd>${bytes(o.temporary_storage.free_bytes)}</dd></dl></div>
    </div>`;
  autoRefresh(render, 10);
});

// ---------------------------------------------------------------- Applications
route(/^\/apps$/, async () => {
  const apps = await api("/apps?include_archived=true");
  view.innerHTML = `<div class="row spread"><h1>Applications</h1>${can("admin") ? `<a class="btn" href="#/apps/new">+ Protect an application</a>` : ""}</div>
    <div class="grid" style="margin-top:14px">${apps.map((a) => appCard({ ...a, freshness: a.archived ? "archived" : (a.last_passed_job ? "tested" : a.latest_job ? "never_passed" : "untested") })).join("") || `<p class="muted">No applications yet.</p>`}</div>`;
});

route(/^\/apps\/(?!new$)([\w-]+)$/, async (id) => {
  const [a, jobs] = await Promise.all([api(`/apps/${id}`), api(`/jobs?app_id=${id}&limit=25`)]);
  const p = a.policy || {}, latest = a.latest_job, active = latest && ["queued", "running"].includes(latest.status);
  const durations = jobs.items.filter((j) => j.finished_at && j.started_at).map((j) => new Date(j.finished_at) - new Date(j.started_at));
  view.innerHTML = `
    <div class="row spread"><div><h1>${esc(a.name)} ${a.archived ? badge("archived") : ""}</h1><p class="muted">${esc(a.description)}</p></div>
      <div class="row">${can("operator") && !a.archived ? `<button class="primary" id="run" ${active ? "disabled" : ""}>${active ? "Test in progress…" : "Test recovery now"}</button>` : ""}</div></div>
    <div class="grid">
      <div class="card"><h3>Latest attempt</h3>${latest ? `<p>${badge(latest.status)} ${when(latest.created_at)} · <a href="#/jobs/${esc(latest.id)}">details</a></p>` : `<p class="muted">Never tested</p>`}
        <h3>Last passed test</h3>${a.last_passed_job ? `<p>${badge("passed")} ${when(a.last_passed_job.finished_at)} · <a href="#/jobs/${esc(a.last_passed_job.id)}">report</a></p>` : `<p class="muted">No successful test yet</p>`}</div>
      <div class="card"><h3>Test configuration</h3><dl class="facts">
        <dt>Recovery point</dt><dd>${esc(a.recovery_point_policy.policy)}${a.recovery_point_policy.maxAgeHours ? ` ≤ ${a.recovery_point_policy.maxAgeHours} h` : ""}${a.recovery_point_policy.host ? ` · host ${esc(a.recovery_point_policy.host)}` : ""}</dd>
        <dt>Test depth</dt><dd>${depthLine(a.layers_configured)}</dd>
        <dt>Checks</dt><dd>${a.check_count}</dd><dt>Databases</dt><dd>${esc(a.resources.databases.join(", ") || "—")}</dd><dt>Services</dt><dd>${esc(a.resources.services.join(", ") || "—")}</dd>
        <dt>Limits</dt><dd>${ms(a.limits.maxDurationSeconds * 1000)} · ${bytes(a.limits.maxBytes)}</dd>
        <dt>Objectives</dt><dd>RPO ${a.objectives.rpoHours ? esc(a.objectives.rpoHours) + " h" : "—"} · RTO ${a.objectives.rtoMinutes ? esc(a.objectives.rtoMinutes) + " min" : "—"}</dd>
        <dt>Definition</dt><dd>v${a.definition_version} <span class="mono">${short(a.definition_sha256, 12)}</span></dd>
        <dt>Test duration</dt><dd>${durations.length ? `median ${ms(durations.sort((x, y) => x - y)[Math.floor(durations.length / 2)])} (indicator for RTO, not a guarantee)` : "—"}</dd></dl></div>
      <div class="card"><h3>Schedule</h3>
        <form id="pol"><label>Cron expression</label><input name="schedule" value="${esc(p.schedule || "0 3 * * *")}" ${can("admin") ? "" : "disabled"}>
        <label>Time zone</label><input name="timezone" value="${esc(p.timezone || "UTC")}" ${can("admin") ? "" : "disabled"}>
        <label>Alert if no pass within (hours)</label><input name="max_age" type="number" min="1" value="${esc(p.max_age_last_success_hours || 48)}" ${can("admin") ? "" : "disabled"}>
        <label>Random jitter (seconds)</label><input name="jitter" type="number" min="0" value="${esc(p.jitter_seconds || 0)}" ${can("admin") ? "" : "disabled"}>
        <label><input type="checkbox" name="enabled" style="width:auto" ${p.enabled ? "checked" : ""} ${can("admin") ? "" : "disabled"}> Scheduled tests enabled</label>
        <p class="small muted">${p.enabled ? `Next run ${when(p.next_run_at)}` : "Scheduling unlocks after a manual test has been run and reviewed."}</p>
        ${can("admin") ? `<div class="actions"><button>Save schedule</button></div>` : ""}<p class="err" id="pe"></p></form></div>
    </div>
    ${a.name === "demo-notes" && can("admin") ? `<div id="demo-panel" style="margin-top:12px"></div>` : ""}
    ${a.has_inventory ? `<h2>Trusted baseline</h2><div id="baselines" class="muted">Loading…</div>` : ""}
    <h2>History</h2><div class="table-wrap"><table><tr><th>Run</th><th>Result</th><th>Cleanup</th><th>Checks</th><th>Recovery point</th><th>Trigger</th><th>Started</th><th>Duration</th></tr>
      ${jobs.items.map((j) => `<tr><td><a href="#/jobs/${esc(j.id)}" class="mono">${short(j.id)}</a></td><td>${badge(j.status)}</td><td>${badge(j.cleanup_status)}</td>
        <td>${j.summary.passed_checks != null ? `${j.summary.passed_checks}✓ ${j.summary.failed_checks}✗ ${(j.summary.error_checks || 0) + (j.summary.skipped_checks || 0)}?` : "—"}</td>
        <td class="mono">${short(j.summary.recovery_point, 12)}</td><td>${esc(j.trigger)}</td><td>${when(j.created_at)}</td>
        <td>${j.finished_at && j.started_at ? ms(new Date(j.finished_at) - new Date(j.started_at)) : "—"}</td></tr>`).join("") || `<tr><td colspan="8" class="muted">No runs yet</td></tr>`}</table></div>
    <h2>Test definition</h2>
    <form id="def" class="card"><textarea name="yaml" spellcheck="false" ${can("admin") ? "" : "readonly"}>${esc(a.test_definition)}</textarea>
      ${can("admin") ? `<div class="actions"><button type="button" id="vd">Validate</button><button>Save as new version</button>
      <button type="button" class="danger" id="arch">${a.archived ? "Unarchive" : "Archive"}</button></div>` : ""}<p class="err" id="de"></p>
      <details><summary>Version history</summary><div id="versions" class="small muted">Loading…</div></details></form>
    <h2>Share &amp; reuse</h2><div class="row">
      <button id="export">Export (.json)</button>
      ${can("admin") ? `<button id="dup">Duplicate</button><button id="as-tpl">Save as my template</button>` : ""}</div>
    <p class="small muted">Export downloads this test so you can keep it, share it, or import it on another RestoreProof.</p>
    ${can("admin") ? `<h2>Danger zone</h2><div class="card danger-zone">
      <b>Delete this application</b>
      <p class="small muted">Stops all testing of ${esc(a.name)}. Your backups are not touched.</p>
      <label class="check"><input type="radio" name="keep" value="1" checked> Keep its past test results and reports (recommended)</label>
      <label class="check"><input type="radio" name="keep" value="0"> Delete everything, including past results and reports</label>
      <div class="actions"><input id="confirm-name" placeholder="type ${esc(a.name)} to confirm" style="max-width:280px"><button class="danger" id="del-app" disabled>Delete application</button></div>
      <p class="err" id="del-err"></p></div>` : ""}`;

  const run = $("#run");
  if (run) run.onclick = async () => {
    if (!confirm(`This restores a backup into a temporary, isolated environment.\nIt may use up to ${bytes(a.limits.maxBytes) || "the snapshot size in"} disk and run for up to ${ms(a.limits.maxDurationSeconds * 1000)}.\n\nStart the test now?`)) return;
    try { const r = await api(`/apps/${id}/test`, { method: "POST", body: { acknowledge_resource_usage: true }, headers: { "Idempotency-Key": crypto.randomUUID() } }); location.hash = `#/jobs/${r.job_id}`; }
    catch (e) { toast(e.message); }
  };
  $("#pol").onsubmit = async (ev) => {
    ev.preventDefault(); const f = new FormData(ev.target);
    try { await api(`/apps/${id}/policy`, { method: "PUT", body: { schedule: f.get("schedule"), timezone: f.get("timezone"), enabled: f.get("enabled") === "on", max_age_last_success_hours: +f.get("max_age"), jitter_seconds: +f.get("jitter") } });
      toast("Schedule saved"); render(); } catch (e) { $("#pe").innerHTML = errText(e); }
  };
  const vd = $("#vd");
  if (vd) {
    vd.onclick = async () => { try { await api("/definitions/validate", { method: "POST", body: { test_definition: $("#def [name=yaml]").value } }); $("#de").textContent = ""; toast("Definition is valid"); } catch (e) { $("#de").innerHTML = errText(e); } };
    $("#def").onsubmit = async (ev) => { ev.preventDefault(); try { await api(`/apps/${id}`, { method: "PATCH", body: { test_definition: $("#def [name=yaml]").value } }); toast("Saved"); render(); } catch (e) { $("#de").innerHTML = errText(e); } };
    $("#arch").onclick = async () => { await api(`/apps/${id}`, { method: "PATCH", body: { archived: !a.archived } }); render(); };
    const cn = $("#confirm-name"), del = $("#del-app");
    cn.oninput = () => { del.disabled = cn.value.trim() !== a.name; };
    del.onclick = async () => {
      const keep = view.querySelector("[name=keep]:checked").value === "1";
      try { const r = await api(`/apps/${id}?keep_history=${keep}`, { method: "DELETE" });
        toast(r.history_kept ? `Deleted. ${r.runs} past run(s) are still listed under Runs.` : "Deleted with its history."); location.hash = "#/apps"; }
      catch (e) { $("#del-err").innerHTML = errText(e); }
    };
    $("#dup").onclick = async () => {
      const copy = a.test_definition.replace(/^(\s*name:\s*)(\S+)/m, (m, p1, p2) => `${p1}${p2.replace(/['"]/g, "")}-copy`);
      try { const n = await api("/apps", { method: "POST", body: { source_id: a.source_id, test_definition: copy } }); location.hash = `#/apps/${n.id}`; }
      catch (e) { toast(e.message); }
    };
    $("#as-tpl").onclick = async () => {
      try { const t = await api(`/apps/${id}/save-as-template`, { method: "POST" }); toast(`Saved as template "${t.name}". It now appears in Protect an application.`); }
      catch (e) { toast(e.message); }
    };
  }
  if (a.has_inventory) api(`/apps/${id}/baselines`).then((bs) => {
    const act = bs.filter((b) => b.active);
    $("#baselines").innerHTML = act.length ? `<div class="card">${act.map((b) => `<div>${badge("ok")} <b>${esc(b.check_name)}</b>: ${b.file_count} files, ${bytes(b.total_bytes)} · snapshot <span class="mono">${short(b.recovery_point, 12)}</span> · approved ${when(b.approved_at)}</div>`).join("")}
      <p class="small muted">Each test fails if too many of these files disappear or the data shrinks sharply. Approve a newer run on its run page to update it.</p></div>`
      : `<div class="notice">No baseline yet. Open a run you have reviewed and press <b>Trust this run as the baseline</b> to turn on shrinking-backup detection.</div>`;
  });
  if ($("#demo-panel")) demoPanel($("#demo-panel"), id);
  $("#export").onclick = () => openAuthed(`/apps/${id}/export`, `${a.name}.restoreproof.json`);
  api(`/apps/${id}/versions`).then((vs) => { $("#versions").innerHTML = vs.map((v) => `<div>v${v.version} · <span class="mono">${short(v.sha256, 12)}</span> · ${when(v.created_at)}</div>`).join(""); });
  if (active) autoRefresh(render, 4);
});

// ---------------------------------------------------------------- Runs
route(/^\/jobs(?:\?(.*))?$/, async (qs) => {
  const params = new URLSearchParams(qs || ""); const status = params.get("status") || "";
  const jobs = await api(`/jobs?limit=100${status ? `&status=${encodeURIComponent(status)}` : ""}`);
  const opt = (v, l) => `<option value="${v}" ${status === v ? "selected" : ""}>${l}</option>`;
  view.innerHTML = `<div class="row spread"><h1>Runs</h1><select id="st" style="width:auto">${opt("", "All")}${opt("passed", "Passed")}${opt("failed,timed_out,blocked,inconclusive", "Not passed")}${opt("queued,running", "Active")}${opt("cancelled", "Cancelled")}</select></div>
    <p class="muted">${jobs.total} runs</p><div class="table-wrap"><table><tr><th>Run</th><th>Application</th><th>Result</th><th>Cleanup</th><th>Trigger</th><th>Attempts</th><th>Created</th></tr>
    ${jobs.items.map((j) => `<tr><td><a class="mono" href="#/jobs/${esc(j.id)}">${short(j.id)}</a></td><td><a href="#/apps/${esc(j.app_id)}">${esc(j.app_name)}</a></td><td>${badge(j.status)}${j.error_code ? ` <span class="small muted">${esc(j.error_code)}</span>` : ""}</td><td>${badge(j.cleanup_status)}</td><td>${esc(j.trigger)}</td><td>${j.attempt_count}</td><td>${when(j.created_at)}</td></tr>`).join("") || `<tr><td colspan="7" class="muted">No runs</td></tr>`}</table></div>`;
  $("#st").onchange = (e) => { location.hash = `#/jobs${e.target.value ? `?status=${encodeURIComponent(e.target.value)}` : ""}`; };
  autoRefresh(render, 10);
});

function checkExtras(c, j) {
  const d = c.details || {};
  let h = "";
  if (d.hint && ["failed", "error"].includes(c.status)) h += `<div class="fix"><b>What to do next:</b> ${esc(d.hint)}</div>`;
  if (d.suggestions && d.suggestions.length) h += `<div class="small">Found in the restore: ${d.suggestions.map((x) => `<code>${esc(x)}</code>`).join(", ")}</div>`;
  if (d.suggested_base_paths && d.suggested_base_paths.length && can("admin")) {
    h += `<div class="row small" style="margin-top:6px">Set basePath to: ${d.suggested_base_paths.slice(0, 3).map((x) => `<button class="mini" data-basepath="${esc(x)}">${esc(x)}</button>`).join("")}</div>`;
  }
  if (c.type === "inventory" && c.status === "skipped" && can("admin") && j.finished_at) {
    h += `<div style="margin-top:6px"><button class="mini primary" data-baseline="${esc(j.id)}">Trust this run as the baseline</button>
      <span class="small muted">Only if you reviewed the restore. Later runs fail when files from it disappear.</span></div>`;
  }
  if (c.type === "inventory" && c.status === "failed" && can("admin") && j.finished_at) {
    h += `<div style="margin-top:6px"><button class="mini" data-baseline="${esc(j.id)}">The deletions were intentional: use this run as the new baseline</button></div>`;
  }
  return h;
}

function wireCheckActions(j) {
  view.querySelectorAll("[data-basepath]").forEach((b) => b.onclick = async () => {
    const app = await api(`/apps/${j.app_id}`);
    const re = /^(\s*)basePath:.*$/m;
    if (!re.test(app.test_definition)) { toast("No basePath line found; edit the definition on the application page"); return; }
    const yaml = app.test_definition.replace(re, `$1basePath: ${JSON.stringify(b.dataset.basepath)}`);
    try {
      await api(`/apps/${j.app_id}`, { method: "PATCH", body: { test_definition: yaml } });
      const r = await api(`/apps/${j.app_id}/test`, { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() } });
      toast("basePath updated, test restarted"); location.hash = `#/jobs/${r.job_id}`;
    } catch (e) { toast(e.message); }
  });
  view.querySelectorAll("[data-baseline]").forEach((b) => b.onclick = async () => {
    if (!confirm("Use the files restored in this run as the trusted reference? Future runs will be compared with it.")) return;
    try { const r = await api(`/apps/${j.app_id}/baselines`, { method: "POST", body: { job_id: b.dataset.baseline } }); toast(`Baseline approved: ${r.map((x) => `${x.file_count} files`).join(", ")}`); b.disabled = true; }
    catch (e) { toast(e.message); }
  });
}

const LAYER_LABEL = { recovery_point: "1 · Recovery point", data: "2 · Backup data", database: "3 · Database", application: "4 · Application", objectives: "Objectives (advisory)" };

route(/^\/jobs\/([\w-]+)$/, async (id) => {
  const j = await api(`/jobs/${id}`);
  const checks = await api(`/jobs/${id}/checks`);
  const att = j.attempts[j.attempts.length - 1] || {};
  const active = ["queued", "running"].includes(j.status);
  const layers = j.summary && j.summary.layers ? j.summary.layers : {};
  const problems = (att.resources || []).filter((r) => r.cleanup_status === "cleanup_failed");
  const hasReport = (att.artifacts || []).some((x) => x.type === "manifest");
  let lastPass = null;
  if (!active && j.status !== "passed") { const lp = await api(`/jobs?app_id=${j.app_id}&status=passed&limit=1`); lastPass = lp.items[0]; }
  view.innerHTML = `
    <p class="small"><a href="#/apps/${esc(j.app_id)}">← ${esc(j.app_name)}</a></p>
    <div class="row spread"><div><h1>Recovery test ${badge(j.status)}</h1>
      <p class="muted">Run <span class="mono">${esc(j.id)}</span> · ${esc(j.trigger)} · created ${when(j.created_at)}${j.not_before && j.status === "queued" ? ` · retry ${when(j.not_before)}` : ""}</p></div>
      <div class="row">${active && can("operator") ? `<button class="danger" id="cancel" ${j.cancel_requested ? "disabled" : ""}>${j.cancel_requested ? "Cancelling…" : "Cancel"}</button>` : ""}
        ${!active && can("operator") ? `<button id="rerun">Run again</button>` : ""}
        ${hasReport ? `<button id="html">Open report</button><button id="json">Download evidence (JSON)</button>` : ""}</div></div>
    ${j.error_message ? `<div class="notice ${["failed", "timed_out"].includes(j.status) ? "bad" : ""}"><b>${esc(j.error_code)}</b>: ${esc(j.error_message)}${j.summary && j.summary.hint ? `<div class="fix"><b>What to do next:</b> ${esc(j.summary.hint)}</div>` : ""}</div>` : ""}
    ${!active && j.summary && j.summary.suggested_base_path ? `<div class="notice good"><b>Likely cause found:</b> the files exist in the snapshot, but under <code>${esc(j.summary.suggested_base_path)}</code>. The backup was taken one level up from what the test expects.
      ${can("admin") ? `<div class="row" style="margin-top:8px"><button class="primary" data-basepath="${esc(j.summary.suggested_base_path)}">Set basePath to ${esc(j.summary.suggested_base_path)} &amp; re-run</button></div>` : ""}</div>` : ""}
    ${!active && j.status !== "passed" && !j.error_message && checks.some((c) => c.required && c.status === "failed") ? `<div class="notice bad"><b>${checks.filter((c) => c.required && c.status === "failed").length} required check(s) failed.</b> Each one below says what to fix.</div>` : ""}
    ${problems.length ? `<div class="notice bad"><b>Cleanup needs attention.</b> These temporary resources could not be removed automatically:<ul>${problems.map((r) => `<li>${esc(r.type)} <span class="mono">${esc(r.external_id)}</span>: ${esc(r.cleanup_error)}</li>`).join("")}</ul>Remove them manually, then run <code>restoreproof reconcile</code>.</div>` : ""}
    <div class="grid">
      <div class="card"><h3>Outcome</h3><dl class="facts"><dt>Recovery</dt><dd>${badge(j.recovery_status || j.status)}</dd><dt>Cleanup</dt><dd>${badge(j.cleanup_status || att.cleanup_status)}</dd>
        <dt>Evidence</dt><dd>${badge(att.evidence_status === "completed" ? "completed" : att.evidence_status)}</dd>
        <dt>Checks</dt><dd>${j.summary.passed_checks ?? "—"} passed · ${j.summary.failed_checks ?? "—"} failed · ${(j.summary.error_checks || 0) + (j.summary.skipped_checks || 0)} could not run</dd>
        <dt>Manifest</dt><dd class="mono">${short(j.summary.manifest_sha256, 16)}</dd></dl></div>
      <div class="card"><h3>Recovery point</h3><dl class="facts"><dt>Snapshot</dt><dd class="mono">${esc(att.recovery_point ? att.recovery_point.native_id : "—")}</dd>
        <dt>Created</dt><dd>${att.recovery_point && att.recovery_point.created_at ? `${esc(new Date(att.recovery_point.created_at).toLocaleString())} (${esc(ago(att.recovery_point.created_at))})` : "—"}</dd>
        <dt>Restored</dt><dd>${att.restored_files ?? "—"} files · ${bytes(att.restored_bytes)}</dd><dt>Definition</dt><dd>v${j.definition_version}</dd></dl></div>
      <div class="card"><h3>Layers</h3><div class="layers">${Object.keys(LAYER_LABEL).filter((k) => layers[k]).map((k) => `<div class="layer">${esc(LAYER_LABEL[k])} ${badge(layers[k])}</div>`).join("") || `<span class="muted">${active ? "in progress" : "—"}</span>`}</div></div>
    </div>
    <h2>Timeline</h2>
    ${j.attempts.map((a) => `<div class="card" style="margin-bottom:8px"><div class="row spread"><b>Attempt ${a.attempt_number}</b><span>${badge(a.status)} ${a.status === "running" ? `stage <b>${esc(a.stage)}</b> · heartbeat ${when(a.heartbeat_at)}` : ""} <span class="muted small">worker ${esc(a.worker_id)}</span></span></div>
      <div class="timeline">${(a.stages || []).map((s) => `<span class="st ${esc(s.status)}">${esc(s.stage)} · ${ms(s.duration_ms)}</span>`).join("")}${a.timings_ms && a.timings_ms.cleanup != null ? `<span class="st completed">cleanup · ${ms(a.timings_ms.cleanup)}</span>` : ""}</div>
      ${a.error_code ? `<p class="small err">${esc(a.error_code)}: ${esc(a.error_message)}</p>` : ""}</div>`).join("") || `<p class="muted">Waiting for a worker…</p>`}
    <h2>Checks <span class="muted small">(attempt ${att.attempt_number || "—"})</span></h2>
    <div class="table-wrap"><table><tr><th>Layer</th><th>Check</th><th>Result</th><th>What happened</th><th>Time</th></tr>
      ${checks.map((c) => `<tr><td class="small">${esc(LAYER_LABEL[c.layer] || c.layer)}</td><td>${esc(c.name)}${c.required ? "" : ` <span class="small muted">advisory</span>`}</td><td>${badge(c.status)}</td>
        <td>${esc(c.message)}${checkExtras(c, j)}${Object.keys(c.details || {}).length ? `<details><summary class="small">details</summary><pre>${esc(JSON.stringify(c.details, null, 2))}</pre></details>` : ""}</td><td class="small">${ms(c.duration_ms)}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">${active ? "Checks appear here as they complete…" : "No checks recorded"}</td></tr>`}</table></div>
    ${lastPass ? `<h2>Compared with last pass</h2><div id="cmp" class="muted">Loading…</div>` : ""}
    <h2>Temporary resources</h2><div class="table-wrap"><table><tr><th>Type</th><th>Identifier</th><th>Cleanup</th></tr>
      ${(att.resources || []).map((r) => `<tr><td>${esc(r.type)}</td><td class="mono">${esc(r.external_id)}</td><td>${badge(r.cleanup_status)} <span class="small err">${esc(r.cleanup_error || "")}</span></td></tr>`).join("") || `<tr><td colspan="3" class="muted">None</td></tr>`}</table></div>
    ${can("operator") && hasReport ? `<h2>Sanitized log</h2><details><summary>Show restore and container log</summary><pre id="log">Loading…</pre></details>` : ""}`;
  wireCheckActions(j);
  const cancel = $("#cancel"); if (cancel) cancel.onclick = async () => { if (confirm("Cancel this test? Temporary resources will be cleaned up.")) { await api(`/jobs/${id}/cancel`, { method: "POST" }); render(); } };
  const rerun = $("#rerun"); if (rerun) rerun.onclick = async () => { try { const r = await api(`/apps/${j.app_id}/test`, { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() } }); location.hash = `#/jobs/${r.job_id}`; } catch (e) { toast(e.message); } };
  const html = $("#html"); if (html) html.onclick = () => openAuthed(`/jobs/${id}/report?format=html`);
  const json = $("#json"); if (json) json.onclick = () => openAuthed(`/jobs/${id}/report?format=json&download=true`, `restoreproof-${id}.json`);
  const log = $("#log"); if (log) log.parentElement.addEventListener("toggle", async () => { try { const r = await api(`/jobs/${id}/log`); log.textContent = r.text || "(empty)"; } catch (e) { log.textContent = e.message; } }, { once: true });
  if (lastPass) api(`/jobs/${id}/compare?other=${lastPass.id}`).then((cmp) => {
    $("#cmp").innerHTML = cmp.changed.length ? `<div class="table-wrap"><table><tr><th>Check</th><th>This run</th><th>Last pass (${when(lastPass.created_at)})</th></tr>${cmp.changed.map((r) => `<tr><td>${esc(r.check)}</td><td>${badge(r.this && r.this.status)} ${esc(r.this ? r.this.message : "not run")}</td><td>${badge(r.other && r.other.status)}</td></tr>`).join("")}</table></div>` : "No check changed status.";
  });
  if (active) autoRefresh(render, 3);
});

// ---------------------------------------------------------------- Sources
route(/^\/sources$/, async () => {
  const sources = await api("/sources");
  view.innerHTML = `<h1>Backup sources</h1><p class="muted">RestoreProof only reads from repositories: it never runs <code>forget</code>, <code>prune</code> or any other command that changes snapshots.</p>
    ${sources.map((s) => `<div class="card" style="margin-bottom:10px"><div class="row spread"><div><b>${esc(s.name)}</b> <span class="muted">${esc(s.adapter)}</span><div class="mono">${esc(s.repository)}</div></div>
      <div class="row">${can("operator") ? `<button data-validate="${esc(s.id)}">Validate access</button><button data-discover="${esc(s.id)}">Discover snapshots</button>` : ""}<a class="btn" href="#/sources/${esc(s.id)}">Snapshots (${s.recovery_points ?? 0})</a><a class="btn" href="#/browse/${esc(s.id)}">Browse files</a>${can("admin") && !s.is_destination ? `<button data-pw="${esc(s.id)}">Change password</button>` : ""}${can("admin") ? `<button class="danger" data-remove="${esc(s.id)}" data-name="${esc(s.name)}">Remove</button>` : ""}</div></div>
      <dl class="facts"><dt>Credentials</dt><dd>${s.has_credentials ? "stored encrypted" : "missing"}</dd><dt>Last validated</dt><dd>${when(s.last_validated_at)} ${s.last_validation_status ? badge(s.last_validation_status === "ok" ? "ok" : "failed") : ""} <span class="small muted">${esc(s.last_validation_message || "")}</span></dd>
      <dt>Last discovery</dt><dd>${when(s.last_discovered_at)}</dd></dl></div>`).join("") || `<p class="muted">No sources configured.</p>`}
    ${can("admin") ? `<h2>Add a Restic repository</h2><form id="f" class="card"><label>Name</label><input name="name" required placeholder="homelab-nas">
      <label>Repository (path, sftp:, s3:, rest:, b2: …)</label><input name="repo" required placeholder="/mnt/backups/restic or s3:s3.amazonaws.com/bucket">
      <label>Repository password</label><input name="pw" type="password" required autocomplete="off">
      <label>Backend credentials (optional, one KEY=value per line, e.g. AWS_ACCESS_KEY_ID)</label><textarea name="env" style="min-height:70px" autocomplete="off"></textarea>
      <p class="small muted">Credentials are encrypted with a key stored outside the database and are never shown again.</p>
      <div class="actions"><button class="primary">Add source</button></div><p class="err" id="e"></p></form>` : ""}`;
  view.querySelectorAll("[data-pw]").forEach((b) => b.onclick = () => {
    const box = b.closest(".card");
    if (box.querySelector(".pw-form")) return;
    const f = document.createElement("form"); f.className = "pw-form row"; f.style.marginTop = "8px";
    f.innerHTML = `<input type="password" name="pw" placeholder="new repository password" required autocomplete="off" style="max-width:300px"><button class="primary">Save &amp; check</button><span class="small out"></span>`;
    box.appendChild(f);
    f.onsubmit = async (ev) => { ev.preventDefault();
      try { await api(`/sources/${b.dataset.pw}`, { method: "PATCH", body: { credentials: { password: f.pw.value } } });
        const v = await api(`/sources/${b.dataset.pw}/validate`, { method: "POST" });
        $(".out", f).textContent = v.ok ? "Saved. Password accepted." : `Saved, but: ${v.message}`; if (v.ok) setTimeout(render, 1200); }
      catch (e) { $(".out", f).textContent = e.message; } };
  });
  view.querySelectorAll("[data-remove]").forEach((b) => b.onclick = async () => {
    const box = b.closest(".card");
    let note = box.querySelector(".remove-note");
    if (!note) { note = document.createElement("div"); note.className = "remove-note notice"; box.appendChild(note); }
    note.innerHTML = `Remove <b>${esc(b.dataset.name)}</b> from RestoreProof? The backups stored in it are <b>not</b> deleted. <button class="mini danger" data-yes>Yes, remove</button> <button class="mini" data-no>Cancel</button>`;
    note.querySelector("[data-no]").onclick = () => note.remove();
    note.querySelector("[data-yes]").onclick = async () => {
      try { await api(`/sources/${b.dataset.remove}`, { method: "DELETE" }); toast("Removed"); render(); }
      catch (e) { note.className = "remove-note notice bad"; note.innerHTML = `<b>Can't remove yet:</b> ${esc(e.message)}`; }
    };
  });
  view.querySelectorAll("[data-validate]").forEach((b) => b.onclick = async () => { b.disabled = true; try { const r = await api(`/sources/${b.dataset.validate}/validate`, { method: "POST" }); toast(r.ok ? `Access OK (${r.tool_version})` : `Failed: ${r.message}`); } catch (e) { toast(e.message); } render(); });
  view.querySelectorAll("[data-discover]").forEach((b) => b.onclick = async () => { b.disabled = true; try { const r = await api(`/sources/${b.dataset.discover}/discover`, { method: "POST" }); toast(`${r.count} snapshots found`); } catch (e) { toast(e.message); } render(); });
  const f = $("#f");
  if (f) f.onsubmit = async (ev) => {
    ev.preventDefault(); const d = new FormData(ev.target); const env = {};
    for (const line of String(d.get("env")).split("\n")) { const i = line.indexOf("="); if (i > 0) env[line.slice(0, i).trim()] = line.slice(i + 1).trim(); }
    try { await api("/sources", { method: "POST", body: { name: d.get("name"), repository: d.get("repo"), credentials: { password: d.get("pw"), env } } }); toast("Source added — validate it next"); render(); }
    catch (e) { $("#e").innerHTML = errText(e); }
  };
});

route(/^\/sources\/([\w-]+)$/, async (id) => {
  const [s, pts] = await Promise.all([api(`/sources/${id}`), api(`/sources/${id}/recovery-points?limit=200`)]);
  view.innerHTML = `<p class="small"><a href="#/sources">← Sources</a></p><h1>${esc(s.name)} recovery points</h1><p class="muted">${pts.total} snapshots known · last discovery ${when(s.last_discovered_at)}</p>
    <div class="table-wrap"><table><tr><th>Snapshot</th><th>Created</th><th>Host</th><th>Paths</th><th>Tags</th></tr>
    ${pts.items.map((p) => `<tr><td class="mono">${short(p.native_id, 12)}</td><td>${esc(new Date(p.created_at).toLocaleString())} <span class="muted small">(${esc(ago(p.created_at))})</span></td><td>${esc(p.hostname)}</td><td class="mono">${esc(p.paths.join(", "))}</td><td>${esc(p.tags.join(", "))}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">Run discovery to list snapshots.</td></tr>`}</table></div>`;
});

// ---------------------------------------------------------------- Settings & audit
route(/^\/settings$/, async () => {
  const workers = await api("/workers");
  const isAdmin = can("admin");
  const [notif, users] = isAdmin ? await Promise.all([api("/notifications"), api("/users")]) : [null, null];
  view.innerHTML = `<h1>Settings</h1><div id="prod-settings"></div>
    <h2>Workers</h2><div class="table-wrap"><table><tr><th>Worker</th><th>Host</th><th>Version</th><th>Status</th><th>Last heartbeat</th></tr>
      ${workers.map((w) => `<tr><td class="mono">${esc(w.id)}</td><td>${esc(w.hostname)}</td><td>${esc(w.version)}</td><td>${badge(w.state || (w.online ? "online" : "offline"))}${w.note ? `<div class="small muted">${esc(w.note)}</div>` : ""}</td><td>${when(w.heartbeat_at)}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">No worker registered. Start <code>restoreproof worker</code>.</td></tr>`}</table></div>
    ${isAdmin ? `<h2>Notifications</h2><div class="table-wrap"><table><tr><th>Name</th><th>Type</th><th>Events</th><th>Last delivery</th><th></th></tr>
      ${notif.items.map((n) => `<tr><td>${esc(n.name)} ${n.enabled ? "" : badge("disabled")}</td><td>${esc(n.type)}</td><td class="small">${esc(n.events.join(", "))}</td><td class="small">${esc(n.last_delivery_status || "—")}</td>
        <td>${n.enabled ? `<button data-test="${esc(n.id)}">Send test</button> <button class="danger" data-del="${esc(n.id)}">Disable</button>` : ""}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">No destinations yet — failures will only be visible here.</td></tr>`}</table></div>
      <form id="nf" class="card" style="margin-top:10px"><h3>Add destination</h3><div class="grid">
        <div><label>Name</label><input name="name" required></div>
        <div><label>Type</label><select name="type"><option value="ntfy">ntfy</option><option value="webhook">Webhook (JSON POST)</option><option value="email">Email (SMTP)</option></select></div></div>
        <div id="nfields"></div>
        <label>Events</label><div class="row small">${notif.events.filter((e) => e !== "test").map((e) => `<label style="margin:0"><input type="checkbox" style="width:auto" name="ev" value="${esc(e)}" ${["recovery_failed", "cleanup_failed", "source_failure", "test_overdue", "worker_offline"].includes(e) ? "checked" : ""}> ${esc(e)}</label>`).join("")}</div>
        <div class="actions"><button class="primary">Add destination</button></div><p class="err" id="ne"></p></form>
      <h2>Users</h2><div class="table-wrap"><table><tr><th>Email</th><th>Role</th><th>Created</th></tr>${users.map((u) => `<tr><td>${esc(u.email)}</td><td>${esc(u.role)}</td><td>${when(u.created_at)}</td></tr>`).join("")}</table></div>
      <form id="uf" class="card" style="margin-top:10px"><h3>Add user</h3><div class="grid"><div><label>Email</label><input name="email" type="email" required></div>
        <div><label>Password (min 12)</label><input name="password" type="password" minlength="12" required autocomplete="new-password"></div>
        <div><label>Role</label><select name="role"><option>viewer</option><option>operator</option><option>admin</option></select></div></div>
        <div class="actions"><button>Add user</button></div><p class="err" id="ue"></p></form>` : ""}
    ${can("operator") ? `<h2>API token</h2><p class="muted">For automation (CI, external monitoring). Shown once; store it securely.</p><button id="tok">Create API token</button><pre id="tokout" hidden></pre>` : ""}`;

  const fields = { ntfy: `<div class="grid"><div><label>Server</label><input name="server" value="https://ntfy.sh"></div><div><label>Topic (stored encrypted)</label><input name="topic" required></div><div><label>Access token (optional)</label><input name="token" type="password" autocomplete="off"></div></div>`,
    webhook: `<label>URL (stored encrypted)</label><input name="url" required placeholder="https://hooks.example/…"><label>Bearer token (optional)</label><input name="bearer" type="password" autocomplete="off">`,
    email: `<div class="grid"><div><label>SMTP host</label><input name="host" required></div><div><label>Port</label><input name="port" value="587"></div><div><label>TLS</label><select name="tls"><option>starttls</option><option>ssl</option><option>none</option></select></div>
      <div><label>From</label><input name="from" required></div><div><label>To (comma separated)</label><input name="to" required></div><div><label>Username</label><input name="username"></div><div><label>Password</label><input name="password" type="password" autocomplete="off"></div></div>` };
  const nf = $("#nf");
  if (nf) {
    const setFields = () => { $("#nfields").innerHTML = fields[nf.type.value]; }; nf.type.onchange = setFields; setFields();
    nf.onsubmit = async (ev) => {
      ev.preventDefault(); const d = new FormData(nf); const t = d.get("type"); let config = {}, secret = {};
      if (t === "ntfy") { config = { server: d.get("server") }; secret = { topic: d.get("topic") }; if (d.get("token")) secret.token = d.get("token"); }
      if (t === "webhook") { secret = { url: d.get("url") }; if (d.get("bearer")) secret.bearer_token = d.get("bearer"); }
      if (t === "email") { config = { host: d.get("host"), port: +d.get("port"), tls: d.get("tls"), from: d.get("from"), to: String(d.get("to")).split(",").map((x) => x.trim()).filter(Boolean), username: d.get("username") || undefined }; if (d.get("password")) secret.password = d.get("password"); }
      try { await api("/notifications", { method: "POST", body: { name: d.get("name"), type: t, config, secret, events: d.getAll("ev") } }); toast("Destination added"); render(); } catch (e) { $("#ne").innerHTML = errText(e); }
    };
    view.querySelectorAll("[data-test]").forEach((b) => b.onclick = async () => { const r = await api(`/notifications/${b.dataset.test}/test`, { method: "POST" }); toast(r.results.map((x) => `${x.endpoint}: ${x.status}`).join("; ")); render(); });
    view.querySelectorAll("[data-del]").forEach((b) => b.onclick = async () => { if (confirm("Disable this destination?")) { await api(`/notifications/${b.dataset.del}`, { method: "DELETE" }); render(); } });
    $("#uf").onsubmit = async (ev) => { ev.preventDefault(); const d = new FormData(ev.target); try { await api("/users", { method: "POST", body: { email: d.get("email"), password: d.get("password"), role: d.get("role") } }); toast("User added"); render(); } catch (e) { $("#ue").innerHTML = errText(e); } };
  }
  if (typeof productSettings === "function") productSettings($("#prod-settings"));
  const tok = $("#tok");
  if (tok) tok.onclick = async () => { const r = await api("/auth/tokens", { method: "POST", body: { name: "dashboard-created" } }); const o = $("#tokout"); o.hidden = false; o.textContent = r.token; };
});

route(/^\/audit$/, async () => {
  if (!can("admin")) { view.innerHTML = `<div class="notice">The audit trail is visible to administrators.</div>`; return; }
  const ev = await api("/audit-events?limit=200");
  view.innerHTML = `<h1>Audit trail</h1><p class="muted">Configuration changes, credential updates, executions and cleanup events. ${ev.total} events.</p>
    <div class="table-wrap"><table><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr>
    ${ev.items.map((e) => `<tr><td>${when(e.created_at)}</td><td>${esc(e.actor)}</td><td class="mono">${esc(e.action)}</td><td class="small">${esc(e.target_type || "")} <span class="mono">${short(e.target_id)}</span></td><td class="small mono">${esc(JSON.stringify(e.details))}</td></tr>`).join("")}</table></div>`;
});

// render() is started by product.js once every route is registered.
