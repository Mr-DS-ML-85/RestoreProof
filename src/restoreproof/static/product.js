/* Product screens: guided setup, template gallery, readiness report. Shares helpers with app.js. */
"use strict";

const LAYER_SHORT = { recovery_point: "Snapshot", data: "Files", database: "Database", application: "App" };
const depthLine = (layers = []) => ["recovery_point", "data", "database", "application"]
  .map((l) => `<span class="depth ${layers.includes(l) ? "on" : ""}" title="${layers.includes(l) ? "verified by this test" : "not covered by this test"}">${LAYER_SHORT[l]}</span>`).join("");

// ---------------------------------------------------------------- Source form (shared)
function sourceForm(el, onCreated) {
  el.innerHTML = `<form class="card sf">
    <div class="grid"><div><label>Name</label><input name="name" required placeholder="nas-restic"></div>
    <div><label>Repository</label><input name="repo" required placeholder="/mnt/backups/restic · s3:host/bucket · sftp:user@host:/srv/restic"></div></div>
    <label>Repository password</label><input name="pw" type="password" required autocomplete="off">
    <details><summary class="small">Cloud / remote backend credentials</summary>
      <label>One KEY=value per line (e.g. AWS_ACCESS_KEY_ID, B2_ACCOUNT_KEY, RESTIC_REST_PASSWORD)</label>
      <textarea name="env" style="min-height:70px" autocomplete="off"></textarea></details>
    <p class="small muted">Stored encrypted with a key kept outside the database. RestoreProof only reads from the
      repository: it never prunes, forgets or writes snapshots.</p>
    <div class="actions"><button class="primary">Connect &amp; check access</button></div><div class="out"></div></form>`;
  const f = $("form", el);
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    const d = new FormData(f), env = {}, out = $(".out", f), btn = $("button", f);
    for (const line of String(d.get("env")).split("\n")) { const i = line.indexOf("="); if (i > 0) env[line.slice(0, i).trim()] = line.slice(i + 1).trim(); }
    btn.disabled = true; out.innerHTML = `<p class="muted">Connecting…</p>`;
    try {
      const src = await api("/sources", { method: "POST", body: { name: d.get("name"), repository: d.get("repo"), credentials: { password: d.get("pw"), env } } });
      const v = await api(`/sources/${src.id}/validate`, { method: "POST" });
      if (!v.ok) { out.innerHTML = `<div class="notice bad"><b>Could not open the repository:</b> ${esc(v.message)}<br><span class="small">The source was saved; fix it on the Sources page or add it again.</span></div>`; btn.disabled = false; return; }
      const disc = await api(`/sources/${src.id}/discover`, { method: "POST" });
      out.innerHTML = `<div class="notice good">Connected. ${disc.count} snapshot(s) found, newest ${when(disc.latest)}.</div>`;
      onCreated && onCreated(src, disc);
    } catch (e) { out.innerHTML = `<p class="err">${errText(e)}</p>`; btn.disabled = false; }
  };
}

// ---------------------------------------------------------------- Snapshot browser
async function snapshotBrowser(el, sourceId, opts = {}) {
  let path = opts.startPath || "/";
  const draw = async () => {
    el.innerHTML = `<p class="muted small">Reading the snapshot…</p>`;
    let r;
    try { r = await api(`/sources/${sourceId}/browse?path=${encodeURIComponent(path)}`); }
    catch (e) { el.innerHTML = `<div class="notice bad">${esc(e.message)}. Is the source reachable? Try <b>Validate access</b> on the Sources page.</div>`; return; }
    const parts = path.split("/").filter(Boolean);
    const crumbs = [`<a data-go="/">snapshot root</a>`].concat(parts.map((p, i) => `<a data-go="/${esc(parts.slice(0, i + 1).join("/"))}">${esc(p)}</a>`)).join(" / ");
    const base = opts.getBase ? opts.getBase() : null;
    const rel = (full) => { const b = "/" + (base || "").replace(/^\/+|\/+$/g, ""); return b === "/" || b === "/." ? full.replace(/^\//, "") : (full.startsWith(b + "/") ? full.slice(b.length + 1) : null); };
    el.innerHTML = `<div class="crumbs">${crumbs}${r.snapshot && r.snapshot.time ? ` <span class="muted">· snapshot ${esc(new Date(r.snapshot.time).toLocaleString())}</span>` : ""}</div>
      ${opts.onPickFolder ? `<div class="row" style="margin:6px 0"><button type="button" class="mini primary" data-pick="${esc(path)}">Use this folder as the app folder</button>
        <span class="small muted">${base && base !== "." ? `Current app folder: <code>/${esc(base)}</code>` : "Pick the folder that holds the app's files (for example the one with its config or database)."}</span></div>` : ""}
      <div class="browser">${r.entries.map((e) => {
        const rp = rel(e.path);
        const acts = rp && opts.onPickFile ? (e.type === "dir" ? `<button type="button" class="mini" data-need-dir="${esc(rp)}">must not be empty</button>`
          : `<button type="button" class="mini" data-need-file="${esc(rp)}">must exist</button>${/\.json$/i.test(e.name) ? ` <button type="button" class="mini" data-need-json="${esc(rp)}">must parse</button>` : ""}`) : "";
        return `<div class="ent"><span>${e.type === "dir" ? `📁 <a data-go="${esc(e.path)}">${esc(e.name)}</a>` : `📄 ${esc(e.name)} <span class="small muted">${bytes(e.size)}</span>`}</span><span>${acts}</span></div>`;
      }).join("") || `<div class="ent muted">(empty folder)</div>`}</div>
      ${r.truncated ? `<p class="small muted">Showing the first ${r.entries.length} entries.</p>` : ""}`;
    el.querySelectorAll("[data-go]").forEach((a) => a.onclick = () => { path = a.dataset.go; draw(); });
    el.querySelectorAll("[data-pick]").forEach((b) => b.onclick = () => { opts.onPickFolder(b.dataset.pick.replace(/^\//, "") || "."); draw(); });
    el.querySelectorAll("[data-need-file]").forEach((b) => b.onclick = () => { opts.onPickFile("required_files", b.dataset.needFile); b.classList.add("chip-on"); });
    el.querySelectorAll("[data-need-dir]").forEach((b) => b.onclick = () => { opts.onPickFile("required_dirs", b.dataset.needDir); b.classList.add("chip-on"); });
    el.querySelectorAll("[data-need-json]").forEach((b) => b.onclick = () => { opts.onPickFile("json_files", b.dataset.needJson); b.classList.add("chip-on"); });
  };
  draw();
}

route(/^\/browse\/([\w-]+)$/, async (id) => {
  const src = await api(`/sources/${id}`);
  view.innerHTML = `<p class="small"><a href="#/sources">← Sources</a></p><h1>Files in ${esc(src.name)}</h1>
    <p class="muted">The newest snapshot, read-only. Use this to find the paths to put in a recovery test.</p><div id="sb"></div>`;
  snapshotBrowser($("#sb"), id);
});

// ---------------------------------------------------------------- Template gallery
let templatesCache = null;
async function templates() { return templatesCache || (templatesCache = await api("/templates")); }

function paramInput(p) {
  const id = `p_${p.key}`, dv = p.default ?? "";
  if (p.type === "bool") return `<label class="check"><input type="checkbox" id="${id}" name="${esc(p.key)}" ${dv ? "checked" : ""}> ${esc(p.label)}</label>${p.help ? `<div class="help">${esc(p.help)}</div>` : ""}`;
  const input = p.type === "select"
    ? `<select id="${id}" name="${esc(p.key)}">${p.options.map((o) => `<option ${String(o) === String(dv) ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`
    : `<input id="${id}" name="${esc(p.key)}" ${p.type === "int" ? 'type="number" min="0"' : ""} value="${esc(Array.isArray(dv) ? dv.join(", ") : dv)}" ${p.required ? "required" : ""} placeholder="${p.type === "list" ? "comma separated" : ""}">`;
  return `<label for="${id}">${esc(p.label)}</label>${input}${p.help ? `<div class="help">${esc(p.help)}</div>` : ""}`;
}

const ADVANCED = new Set(["max_age_hours", "host", "tag", "rpo_hours", "image", "pg_image"]);

async function gallery(el, { sourceId = null, runAfter = true, onCreated = null } = {}) {
  const [ts, sources] = await Promise.all([templates(), api("/sources")]);
  if (!sources.length) { el.innerHTML = `<div class="notice">Connect a backup repository first.</div>`; return; }
  const sel = sourceId || sources[0].id;
  el.innerHTML = `
    <div class="row"><label style="margin:0">Backup source</label><select id="g-src" style="width:auto">${sources.map((s) => `<option value="${esc(s.id)}" ${s.id === sel ? "selected" : ""}>${esc(s.name)}</option>`).join("")}</select></div>
    <div class="row" style="margin-top:10px"><input id="tsearch" placeholder="Search apps (e.g. wordpress, sqlite, media)" style="max-width:340px">
      ${can("admin") ? `<label class="btn" style="margin:0">Upload template (.json)<input type="file" id="tpl-file" accept=".json,application/json" hidden></label>
      <label class="btn" style="margin:0">Import an app (.json/.yaml)<input type="file" id="app-file" accept=".json,.yaml,.yml" hidden></label>` : ""}
      <a class="btn" href="#/help/templates">How templates work</a></div>
    <div id="up-out"></div>
    <div class="tgrid">${ts.map((t) => `<button type="button" class="tcard" data-t="${esc(t.id)}" data-text="${esc((t.name + " " + t.category + " " + t.summary).toLowerCase())}"><div class="tcat">${esc(t.category)} ${t.source === "custom" ? `<span class="tbadge mine">my template</span>` : t.verified ? `<span class="tbadge ok" title="Tested against the real app">✓ verified</span>` : `<span class="tbadge" title="Built from the app's documentation; not yet tested against a real install">unverified</span>`}</div><div class="tname">${esc(t.name)}</div><div class="small muted">${esc(t.summary)}</div><div class="tdepth">${depthLine(["recovery_point", ...t.layers])}</div></button>`).join("")}
      <button type="button" class="tcard" data-t="__yaml"><div class="tcat">Advanced</div><div class="tname">Write your own</div><div class="small muted">Start from a blank RecoveryTest definition in YAML.</div></button></div>
    <div id="g-form"></div>`;
  const search = $("#tsearch", el);
  search.oninput = () => { const q = search.value.toLowerCase().trim(); el.querySelectorAll(".tcard").forEach((c) => { c.hidden = q && c.dataset.t !== "__yaml" && !c.dataset.text.includes(q); }); };
  const readFile = (input) => new Promise((ok, bad) => { const f = input.files[0]; if (!f) return bad(new Error("no file")); const r = new FileReader(); r.onload = () => ok(r.result); r.onerror = bad; r.readAsText(f); });
  const tf = $("#tpl-file", el);
  if (tf) tf.onchange = async () => {
    try { const text = await readFile(tf); const doc = JSON.parse(text); const t = await api("/templates", { method: "POST", body: doc });
      templatesCache = null; toast(`Template "${t.name}" added`); gallery(el, { sourceId: $("#g-src", el).value, runAfter, onCreated }); }
    catch (e) { $("#up-out", el).innerHTML = `<div class="notice bad"><b>Template not added:</b> ${errText(e)}</div>`; }
  };
  const af = $("#app-file", el);
  if (af) af.onchange = async () => {
    try { const text = await readFile(af); let file = text; try { file = JSON.parse(text); } catch { /* YAML text */ }
      const a = await api("/apps/import", { method: "POST", body: { source_id: $("#g-src", el).value, file } });
      toast(a.renamed_from ? `Imported as ${a.name} (name was taken)` : `Imported ${a.name}`); location.hash = `#/apps/${a.id}`; }
    catch (e) { $("#up-out", el).innerHTML = `<div class="notice bad"><b>Import failed:</b> ${errText(e)}</div>`; }
  };
  el.querySelectorAll(".tcard").forEach((b) => b.onclick = () => {
    el.querySelectorAll(".tcard").forEach((x) => x.classList.toggle("sel", x === b));
    const t = ts.find((x) => x.id === b.dataset.t);
    templateForm($("#g-form", el), t, () => $("#g-src", el).value, { runAfter, onCreated });
    $("#g-form", el).scrollIntoView({ behavior: "smooth", block: "start" });
  });
}

function templateForm(el, t, getSource, { runAfter, onCreated }) {
  const isYaml = !t;
  const basic = isYaml ? [] : t.params.filter((p) => !ADVANCED.has(p.key));
  const adv = isYaml ? [] : t.params.filter((p) => ADVANCED.has(p.key));
  el.innerHTML = `<form class="card tf"><div class="row spread"><h2 style="margin-top:0">${isYaml ? "Custom definition" : esc(t.name)}</h2>
    ${!isYaml && t.exportable ? `<div class="row"><button type="button" class="mini" id="tpl-export">Export template</button>${t.source === "custom" && can("admin") ? `<button type="button" class="mini danger" id="tpl-del">Delete template</button>` : ""}</div>` : ""}</div>
    ${!isYaml ? `<p class="small muted">${t.verified ? `✓ Verified against a real ${esc(t.verified)} install.` : t.source === "custom" ? "Your own template." : "Built from the app's documentation, not yet tested against a real install. Run the test once and check the result."}</p>` : `<p class="small muted">Write a RecoveryTest in YAML (or JSON). Start by browsing your backup on the Sources page to find real paths. Guide: <a href="#/help/writing-tests">Writing a test</a>.</p>`}
    ${!isYaml && t.backup_guidance.length ? `<div class="notice"><b>Before you rely on this, check your backup job:</b><ul>${t.backup_guidance.map((g) => `<li>${esc(g)}</li>`).join("")}</ul></div>` : ""}
    ${!isYaml ? `<div class="grid">${basic.map((p) => `<div>${paramInput(p)}</div>`).join("")}</div>
      ${adv.length ? `<details><summary>Snapshot selection, objectives &amp; images</summary><div class="grid">${adv.map((p) => `<div>${paramInput(p)}</div>`).join("")}</div></details>` : ""}
      ${t.caveats.length ? `<p class="small muted">${t.caveats.map(esc).join(" ")}</p>` : ""}` : ""}
    ${!isYaml && t.params.some((p) => p.key === "base_path") ? `<details class="yaml" id="browse-d"><summary><b>Browse your backup</b> and pick the folder and files (recommended)</summary><div id="browse"></div></details>` : ""}
    <details ${isYaml ? "open" : ""} class="yaml"><summary>${isYaml ? "Definition" : "Review the generated definition"}</summary>
      <textarea name="yaml" spellcheck="false">${isYaml ? esc(BLANK()) : ""}</textarea></details>
    <div class="actions">${runAfter ? `<button class="primary" data-run="1">Create &amp; run first test</button><button data-run="0">Create only</button>` : `<button class="primary" data-run="0">Create</button>`}</div>
    <div class="err out"></div></form>`;
  const f = $("form", el), ta = $("textarea[name=yaml]", f), out = $(".out", f);
  const te = $("#tpl-export", f); if (te) te.onclick = () => openAuthed(`/templates/${t.id}/export`, `${t.id}.template.json`);
  const td = $("#tpl-del", f); if (td) td.onclick = async () => { td.textContent = "Click again to delete"; td.onclick = async () => { await api(`/templates/${t.id}`, { method: "DELETE" }); templatesCache = null; toast("Template deleted"); render(); }; };
  let dirty = isYaml;
  ta.addEventListener("input", () => { dirty = true; });
  const answers = () => {
    const a = {};
    (isYaml ? [] : t.params).forEach((p) => { const i = f.elements[p.key]; a[p.key] = p.type === "bool" ? i.checked : i.value; });
    return a;
  };
  const regen = async () => {
    if (isYaml || dirty) return true;
    try { const r = await api(`/templates/${t.id}/render`, { method: "POST", body: { answers: answers() } }); ta.value = r.test_definition; out.innerHTML = ""; return true; }
    catch (e) { out.innerHTML = errText(e); return false; }
  };
  if (!isYaml) { f.addEventListener("change", (e) => { if (e.target !== ta) regen(); }); f.querySelectorAll("details.yaml").forEach((d) => d.addEventListener("toggle", regen)); }
  const bd = $("#browse-d", f);
  if (bd) bd.addEventListener("toggle", () => {
    if (!bd.open || $("#browse", f).dataset.loaded) return;
    $("#browse", f).dataset.loaded = "1";
    snapshotBrowser($("#browse", f), getSource(), {
      getBase: () => f.elements.base_path.value,
      onPickFolder: (p) => { f.elements.base_path.value = p; dirty = false; regen(); toast(`App folder set to /${p}`); },
      onPickFile: f.elements.required_files ? (key, rel) => {
        const inp = f.elements[key]; if (!inp) return;
        const cur = inp.value.split(",").map((x) => x.trim()).filter(Boolean);
        if (!cur.includes(rel)) cur.push(rel);
        inp.value = cur.join(", "); dirty = false; regen();
      } : null,
    });
  });
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    const run = ev.submitter && ev.submitter.dataset.run === "1";
    if (!(await regen())) return;
    f.querySelectorAll("button").forEach((b) => { b.disabled = true; });
    try {
      const app = await api("/apps", { method: "POST", body: { source_id: getSource(), test_definition: ta.value } });
      let job = null;
      if (run) job = await api(`/apps/${app.id}/test`, { method: "POST", body: { acknowledge_resource_usage: true }, headers: { "Idempotency-Key": crypto.randomUUID() } });
      if (onCreated) onCreated(app, job); else location.hash = job ? `#/jobs/${job.job_id}` : `#/apps/${app.id}`;
    } catch (e) { out.innerHTML = errText(e); f.querySelectorAll("button").forEach((b) => { b.disabled = false; }); }
  };
}

const BLANK = () => `# A RecoveryTest. Every field is explained in Help → Writing a test.
# Tip: open Sources → Browse files to find the real paths in your backup first.
apiVersion: restoreproof.io/v1alpha1
kind: RecoveryTest
metadata:
  name: my-test-${Math.random().toString(36).slice(2, 6)}
spec:
  source:
    recoveryPoint: latest          # or {policy: max_age, maxAgeHours: 36}
  restore:
    maxDurationSeconds: 1800
    basePath: "."                  # the app's folder inside the snapshot, e.g. srv/myapp
  checks:
    # Replace this example with files that really exist in your backup:
    - type: file_count
      path: "."
      min: 1
      name: backup-is-not-empty
`;

route(/^\/apps\/new(?:\?(.*))?$/, async (qs) => {
  const src = new URLSearchParams(qs || "").get("source");
  view.innerHTML = `<h1>Protect an application</h1>
    <p class="muted">Pick what you run. RestoreProof restores it from your backup into a sealed-off sandbox and checks it really works.</p><div id="gal"></div>`;
  await gallery($("#gal"), { sourceId: src });
});

// ---------------------------------------------------------------- Guided setup
route(/^\/welcome$/, async () => {
  const [sources, apps, jobs, workers] = await Promise.all([api("/sources"), api("/apps"), api("/jobs?limit=5"), api("/workers")]);
  const okSource = sources.find((s) => s.last_validation_status === "ok") || sources[0];
  const firstApp = apps[0];
  const firstJob = jobs.items[0];
  const scheduled = apps.some((a) => a.policy && a.policy.enabled);
  const done = [!!(okSource && okSource.last_validation_status === "ok"), !!firstApp, !!(firstJob && firstJob.finished_at), scheduled];
  const current = done.indexOf(false);
  const step = (i, title, body) => `<section class="wstep ${done[i] ? "done" : i === current ? "current" : "todo"}">
    <div class="wnum">${done[i] ? "✓" : i + 1}</div><div class="wbody"><h2>${title}</h2><div id="ws${i}">${i === current || done[i] ? body : ""}</div></div></section>`;
  const online = workers.some((w) => w.online);
  view.innerHTML = `<h1>Set up your first recovery test</h1>
    <p class="muted">About five minutes. Nothing touches your production data: backups are restored into a temporary, isolated sandbox and deleted afterwards.</p>
    ${!online ? `<div class="notice bad"><b>No worker is running.</b> Tests will wait in the queue until one starts (<code>restoreproof worker</code> or the compose <code>worker</code> service).</div>` : ""}
    ${!apps.length && can("admin") ? `<div class="card hero"><div><h2 style="margin:0">No backup handy? Try it with demo data</h2>
      <p class="muted" style="margin:4px 0 0">Creates a tiny pretend app, backs it up with restic and tests it, so you see a real result in about a minute. Delete it afterwards.</p></div>
      <button class="primary" id="demo-go">Try it with demo data</button></div><div id="demo-out"></div>` : ""}
    ${step(0, "Connect your backup repository", done[0] ? `<p>${esc(okSource.name)} · ${okSource.recovery_points ?? "?"} snapshots · <a href="#/sources">manage</a></p>` : `<div id="w-src"></div>`)}
    ${step(1, "Choose what to protect", done[1] ? `<p><a href="#/apps/${esc(firstApp.id)}">${esc(firstApp.name)}</a> ${depthLine(firstApp.layers_configured)}</p>` : `<div id="w-gal"></div>`)}
    ${step(2, "Run the first test", done[2] ? `<p>${badge(firstJob.status)} <a href="#/jobs/${esc(firstJob.id)}">open the result</a>${firstJob.status !== "passed" ? " — each failed check explains what to fix." : ""}</p>` : `<div id="w-run"></div>`)}
    ${step(3, "Automate it", `<p class="muted">Run the test every night and get told when recovery breaks.</p><div class="row"><button class="primary" id="w-sched">Test daily at 03:00</button><a class="btn" href="#/settings">Add a notification (ntfy, email, webhook)</a></div>`)}
    ${done.every(Boolean) ? `<div class="notice good"><b>You're set.</b> Go to the <a href="#/">overview</a>, or <a href="#/apps/new">protect another application</a>.</div>` : ""}`;
  if (!done[0]) sourceForm($("#w-src"), () => render());
  else if (!done[1]) gallery($("#w-gal"), { sourceId: okSource.id, onCreated: (app, job) => { location.hash = job ? `#/jobs/${job.job_id}` : "#/welcome"; render(); } });
  else if (!done[2]) {
    const active = firstJob && !firstJob.finished_at;
    $("#w-run").innerHTML = active ? `<p>${badge(firstJob.status)} running… <a href="#/jobs/${esc(firstJob.id)}">watch live</a></p>`
      : `<button class="primary" id="w-go">Test recovery of ${esc(firstApp.name)} now</button>`;
    const go = $("#w-go"); if (go) go.onclick = async () => { const r = await api(`/apps/${firstApp.id}/test`, { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() } }); location.hash = `#/jobs/${r.job_id}`; };
    if (active) autoRefresh(render, 4);
  }
  const dg = $("#demo-go");
  if (dg) dg.onclick = async () => {
    dg.disabled = true; dg.textContent = "Creating demo…";
    try { const r = await api("/demo", { method: "POST" }); location.hash = r.job_id ? `#/jobs/${r.job_id}` : `#/apps/${r.app_id}`; }
    catch (e) { $("#demo-out").innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; dg.disabled = false; dg.textContent = "Try it with demo data"; }
  };
  const sch = $("#w-sched");
  if (sch) sch.onclick = async () => {
    try { for (const a of apps) await api(`/apps/${a.id}/policy`, { method: "PUT", body: { schedule: "0 3 * * *", timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC", enabled: true, jitter_seconds: 900, max_age_last_success_hours: 48 } });
      toast("Daily tests scheduled"); render(); } catch (e) { toast(e.message); }
  };
});

// ---------------------------------------------------------------- Readiness report
route(/^\/report$/, async () => {
  const r = await api("/readiness-report?days=30");
  const V = { ready: ["passed", "Ready"], stale: ["warning", "Stale"], at_risk: ["failed", "At risk"], not_ready: ["failed", "Not ready"], untested: ["", "Untested"] };
  view.innerHTML = `<div class="row spread"><div><h1>Recovery readiness report</h1><p class="muted">Every protected application, its last verified recovery and what needs attention. Share it with whoever relies on these systems.</p></div>
    <div class="row"><button class="primary" id="r-html">Open printable report</button><button id="r-json">Download JSON (hashed)</button></div></div>
    <div class="stats">${["ready", "stale", "at_risk", "not_ready", "untested"].map((k) => `<div class="card stat"><div class="n">${r.summary[k] || 0}</div><div class="l">${V[k][1]}</div></div>`).join("")}</div>
    <div class="table-wrap"><table><tr><th>Application</th><th>Verdict</th><th>Last pass</th><th>Depth verified</th><th>30-day pass rate</th><th>What to do</th></tr>
    ${r.applications.map((a) => `<tr><td><a href="#/apps/${esc(a.id)}">${esc(a.name)}</a></td><td><span class="badge b-${V[a.verdict][0]}">${V[a.verdict][1]}</span><div class="small muted">${esc(a.verdict_reason)}</div></td>
      <td>${a.last_pass ? `${when(a.last_pass.finished_at)}` : "—"}</td><td>${depthLine(a.last_pass ? a.last_pass.layers_verified.concat(["recovery_point"]) : [])}</td>
      <td>${a.runs_in_period ? `${a.passes_in_period}/${a.runs_in_period}` : "—"}</td>
      <td class="small">${(a.latest_failed_checks || []).map((f) => `<div>✗ <b>${esc(f.name)}</b>: ${esc(f.message)}</div>`).join("")}${a.verdict === "ready" ? "—" : a.latest_hint ? `<div class="fix">${esc(a.latest_hint)}</div>` : a.verdict === "untested" ? `<a href="#/apps/${esc(a.id)}">Run the first test</a>` : a.verdict === "stale" ? "Enable or check the schedule" : `<a href="#/jobs/${esc(a.latest_job_id)}">Open the failed run</a>`}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">No applications yet.</td></tr>`}</table></div>
    <p class="small muted">Report sha256 <span class="mono">${esc(r.evidence.manifest_sha256)}</span>. Set an organization name and footer under Settings.</p>`;
  $("#r-html").onclick = () => openAuthed("/readiness-report?format=html");
  $("#r-json").onclick = () => openAuthed("/readiness-report?format=download", `readiness-${new Date().toISOString().slice(0, 10)}.json`);
});

// ---------------------------------------------------------------- Help (Markdown rendered safely: escape first)
function md(src) {
  const inline = (t) => esc(t).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<i>$2</i>")
    .replace(/\[([^\]]+)\]\((#\/[^)\s]*|https?:\/\/[^)\s]+)\)/g, (m, a, h) => `<a href="${h}"${h.startsWith("http") ? ' target="_blank" rel="noopener"' : ""}>${a}</a>`);
  const lines = src.replace(/\r/g, "").split("\n");
  let out = "", i = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (l.startsWith("```")) { const buf = []; i++; while (i < lines.length && !lines[i].startsWith("```")) buf.push(lines[i++]); i++; out += `<pre>${esc(buf.join("\n"))}</pre>`; continue; }
    const h = l.match(/^(#{1,3})\s+(.*)/); if (h) { const n = h[1].length; out += `<h${n}>${inline(h[2])}</h${n}>`; i++; continue; }
    if (l.startsWith("|")) { const rows = []; while (i < lines.length && lines[i].startsWith("|")) rows.push(lines[i++]);
      const cells = (r) => r.replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));
      out += `<div class="table-wrap"><table><tr>${cells(rows[0]).map((c) => `<th>${inline(c)}</th>`).join("")}</tr>${rows.slice(2).map((r) => `<tr>${cells(r).map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("")}</table></div>`; continue; }
    if (/^\s*[-*] /.test(l) || /^\s*\d+\. /.test(l)) { const ordered = /^\s*\d+\. /.test(l); const items = [];
      while (i < lines.length && (/^\s*([-*]|\d+\.) /.test(lines[i]) || (/^\s{2,}\S/.test(lines[i]) && items.length))) {
        if (/^\s*([-*]|\d+\.) /.test(lines[i])) items.push(lines[i].replace(/^\s*([-*]|\d+\.) /, "")); else items[items.length - 1] += " " + lines[i].trim(); i++; }
      out += `<${ordered ? "ol" : "ul"}>${items.map((x) => `<li>${inline(x)}</li>`).join("")}</${ordered ? "ol" : "ul"}>`; continue; }
    if (l.startsWith(">")) { const buf = []; while (i < lines.length && lines[i].startsWith(">")) buf.push(lines[i++].replace(/^>\s?/, "")); out += `<div class="tip">${inline(buf.join(" "))}</div>`; continue; }
    if (!l.trim()) { i++; continue; }
    const buf = []; while (i < lines.length && lines[i].trim() && !/^(#|```|\||>|\s*[-*] |\s*\d+\. )/.test(lines[i])) buf.push(lines[i++]);
    out += `<p>${inline(buf.join(" "))}</p>`;
  }
  return out;
}

route(/^\/help(?:\/([\w-]+))?$/, async (topic) => {
  const idx = await api("/help");
  const t = topic || "getting-started";
  const page = await api(`/help/${t}`);
  view.innerHTML = `<div class="help-layout"><nav class="help-nav">${idx.topics.map((x) => `<a href="#/help/${esc(x.id)}" class="${x.id === t ? "active" : ""}">${esc(x.title)}</a>`).join("")}</nav>
    <article class="help">${md(page.markdown)}</article></div>`;
  window.scrollTo(0, 0);
});

// ---------------------------------------------------------------- Settings additions
async function productSettings(el) {
  const isAdmin = can("admin");
  const [st, diag] = await Promise.all([api("/settings"), can("operator") ? api("/diagnostics") : null]);
  const icon = { ok: "ok", warn: "warning", fail: "failed" };
  el.innerHTML = `
    ${diag ? `<h2>Health check</h2><div class="table-wrap"><table><tr><th>Component</th><th>Status</th><th>Detail</th></tr>
      ${diag.items.map((i) => `<tr><td>${esc(i.name)}</td><td>${badge(icon[i.status])}</td><td>${esc(i.detail)}${i.fix && i.status !== "ok" ? `<div class="fix small">${esc(i.fix)}</div>` : ""}</td></tr>`).join("")}</table></div>` : ""}
    ${isAdmin ? `<div class="grid" style="margin-top:12px">
      <form class="card" id="ret"><h3 style="margin-top:0">Evidence retention</h3>
        <label>Keep sanitized run logs (days)</label><input name="log_days" type="number" min="1" value="${st.retention.log_days}">
        <label>Keep file inventories (days)</label><input name="inventory_days" type="number" min="1" value="${st.retention.inventory_days}">
        <label>Keep reports (days, 0 = forever)</label><input name="report_days" type="number" min="0" value="${st.retention.report_days}">
        <p class="small muted">Only files are removed. Results, check history and hashes stay, and so does the latest passing report of every app and every trusted baseline.</p>
        <div class="actions"><button>Save retention</button></div></form>
      <form class="card" id="wl"><h3 style="margin-top:0">Protect production</h3>
        <label>Pause new tests when load is above (× CPU count, 0 = never)</label><input name="max_load_per_cpu" type="number" step="0.1" min="0" value="${st.workload.max_load_per_cpu}">
        <label>Maintenance window for scheduled tests (HH:MM-HH:MM, empty = any time)</label><input name="maintenance_window" value="${esc(st.workload.maintenance_window)}" placeholder="01:00-06:00">
        <label>Window time zone</label><input name="timezone" value="${esc(st.workload.timezone)}">
        <p class="small muted">Restores already run at the lowest CPU and disk priority. Manual tests ignore the window.</p>
        <div class="actions"><button>Save</button></div></form>
      <form class="card" id="org"><h3 style="margin-top:0">Report branding</h3>
        <label>Organization / customer name</label><input name="name" value="${esc(st.organization.name)}" placeholder="Smith family homelab">
        <label>Report footer</label><textarea name="report_footer" style="min-height:80px;font-family:inherit">${esc(st.organization.report_footer)}</textarea>
        <div class="actions"><button>Save branding</button></div></form></div>` : ""}`;
  const save = (id, key, conv) => { const f = $(`#${id}`); if (f) f.onsubmit = async (ev) => { ev.preventDefault(); const d = Object.fromEntries(new FormData(f)); try { await api(`/settings/${key}`, { method: "PUT", body: conv(d) }); toast("Saved"); } catch (e) { toast(e.message); } }; };
  save("ret", "retention", (d) => ({ log_days: +d.log_days, inventory_days: +d.inventory_days, report_days: +d.report_days }));
  save("org", "organization", (d) => d);
  save("wl", "workload", (d) => ({ max_load_per_cpu: +d.max_load_per_cpu, maintenance_window: d.maintenance_window, timezone: d.timezone }));
}

// Demo app helpers on its application page
async function demoPanel(el, appId) {
  el.innerHTML = `<div class="card"><b>This is the demo app.</b> <span class="muted small">Try breaking it to see what a bad backup looks like.</span>
    <div class="row" style="margin-top:8px"><button id="d-break" class="danger">Break the demo backup</button><button id="d-fix">Repair it</button></div><div id="d-out" class="small"></div></div>`;
  const go = async (what, label) => {
    try { const r = await api(`/demo/${what}`, { method: "POST" });
      const j = await api(`/apps/${appId}/test`, { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() } });
      toast(`${label}. Testing the new backup…`); location.hash = `#/jobs/${j.job_id}`; }
    catch (e) { $("#d-out", el).textContent = e.message; }
  };
  $("#d-break", el).onclick = () => go("break", "Backup broken (2 notes lost, database damaged)");
  $("#d-fix", el).onclick = () => go("repair", "Backup repaired");
}

render();
