/* Backups: destinations (any protocol), plans with ordered fallback, run history with the "why". */
"use strict";

const PROTO_FIELDS = {
  local: [["path", "Folder on this machine", "/mnt/usb/restoreproof"]],
  sftp: [["host", "Server", "nas.lan"], ["port", "Port", "22"], ["user", "User", "backup"], ["path", "Folder on the server", "/srv/backups/restoreproof"]],
  smb: [["host", "Server", "nas.lan"], ["share", "Share", "backups"], ["path", "Folder in the share", "restoreproof"], ["user", "User", "backup"], ["domain", "Domain", "WORKGROUP"], ["port", "Port", "445"]],
  webdav: [["url", "WebDAV URL (Nextcloud: https://host/remote.php/dav/files/USER)", "https://cloud.example/remote.php/dav/files/me"], ["vendor", "Vendor (nextcloud, owncloud, other)", "nextcloud"], ["user", "User", "me"], ["path", "Folder", "restoreproof"]],
  ftp: [["host", "Server", "ftp.lan"], ["port", "Port", "21"], ["user", "User", "backup"], ["path", "Folder", "restoreproof"], ["tls", "TLS (explicit, implicit, none)", "explicit"]],
  rest: [["url", "REST server URL", "https://backup.lan:8000/homelab"]],
  s3: [["endpoint", "Endpoint", "s3.amazonaws.com"], ["bucket", "Bucket", "my-backups"], ["prefix", "Prefix", "restoreproof"], ["region", "Region (optional)", "us-east-1"]],
  b2: [["bucket", "Bucket", "my-backups"], ["prefix", "Prefix", "restoreproof"]],
  gdrive: [["path", "Folder in Drive", "restoreproof"], ["root_folder_id", "Root folder ID (optional)", ""]],
};
const SECRET_LABEL = { private_key: "SSH private key (paste the whole key)", password: "Password", username: "Username (optional)", access_key: "Access key", secret_key: "Secret key", account_id: "Account ID", account_key: "Application key", token: 'OAuth token JSON from `rclone authorize "drive"`' };
const NUMERIC = new Set(["port"]);
const runBadge = (s) => badge({ succeeded: "passed", partial: "warning", failed: "failed", blocked: "blocked", running: "running", queued: "queued" }[s] || s).replace(/>[^<]*</, `>${esc(s)}<`);

route(/^\/backups$/, async () => {
  const [plans, dests] = await Promise.all([api("/backup-plans"), api("/destinations")]);
  view.innerHTML = `<div class="row spread"><div><h1>Backups</h1>
    <p class="muted">Optional: let RestoreProof make the backups too. Each plan uses the first destination that fits. A local disk is used only if enough space stays free, otherwise it falls back to the next one. Recovery tests stay read-only.</p></div>
    ${can("admin") ? `<a class="btn primary" href="#/backups/new">+ New backup plan</a>` : ""}</div>
    <div class="grid">${plans.map((p) => `<a class="card app-card ${p.last_run ? (p.last_run.status === "succeeded" ? "passed" : p.last_run.status) : ""}" href="#/backups/${esc(p.id)}">
      <div class="row spread"><span class="name">${esc(p.name)}</span>${p.last_run ? runBadge(p.last_run.status) : badge("untested")}</div>
      <dl class="facts"><dt>Backs up</dt><dd class="mono">${esc(p.paths.join(", "))}</dd>
      <dt>Destinations</dt><dd>${p.destinations.map((d, i) => `${i + 1}. ${esc(d.name)}`).join(" → ")}</dd>
      <dt>Last success</dt><dd>${p.last_success ? `${when(p.last_success.finished_at)} · ${bytes(p.last_success.bytes_added)} added` : `<span class="muted">never</span>`}</dd>
      <dt>Schedule</dt><dd>${p.enabled ? `${esc(p.schedule)} · next ${when(p.next_run_at)}` : `<span class="muted">manual only</span>`}</dd></dl></a>`).join("") || `<p class="muted">No backup plans yet.</p>`}</div>
    <h2>Destinations</h2><p class="muted">Where backups are stored. Each destination is also available to recovery tests.</p>
    <div class="table-wrap"><table><tr><th>Name</th><th>Where</th><th>Status</th><th></th></tr>
    ${dests.map((d) => `<tr><td><b>${esc(d.name)}</b></td><td class="small">${esc(d.description)}</td><td>${d.last_validation_status ? badge(d.last_validation_status === "ok" ? "ok" : "failed") : `<span class="muted">not checked</span>`}</td>
      <td>${can("operator") ? `<button class="mini" data-check="${esc(d.id)}">Check</button>` : ""} ${can("admin") ? `<button class="mini danger" data-del-dest="${esc(d.id)}">Remove</button>` : ""}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">None yet.</td></tr>`}</table></div>
    ${can("admin") ? `<h2>Add a destination</h2><div id="dest-form"></div>` : ""}`;
  view.querySelectorAll("[data-check]").forEach((b) => b.onclick = async () => {
    b.disabled = true;
    try { const r = await api(`/destinations/${b.dataset.check}/check`, { method: "POST" });
      toast(r.ok ? `OK${r.created ? " (new repository created)" : ""}${r.space ? ` · ${bytes(r.space.free_bytes)} free` : ""}` : `Not reachable: ${r.code}`);
    } catch (e) { toast(e.message); }
    render();
  });
  view.querySelectorAll("[data-del-dest]").forEach((b) => b.onclick = async () => {
    b.textContent = "Click again to remove"; b.onclick = async () => {
      try { await api(`/destinations/${b.dataset.delDest}`, { method: "DELETE" }); toast("Removed (stored backups were not deleted)"); render(); }
      catch (e) { toast(e.message); b.textContent = "Remove"; }
    };
  });
  if ($("#dest-form")) destinationForm($("#dest-form"), () => render());
});

async function destinationForm(el, onDone) {
  const types = (await api("/destinations/types")).types;
  el.innerHTML = `<form class="card"><div class="grid"><div><label>Name</label><input name="name" required placeholder="nas-sftp"></div>
    <div><label>Type</label><select name="type">${types.map((t) => `<option value="${t.type}">${esc(t.label)}</option>`).join("")}</select></div></div>
    <div id="pf"></div><div id="sf"></div>
    <details><summary class="small">Connect an existing restic repository (enter its password)</summary><label>Repository password</label><input name="repo_pw" type="password" autocomplete="off"></details>
    <div class="actions"><button class="primary">Add destination</button></div><div class="out"></div></form>`;
  const f = $("form", el);
  const draw = () => {
    const t = f.type.value, def = types.find((x) => x.type === t);
    $("#pf", el).innerHTML = `<div class="grid">${PROTO_FIELDS[t].map(([k, l, ph]) => `<div><label>${esc(l)}</label><input name="loc_${k}" placeholder="${esc(ph)}" ${["share", "host", "user", "path", "url", "endpoint", "bucket"].includes(k) && !(t === "gdrive") ? "required" : ""}></div>`).join("")}</div>
      ${t === "sftp" ? `<label>Host key</label><div class="row"><input name="loc_host_key" placeholder="press Fetch, then compare the fingerprint with the server" style="flex:1"><button type="button" class="mini" id="scan">Fetch</button></div><div id="fp" class="small"></div>` : ""}
      ${t === "local" ? `<p class="small muted">Used only while enough space stays free (set per plan). In Docker, mount this folder into the worker; on systemd installs, allow it with <code>ReadWritePaths=</code>.</p>` : ""}
      ${t === "gdrive" ? `<p class="small muted">On any computer with a browser run <code>rclone authorize "drive"</code> and paste the JSON it prints below.</p>` : ""}`;
    $("#sf", el).innerHTML = def.secrets.map((k) => `<label>${esc(SECRET_LABEL[k] || k)}</label>${k === "private_key" || k === "token" ? `<textarea name="sec_${k}" style="min-height:90px" autocomplete="off"></textarea>` : `<input name="sec_${k}" type="password" autocomplete="off">`}`).join("");
    const scan = $("#scan", el);
    if (scan) scan.onclick = async () => {
      try { const r = await api("/destinations/scan-host-key", { method: "POST", body: { host: f.loc_host.value, port: +(f.loc_port.value || 22) } });
        f.loc_host_key.value = r.keys[0].key;
        $("#fp", el).innerHTML = `Fingerprint <b class="mono">${esc(r.keys[0].fingerprint)}</b>. ${esc(r.note)}`;
      } catch (e) { $("#fp", el).innerHTML = `<span class="err">${esc(e.message)}</span>`; }
    };
  };
  f.type.onchange = draw; draw();
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    const t = f.type.value, location = { type: t }, secret = {};
    for (const el2 of f.elements) {
      if (!el2.name || !el2.value) continue;
      if (el2.name.startsWith("loc_")) { const k = el2.name.slice(4); location[k] = NUMERIC.has(k) ? +el2.value : el2.value; }
      if (el2.name.startsWith("sec_")) secret[el2.name.slice(4)] = el2.value;
    }
    const out = $(".out", f);
    try {
      const d = await api("/destinations", { method: "POST", body: { name: f.name.value, location, secret, ...(f.repo_pw.value ? { repository_password: f.repo_pw.value } : {}) } });
      const chk = await api(`/destinations/${d.id}/check`, { method: "POST" });
      out.innerHTML = `${d.repository_password ? `<div class="notice"><b>Save this repository password now:</b> <code>${esc(d.repository_password)}</code><br><span class="small">${esc(d.repository_password_note)}</span><div class="actions"><button type="button" class="mini primary" id="saved-pw">I've saved it, continue</button></div></div>` : ""}
        <div class="notice ${chk.ok ? "good" : "bad"}">${chk.ok ? `Connected${chk.created ? ", new repository created" : ""}${chk.space ? `, ${bytes(chk.space.free_bytes)} free` : ""}.` : `Saved, but not reachable yet: ${esc(chk.code || "")}`}</div>`;
      if (!d.repository_password) setTimeout(onDone, 1500);
      else $("#saved-pw", out).onclick = onDone;
    } catch (e) { out.innerHTML = `<p class="err">${errText(e)}</p>`; }
  };
}

function hookRows(hooks) {
  return hooks.map((h) => `<li class="small">${esc(h.type)}: ${esc(h.container || h.source || "")}${h.output ? ` → ${esc(h.output)}` : ""}</li>`).join("");
}

async function planForm(el, plan) {
  const [dests, apps] = await Promise.all([api("/destinations"), api("/apps")]);
  if (!dests.length) { el.innerHTML = `<div class="notice">Add a destination on the <a href="#/backups">Backups</a> page first.</div>`; return; }
  const p = plan || { name: "", paths: [], excludes: [], destinations: [], hooks: [], retention: { enabled: false, daily: 7, weekly: 4, monthly: 6 }, min_free_percent: 10, schedule: "0 2 * * *", timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC", enabled: false, verify_app_ids: [] };
  const chosen = p.destinations.map((d) => d.id);
  el.innerHTML = `<form class="card">
    <div class="grid"><div><label>Plan name</label><input name="name" required value="${esc(p.name)}" ${plan ? "readonly" : ""}></div>
      <div><label>Schedule (cron)</label><input name="schedule" value="${esc(p.schedule)}"></div><div><label>Time zone</label><input name="timezone" value="${esc(p.timezone)}"></div></div>
    <label>Folders to back up (one per line, absolute paths)</label><textarea name="paths" style="min-height:70px;font-family:var(--mono)" required>${esc(p.paths.join("\n"))}</textarea>
    <label>Exclude patterns (one per line, e.g. *.tmp, cache)</label><textarea name="excludes" style="min-height:50px;font-family:var(--mono)">${esc(p.excludes.join("\n"))}</textarea>
    <label>Destinations, in order of preference (the first one that fits is used)</label>
    <div>${[...chosen, ...dests.map((d) => d.id).filter((id) => !chosen.includes(id))].map((id) => { const d = dests.find((x) => x.id === id); return d ? `<label class="check"><input type="checkbox" name="dest" value="${esc(d.id)}" ${chosen.includes(d.id) ? "checked" : ""}> ${esc(d.name)} <span class="small muted">${esc(d.description)}</span></label>` : ""; }).join("")}</div>
    <label>Keep at least this much of a local disk free (%)</label><input name="min_free_percent" type="number" min="0" max="90" value="${p.min_free_percent}">
    <details ${p.hooks.length ? "open" : ""}><summary>Make databases consistent before the backup</summary>
      <p class="small muted">Copying a running database file can produce a backup that won't restore. Each line adds one step:</p>
      <ul>${hookRows(p.hooks)}</ul>
      <label>Hooks (JSON list)</label><textarea name="hooks" style="min-height:90px;font-family:var(--mono)" placeholder='[{"type":"sqlite_backup","source":"/srv/vw/db.sqlite3","output":"/srv/vw/backup/db.sqlite3"},
 {"type":"postgres_dump","container":"nextcloud-db","database":"nextcloud","user":"nextcloud","output":"/srv/nc/db/dump.sql"},
 {"type":"pause_container","container":"paperless"}]'>${p.hooks.length ? esc(JSON.stringify(p.hooks, null, 1)) : ""}</textarea></details>
    <details ${p.retention.enabled ? "open" : ""}><summary>Retention (delete old snapshots of this plan)</summary>
      <label class="check"><input type="checkbox" name="ret_enabled" ${p.retention.enabled ? "checked" : ""}> Apply retention after each backup</label>
      <div class="grid">${["daily", "weekly", "monthly", "yearly"].map((k) => `<div><label>Keep ${k}</label><input type="number" min="0" name="ret_${k}" value="${p.retention[k] ?? 0}"></div>`).join("")}</div>
      <p class="small muted">Only snapshots made by this plan are affected. Pruning waits while a recovery test is reading the repository.</p></details>
    ${apps.length ? `<label>After each backup, run these recovery tests (when they read the destination that was used)</label>${apps.map((a) => `<label class="check"><input type="checkbox" name="verify" value="${esc(a.id)}" ${p.verify_app_ids.includes(a.id) ? "checked" : ""}> ${esc(a.name)}</label>`).join("")}` : ""}
    <label class="check"><input type="checkbox" name="enabled" ${p.enabled ? "checked" : ""}> Run on schedule</label>
    <div class="actions"><button class="primary">${plan ? "Save plan" : "Create plan"}</button></div><div class="err out"></div></form>`;
  const f = $("form", el);
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    const lines = (v) => v.split("\n").map((x) => x.trim()).filter(Boolean);
    let hooks = [];
    try { hooks = f.hooks.value.trim() ? JSON.parse(f.hooks.value) : []; } catch { $(".out", f).textContent = "Hooks must be valid JSON."; return; }
    const body = { name: f.name.value, paths: lines(f.paths.value), excludes: lines(f.excludes.value), destination_ids: [...f.querySelectorAll("[name=dest]:checked")].map((x) => x.value),
      hooks, min_free_percent: +f.min_free_percent.value, schedule: f.schedule.value, timezone: f.timezone.value, enabled: f.enabled.checked,
      verify_app_ids: [...f.querySelectorAll("[name=verify]:checked")].map((x) => x.value),
      retention: { enabled: f.ret_enabled.checked, daily: +f.ret_daily.value, weekly: +f.ret_weekly.value, monthly: +f.ret_monthly.value, yearly: +f.ret_yearly.value } };
    try { const r = await api(plan ? `/backup-plans/${plan.id}` : "/backup-plans", { method: plan ? "PUT" : "POST", body }); location.hash = `#/backups/${r.id}`; render(); }
    catch (e) { $(".out", f).innerHTML = errText(e); }
  };
}

route(/^\/backups\/new$/, async () => {
  view.innerHTML = `<p class="small"><a href="#/backups">← Backups</a></p><h1>New backup plan</h1><div id="pf"></div>`;
  await planForm($("#pf"));
});

route(/^\/backups\/(?!new$)([\w-]+)$/, async (id) => {
  const [p, runs] = await Promise.all([api(`/backup-plans/${id}`), api(`/backup-runs?plan_id=${id}&limit=30`)]);
  const active = runs.items.some((r) => ["queued", "running"].includes(r.status));
  const last = runs.items[0];
  view.innerHTML = `<p class="small"><a href="#/backups">← Backups</a></p>
    <div class="row spread"><h1>${esc(p.name)}</h1>${can("operator") ? `<button class="primary" id="run" ${active ? "disabled" : ""}>${active ? "Backing up…" : "Back up now"}</button>` : ""}</div>
    ${last && last.error_message ? `<div class="notice ${last.status === "partial" ? "" : "bad"}"><b>${esc(last.error_code)}</b>: ${esc(last.error_message)}</div>` : ""}
    ${last && last.decision && last.decision.some((d) => d.destination) ? `<div class="card"><h3 style="margin-top:0">Where the last backup went, and why</h3>
      ${last.decision.filter((d) => d.destination).map((d) => `<div>${badge(d.verdict === "chosen" ? "passed" : "skipped")} <b>${esc(d.destination)}</b> <span class="small muted">${esc(d.reason)}</span></div>`).join("")}</div>` : ""}
    <h2>History</h2><div class="table-wrap"><table><tr><th>When</th><th>Result</th><th>Destination</th><th>Added</th><th>Files new/changed</th><th>Duration</th><th>Snapshot</th><th>Verified by</th></tr>
    ${runs.items.map((r) => `<tr><td>${when(r.created_at)} <span class="small muted">${esc(r.trigger)}</span></td><td>${runBadge(r.status)}</td>
      <td class="small">${esc((p.destinations.find((d) => d.id === r.destination_id) || {}).name || "—")}</td><td>${bytes(r.bytes_added)}</td>
      <td>${r.files_new ?? "—"} / ${r.files_changed ?? "—"}</td><td>${r.duration_ms != null ? ms(r.duration_ms) : "—"}</td><td class="mono">${short(r.snapshot_id, 10)}</td>
      <td>${(r.verify_job_ids || []).map((j) => `<a href="#/jobs/${esc(j)}">test</a>`).join(" ") || "—"}</td></tr>`).join("") || `<tr><td colspan="8" class="muted">No backups yet.</td></tr>`}</table></div>
    ${can("admin") ? `<h2>Settings</h2><div id="pf"></div>
      <h2>Danger zone</h2><div class="card danger-zone"><b>Delete this plan</b><p class="small muted">Removes the plan and its run history. Snapshots it already made stay in the destination and can still be restored.</p>
      <button class="danger" id="del-plan">Delete plan</button> <span class="err" id="dp-err"></span></div>` : ""}`;
  const run = $("#run");
  if (run) run.onclick = async () => { try { await api(`/backup-plans/${id}/run`, { method: "POST" }); toast("Backup queued"); render(); } catch (e) { toast(e.message); } };
  if ($("#pf")) planForm($("#pf"), p);
  const dp = $("#del-plan");
  if (dp) dp.onclick = () => { dp.textContent = "Click again to delete"; dp.onclick = async () => {
    try { await api(`/backup-plans/${id}`, { method: "DELETE" }); toast("Plan deleted"); location.hash = "#/backups"; }
    catch (e) { $("#dp-err").textContent = e.message; } }; };
  if (active) autoRefresh(render, 4);
});
