"""Human-readable HTML report rendered from the sealed manifest (never from live DB state)."""

from __future__ import annotations

import json
from html import escape
from typing import Any

STATUS_COLORS = {
    "passed": "#1a7f37", "failed": "#cf222e", "error": "#9a6700", "skipped": "#6e7781",
    "inconclusive": "#9a6700", "timed_out": "#cf222e", "cancelled": "#6e7781", "blocked": "#9a6700",
    "interrupted": "#9a6700", "completed": "#1a7f37", "cleanup_failed": "#cf222e", "not_required": "#6e7781",
    "warning": "#9a6700",
}


def _badge(status: str | None) -> str:
    s = status or "unknown"
    return f'<span class="b" style="background:{STATUS_COLORS.get(s, "#6e7781")}">{escape(s)}</span>'


def _ms(v: Any) -> str:
    if not isinstance(v, (int, float)):
        return "—"
    return f"{v / 1000:.1f}s" if v >= 1000 else f"{int(v)}ms"


def render_html(m: dict[str, Any]) -> str:
    rp = m.get("recovery_point") or {}
    res = m.get("result") or {}
    cl = m.get("cleanup") or {}
    ev = m.get("evidence") or {}
    rows = []
    for c in m.get("checks", []):
        rows.append(
            f"<tr><td>{escape(c['layer'])}</td><td>{escape(c['name'])}{'' if c['required'] else ' <i>(advisory)</i>'}"
            f"</td><td>{_badge(c['status'])}</td><td>{escape(c['message'])}</td><td>{_ms(c['duration_ms'])}</td></tr>")
    layers = "".join(f"<li>{escape(k)}: {_badge(v)}</li>" for k, v in (m.get("layers") or {}).items())
    timings = "".join(f"<tr><td>{escape(k)}</td><td>{_ms(v)}</td></tr>" for k, v in (m.get("timings_ms") or {}).items())
    leftovers = "".join(f"<li>{escape(p['resource_type'])} <code>{escape(p['external_id'])}</code>: "
                        f"{escape(p['error'])}</li>" for p in cl.get("problems", []))
    guarantees = "".join(f"<li><b>{escape(k)}</b>: {escape(v)}</li>"
                         for k, v in (m.get("adapter_guarantees") or {}).items())
    sig = ev.get("signature") or {}
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RestoreProof report {escape(m.get('run_id', ''))}</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1f2328}}
h1{{font-size:22px}} h2{{font-size:16px;margin-top:28px;border-bottom:1px solid #d0d7de;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #eaeef2;padding:6px;text-align:left;vertical-align:top}}
.b{{color:#fff;border-radius:10px;padding:1px 8px;font-size:12px;white-space:nowrap}}
code,pre{{font:12px ui-monospace,monospace;background:#f6f8fa;border-radius:4px}} pre{{padding:10px;overflow:auto;max-height:420px}}
dl{{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px}} dt{{color:#59636e}}
.note{{color:#59636e;font-size:12px}}
</style></head><body>
<h1>Recovery test: {escape(str(m.get('application', {}).get('name', '')))} {_badge(res.get('status'))}</h1>
<p class="note">A passing result is evidence of recoverability under the tested conditions only. It is not a
guarantee that every future recovery will succeed.</p>
<dl>
<dt>Report / run ID</dt><dd><code>{escape(m.get('run_id', ''))}</code> (job <code>{escape(m.get('job_id', ''))}</code>, attempt {m.get('attempt_number')})</dd>
<dt>RestoreProof</dt><dd>{escape(m.get('restoreproof_version', ''))}</dd>
<dt>Recovery point</dt><dd><code>{escape(str(rp.get('native_id')))}</code> from {escape(str(rp.get('timestamp')))} (host {escape(str(rp.get('hostname')))}, {escape(str(rp.get('adapter')))})</dd>
<dt>Selection policy</dt><dd>{escape(json.dumps(rp.get('selection')))}</dd>
<dt>Tool version</dt><dd>{escape(str(m.get('tool_version')))}</dd>
<dt>Started / finished</dt><dd>{escape(str(m.get('started_at')))} → {escape(str(m.get('finished_at')))}</dd>
<dt>Isolation</dt><dd>{escape(json.dumps(m.get('isolation')))}</dd>
<dt>Restored</dt><dd>{m.get('restore', {}).get('files', '—')} files, {m.get('restore', {}).get('bytes', '—')} bytes</dd>
<dt>Definition</dt><dd>v{m.get('definition', {}).get('version')} sha256 <code>{escape(str(m.get('definition', {}).get('sha256')))}</code></dd>
<dt>Cleanup</dt><dd>{_badge(cl.get('status'))} {len(cl.get('problems', []))} resources need attention</dd>
</dl>
<h2>Result</h2>
<p>{escape(res.get('reason', ''))}. Passed {res.get('checks_passed', 0)}, failed {res.get('checks_failed', 0)},
could not run {res.get('checks_error', 0)}, skipped {res.get('checks_skipped', 0)}.
{('<br><b>Error:</b> ' + escape(str(res.get('error_code'))) + ' — ' + escape(str(res.get('error_message')))) if res.get('error_code') else ''}</p>
<ul>{layers}</ul>
<h2>Checks</h2>
<table><tr><th>Layer</th><th>Check</th><th>Status</th><th>Detail</th><th>Time</th></tr>{''.join(rows)}</table>
<h2>Timings</h2><table>{timings}</table>
{'<h2>Resources requiring manual cleanup</h2><ul>' + leftovers + '</ul>' if leftovers else ''}
<h2>What the backup tool's checks establish</h2><ul>{guarantees}</ul>
<h2>Evidence</h2>
<dl><dt>Manifest sha256</dt><dd><code>{escape(str(ev.get('manifest_sha256')))}</code></dd>
<dt>Signature</dt><dd>{escape(sig.get('algorithm', 'none'))} key fingerprint <code>{escape(sig.get('public_key_fingerprint', '—'))}</code></dd></dl>
<details><summary>Machine-readable manifest</summary><pre>{escape(json.dumps(m, indent=2, sort_keys=True, default=str))}</pre></details>
</body></html>"""
