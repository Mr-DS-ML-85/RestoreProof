"""Recovery Readiness Report: one document covering every protected application.

Answers, per application: when did a meaningful recovery test last pass, how deep was it (which layers were
verified), how fresh was the recovery point, what is the recent pass rate, and what needs attention.
Suitable for a maintenance review, a hand-over, or your own records.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from html import escape
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from restoreproof import settings_store
from restoreproof.config import VERSION
from restoreproof.db.models import Job, Policy, ProtectedApp, utcnow
from restoreproof.definitions import parse_definition
from restoreproof.evidence.manifest import seal

LAYER_NAMES = {"recovery_point": "Recovery point", "data": "Backup data", "database": "Database",
               "application": "Application"}


def _verdict(app: dict[str, Any]) -> tuple[str, str]:
    lp = app["last_pass"]
    if app["latest_status"] is None:
        return "untested", "No recovery test has run yet."
    if lp is None:
        return "not_ready", "No recovery test has ever passed."
    if app["latest_status"] != "passed":
        return "at_risk", f"Latest test {app['latest_status']}; last pass {lp['age_hours']:.0f}h ago."
    if app["overdue"]:
        return "stale", f"Last pass is {lp['age_hours']:.0f}h old (limit {app['max_age_hours']}h)."
    if app["rpo_hours"] and lp.get("recovery_point_age_hours") and lp["recovery_point_age_hours"] > app["rpo_hours"]:
        return "at_risk", "Restorable, but the tested recovery point was older than the RPO target."
    return "ready", "Recently restored and verified."


def build(s: Session, days: int = 30) -> dict[str, Any]:
    now = utcnow()
    since = now - timedelta(days=days)
    org = settings_store.get(s, "organization")
    apps_out = []
    for app in s.scalars(select(ProtectedApp).where(ProtectedApp.archived.is_(False)).order_by(ProtectedApp.name)):
        defn = parse_definition(app.test_definition)
        policy = s.scalar(select(Policy).where(Policy.app_id == app.id))
        jobs = s.scalars(select(Job).where(Job.app_id == app.id, Job.created_at >= since,
                                           Job.finished_at.is_not(None))).all()
        latest = s.scalars(select(Job).where(Job.app_id == app.id, Job.finished_at.is_not(None))
                           .order_by(Job.finished_at.desc()).limit(1)).first()
        lp = s.scalars(select(Job).where(Job.app_id == app.id, Job.status == "passed")
                       .order_by(Job.finished_at.desc()).limit(1)).first()
        last_pass = None
        if lp:
            rp_time = None
            from restoreproof.db.models import JobAttempt
            att = s.scalars(select(JobAttempt).where(JobAttempt.job_id == lp.id)
                            .order_by(JobAttempt.attempt_number.desc()).limit(1)).first()
            if att and att.recovery_point_time:
                rp_time = att.recovery_point_time
            last_pass = {
                "job_id": lp.id, "finished_at": lp.finished_at.isoformat(),
                "age_hours": round((now - lp.finished_at).total_seconds() / 3600, 1),
                "recovery_point": (lp.summary_json or {}).get("recovery_point"),
                "recovery_point_time": rp_time.isoformat() if rp_time else None,
                "recovery_point_age_hours": round((lp.finished_at - rp_time).total_seconds() / 3600, 1) if rp_time else None,
                "layers_verified": [k for k, v in ((lp.summary_json or {}).get("layers") or {}).items()
                                    if v == "passed" and k in LAYER_NAMES],
                "duration_ms": int((lp.finished_at - lp.started_at).total_seconds() * 1000) if lp.started_at else None,
                "manifest_sha256": (lp.summary_json or {}).get("manifest_sha256"),
            }
        configured = ["recovery_point", "data"]
        if defn.spec.resources.databases or any(c.type.startswith(("postgres", "sqlite", "mysql")) for c in defn.spec.checks):
            configured.append("database")
        if defn.spec.resources.services:
            configured.append("application")
        max_age = policy.max_age_last_success_hours if policy else 48
        failed_checks: list[dict[str, str]] = []
        if latest and latest.status != "passed":
            from restoreproof.db.models import CheckResult, JobAttempt as _A
            la = s.scalars(select(_A).where(_A.job_id == latest.id).order_by(_A.attempt_number.desc()).limit(1)).first()
            if la:
                for r in s.scalars(select(CheckResult).where(CheckResult.attempt_id == la.id,
                                                             CheckResult.required.is_(True),
                                                             CheckResult.status.in_(["failed", "error"]))
                                   .order_by(CheckResult.seq)).all()[:5]:
                    failed_checks.append({"name": r.name, "message": r.message,
                                          "hint": (r.details_json or {}).get("hint", "")})
        entry = {
            "id": app.id, "name": app.name, "description": app.description,
            "definition_version": app.definition_version, "definition_sha256": app.definition_sha256,
            "layers_configured": configured, "checks": len(defn.spec.checks),
            "scheduled": bool(policy and policy.enabled), "schedule": policy.schedule if policy and policy.enabled else None,
            "max_age_hours": max_age, "rpo_hours": defn.spec.objectives.rpoHours,
            "rto_minutes": defn.spec.objectives.rtoMinutes,
            "latest_status": latest.status if latest else None,
            "latest_cleanup": latest.cleanup_status if latest else None,
            "latest_job_id": latest.id if latest else None,
            "latest_error_code": latest.error_code if latest else None,
            "latest_hint": ((latest.summary_json or {}).get("hint") if latest else None)
                           or (failed_checks[0]["hint"] if failed_checks else None),
            "latest_failed_checks": failed_checks,
            "last_pass": last_pass,
            "overdue": bool(last_pass and last_pass["age_hours"] > max_age),
            "runs_in_period": len(jobs), "passes_in_period": sum(j.status == "passed" for j in jobs),
        }
        entry["verdict"], entry["verdict_reason"] = _verdict(entry)
        apps_out.append(entry)
    counts: dict[str, int] = {}
    for a in apps_out:
        counts[a["verdict"]] = counts.get(a["verdict"], 0) + 1
    report = {
        "schema_version": "1.0", "kind": "RecoveryReadinessReport", "restoreproof_version": VERSION,
        "generated_at": now.isoformat(), "period_days": days, "organization": org.name or None,
        "summary": {"applications": len(apps_out), **counts}, "applications": apps_out, "evidence": {},
    }
    return seal(report, None)


VERDICT = {"ready": ("#1a7f37", "Ready"), "stale": ("#9a6700", "Stale"), "at_risk": ("#cf222e", "At risk"),
           "not_ready": ("#cf222e", "Not ready"), "untested": ("#6e7781", "Untested")}


def _fmt(ts: str | None) -> str:
    if not ts:
        return "—"
    return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M UTC")


def render_html(r: dict[str, Any], footer: str = "") -> str:
    rows = []
    for a in r["applications"]:
        color, label = VERDICT[a["verdict"]]
        lp = a["last_pass"] or {}
        depth = " · ".join(f"<b>{escape(LAYER_NAMES[x])}</b>" if x in lp.get("layers_verified", []) else
                           f"<span class=m>{escape(LAYER_NAMES[x])}</span>" for x in a["layers_configured"])
        rate = f"{a['passes_in_period']}/{a['runs_in_period']}" if a["runs_in_period"] else "—"
        rows.append(f"""<tr><td><b>{escape(a['name'])}</b><div class=m>{escape(a['description'])}</div></td>
<td><span class=b style="background:{color}">{label}</span><div class=s>{escape(a['verdict_reason'])}</div>
{''.join(f"<div class=s>✗ {escape(fc['name'])}: {escape(fc['message'][:160])}</div>" for fc in a.get('latest_failed_checks', []))}
{f"<div class=s><i>Next step: {escape(a['latest_hint'])}</i></div>" if a['latest_hint'] and a['verdict'] != 'ready' else ''}</td>
<td>{_fmt(lp.get('finished_at'))}<div class=m>{f"{lp['age_hours']:.0f} h ago" if lp else ''}</div></td>
<td>{_fmt(lp.get('recovery_point_time'))}<div class=m>{escape(str(lp.get('recovery_point') or '')[:12])}</div></td>
<td>{depth}</td><td>{rate}</td>
<td>{f"{lp['duration_ms']/60000:.1f} min" if lp.get('duration_ms') else '—'}{f"<div class=m>RTO {a['rto_minutes']} min</div>" if a['rto_minutes'] else ''}</td>
<td>{escape(a['schedule'] or 'manual')}</td></tr>""")
    s = r["summary"]
    tiles = "".join(f"<div class=t><div class=n>{s.get(k, 0)}</div><div class=m>{VERDICT[k][1]}</div></div>"
                    for k in ("ready", "stale", "at_risk", "not_ready", "untested"))
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Recovery Readiness Report</title><style>
body{{font:13px/1.5 system-ui,sans-serif;color:#1f2328;max-width:1100px;margin:28px auto;padding:0 16px}}
h1{{font-size:24px;margin:0}} .m{{color:#59636e;font-size:12px}} .s{{font-size:12px;margin-top:3px}}
table{{width:100%;border-collapse:collapse;margin-top:18px}} th,td{{text-align:left;vertical-align:top;padding:8px 6px;border-bottom:1px solid #d8dee4}}
th{{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#59636e}}
.b{{color:#fff;border-radius:10px;padding:1px 9px;font-size:12px;font-weight:600}}
.tiles{{display:flex;gap:10px;margin:18px 0;flex-wrap:wrap}} .t{{border:1px solid #d8dee4;border-radius:8px;padding:8px 14px;min-width:100px}} .n{{font-size:22px;font-weight:650}}
footer{{margin-top:26px;color:#59636e;font-size:11px;border-top:1px solid #d8dee4;padding-top:10px}}
@media print{{body{{margin:0}} a{{color:inherit}}}}
</style></head><body>
<div class=m>RECOVERY READINESS REPORT{(' · ' + escape(r['organization'])) if r.get('organization') else ''}</div>
<h1>{s['applications']} protected application{'s' if s['applications'] != 1 else ''}</h1>
<div class=m>Generated {_fmt(r['generated_at'])} · last {r['period_days']} days · RestoreProof {escape(r['restoreproof_version'])}</div>
<div class=tiles>{tiles}</div>
<table><tr><th>Application</th><th>Verdict</th><th>Last passed test</th><th>Tested recovery point</th>
<th>Verified layers</th><th>Pass rate</th><th>Test duration</th><th>Schedule</th></tr>{''.join(rows)}</table>
<footer>Each passed test restored the stated recovery point into an isolated environment and passed the checks in
the application's versioned test definition. Bold layers were verified in the last passing test; grey layers are
configured but were not verified by it. A passing test is evidence of recoverability under the tested conditions,
not a guarantee of future recovery. Measured test duration is an indicator for RTO planning only.
<br>Report sha256 {escape(r['evidence']['manifest_sha256'])}{('<br>' + escape(footer)) if footer else ''}</footer>
</body></html>"""
