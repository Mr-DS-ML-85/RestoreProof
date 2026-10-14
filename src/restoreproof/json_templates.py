"""JSON templates (format "restoreproof-template/v1"): shareable, uploadable, exportable app templates.

{
  "format": "restoreproof-template/v1",
  "id": "uptime-kuma", "name": "Uptime Kuma", "category": "Monitoring",
  "summary": "...", "homepage": "https://...", "layers": ["data", "database"],
  "backup_guidance": ["..."], "caveats": ["..."],
  "params": [{"key": "check_heartbeats", "label": "Check recent heartbeats", "type": "bool", "default": true}],
  "definition": { "apiVersion": "restoreproof.io/v1alpha1", "kind": "RecoveryTest",
                  "metadata": {"name": "{{name}}"},
                  "spec": {"checks": [ {"type": "sqlite_integrity", "path": "kuma.db"},
                                       {"$if": "check_heartbeats", "type": "sqlite_query", ...} ]}}
}

Placeholders:  "{{key}}" as a whole value keeps the parameter's type (number, bool, list); inside a longer
string it is inserted as text. Filters: {{key|gz}} -> "gzip"/"none" from a .gz suffix, {{key|prefix}} -> ""
for "." else "key/". Conditional list items: "$if": "key", "key == value" or "key != value".
Standard options (test name, path in snapshot, snapshot age/host/tag, RPO, shrink detection) are added
automatically unless "standard_options": false.
"""

from __future__ import annotations

import copy
import json
import re
from importlib import resources
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from restoreproof.definitions import DefinitionError, parse_definition
from restoreproof.templates import COMMON, NAME, Param, _coerce

FORMAT = "restoreproof-template/v1"
PH = re.compile(r"\{\{\s*([a-z_][a-z0-9_]*)\s*(?:\|\s*(gz|prefix))?\s*\}\}")


class ParamDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(pattern=r"^[a-z_][a-z0-9_]{0,40}$")
    label: str = Field(min_length=1, max_length=120)
    type: Literal["string", "int", "bool", "select", "list"] = "string"
    default: Any = None
    help: str = Field(default="", max_length=400)
    options: list[str] = []
    required: bool = False


class TemplateDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["restoreproof-template/v1"]
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,40}$")
    name: str = Field(min_length=1, max_length=80)
    category: str = Field(default="Custom", max_length=40)
    summary: str = Field(default="", max_length=300)
    homepage: str = Field(default="", max_length=300)
    layers: list[Literal["data", "database", "application"]] = ["data"]
    backup_guidance: list[str] = Field(default=[], max_length=10)
    caveats: list[str] = Field(default=[], max_length=10)
    verified: str = Field(default="", max_length=120)  # e.g. "Uptime Kuma 1.23.16 on 2026-10-15"
    standard_options: bool = True
    params: list[ParamDoc] = Field(default=[], max_length=40)
    definition: dict[str, Any]


class TemplateError(Exception):
    def __init__(self, message: str, errors: list | None = None):
        super().__init__(message)
        self.errors = errors or []


def _params(doc: TemplateDoc) -> list[Param]:
    own = [Param(p.key, p.label, p.type, p.default, p.help, tuple(p.options), p.required) for p in doc.params]
    if not doc.standard_options:
        keys = {p.key for p in own}
        std = [p for p in (NAME,) + tuple(COMMON[:1]) if p.key not in keys]  # name + base_path always exist
        return std + own
    keys = {p.key for p in own}
    return [NAME] + [p for p in COMMON if p.key not in keys] + own


def _cond(expr: str, values: dict[str, Any]) -> bool:
    m = re.match(r"^\s*([a-z_][a-z0-9_]*)\s*(==|!=)?\s*(.*?)\s*$", expr)
    if not m:
        raise TemplateError(f"invalid $if expression {expr!r}")
    key, op, val = m.groups()
    cur = values.get(key)
    if not op:
        return bool(cur)
    return (str(cur) == val) if op == "==" else (str(cur) != val)


def _filter(value: Any, f: str | None) -> Any:
    if f == "gz":
        return "gzip" if str(value).endswith(".gz") else "none"
    if f == "prefix":
        v = str(value or ".").strip("/")
        return "" if v in ("", ".") else v + "/"
    return value


def _subst(node: Any, values: dict[str, Any]) -> Any:
    if isinstance(node, str):
        whole = PH.fullmatch(node.strip())
        if whole:
            if whole.group(1) not in values:
                raise TemplateError(f"unknown placeholder {{{{{whole.group(1)}}}}}")
            return _filter(values[whole.group(1)], whole.group(2))

        def rep(m: re.Match) -> str:
            if m.group(1) not in values:
                raise TemplateError(f"unknown placeholder {{{{{m.group(1)}}}}}")
            v = _filter(values[m.group(1)], m.group(2))
            return ",".join(map(str, v)) if isinstance(v, list) else str(v)
        return PH.sub(rep, node)
    if isinstance(node, list):
        out = []
        for item in node:
            if isinstance(item, dict) and "$if" in item:
                if not _cond(str(item["$if"]), values):
                    continue
                item = {k: v for k, v in item.items() if k != "$if"}
                if set(item) == {"$each"}:  # {"$if": ..., "$each": [...]} adds several items
                    out.extend(_subst(item["$each"], values))
                    continue
            if isinstance(item, dict) and set(item) == {"$for", "$item"}:
                # {"$for": "required_files", "$item": {"type": "file_exists", "path": "{{_}}"}}
                for v in values.get(item["$for"]) or []:
                    out.append(_subst(item["$item"], {**values, "_": v}))
                continue
            out.append(_subst(item, values))
        return out
    if isinstance(node, dict):
        return {k: _subst(v, values) for k, v in node.items()}
    return node


def _apply_standard(defn: dict[str, Any], v: dict[str, Any], standard: bool) -> None:
    spec = defn.setdefault("spec", {})
    defn.setdefault("metadata", {})["name"] = v["name"]
    restore = spec.setdefault("restore", {})
    restore.setdefault("basePath", v.get("base_path") or ".")
    if not standard:
        return
    src = spec.setdefault("source", {})
    if "recoveryPoint" not in src:
        rp: dict[str, Any] = ({"policy": "max_age", "maxAgeHours": int(v["max_age_hours"])}
                              if int(v.get("max_age_hours") or 0) else {"policy": "latest"})
        if v.get("host"):
            rp["host"] = v["host"]
        if v.get("tag"):
            rp["tags"] = [v["tag"]]
        src["recoveryPoint"] = rp
    if v.get("rpo_hours"):
        spec.setdefault("objectives", {}).setdefault("rpoHours", int(v["rpo_hours"]))
    if v.get("inventory") and not any(c.get("type") == "inventory" for c in spec.get("checks", [])):
        spec.setdefault("checks", []).append({"type": "inventory", "name": "inventory",
                                              "path": v.get("inventory_path") or "."})


def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", str(name).lower()).strip("-")[:40] or "app"
    return s if s[0].isalpha() else f"app-{s}"[:40]


def load_doc(data: Any) -> TemplateDoc:
    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data)
        except ValueError as exc:
            raise TemplateError(f"not valid JSON: {exc}") from exc
    try:
        return TemplateDoc.model_validate(data)
    except ValidationError as exc:
        raise TemplateError("the template file is invalid",
                            [{"loc": ".".join(str(x) for x in e["loc"]), "msg": e["msg"]} for e in exc.errors()]) from exc


def render(doc: TemplateDoc, answers: dict[str, Any]) -> str:
    values: dict[str, Any] = {}
    for p in _params(doc):
        values[p.key] = _coerce(p, answers.get(p.key))
        if p.key == "name" and not values["name"]:
            values["name"] = doc.id
        if p.required and values[p.key] in (None, "", []):
            raise ValueError(f"{p.label} is required")
    values["name"] = slug(values["name"])
    defn = _subst(copy.deepcopy(doc.definition), values)
    if not isinstance(defn, dict):
        raise TemplateError("definition must be an object")
    defn.setdefault("apiVersion", "restoreproof.io/v1alpha1")
    defn.setdefault("kind", "RecoveryTest")
    _apply_standard(defn, values, doc.standard_options)
    if doc.summary and not defn["metadata"].get("description"):
        defn["metadata"]["description"] = doc.summary[:200]
    header = (f"# Generated from the '{doc.name}' template. Edit freely; it is validated on save.\n"
              + "".join(f"# Backup tip: {g}\n" for g in doc.backup_guidance))
    text = header + yaml.safe_dump(defn, sort_keys=False, default_flow_style=False, width=110)
    parse_definition(text)
    return text


def check(doc: TemplateDoc) -> None:
    """A template must render to a valid definition with its default answers."""
    try:
        render(doc, {})
    except DefinitionError as exc:
        raise TemplateError("with its default answers the template produces an invalid test", exc.errors) from exc
    except ValueError as exc:
        if "is required" in str(exc):
            return  # required fields without defaults are fine; the user fills them in
        raise TemplateError(str(exc)) from exc


def describe(doc: TemplateDoc, *, source: str) -> dict[str, Any]:
    return {"id": doc.id, "name": doc.name, "category": doc.category, "summary": doc.summary, "layers": doc.layers,
            "backup_guidance": doc.backup_guidance, "caveats": doc.caveats, "homepage": doc.homepage,
            "verified": doc.verified, "source": source, "exportable": True,
            "params": [{"key": p.key, "label": p.label, "type": p.type,
                        "default": doc.id if p.key == "name" else p.default, "help": p.help,
                        "options": list(p.options), "required": p.required} for p in _params(doc)]}


def library() -> list[TemplateDoc]:
    """Templates shipped with RestoreProof as JSON files (restoreproof/template_library/*.json)."""
    out = []
    pkg = resources.files("restoreproof") / "template_library"
    if pkg.is_dir():
        for f in sorted(pkg.iterdir(), key=lambda x: x.name):
            if f.name.endswith(".json"):
                out.append(load_doc(f.read_text()))
    return out


def from_app(app_name: str, definition_yaml: str, *, template_id: str | None = None) -> TemplateDoc:
    """Turn an existing application's test into a reusable template (name and path become questions)."""
    d = yaml.safe_load(definition_yaml)
    base = (d.get("spec", {}).get("restore", {}) or {}).get("basePath", ".")
    d["metadata"]["name"] = "{{name}}"
    d["spec"].setdefault("restore", {})["basePath"] = "{{base_path}}"
    return TemplateDoc(format=FORMAT, id=template_id or slug(app_name), name=app_name, category="My templates",
                       summary=(d.get("metadata", {}).get("description") or f"Saved from {app_name}")[:300],
                       standard_options=False,
                       params=[ParamDoc(key="base_path", label="Path inside the snapshot", default=base,
                                        help="Where the app's folder sits in the snapshot")],
                       definition=d)
