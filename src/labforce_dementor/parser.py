from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from .apex_lexical import code_only


def local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def child_text(root: ET.Element, name: str, default: str = "") -> str:
    for child in list(root):
        if local(child.tag) == name:
            return (child.text or "").strip()
    return default


def all_text(root: ET.Element, name: str) -> list[str]:
    out: list[str] = []
    for node in root.iter():
        if local(node.tag) == name and node.text:
            out.append(node.text.strip())
    return out


def xml_root(path: Path) -> ET.Element | None:
    try:
        return ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return None


def api_name_from_meta(path: Path) -> str:
    name = path.name
    for suffix in (
        ".object-meta.xml", ".field-meta.xml", ".layout-meta.xml", ".app-meta.xml",
        ".flexipage-meta.xml", ".flow-meta.xml", ".cls-meta.xml", ".trigger-meta.xml",
        ".permissionset-meta.xml", ".profile-meta.xml", ".namedCredential-meta.xml",
        ".externalCredential-meta.xml", ".connectedApp-meta.xml", ".remoteSite-meta.xml",
        ".authprovider-meta.xml", ".reportType-meta.xml", ".report-meta.xml", ".dashboard-meta.xml",
        ".workflow-meta.xml", ".approvalProcess-meta.xml", ".sharingRules-meta.xml",
        ".permissionsetgroup-meta.xml", ".customPermission-meta.xml",
        ".corsWhitelistOrigin-meta.xml", ".cspTrustedSite-meta.xml",
    ):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


def parse_objects(root_dir: Path) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    objects_dir = root_dir / "objects"
    if not objects_dir.exists():
        return objects
    for obj_dir in sorted(p for p in objects_dir.iterdir() if p.is_dir()):
        object_meta = obj_dir / f"{obj_dir.name}.object-meta.xml"
        root = xml_root(object_meta)
        obj = {
            "api_name": obj_dir.name,
            "label": child_text(root, "label") if root is not None else "",
            "plural_label": child_text(root, "pluralLabel") if root is not None else "",
            "description": child_text(root, "description") if root is not None else "",
            "sharing_model": child_text(root, "sharingModel") if root is not None else "",
            "external_sharing_model": child_text(root, "externalSharingModel") if root is not None else "",
            "fields": [],
            "record_types": [],
            "validation_rules": [],
        }
        fields_dir = obj_dir / "fields"
        if fields_dir.exists():
            for field_path in sorted(fields_dir.glob("*.field-meta.xml")):
                fr = xml_root(field_path)
                if fr is None:
                    continue
                field_name = api_name_from_meta(field_path)
                obj["fields"].append({
                    "api_name": field_name,
                    "full_name": f"{obj_dir.name}.{field_name}",
                    "label": child_text(fr, "label"),
                    "type": child_text(fr, "type"),
                    "description": child_text(fr, "description"),
                    "help_text": child_text(fr, "inlineHelpText"),
                    "required": child_text(fr, "required").lower() == "true",
                    "unique": child_text(fr, "unique").lower() == "true",
                    "external_id": child_text(fr, "externalId").lower() == "true",
                    "formula": child_text(fr, "formula"),
                    "reference_to": all_text(fr, "referenceTo"),
                    "relationship_name": child_text(fr, "relationshipName"),
                    "source_file": str(field_path),
                })
        rt_dir = obj_dir / "recordTypes"
        if rt_dir.exists():
            obj["record_types"] = [api_name_from_meta(p) for p in sorted(rt_dir.glob("*.recordType-meta.xml"))]
        vr_dir = obj_dir / "validationRules"
        if vr_dir.exists():
            for p in sorted(vr_dir.glob("*.validationRule-meta.xml")):
                rr = xml_root(p)
                obj["validation_rules"].append({
                    "api_name": api_name_from_meta(p),
                    "active": child_text(rr, "active").lower() == "true" if rr is not None else None,
                    "description": child_text(rr, "description") if rr is not None else "",
                    "formula": child_text(rr, "errorConditionFormula") if rr is not None else "",
                    "source_file": str(p),
                })
        objects.append(obj)
    return objects


def parse_layouts(root_dir: Path) -> list[dict[str, Any]]:
    out = []
    d = root_dir / "layouts"
    if not d.exists():
        return out
    for p in sorted(d.glob("*.layout-meta.xml")):
        r = xml_root(p)
        if r is None:
            continue
        name = api_name_from_meta(p)
        obj = name.split("-", 1)[0] if "-" in name else ""
        fields = sorted(set(all_text(r, "field")))
        out.append({"api_name": name, "object": obj, "fields": fields, "source_file": str(p)})
    return out


def parse_apps(root_dir: Path) -> list[dict[str, Any]]:
    out = []
    d = root_dir / "applications"
    if not d.exists():
        return out
    for p in sorted(d.glob("*.app-meta.xml")):
        r = xml_root(p)
        if r is None:
            continue
        tabs = all_text(r, "tabs")
        out.append({
            "api_name": api_name_from_meta(p),
            "label": child_text(r, "label"),
            "description": child_text(r, "description"),
            "tabs": tabs,
            "source_file": str(p),
        })
    return out


def parse_flows(root_dir: Path) -> list[dict[str, Any]]:
    out = []
    d = root_dir / "flows"
    if not d.exists():
        return out
    for p in sorted(d.glob("*.flow-meta.xml")):
        r = xml_root(p)
        if r is None:
            continue
        counts = defaultdict(int)
        interesting = {
            "recordCreates", "recordUpdates", "recordDeletes", "recordLookups", "loops",
            "subflows", "decisions", "assignments", "actionCalls", "waits", "screens"
        }
        for n in r.iter():
            ln = local(n.tag)
            if ln in interesting:
                counts[ln] += 1
        out.append({
            "api_name": api_name_from_meta(p),
            "label": child_text(r, "label"),
            "description": child_text(r, "description"),
            "status": child_text(r, "status"),
            "process_type": child_text(r, "processType"),
            "object": child_text(r, "object"),
            "trigger_type": child_text(r, "triggerType"),
            "record_trigger_type": child_text(r, "recordTriggerType"),
            "counts": dict(counts),
            "field_references": sorted(set(all_text(r, "field"))),
            "object_references": sorted(set(all_text(r, "object"))),
            "source_file": str(p),
        })
    return out


def parse_apex(root_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    classes = []
    triggers = []
    for folder, extension, target in (("classes", ".cls", classes), ("triggers", ".trigger", triggers)):
        d = root_dir / folder
        if not d.exists():
            continue
        for p in sorted(d.glob(f"*{extension}")):
            text = p.read_text(encoding="utf-8", errors="ignore")
            meta = xml_root(Path(str(p) + "-meta.xml"))
            target.append({
                "api_name": p.stem,
                "api_version": child_text(meta, "apiVersion") if meta is not None else "",
                "status": child_text(meta, "status") if meta is not None else "",
                "length": len(text),
                "lines": text.count("\n") + 1,
                "is_test": bool(re.search(r"@isTest\b|testMethod\b", code_only(text), re.I)),
                "is_rest": bool(re.search(r"@RestResource\b", text, re.I)),
                "is_aura_enabled": bool(re.search(r"@AuraEnabled\b", text, re.I)),
                "is_invocable": bool(re.search(r"@InvocableMethod\b", text, re.I)),
                "is_batch": bool(re.search(r"Database\.Batchable\b", text)),
                "is_queueable": bool(re.search(r"\bQueueable\b", text)),
                "is_schedulable": bool(re.search(r"\bSchedulable\b", text)),
                "uses_callout": bool(re.search(r"HttpRequest|callout:|NamedCredential", text, re.I)),
                "source_file": str(p),
                "text": text,
            })
    return classes, triggers


def _parse_permissions_file(path: Path) -> dict[str, Any]:
    r = xml_root(path)
    if r is None:
        return {}
    user_permissions = []
    field_permissions = []
    object_permissions = []
    for node in list(r):
        ln = local(node.tag)
        if ln == "userPermissions":
            name = child_text(node, "name")
            enabled = child_text(node, "enabled").lower() == "true"
            if name:
                user_permissions.append({"name": name, "enabled": enabled})
        elif ln == "fieldPermissions":
            field_permissions.append({
                "field": child_text(node, "field"),
                "readable": child_text(node, "readable").lower() == "true",
                "editable": child_text(node, "editable").lower() == "true",
            })
        elif ln == "objectPermissions":
            object_permissions.append({
                "object": child_text(node, "object"),
                "allow_read": child_text(node, "allowRead").lower() == "true",
                "allow_create": child_text(node, "allowCreate").lower() == "true",
                "allow_edit": child_text(node, "allowEdit").lower() == "true",
                "allow_delete": child_text(node, "allowDelete").lower() == "true",
                "view_all": child_text(node, "viewAllRecords").lower() == "true",
                "modify_all": child_text(node, "modifyAllRecords").lower() == "true",
            })
    return {
        "api_name": api_name_from_meta(path),
        "label": child_text(r, "label"),
        "user_permissions": user_permissions,
        "field_permissions": field_permissions,
        "object_permissions": object_permissions,
        "source_file": str(path),
    }


def parse_permissions(root_dir: Path) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {"permission_sets": [], "profiles": []}
    d = root_dir / "permissionsets"
    if d.exists():
        result["permission_sets"] = [_parse_permissions_file(p) for p in sorted(d.glob("*.permissionset-meta.xml"))]
    d = root_dir / "profiles"
    if d.exists():
        result["profiles"] = [_parse_permissions_file(p) for p in sorted(d.glob("*.profile-meta.xml"))]
    return result


def parse_generic_metadata(root_dir: Path) -> dict[str, list[dict[str, Any]]]:
    mapping = {
        "flexipages": ("flexipages", "*.flexipage-meta.xml"),
        "named_credentials": ("namedCredentials", "*.namedCredential-meta.xml"),
        "external_credentials": ("externalCredentials", "*.externalCredential-meta.xml"),
        "connected_apps": ("connectedApps", "*.connectedApp-meta.xml"),
        "remote_sites": ("remoteSiteSettings", "*.remoteSite-meta.xml"),
        "auth_providers": ("authproviders", "*.authprovider-meta.xml"),
        "report_types": ("reportTypes", "*.reportType-meta.xml"),
        "reports": ("reports", "**/*.report-meta.xml"),
        "dashboards": ("dashboards", "**/*.dashboard-meta.xml"),
        "pages": ("pages", "*.page"),
        "lwc": ("lwc", "**/*.js"),
        "aura": ("aura", "**/*.cmp"),
    }
    out: dict[str, list[dict[str, Any]]] = {}
    for key, (folder, pattern) in mapping.items():
        d = root_dir / folder
        items = []
        if d.exists():
            for p in sorted(d.glob(pattern)):
                r = xml_root(p)
                items.append({
                    "api_name": api_name_from_meta(p),
                    "label": child_text(r, "label") if r is not None else "",
                    "description": child_text(r, "description") if r is not None else "",
                    "source_file": str(p),
                })
        out[key] = items
    return out



def parse_extended_metadata(root_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Parse governance/security metadata that was retrieved but previously invisible.

    The parser intentionally keeps only assessment-safe structural attributes; it does
    not attempt to reconstruct mutable deployment payloads.
    """
    out: dict[str, list[dict[str, Any]]] = {
        "workflows": [], "approval_processes": [], "sharing_rules": [],
        "permission_set_groups": [], "custom_permissions": [],
        "cors_whitelist_origins": [], "csp_trusted_sites": [],
    }

    wf_dir = root_dir / "workflows"
    if wf_dir.exists():
        for path in sorted(wf_dir.glob("*.workflow-meta.xml")):
            r = xml_root(path)
            if r is None:
                continue
            obj = api_name_from_meta(path)
            rules = []
            for node in list(r):
                if local(node.tag) != "rules":
                    continue
                name = child_text(node, "fullName")
                rules.append({
                    "api_name": name,
                    "active": child_text(node, "active").lower() == "true",
                    "description": child_text(node, "description"),
                    "trigger_type": child_text(node, "triggerType"),
                    "formula": child_text(node, "formula"),
                })
            out["workflows"].append({"object": obj, "rules": rules, "source_file": str(path)})

    ap_dir = root_dir / "approvalProcesses"
    if ap_dir.exists():
        for path in sorted(ap_dir.glob("*.approvalProcess-meta.xml")):
            r = xml_root(path)
            if r is None:
                continue
            name = api_name_from_meta(path)
            obj = name.split(".", 1)[0] if "." in name else ""
            out["approval_processes"].append({
                "api_name": name, "object": obj,
                "active": child_text(r, "active").lower() == "true",
                "description": child_text(r, "description"),
                "entry_criteria_count": len(all_text(r, "field")),
                "steps": sum(1 for n in list(r) if local(n.tag) == "approvalStep"),
                "source_file": str(path),
            })

    sr_dir = root_dir / "sharingRules"
    if sr_dir.exists():
        for path in sorted(sr_dir.glob("*.sharingRules-meta.xml")):
            r = xml_root(path)
            if r is None:
                continue
            obj = api_name_from_meta(path)
            counts = defaultdict(int)
            for n in r.iter():
                ln = local(n.tag)
                if ln.endswith("SharingRules") or ln in {"sharingCriteriaRules", "sharingOwnerRules", "sharingTerritoryRules"}:
                    counts[ln] += 1
            out["sharing_rules"].append({"object": obj, "counts": dict(counts), "source_file": str(path)})

    psg_dir = root_dir / "permissionsetgroups"
    if psg_dir.exists():
        for path in sorted(psg_dir.glob("*.permissionsetgroup-meta.xml")):
            r = xml_root(path)
            if r is None:
                continue
            out["permission_set_groups"].append({
                "api_name": api_name_from_meta(path),
                "label": child_text(r, "label"),
                "description": child_text(r, "description"),
                "permission_sets": sorted(set(all_text(r, "permissionSets"))),
                "status": child_text(r, "status"),
                "source_file": str(path),
            })

    cp_dir = root_dir / "customPermissions"
    if cp_dir.exists():
        for path in sorted(cp_dir.glob("*.customPermission-meta.xml")):
            r = xml_root(path)
            if r is None:
                continue
            out["custom_permissions"].append({
                "api_name": api_name_from_meta(path), "label": child_text(r, "label"),
                "description": child_text(r, "description"), "source_file": str(path),
            })

    for key, folder, pattern in (
        ("cors_whitelist_origins", "corsWhitelistOrigins", "*.corsWhitelistOrigin-meta.xml"),
        ("csp_trusted_sites", "cspTrustedSites", "*.cspTrustedSite-meta.xml"),
    ):
        d = root_dir / folder
        if d.exists():
            for path in sorted(d.glob(pattern)):
                r = xml_root(path)
                out[key].append({
                    "api_name": api_name_from_meta(path),
                    "endpoint": child_text(r, "url") if r is not None else "",
                    "active": child_text(r, "isActive").lower() == "true" if r is not None and child_text(r, "isActive") else None,
                    "source_file": str(path),
                })
    return out

def parse_source(root_dir: Path) -> dict[str, Any]:
    objects = parse_objects(root_dir)
    layouts = parse_layouts(root_dir)
    apps = parse_apps(root_dir)
    flows = parse_flows(root_dir)
    classes, triggers = parse_apex(root_dir)
    permissions = parse_permissions(root_dir)
    generic = parse_generic_metadata(root_dir)
    extended = parse_extended_metadata(root_dir)

    field_count = sum(len(o["fields"]) for o in objects)
    validation_rule_count = sum(len(o["validation_rules"]) for o in objects)
    return {
        "objects": objects,
        "layouts": layouts,
        "applications": apps,
        "flows": flows,
        "apex_classes": classes,
        "apex_triggers": triggers,
        "permission_sets": permissions["permission_sets"],
        "profiles": permissions["profiles"],
        **generic,
        **extended,
        "inventory": {
            "applications": len(apps),
            "objects": len(objects),
            "fields": field_count,
            "layouts": len(layouts),
            "validation_rules": validation_rule_count,
            "flows": len(flows),
            "apex_classes": len(classes),
            "apex_triggers": len(triggers),
            "permission_sets": len(permissions["permission_sets"]),
            "profiles": len(permissions["profiles"]),
            "named_credentials": len(generic["named_credentials"]),
            "external_credentials": len(generic["external_credentials"]),
            "connected_apps": len(generic["connected_apps"]),
            "reports": len(generic["reports"]),
            "dashboards": len(generic["dashboards"]),
            "workflow_rules": sum(len(x.get("rules", [])) for x in extended["workflows"]),
            "approval_processes": len(extended["approval_processes"]),
            "sharing_rule_files": len(extended["sharing_rules"]),
            "permission_set_groups": len(extended["permission_set_groups"]),
            "custom_permissions": len(extended["custom_permissions"]),
        },
    }
