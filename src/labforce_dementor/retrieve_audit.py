from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def manifest_summary(path: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {"path": str(path), "exists": path.exists(), "types": 0, "members": 0}
    if not path.exists():
        return summary
    summary["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        root = ET.parse(path).getroot()
        entries = []
        for row in root:
            if row.tag.split("}")[-1] == "version":
                summary["api_version"] = row.text
            if row.tag.split("}")[-1] != "types":
                continue
            name = next((node.text for node in row if node.tag.split("}")[-1] == "name"), "")
            members = sorted({node.text for node in row if node.tag.split("}")[-1] == "members" and node.text})
            entries.append({"type": name, "members": members, "wildcard": "*" in members})
        summary.update(types=len(entries), members=sum(len(row["members"]) for row in entries), entries=entries)
    except (ET.ParseError, OSError) as exc:
        summary["error"] = str(exc)
    return summary


def snapshot_files(root: Path) -> list[dict[str, Any]]:
    return [{"path": path.relative_to(root).as_posix(), "bytes": path.stat().st_size,
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(root.rglob("*")) if path.is_file()]


def retrieve_audit(manifest: Path, root: Path, payload: dict[str, Any], *, mode: str,
                   include_packages: list[str]) -> dict[str, Any]:
    summary = manifest_summary(manifest)
    result = payload.get("result", payload)
    result = result if isinstance(result, dict) else {}
    reported = result.get("files", result.get("fileProperties", [])) or []
    if isinstance(reported, dict):
        reported = [reported]
    returned = set()
    rejected = []
    for row in reported:
        if not isinstance(row, dict) or not row.get("fullName"):
            continue
        pair = (str(row.get("type", "")), str(row["fullName"]))
        file_path = row.get("filePath")
        invalid = str(row.get("state", "")).lower() in {"ignored", "failed", "deleted"}
        if file_path:
            reported_path = Path(file_path)
            candidates = [reported_path] if reported_path.is_absolute() else [root / reported_path, root.parents[2] / reported_path] if len(root.parents) > 2 else [root / reported_path]
            invalid = invalid or not any(path.is_file() and path.resolve().is_relative_to(root.resolve()) for path in candidates)
        if invalid:
            rejected.append({"type": pair[0], "member": pair[1], "reason": "ignored/failed or reported local file unavailable"})
        else:
            returned.add(pair)
    files = snapshot_files(root)
    # These source types can be reconciled even when older CLIs omit the files array.
    suffixes = {"ApexClass": ("classes", ".cls"), "ApexTrigger": ("triggers", ".trigger"),
                "Flow": ("flows", ".flow-meta.xml"), "Profile": ("profiles", ".profile-meta.xml"),
                "PermissionSet": ("permissionsets", ".permissionset-meta.xml")}
    for metadata_type, (directory, suffix) in suffixes.items():
        returned.update((metadata_type, path.name[:-len(suffix)]) for path in (root / directory).glob(f"*{suffix}"))
    missing = []
    unverified = []
    for entry in summary.get("entries", []):
        for member in entry["members"]:
            if member == "*":
                unverified.append({"type": entry["type"], "member": member, "reason": "wildcard requires a separate org inventory"})
            elif (entry["type"], member) not in returned:
                (missing if reported or entry["type"] in suffixes else unverified).append({"type": entry["type"], "member": member})
    messages = result.get("messages", []) or []
    warnings = payload.get("warnings", []) or []
    failed = payload.get("status", 0) not in (0, None) or result.get("success") is False or result.get("done") is False
    status = str(result.get("status", "")).lower()
    failed = failed or status in {"failed", "error", "pending", "inprogress", "canceled"}
    partial = mode == "configured_types_fallback" or bool(missing or rejected or messages or warnings or failed or not files)
    return {"schema": "dementor-retrieve-audit-v1", "collected_at": datetime.now(timezone.utc).isoformat(),
            "discovery_mode": mode, "manifest": summary, "include_packages": include_packages,
            "excluded_packages": sorted({"managed", "unlocked"} - set(include_packages)),
            "status": "partial" if partial else ("unverified" if unverified else "verified_requested_members"),
            "org_completeness_proven": False,
            "boundary": "Coverage is limited to metadata exposed to this user and API version. Managed Apex bodies and unsupported metadata may be unavailable.",
            "retrieve_status": result.get("status"), "retrieve_id": result.get("id"),
            "retrieve_failed": failed, "messages": messages, "warnings": warnings,
            "missing_members": missing, "unverified_members": unverified,
            "rejected_returned_members": rejected,
            "returned_members": [{"type": kind, "member": name} for kind, name in sorted(returned)],
            "file_count": len(files), "files": files}


def write_retrieve_audit(value: dict[str, Any], output: Path) -> None:
    output.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def split_manifest(path: Path, destination: Path, max_members: int) -> list[Path]:
    """Keep all explicit requests, splitting only the retrieve request size."""
    if max_members < 1:
        raise RuntimeError("metadata.retrieve_batch_members must be positive")
    summary = manifest_summary(path)
    pairs = [(entry["type"], member) for entry in summary.get("entries", []) for member in entry["members"]]
    profiles = [pair for pair in pairs if pair[0] == "Profile"]
    other_pairs = [pair for pair in pairs if pair[0] != "Profile"]
    if profiles and other_pairs:
        if len(profiles) >= max_members:
            raise RuntimeError("Increase metadata.retrieve_batch_members above the number of Profiles to preserve contextual Profile permissions.")
        pairs = other_pairs
        batch_size = max_members - len(profiles)
    else:
        profiles = []
        batch_size = max_members
    namespace = "http://soap.sforce.com/2006/04/metadata"
    ET.register_namespace("", namespace)
    destination.mkdir(parents=True, exist_ok=True)
    paths = []
    for start in range(0, len(pairs), batch_size):
        root = ET.Element(f"{{{namespace}}}Package")
        grouped: dict[str, list[str]] = {}
        for kind, member in pairs[start:start + batch_size] + profiles:
            grouped.setdefault(kind, []).append(member)
        for kind, members in grouped.items():
            types = ET.SubElement(root, f"{{{namespace}}}types")
            for member in members:
                ET.SubElement(types, f"{{{namespace}}}members").text = member
            ET.SubElement(types, f"{{{namespace}}}name").text = kind
        ET.SubElement(root, f"{{{namespace}}}version").text = summary.get("api_version")
        output = destination / f"part-{len(paths) + 1:03d}.xml"
        ET.ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)
        paths.append(output)
    return paths


def merge_profile_fragments(previous: dict[str, bytes], root: Path) -> int:
    """Metadata API returns contextual Profile grants; accumulate their local union."""
    reference_tags = {"name", "field", "object", "apexClass", "apexPage", "application", "layout",
                      "recordType", "tab", "externalDataSource", "customPermission", "customMetadataType", "customSetting",
                      "actionName", "formFactor", "pageOrSobjectType", "dataCategoryGroup", "dataCategory", "flow",
                      "startAddress", "endAddress", "connectedApp", "servicePresenceStatus", "externalCredentialPrincipal"}
    def identity(node: ET.Element) -> tuple[Any, ...]:
        refs = tuple(sorted((child.tag.split("}")[-1], child.text or "") for child in node
                            if child.tag.split("}")[-1] in reference_tags))
        return node.tag, refs
    merged_count = 0
    for name, content in previous.items():
        path = root / "profiles" / name
        if not path.exists():
            path.write_bytes(content)
            continue
        try:
            old, new = ET.fromstring(content), ET.parse(path).getroot()
        except ET.ParseError as exc:
            raise RuntimeError(f"Cannot merge malformed Profile fragments: {name}") from exc
        if old.tag != new.tag or old.tag.split("}")[-1] != "Profile":
            raise RuntimeError(f"Unexpected Profile fragment type: {name}")
        keys = {identity(node) for node in new}
        for node in old:
            if identity(node) not in keys:
                new.append(node)
                merged_count += 1
        ET.ElementTree(new).write(path, encoding="utf-8", xml_declaration=True)
    return merged_count
