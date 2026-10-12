from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


COMPANY_NAME = "Labforce"
SYSTEM_NAME = "Labforce Dementor"
DEFAULT_TIMEZONE = "America/Maceio"


def _timezone(config: dict[str, Any] | None = None) -> tuple[str, ZoneInfo]:
    name = str((config or {}).get("report", {}).get("timezone") or DEFAULT_TIMEZONE)
    try:
        return name, ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return "UTC", ZoneInfo("UTC")


def report_metadata(
    config: dict[str, Any] | None = None,
    *,
    generated_at: datetime | None = None,
) -> dict[str, str]:
    timezone_name, timezone = _timezone(config)
    instant = generated_at or datetime.now(timezone)
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone)
    else:
        instant = instant.astimezone(timezone)
    return {
        "company": COMPANY_NAME,
        "system": SYSTEM_NAME,
        "generated_at": instant.isoformat(timespec="seconds"),
        "generated_at_display": instant.strftime("%d/%m/%Y %H:%M:%S %Z"),
        "timezone": timezone_name,
    }


def with_report_metadata(
    payload: dict[str, Any],
    config: dict[str, Any] | None = None,
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    branded = deepcopy(payload)
    branded["report_metadata"] = report_metadata(config, generated_at=generated_at)
    return branded


def logo_path() -> Path:
    return Path(__file__).resolve().parent / "assets" / "labforce-logo.webp"


def logo_data_uri() -> str:
    encoded = base64.b64encode(logo_path().read_bytes()).decode("ascii")
    return f"data:image/webp;base64,{encoded}"


def footer_text(metadata: dict[str, str]) -> str:
    return (
        f"{metadata['company']} · {metadata['system']} · "
        f"Gerado em {metadata['generated_at_display']}"
    )
