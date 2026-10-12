from __future__ import annotations

from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any


@dataclass
class Evidence:
    kind: str
    source: str
    detail: str = ""
    confidence: float = 1.0


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    title: str
    description: str
    component: str = ""
    recommendation: str = ""
    effort: str = "Unknown"
    confidence: float = 1.0
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


@dataclass
class AssessmentResult:
    product: dict[str, Any]
    run: dict[str, Any]
    org: dict[str, Any]
    limits_before: dict[str, Any]
    limits_after: dict[str, Any]
    inventory: dict[str, Any]
    components: dict[str, Any]
    dependencies: list[dict[str, Any]]
    findings: list[Finding]
    health: dict[str, Any]
    audit: dict[str, Any]
    code_analyzer: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "run": self.run,
            "org": self.org,
            "limits_before": self.limits_before,
            "limits_after": self.limits_after,
            "inventory": self.inventory,
            "components": self.components,
            "dependencies": self.dependencies,
            "findings": [f.to_dict() for f in self.findings],
            "health": self.health,
            "audit": self.audit,
            "code_analyzer": self.code_analyzer,
        }
