from __future__ import annotations

from copy import deepcopy
from typing import Any


LOCALE = "pt-BR"

CATEGORY_LABELS = {
    "security": "Segurança",
    "architecture": "Arquitetura",
    "performance": "Desempenho",
    "automation": "Automação",
    "apex": "Apex",
    "testing": "Testes",
    "integrations": "Integrações",
    "data_quality": "Qualidade dos dados",
    "governance": "Governança",
    "maintainability": "Manutenibilidade",
    "observability": "Observabilidade",
}

SEVERITY_LABELS = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Informativa",
}

EFFORT_LABELS = {
    "High": "Alto",
    "Medium": "Médio",
    "Low": "Baixo",
    "Unknown": "Não estimado",
}

INVENTORY_LABELS = {
    "applications": "Aplicações",
    "objects": "Objetos",
    "fields": "Campos",
    "flows": "Flows",
    "apex_classes": "Classes Apex",
    "apex_triggers": "Triggers Apex",
    "profiles": "Perfis",
    "permission_sets": "Conjuntos de permissões",
    "named_credentials": "Credenciais nomeadas",
    "external_credentials": "Credenciais externas",
    "connected_apps": "Aplicações conectadas",
    "remote_sites": "Sites remotos",
    "workflows": "Regras de Workflow",
    "approval_processes": "Processos de aprovação",
    "validation_rules": "Regras de validação",
    "reports": "Relatórios",
    "dashboards": "Painéis",
}


def category_label(value: str) -> str:
    return CATEGORY_LABELS.get(value.lower(), value.replace("_", " ").capitalize())


def severity_label(value: str) -> str:
    return SEVERITY_LABELS.get(value.lower(), value.capitalize())


def effort_label(value: str) -> str:
    return EFFORT_LABELS.get(value, value)


def inventory_label(value: str) -> str:
    return INVENTORY_LABELS.get(value, value.replace("_", " ").capitalize())


def localize_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    """Adiciona rótulos pt-BR sem alterar chaves/enums usados por integrações."""
    data = deepcopy(payload)
    data["locale"] = LOCALE
    data["rotulos"] = {
        "categorias": CATEGORY_LABELS,
        "severidades": SEVERITY_LABELS,
        "esforcos": EFFORT_LABELS,
        "inventario": INVENTORY_LABELS,
    }
    for finding in data.get("findings", []):
        finding["category_label"] = category_label(str(finding.get("category", "")))
        finding["severity_label"] = severity_label(str(finding.get("severity", "")))
        finding["effort_label"] = effort_label(str(finding.get("effort", "")))
    health = data.get("health", {})
    health["category_labels"] = {
        key: category_label(key) for key in health.get("categories", {})
    }
    health["findings_by_severity_labels"] = {
        severity_label(key): value
        for key, value in health.get("findings_by_severity", {}).items()
    }
    data["inventory_labels"] = {
        key: inventory_label(key) for key in data.get("inventory", {})
    }
    return data
