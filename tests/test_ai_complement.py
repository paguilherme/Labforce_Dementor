from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from labforce_dementor.ai_complement import (
    AiComplementError,
    build_ai_payload,
    create_preview,
    execute_complement,
)


ASSESSMENT = {
    "product": {"name": "Labforce Dementor", "version": "4.1.0"},
    "health": {"overall": 82, "categories": {"security": 75}},
    "inventory": {"flows": 2},
    "findings": [{
        "id": "SEC-001",
        "severity": "high",
        "category": "security",
        "title": "Sensitive setting",
        "description": "Authorization: Bearer must-not-leak",
        "component": "NamedCredential:Example",
        "recommendation": "Rotate token=must-not-leak",
        "confidence": 0.98,
        "evidence": [{"kind": "metadata", "source": "/home/customer/project/file.xml", "detail": "api_key=must-not-leak", "confidence": 1.0}],
    }],
    "dependencies": [{"source": "NamedCredential:Example", "relationship": "USED_BY", "target": "ApexClass:Caller", "confidence": 1.0}],
}


class AiComplementTests(unittest.TestCase):
    def test_payload_is_allowlisted_and_sanitized(self) -> None:
        payload = build_ai_payload(ASSESSMENT, ["findings_with_evidence"])
        serialized = json.dumps(payload)
        self.assertNotIn("must-not-leak", serialized)
        self.assertNotIn("/home/customer/project", serialized)
        self.assertEqual(payload["findings"][0]["id"], "SEC-001")

    def test_no_provider_call_before_exact_consent_and_assessment_is_unchanged(self) -> None:
        calls: list[dict[str, object]] = []
        credential_loads: list[bool] = []

        def transport(url: str, headers: dict[str, str], body: dict[str, object], timeout: int) -> dict[str, object]:
            calls.append({"url": url, "headers": sorted(headers), "body": body, "timeout": timeout})
            return {
                "output_text": json.dumps({
                    "executive_summary": "Há um risco confirmado.",
                    "correlations": [{"title": "Credencial", "analysis": "Revisar rotação.", "finding_ids": ["SEC-001"]}],
                    "recommendations": [{"priority": "P1", "action": "Rotacionar", "rationale": "Reduz exposição.", "finding_ids": ["SEC-001"]}],
                    "limitations": ["Sem telemetria de runtime."],
                }),
                "usage": {"input_tokens": 100, "output_tokens": 40},
            }

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            assessment_path = root / "assessment.json"
            original = json.dumps(ASSESSMENT, indent=2)
            assessment_path.write_text(original, encoding="utf-8")
            preview_path = root / "preview.json"
            plan = create_preview(
                assessment_path,
                provider="openai",
                model="model-selected-by-user",
                data_scopes=["findings_with_evidence"],
                output_path=preview_path,
                now=datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(calls, [])
            with self.assertRaises(AiComplementError):
                execute_complement(
                    preview_path,
                    authorization_phrase="AUTORIZAR-ERRADO",
                    authorized_by="user@example.com",
                    output_dir=root / "reports",
                    credential_loader=lambda: (credential_loads.append(True) or ("secret-key", "tenant:project:ai_openai")),
                    now=datetime(2026, 10, 12, 12, 1, tzinfo=timezone.utc),
                    transport=transport,
                )
            self.assertEqual(calls, [])
            self.assertEqual(credential_loads, [])
            result = execute_complement(
                preview_path,
                authorization_phrase=plan["authorization_phrase"],
                authorized_by="user@example.com",
                api_key="secret-key",
                output_dir=root / "reports",
                credential_reference="tenant:project:ai_openai",
                now=datetime(2026, 10, 12, 12, 1, tzinfo=timezone.utc),
                transport=transport,
            )
            self.assertEqual(len(calls), 1)
            self.assertFalse(result["deterministic_result_modified"])
            self.assertEqual(assessment_path.read_text(encoding="utf-8"), original)
            self.assertNotIn("secret-key", (root / "reports" / "ai-complement.json").read_text(encoding="utf-8"))
            html_report = (root / "reports" / "ai-complement.html").read_text(encoding="utf-8")
            self.assertIn("Labforce · Labforce Dementor · Gerado em", html_report)
            self.assertIn("data:image/webp;base64,", html_report)
            with self.assertRaises(AiComplementError):
                execute_complement(
                    preview_path,
                    authorization_phrase=plan["authorization_phrase"],
                    authorized_by="user@example.com",
                    api_key="secret-key",
                    output_dir=root / "reports-two",
                    credential_reference="tenant:project:ai_openai",
                    now=datetime(2026, 10, 12, 12, 2, tzinfo=timezone.utc),
                    transport=transport,
                )


    def test_local_authenticated_cli_generates_reports_without_api_credential(self) -> None:
        response = json.dumps({
            "executive_summary": "Complemento local.",
            "correlations": [],
            "recommendations": [],
            "limitations": [],
        })
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(ASSESSMENT), encoding="utf-8")
            preview_path = root / "preview.json"
            plan = create_preview(
                assessment_path,
                provider="codex-local",
                model="default",
                data_scopes=["findings_summary"],
                output_path=preview_path,
                now=datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc),
            )
            original_hash = assessment_path.read_bytes()
            with patch("labforce_dementor.ai_complement.invoke_local_ai", return_value=(response, {"input_tokens": 10}, "local-session:codex")) as invoke, patch("labforce_dementor.ai_complement._http_transport") as http, patch("labforce_dementor.ai_credentials.resolve_ai_credential") as credentials:
                result = execute_complement(
                    preview_path,
                    authorization_phrase=plan["authorization_phrase"],
                    authorized_by="paulo",
                    output_dir=root / "reports",
                    now=datetime(2026, 10, 12, 12, 1, tzinfo=timezone.utc),
                )
            invoke.assert_called_once()
            self.assertEqual(result["consent"]["credential_reference"], "local-session:codex")
            self.assertTrue((root / "reports" / "ai-complement.pdf").exists())
            http.assert_not_called()
            credentials.assert_not_called()
            self.assertEqual(assessment_path.read_bytes(), original_hash)

if __name__ == "__main__":
    unittest.main()
