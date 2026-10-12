from __future__ import annotations

import unittest
import tempfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from labforce_dementor.branding import footer_text, logo_path, report_metadata, with_report_metadata
from labforce_dementor.impact_reporting import render_impact_html


class ReportBrandingTests(unittest.TestCase):
    def test_footer_has_fixed_identity_and_generation_time(self) -> None:
        generated_at = datetime(2026, 10, 12, 7, 45, 30, tzinfo=ZoneInfo("America/Maceio"))
        metadata = report_metadata(generated_at=generated_at)
        self.assertEqual(metadata["company"], "Labforce")
        self.assertEqual(metadata["system"], "Labforce Dementor")
        self.assertEqual(metadata["timezone"], "America/Maceio")
        self.assertEqual(
            footer_text(metadata),
            "Labforce · Labforce Dementor · Gerado em 12/10/2026 07:45:30 -03",
        )

    def test_packaged_logo_is_the_canonical_base_ui_asset(self) -> None:
        asset = logo_path().read_bytes()
        self.assertTrue(asset.startswith(b"RIFF"))
        self.assertIn(b"WEBP", asset[:16])
        self.assertGreater(len(asset), 1_000)

    def test_impact_report_renders_logo_and_required_footer(self) -> None:
        generated_at = datetime(2026, 10, 12, 7, 45, 30, tzinfo=ZoneInfo("America/Maceio"))
        with tempfile.TemporaryDirectory() as temp:
            path = render_impact_html({
                "component": "Account.Status__c",
                "risk": "HIGH",
                "change_risk_score": 80,
                "blast_radius": 3,
                "affected_by_type": {"Flow": 2},
                "affected_components": ["Flow:A"],
                "related_findings": [],
            }, Path(temp) / "impact.html", generated_at=generated_at)
            rendered = path.read_text(encoding="utf-8")
            self.assertIn("data:image/webp;base64,", rendered)
            self.assertIn("Labforce · Labforce Dementor · Gerado em 12/10/2026 07:45:30 -03", rendered)
            self.assertIn("Página", rendered)
            self.assertIn("Assessment de impacto da mudança", rendered)
            self.assertIn("Risco da mudança", rendered)
            self.assertNotIn("Change Impact Assessment", rendered)

    def test_assessment_data_contains_portuguese_labels_without_breaking_enums(self) -> None:
        localized = with_report_metadata({
            "findings": [{"category": "security", "severity": "high", "effort": "Medium"}],
            "health": {
                "categories": {"security": 90},
                "findings_by_severity": {"high": 1},
            },
            "inventory": {"apex_classes": 3},
        })
        self.assertEqual(localized["locale"], "pt-BR")
        self.assertEqual(localized["findings"][0]["severity"], "high")
        self.assertEqual(localized["findings"][0]["severity_label"], "Alta")
        self.assertEqual(localized["findings"][0]["category_label"], "Segurança")
        self.assertEqual(localized["findings"][0]["effort_label"], "Médio")
        self.assertEqual(localized["inventory_labels"]["apex_classes"], "Classes Apex")

    def test_main_report_template_is_portuguese(self) -> None:
        template = (
            Path(__file__).resolve().parents[1]
            / "src/labforce_dementor/templates/report.html.j2"
        ).read_text(encoding="utf-8")
        for text in (
            "Resumo executivo",
            "Pontuação de saúde",
            "Principais achados",
            "Manifesto de segurança do assessment",
            "Plano de remediação",
        ):
            self.assertIn(text, template)


if __name__ == "__main__":
    unittest.main()
