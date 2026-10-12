from __future__ import annotations

import unittest
import tempfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from labforce_dementor.branding import footer_text, logo_path, report_metadata
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


if __name__ == "__main__":
    unittest.main()
