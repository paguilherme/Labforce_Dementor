from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from labforce_dementor.ai_complement import AiComplementError
from labforce_dementor.ai_wizard import offer_ai_report
from labforce_dementor.cli import main


class AiWizardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.assessment = Path(self.temp.name) / "assessment.json"
        self.original = json.dumps({"health": {"overall": 73.1}, "findings": []})
        self.assessment.write_text(self.original, encoding="utf-8")

    @contextlib.contextmanager
    def terminal(self, interactive: bool = True):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch("sys.stdin.isatty", return_value=interactive), patch.object(output, "isatty", return_value=interactive):
            yield output

    def test_declining_does_not_prepare_payload_or_load_credentials(self) -> None:
        with self.terminal(), patch("builtins.input", return_value="n"), patch("labforce_dementor.ai_wizard.create_preview") as preview, patch("labforce_dementor.ai_wizard.execute_complement") as execute, patch("labforce_dementor.ai_wizard.resolve_ai_credential") as credential:
            self.assertTrue(offer_ai_report(self.assessment))
        preview.assert_not_called()
        execute.assert_not_called()
        credential.assert_not_called()

    def test_noninteractive_sessions_never_prompt_or_call_ai(self) -> None:
        with self.terminal(False) as output, patch("builtins.input") as ask, patch("labforce_dementor.ai_wizard.execute_complement") as execute:
            self.assertTrue(offer_ai_report(self.assessment))
        ask.assert_not_called()
        execute.assert_not_called()
        self.assertIn("dementor ai-report --assessment", output.getvalue())

    def test_exact_consent_is_required_after_the_preview(self) -> None:
        answers = ["s", "1", "user-selected-model", "2", "1", "paulo@example.com", "sim"]
        with self.terminal() as output, patch("builtins.input", side_effect=answers), patch("labforce_dementor.ai_wizard.execute_complement") as execute, patch("labforce_dementor.ai_wizard.resolve_ai_credential") as credential:
            self.assertTrue(offer_ai_report(self.assessment))
        execute.assert_not_called()
        credential.assert_not_called()
        preview = json.loads((self.assessment.parent / "ai-consent-preview.json").read_text())
        self.assertEqual(preview["provider"], "openai")
        self.assertEqual(preview["model"], "user-selected-model")
        self.assertEqual(preview["data_scopes"], ["findings_with_evidence"])
        self.assertIn("Nenhum dado foi enviado", output.getvalue())
        self.assertEqual(self.assessment.read_text(), self.original)

    def test_authorized_selection_delegates_to_existing_consent_engine(self) -> None:
        answers = iter(["s", "ollama", "local-user-model", "findings_summary", "Paulo"])

        def answer(prompt: str) -> str:
            if "Para autorizar" in prompt:
                plan = json.loads((self.assessment.parent / "ai-consent-preview.json").read_text())
                return plan["authorization_phrase"]
            return next(answers)

        with self.terminal(), patch("builtins.input", side_effect=answer), patch("labforce_dementor.ai_wizard.execute_complement", return_value={"provider": "ollama", "model": "local-user-model"}) as execute:
            self.assertTrue(offer_ai_report(self.assessment))
        self.assertEqual(execute.call_count, 1)
        call = execute.call_args.kwargs
        self.assertEqual(call["authorized_by"], "Paulo")
        self.assertEqual(call["credential_loader"](), (None, "local-loopback:ollama"))
        self.assertEqual(self.assessment.read_text(), self.original)

    def test_eof_and_keyboard_interrupt_keep_assessment(self) -> None:
        for error in (EOFError, KeyboardInterrupt):
            with self.subTest(error=error), self.terminal(), patch("builtins.input", side_effect=error), patch("labforce_dementor.ai_wizard.execute_complement") as execute:
                self.assertTrue(offer_ai_report(self.assessment))
            execute.assert_not_called()
            self.assertEqual(self.assessment.read_text(), self.original)

    def test_run_offers_ai_even_when_pdf_generation_fails(self) -> None:
        manifest = {"health": {"overall": 73.1}, "reports": {"json": str(self.assessment), "markdown": "assessment.md", "html": "assessment.html", "pdf": {"path": "assessment.pdf", "generated": False, "error": "missing libgobject"}}}
        with self.terminal(), patch("labforce_dementor.cli.run_assessment", return_value=manifest), patch("labforce_dementor.cli.offer_ai_report") as offer:
            main(["run", "--target-org", "example"])
        offer.assert_called_once_with(self.assessment)
        with self.terminal(), patch("labforce_dementor.cli.run_assessment", return_value=manifest), patch("labforce_dementor.cli.offer_ai_report") as offer:
            main(["run", "--target-org", "example", "--no-ai-prompt"])
        offer.assert_not_called()

    def test_ai_report_reuses_snapshot_without_salesforce_collection(self) -> None:
        with patch("labforce_dementor.cli.offer_ai_report", return_value=True) as offer, patch("labforce_dementor.cli.run_assessment") as collect:
            main(["ai-report", "--assessment", str(self.assessment)])
        offer.assert_called_once_with(self.assessment)
        collect.assert_not_called()

    def test_preview_failure_reports_error_and_preserves_snapshot(self) -> None:
        answers = ["s", "ollama", "local-user-model", "1", "Paulo"]
        with self.terminal(), contextlib.redirect_stderr(io.StringIO()), patch("builtins.input", side_effect=answers), patch("labforce_dementor.ai_wizard.create_preview", side_effect=AiComplementError("invalid snapshot")), patch("labforce_dementor.ai_wizard.execute_complement") as execute:
            self.assertFalse(offer_ai_report(self.assessment))
        execute.assert_not_called()
        self.assertEqual(self.assessment.read_text(), self.original)
