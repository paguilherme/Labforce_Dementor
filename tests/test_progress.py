from __future__ import annotations

import io
import unittest

from labforce_dementor.cli import build_parser
from labforce_dementor.progress import AssessmentProgress, STAGES


class AssessmentProgressTests(unittest.TestCase):
    def test_plain_progress_is_stable_for_logs_and_ci(self) -> None:
        stream = io.StringIO()
        progress = AssessmentProgress(stream=stream, interactive=False)
        progress.update("preflight", "start", "Conferindo autenticação")
        progress.update("preflight", "update", "Detalhe transitório")
        progress.update("preflight", "done", "Org de teste")
        progress.update("metadata_retrieve", "start", "Preparando")
        progress.update("metadata_retrieve", "skipped", "Snapshot local")
        progress.close()

        output = stream.getvalue()
        self.assertIn(f"→ [1/{len(STAGES)}] Validando organização e limites de API", output)
        self.assertIn(f"✓ [1/{len(STAGES)}] Validando organização e limites de API · Org de teste", output)
        self.assertIn(f"↷ [4/{len(STAGES)}] Descobrindo e recuperando metadados · Snapshot local", output)
        self.assertNotIn("Detalhe transitório", output)
        self.assertNotIn("\033", output)

    def test_progress_can_be_disabled(self) -> None:
        stream = io.StringIO()
        progress = AssessmentProgress(enabled=False, stream=stream, interactive=False)
        progress.update("preflight", "start", "ignored")
        progress.fail("ignored")
        progress.close()
        self.assertEqual(stream.getvalue(), "")

    def test_run_parser_accepts_no_progress(self) -> None:
        args = build_parser().parse_args(["run", "--target-org", "example", "--no-progress"])
        self.assertTrue(args.no_progress)


if __name__ == "__main__":
    unittest.main()
