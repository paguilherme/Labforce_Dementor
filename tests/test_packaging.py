from __future__ import annotations

import contextlib
import io
import sys
import tomllib
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"


class PackagingContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pyproject = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_distribution_name_and_cli_aliases(self) -> None:
        project = self.pyproject["project"]
        self.assertEqual(project["name"], "labforce-dementor")
        self.assertEqual(project["license"], "LicenseRef-Labforce-Free-Proprietary-1.0")
        self.assertEqual(project["license-files"], ["LICENSE"])
        self.assertEqual(project["readme"], "PYPI_README.md")
        self.assertEqual(project["urls"]["Homepage"], "https://labforce.com.br/dementor/")
        self.assertTrue((PACKAGE_ROOT / "LICENSE").is_file())
        self.assertTrue((PACKAGE_ROOT / "PYPI_README.md").is_file())
        self.assertEqual(
            project["scripts"],
            {
                "dementor": "labforce_dementor.entrypoint:main",
                "labforce-dementor": "labforce_dementor.entrypoint:main",
            },
        )

    def test_versions_are_synchronized(self) -> None:
        project_version = self.pyproject["project"]["version"]
        init_source = (SOURCE_ROOT / "labforce_dementor" / "__init__.py").read_text(encoding="utf-8")
        embedded_config = (SOURCE_ROOT / "labforce_dementor" / "config.py").read_text(encoding="utf-8")
        default_config = (PACKAGE_ROOT / "config" / "default.yml").read_text(encoding="utf-8")
        self.assertIn(f'__version__ = "{project_version}"', init_source)
        self.assertIn(f'"version": "{project_version}"', embedded_config)
        self.assertIn(f'version: "{project_version}"', default_config)

    def test_lightweight_entrypoint_reports_version(self) -> None:
        sys.path.insert(0, str(SOURCE_ROOT))
        try:
            from labforce_dementor.entrypoint import main

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                main(["--version"])
        finally:
            sys.path.remove(str(SOURCE_ROOT))
        self.assertEqual(output.getvalue().strip(), f"dementor {self.pyproject['project']['version']}")


if __name__ == "__main__":
    unittest.main()
