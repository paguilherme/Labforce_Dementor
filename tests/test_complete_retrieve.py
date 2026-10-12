from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import Mock

from labforce_dementor.engine import _manifest_summary
from labforce_dementor.sfcli import SFCLI


def test_full_org_manifest_discovery_does_not_restrict_metadata_types() -> None:
    with tempfile.TemporaryDirectory() as temp:
        sf = object.__new__(SFCLI)
        sf.target_org = "example"
        sf.run = Mock(return_value={"payload": {}})
        sf.generate_manifest(None, Path(temp), batch_size=7, include_packages=[])
        args = sf.run.call_args.args[0]
        assert args[:4] == ["project", "generate", "manifest", "--from-org"]
        assert "--metadata" not in args
        assert sf.run.call_args.kwargs["extra_env"]["SF_LIST_METADATA_BATCH_SIZE"] == "7"


def test_package_inclusion_is_explicit() -> None:
    with tempfile.TemporaryDirectory() as temp:
        sf = object.__new__(SFCLI)
        sf.target_org = "example"
        sf.run = Mock(return_value={"payload": {}})
        sf.generate_manifest(None, Path(temp), include_packages=["managed", "unlocked"])
        args = sf.run.call_args.args[0]
        assert args.count("--include-packages") == 2
        assert "managed" in args and "unlocked" in args


def test_manifest_summary_counts_types_and_members() -> None:
    with tempfile.TemporaryDirectory() as temp:
        manifest = Path(temp) / "package.xml"
        manifest.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<Package xmlns="http://soap.sforce.com/2006/04/metadata">
  <types><members>A</members><members>B</members><name>ApexClass</name></types>
  <types><members>*</members><name>CustomObject</name></types>
  <version>66.0</version>
</Package>""", encoding="utf-8")
        assert _manifest_summary(manifest)["types"] == 2
        assert _manifest_summary(manifest)["members"] == 3
