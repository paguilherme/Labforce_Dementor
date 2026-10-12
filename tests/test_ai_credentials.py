from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from labforce_dementor.ai_credentials import resolve_ai_credential


class AiCredentialTests(unittest.TestCase):
    def test_labforce_base_lease_reads_only_requested_tenant_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "platform" / "credentials"
            target.mkdir(parents=True)
            (target / "secret_broker.py").write_text(
                """
from types import SimpleNamespace

class SecretBroker:
    def __init__(self, root):
        self.root = root

    def lease_environment(self, *, tool, organization, client, project):
        if organization != "org-a":
            raise KeyError(organization)
        return SimpleNamespace(
            environment={"OPENAI_API_KEY": "key-for-a"},
            reference=f"{organization}:{client or '-'}:{project or '-'}:{tool}",
        )
""".strip(),
                encoding="utf-8",
            )
            lease = resolve_ai_credential(
                "openai",
                source="labforce-base",
                organization="org-a",
                base_root=root,
            )
            self.assertEqual(lease.api_key, "key-for-a")
            self.assertEqual(lease.reference, "org-a:-:-:ai_openai")


if __name__ == "__main__":
    unittest.main()
