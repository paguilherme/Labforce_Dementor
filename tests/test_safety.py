import unittest

from labforce_dementor.safety import ReadOnlyCommandGuard, UnsafeCommandError


class SafetyGuardTest(unittest.TestCase):
    def test_allows_query(self):
        ReadOnlyCommandGuard.validate(["sf", "data", "query", "--query", "SELECT Id FROM Account", "--json"])

    def test_allows_retrieve(self):
        ReadOnlyCommandGuard.validate(["sf", "project", "retrieve", "start", "--manifest", "manifest/package.xml", "--json"])

    def test_blocks_deploy(self):
        with self.assertRaises(UnsafeCommandError):
            ReadOnlyCommandGuard.validate(["sf", "project", "deploy", "start", "--source-dir", "force-app"])

    def test_blocks_data_update(self):
        with self.assertRaises(UnsafeCommandError):
            ReadOnlyCommandGuard.validate(["sf", "data", "update", "record", "--sobject", "Account"])

    def test_blocks_unknown_command(self):
        with self.assertRaises(UnsafeCommandError):
            ReadOnlyCommandGuard.validate(["sf", "apex", "run", "--file", "x.apex"])


if __name__ == "__main__":
    unittest.main()
