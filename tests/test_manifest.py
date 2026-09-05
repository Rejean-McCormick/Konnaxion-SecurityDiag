import unittest
from pathlib import Path
from securitydiag_core.manifest import load_manifest, resolve_selection

ROOT=Path(__file__).resolve().parents[1]

class ManifestTests(unittest.TestCase):
    def test_manifest_has_s00_s14(self):
        m=load_manifest(ROOT)
        ids=[x["id"] for x in m["levels"]]
        self.assertEqual(ids,[f"S{i:02d}" for i in range(15)])

    def test_release_selects_all(self):
        m=load_manifest(ROOT)
        ids=[x["id"] for x in resolve_selection(m,"release")]
        self.assertEqual(ids,[f"S{i:02d}" for i in range(15)])

if __name__=="__main__":
    unittest.main()
