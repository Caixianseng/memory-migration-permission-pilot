"""Tiny synthetic public-download fixtures; no network or model is used."""
from __future__ import annotations
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import setup_mdeberta_nli_assets as assets


class AssetDownloadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.patcher = patch.object(assets, "ASSETS", self.root)
        self.patcher.start(); self.addCleanup(self.patcher.stop)

    def entry(self, raw=b"public fixture"):
        return {"name": "config.json", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def test_fixed_manifest_is_complete_without_loading_or_network(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            manifest, _ = assets.load_manifest()
        self.assertEqual(manifest["revision"], assets.REVISION)
        self.assertEqual({r["name"] for r in manifest["files"]}, assets.NAMES)
        self.assertEqual(manifest["total_bytes_including_model_card"], 578297612)
        self.assertFalse(manifest["task_effectiveness_measured"])

    def test_anonymous_pinned_url_and_verified_exact_bytes(self):
        raw = b"public fixture"; seen = []
        def opening(request, timeout):
            seen.append(request)
            self.assertEqual(timeout, 60)
            return io.BytesIO(raw)
        with patch("urllib.request.urlopen", opening):
            receipt = assets.fetch_one(self.root / "config.json", self.entry(raw))
        self.assertEqual((self.root / "config.json").read_bytes(), raw)
        self.assertEqual(receipt["sha256"], self.entry(raw)["sha256"])
        self.assertIn("/resolve/" + assets.REVISION + "/config.json", seen[0].full_url)
        self.assertEqual({k.lower() for k, _ in seen[0].header_items()}, {"user-agent"})

    def test_corrupt_or_oversize_file_is_not_published_or_silently_retried(self):
        for kind in ("hash", "size"):
            directory = self.root / kind; directory.mkdir()
            entry = self.entry(b"expected")
            bad = b"not_same" if kind == "hash" else b"different bytes"
            with patch("urllib.request.urlopen", return_value=io.BytesIO(bad)) as opening:
                with self.assertRaises(ValueError): assets.fetch_one(directory / "config.json", entry)
            self.assertEqual(opening.call_count, 1)
            self.assertFalse((directory / "config.json").exists())
            self.assertTrue((directory / "config.json.part").exists())
        # A supplied partial is diagnostic evidence, not silently overwritten.
        with patch("urllib.request.urlopen", side_effect=AssertionError("retry")):
            with self.assertRaisesRegex(ValueError, "previous_partial"):
                assets.fetch_one(self.root / "hash/config.json", self.entry())

    def test_parent_escape_is_rejected_before_filesystem_or_network_use(self):
        with self.assertRaisesRegex(ValueError, "asset_scope"):
            assets.scoped(self.root / "../outside.json")


if __name__ == "__main__": unittest.main()
