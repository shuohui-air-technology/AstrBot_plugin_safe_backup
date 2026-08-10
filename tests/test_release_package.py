"""Release-asset contract tests; all output is confined to a temporary directory."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_release_package.ps1"
HELPER = ROOT / "scripts" / "release_packager.py"
ASSET = "astrbot_plugin_safe_backup-v0.1.0-beta.zip"
sys.path.insert(0, str(HELPER.parent))
import release_packager  # noqa: E402


class ReleasePackageTests(unittest.TestCase):
    def _copy_source(self, parent: Path) -> Path:
        source = parent / "source"
        shutil.copytree(
            ROOT, source,
            ignore=shutil.ignore_patterns("__pycache__", ".superpowers", ".git"),
        )
        return source
    def test_packaging_script_exists_with_a_narrow_allowlist(self):
        wrapper = SCRIPT.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")
        self.assertIn("astrbot_plugin_safe_backup-v0.1.0-beta.zip", wrapper)
        self.assertIn(".sha256", wrapper)
        self.assertIn("ROOT_FILES", helper)
        self.assertIn("PACKAGE_FILES", helper)
        self.assertIn("RUNTIME_SCRIPTS", helper)
        self.assertNotIn("rglob(\"*.py\")", helper)
        self.assertIn("partial.zip", helper)
        self.assertIn("os.link", helper)

    @unittest.skipUnless(shutil.which("powershell") or shutil.which("pwsh"), "PowerShell unavailable")
    def test_release_asset_has_a_flat_plugin_root_and_checksum(self):
        shell = shutil.which("powershell") or shutil.which("pwsh")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._copy_source(root)
            output = root / "output"
            completed = subprocess.run(
                [shell, "-NoProfile", "-File", str(SCRIPT), "-SourceDirectory", str(source),
                 "-OutputDirectory", str(output)],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            archive = output / ASSET
            checksum = output / f"{ASSET}.sha256"
            self.assertTrue(archive.is_file())
            self.assertTrue(checksum.is_file())
            self.assertFalse(any(path.name.startswith(".") and "partial" in path.name for path in output.iterdir()))
            expected = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertEqual(checksum.read_text(encoding="ascii").strip(), f"{expected}  {ASSET}")
            with zipfile.ZipFile(archive) as bundle:
                names = set(bundle.namelist())
            for required in ("main.py", "metadata.yaml", "_conf_schema.json", "safe_backup/engine.py", "scripts/task_launcher.ps1"):
                self.assertIn(required, names)
            self.assertFalse(any(name.startswith(("tests/", ".git/", ".superpowers/")) for name in names))
            self.assertFalse(any(".." in Path(name).parts or ":" in name for name in names))

    def test_validate_only_rejects_overlap_root_and_leaves_missing_output_absent(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = self._copy_source(parent)
            missing = parent / "missing-output"
            release_packager.build(str(source), str(missing), True)
            self.assertFalse(missing.exists())
            with self.assertRaises(release_packager.PackageError):
                release_packager.build(str(source), str(parent / "missing-parent" / "output"), True)
            non_directory_parent = parent / "not-a-directory"
            non_directory_parent.write_text("ordinary file", encoding="utf-8")
            with self.assertRaises(release_packager.PackageError):
                release_packager.build(str(source), str(non_directory_parent / "output"), True)
            self.assertFalse((non_directory_parent / "output").exists())
            for unsafe in (source, parent, Path(source.anchor)):
                with self.subTest(unsafe=unsafe), self.assertRaises(release_packager.PackageError):
                    release_packager.build(str(source), str(unsafe), True)

    def test_exact_namespace_and_object_gates_reject_unexpected_and_hardlinked_files(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = self._copy_source(parent)
            unexpected = source / "safe_backup" / "unexpected.py"
            unexpected.write_text("x = 1\n", encoding="utf-8")
            with self.assertRaises(release_packager.PackageError):
                release_packager.build(str(source), str(parent / "out-a"), True)
            unexpected.unlink()
            leaf = source / "safe_backup" / "engine.py"
            alias = source / "engine-alias.py"
            os.link(leaf, alias)
            with self.assertRaises(release_packager.PackageError):
                release_packager.build(str(source), str(parent / "out-b"), True)
            self.assertTrue(alias.is_file())

    def test_cache_or_unexpected_directory_in_packaged_namespace_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = self._copy_source(parent)
            cache = source / "safe_backup" / "__pycache__"
            cache.mkdir()
            (cache / "engine.pyc").write_bytes(b"cache")
            with self.assertRaises(release_packager.PackageError):
                release_packager.build(str(source), str(parent / "out"), True)

    def test_preexisting_release_asset_is_preserved_without_partial_cleanup(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = self._copy_source(parent)
            output = parent / "out"
            output.mkdir()
            archive = output / ASSET
            checksum = output / f"{ASSET}.sha256"
            archive.write_bytes(b"foreign archive")
            checksum.write_text("foreign checksum\n", encoding="ascii")
            before = (archive.read_bytes(), checksum.read_bytes())
            with self.assertRaises(release_packager.PackageError):
                release_packager.build(str(source), str(output), False)
            self.assertEqual(before, (archive.read_bytes(), checksum.read_bytes()))
            self.assertFalse(any(path.name.startswith(".") and "partial" in path.name for path in output.iterdir()))

    @unittest.skipUnless(os.name == "nt", "ADS requires Windows NTFS")
    def test_selected_alternate_data_stream_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = self._copy_source(parent)
            leaf = source / "safe_backup" / "engine.py"
            stream = str(leaf) + ":release-test-stream"
            try:
                with open(stream, "wb") as handle:
                    handle.write(b"not package content")
                with self.assertRaises(release_packager.PackageError):
                    release_packager.build(str(source), str(parent / "out"), True)
            finally:
                try:
                    os.remove(stream)
                except FileNotFoundError:
                    pass

    def test_second_publication_race_preserves_foreign_asset_and_rolls_back_our_checksum(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = self._copy_source(parent)
            output = parent / "out"
            output.mkdir()
            foreign = output / ASSET
            real_link = release_packager.os.link
            calls = 0

            def race_link(src, dst, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    foreign.write_bytes(b"foreign winner")
                return real_link(src, dst, **kwargs)

            with mock.patch.object(release_packager.os, "link", side_effect=race_link):
                with self.assertRaises(release_packager.PackageError):
                    release_packager.build(str(source), str(output), False)
            self.assertEqual(foreign.read_bytes(), b"foreign winner")
            self.assertFalse((output / f"{ASSET}.sha256").exists())
            self.assertFalse(any(path.name.startswith(".") for path in output.iterdir()))

    def test_final_candidate_validation_failure_rolls_back_the_published_pair(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = self._copy_source(parent)
            output = parent / "out"
            original = release_packager._verify_candidate
            calls = 0

            def fail_final(path, selected):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise release_packager.PackageError("synthetic final verification failure")
                return original(path, selected)

            with mock.patch.object(release_packager, "_verify_candidate", side_effect=fail_final):
                with self.assertRaises(release_packager.PackageError):
                    release_packager.build(str(source), str(output), False)
            self.assertFalse((output / ASSET).exists())
            self.assertFalse((output / f"{ASSET}.sha256").exists())
            self.assertFalse(any(path.name.startswith(".") for path in output.iterdir()))

    def test_source_drift_after_partial_write_fails_without_formal_output(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = self._copy_source(parent)
            output = parent / "out"
            original = release_packager._assert_unchanged

            def mutate_then_check(root, selected):
                (root / "README.md").write_text("changed during packaging\n", encoding="utf-8")
                return original(root, selected)

            with mock.patch.object(release_packager, "_assert_unchanged", side_effect=mutate_then_check):
                with self.assertRaises(release_packager.PackageError):
                    release_packager.build(str(source), str(output), False)
            self.assertFalse((output / ASSET).exists())
            self.assertFalse((output / f"{ASSET}.sha256").exists())
            self.assertFalse(any(path.name.startswith(".") for path in output.iterdir()))
