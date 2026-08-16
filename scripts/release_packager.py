"""Fail-closed, local-only release asset builder used by build_release_package.ps1."""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath


ASSET = "astrbot_plugin_safe_backup-v0.1.0-beta.zip"
MAX_BYTES = 16 * 1024 * 1024
ROOT_FILES = (
    "main.py", "metadata.yaml", "_conf_schema.json", "requirements.txt",
    "README.md", "README_EN.md", "SECURITY.md", "CHANGELOG.md",
    "CONTRIBUTING.md", "LICENSE", "PUBLISHING_AGENT_PROMPT.md", "logo.svg",
)
PACKAGE_FILES = (
    "safe_backup/__init__.py", "safe_backup/engine.py", "safe_backup/setup.py",
    "safe_backup/task_control.py", "safe_backup/exit_waiter.py",
    "safe_backup/progress.py", "safe_backup/console_runner.py",
)
RUNTIME_SCRIPTS = (
    "scripts/install_task.ps1", "scripts/update_task.ps1", "scripts/remove_task.ps1",
    "scripts/task_common.ps1", "scripts/task_launcher.ps1",
    "scripts/run_backup_visible.ps1", "scripts/start_task.ps1", "scripts/manual_backup.ps1",
)
TOOLING = {"scripts/build_release_package.ps1", "scripts/release_packager.py"}
ENTRIES = ROOT_FILES + PACKAGE_FILES + RUNTIME_SCRIPTS
PRIVATE = (
    re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+", re.I),
    re.compile(r"[A-Za-z]:\\qq(?:\\|$)", re.I),
    re.compile(re.escape("AstrBot" + " NapCat " + "Read-Only " + "Backup"), re.I),
    re.compile(r"(?:api[_-]?key|token|passkey|cookie|password)\s*[:=]\s*[\"'][^\"']+[\"']", re.I),
)


class PackageError(RuntimeError):
    pass


@dataclass(frozen=True)
class Snapshot:
    dev: int
    ino: int
    size: int
    mtime_ns: int
    nlink: int
    digest: str
    data: bytes


def _fail(message: str) -> None:
    raise PackageError(message)


def _reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _windows_input(raw: str, label: str) -> Path:
    if not isinstance(raw, str) or not re.fullmatch(r"[A-Za-z]:[\\/].*", raw):
        _fail(f"{label} is not an absolute local Windows path")
    if raw.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\")):
        _fail(f"{label} is not a local Windows path")
    # A colon after the drive marker is ADS syntax, not a directory path.
    if ":" in raw[2:]:
        _fail(f"{label} contains ADS syntax")
    lexical = Path(os.path.abspath(raw))
    drive, tail = os.path.splitdrive(str(lexical))
    if tail.rstrip("\\/") == "":
        _fail(f"{label} may not be a volume root")
    return lexical


def _ancestor_chain(path: Path, *, missing_ok: bool) -> list[Path]:
    current = path
    if not os.path.lexists(str(current)) and not missing_ok:
        _fail("required source directory is missing")
    if not os.path.lexists(str(current)) and missing_ok:
        parent = current.parent
        # A single missing output leaf is allowed; recursive output creation is
        # deliberately not. This is shared by ValidateOnly and real builds.
        if parent == current or not os.path.lexists(str(parent)):
            _fail("output parent must already exist")
        try:
            parent_info = parent.lstat()
        except OSError:
            _fail("output parent cannot be inspected")
        if _reparse(parent) or not stat.S_ISDIR(parent_info.st_mode):
            _fail("output parent must be an ordinary directory")
        current = parent
    chain: list[Path] = []
    while True:
        chain.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return chain


def _assert_trusted_ancestors(path: Path, *, missing_ok: bool) -> None:
    for ancestor in _ancestor_chain(path, missing_ok=missing_ok):
        try:
            if _reparse(ancestor):
                _fail("a path or existing ancestor is a reparse point")
        except OSError:
            _fail("a path ancestor cannot be inspected")


def _key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path.resolve(strict=False)))).casefold()


def _is_inside(child: Path, parent: Path) -> bool:
    ck, pk = _key(child), _key(parent)
    return ck == pk or ck.startswith(pk.rstrip("\\/") + os.sep.casefold())


def _admit(source_raw: str, output_raw: str) -> tuple[Path, Path]:
    source = _windows_input(source_raw, "source")
    output = _windows_input(output_raw, "output")
    _assert_trusted_ancestors(source, missing_ok=False)
    _assert_trusted_ancestors(output, missing_ok=True)
    if not source.is_dir() or _reparse(source):
        _fail("source is not a trusted directory")
    if os.path.lexists(str(output)) and (not output.is_dir() or _reparse(output)):
        _fail("output is not a trusted directory")
    # Both spellings and final identities must stay disjoint.
    final_source = source.resolve(strict=True)
    final_output = output.resolve(strict=False)
    if _is_inside(final_source, final_output) or _is_inside(final_output, final_source):
        _fail("source and output overlap")
    if os.path.lexists(str(output)) and os.path.samestat(source.stat(), output.stat()):
        _fail("source and output are the same object")
    return final_source, final_output


def _ads(path: Path) -> bool:
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes
    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", wintypes.WCHAR * 296)]
    data = WIN32_FIND_STREAM_DATA()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.FindFirstStreamW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(WIN32_FIND_STREAM_DATA), wintypes.DWORD)
    kernel.FindFirstStreamW.restype = wintypes.HANDLE
    kernel.FindNextStreamW.argtypes = (wintypes.HANDLE, ctypes.POINTER(WIN32_FIND_STREAM_DATA))
    kernel.FindNextStreamW.restype = wintypes.BOOL
    kernel.FindClose.argtypes = (wintypes.HANDLE,)
    kernel.FindClose.restype = wintypes.BOOL
    handle = kernel.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        _fail("file streams cannot be inspected")
    try:
        while True:
            name = data.cStreamName
            if name and name.casefold() != "::$data":
                return True
            if not kernel.FindNextStreamW(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error == 38:  # ERROR_HANDLE_EOF
                    return False
                _fail("file streams cannot be inspected")
    finally:
        kernel.FindClose(handle)


def _entry_name(raw: str) -> str:
    candidate = PureWindowsPath(raw.replace("/", "\\"))
    if candidate.is_absolute() or candidate.drive or any(part in ("", ".", "..") for part in candidate.parts):
        _fail("unsafe archive entry")
    if any(":" in part or "\\" in part or "/" in part for part in candidate.parts):
        _fail("unsafe archive entry")
    return "/".join(candidate.parts)


def _namespace_is_exact(root: Path) -> None:
    expected = set(ENTRIES) | TOOLING
    folded: dict[str, str] = {}
    for name in expected:
        old = folded.setdefault(name.casefold(), name)
        if old != name:
            _fail("case-equivalent expected namespace collision")
    for namespace in (root / "safe_backup", root / "scripts"):
        _assert_trusted_ancestors(namespace, missing_ok=False)
        if not namespace.is_dir() or _reparse(namespace):
            _fail("packaged namespace is unsafe")
        for path in namespace.rglob("*"):
            rel = path.relative_to(root).as_posix()
            if _reparse(path):
                _fail("packaged namespace has a reparse object")
            if path.is_dir():
                _fail("unexpected directory in packaged namespace")
            if rel not in expected or folded.get(rel.casefold()) != rel:
                _fail("unexpected file in packaged namespace")


def _read_stable(root: Path, entry: str) -> Snapshot:
    path = root.joinpath(*entry.split("/"))
    _assert_trusted_ancestors(path.parent, missing_ok=False)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or _reparse(path) or before.st_nlink != 1 or _ads(path):
            _fail("selected release object is not an ordinary single-link file")
        with path.open("rb") as handle:
            data = handle.read()
        after = path.lstat()
    except OSError:
        _fail("selected release object cannot be read")
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        _fail("selected release object changed while read")
    if len(data) != before.st_size:
        _fail("selected release object changed while read")
    text = data.decode("utf-8", errors="replace")
    if data.startswith((b"SQLite format 3\x00", b"PK\x03\x04")) or any(pattern.search(text) for pattern in PRIVATE):
        _fail("selected release object violates privacy policy")
    return Snapshot(before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_nlink, hashlib.sha256(data).hexdigest(), data)


def _selected(root: Path) -> dict[str, Snapshot]:
    _namespace_is_exact(root)
    names = tuple(_entry_name(item) for item in ENTRIES)
    if len({name.casefold() for name in names}) != len(names):
        _fail("duplicate archive entry")
    selected = {name: _read_stable(root, name) for name in sorted(names, key=str.casefold)}
    if sum(item.size for item in selected.values()) >= MAX_BYTES:
        _fail("release source exceeds size limit")
    return selected


def _assert_unchanged(root: Path, selected: dict[str, Snapshot]) -> None:
    for name, original in selected.items():
        current = _read_stable(root, name)
        if current != original:
            _fail("selected release object changed during packaging")


def _safe_remove(path: Path, token: tuple[int, int] | None, expected_links: int = 1) -> bool:
    if token is None:
        return True
    try:
        info = path.lstat()
        if (stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == token
                and info.st_nlink == expected_links):
            path.unlink()
            return not os.path.lexists(str(path))
    except OSError:
        return False
    return False


def _verify_candidate(path: Path, selected: dict[str, Snapshot]) -> None:
    if path.stat().st_size >= MAX_BYTES:
        _fail("release archive exceeds size limit")
    expected = {name.casefold(): value for name, value in selected.items()}
    with zipfile.ZipFile(path, "r") as bundle:
        seen: set[str] = set()
        total = 0
        for info in bundle.infolist():
            name = _entry_name(info.filename)
            key = name.casefold()
            if key in seen or key not in expected or info.is_dir() or info.file_size < 0:
                _fail("release archive has invalid entries")
            if info.file_size > MAX_BYTES or total + info.file_size > MAX_BYTES:
                _fail("release archive exceeds entry limit")
            data = bundle.read(info)
            if len(data) != info.file_size or hashlib.sha256(data).hexdigest() != expected[key].digest:
                _fail("release archive entry differs from source")
            total += info.file_size
            seen.add(key)
        if seen != set(expected):
            _fail("release archive layout is incomplete")
        if bundle.testzip() is not None:
            _fail("release archive CRC validation failed")


def _write_checksum(path: Path, archive_digest: str) -> tuple[int, int]:
    data = f"{archive_digest}  {ASSET}\n".encode("ascii")
    with path.open("xb") as handle:
        handle.write(data)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or _ads(path)
            or path.read_bytes() != data):
        _fail("temporary checksum validation failed")
    return info.st_dev, info.st_ino


def build(source_raw: str, output_raw: str, validate_only: bool) -> None:
    source, output = _admit(source_raw, output_raw)
    selected = _selected(source)
    if validate_only:
        return
    if not os.path.lexists(str(output)):
        output.mkdir(mode=0o700)
    _assert_trusted_ancestors(output, missing_ok=False)
    if not output.is_dir() or _reparse(output):
        _fail("output is unsafe after creation")
    final = output / ASSET
    final_sha = output / (ASSET + ".sha256")
    if final.exists() or final_sha.exists():
        _fail("release asset already exists")
    nonce = uuid.uuid4().hex
    partial = output / ("." + nonce + ".partial.zip")
    partial_sha = output / ("." + nonce + ".partial.sha256")
    zip_token = sha_token = final_token = final_sha_token = None
    zip_published = sha_published = False

    def rollback() -> bool:
        """Remove only run-owned objects, in safe reverse link order."""
        clean = True
        if zip_published:
            clean = _safe_remove(final, final_token, expected_links=2) and clean
        if sha_published:
            clean = _safe_remove(final_sha, final_sha_token, expected_links=2) and clean
        clean = _safe_remove(partial, zip_token, expected_links=1) and clean
        clean = _safe_remove(partial_sha, sha_token, expected_links=1) and clean
        return clean

    try:
        with partial.open("xb") as raw:
            opened = os.fstat(raw.fileno())
            zip_token = (opened.st_dev, opened.st_ino)
            with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as bundle:
                for name, snapshot in selected.items():
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = (0o100644 << 16)
                    bundle.writestr(info, snapshot.data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        _assert_unchanged(source, selected)
        _verify_candidate(partial, selected)
        archive_digest = hashlib.sha256(partial.read_bytes()).hexdigest()
        # Capture ownership at exclusive creation, before any later write can
        # fail, so cleanup never needs to guess whether a partial is ours.
        with partial_sha.open("xb") as handle:
            opened = os.fstat(handle.fileno())
            sha_token = (opened.st_dev, opened.st_ino)
            handle.write(f"{archive_digest}  {ASSET}\n".encode("ascii"))
        checksum_info = partial_sha.lstat()
        if (not stat.S_ISREG(checksum_info.st_mode) or checksum_info.st_nlink != 1
                or _ads(partial_sha)
                or partial_sha.read_text(encoding="ascii") != f"{archive_digest}  {ASSET}\n"):
            _fail("temporary checksum validation failed")
        _assert_trusted_ancestors(output, missing_ok=False)
        os.link(partial_sha, final_sha, follow_symlinks=False)
        created = final_sha.lstat()
        final_sha_token = (created.st_dev, created.st_ino)
        if final_sha_token != sha_token or created.st_nlink != 2:
            _fail("checksum publication identity changed")
        sha_published = True
        os.link(partial, final, follow_symlinks=False)
        created = final.lstat()
        final_token = (created.st_dev, created.st_ino)
        if final_token != zip_token or created.st_nlink != 2:
            _fail("archive publication identity changed")
        zip_published = True
        _verify_candidate(final, selected)
        if final_sha.read_text(encoding="ascii") != f"{archive_digest}  {ASSET}\n":
            _fail("published checksum validation failed")
        if not _safe_remove(partial, zip_token, expected_links=2):
            _fail("temporary archive cleanup is uncertain")
        if not _safe_remove(partial_sha, sha_token, expected_links=2):
            _fail("temporary checksum cleanup is uncertain")
        zip_published = sha_published = False
        final_info, final_sha_info = final.lstat(), final_sha.lstat()
        if (not stat.S_ISREG(final_info.st_mode) or final_info.st_nlink != 1
                or (final_info.st_dev, final_info.st_ino) != final_token
                or not stat.S_ISREG(final_sha_info.st_mode) or final_sha_info.st_nlink != 1
                or (final_sha_info.st_dev, final_sha_info.st_ino) != final_sha_token
                or os.path.lexists(str(partial)) or os.path.lexists(str(partial_sha))):
            _fail("published pair cleanup is uncertain")
    except BaseException as exc:
        if not rollback():
            raise PackageError("release package is quarantined for inspection") from None
        if isinstance(exc, PackageError):
            raise
        raise PackageError("release package transaction failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--validate-only", action="store_true")
    try:
        args = parser.parse_args(argv)
        build(args.source, args.output, args.validate_only)
    except (PackageError, OSError, ValueError, zipfile.BadZipFile):
        print("Release package was not created; output may require inspection.", file=sys.stderr)
        return 1
    print("Release package validation passed." if args.validate_only else "Release package created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
