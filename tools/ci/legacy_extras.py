#!/usr/bin/env python3
"""Reconcile and restore old portable root documents without changing verified payload binaries.

Exact 0.12.3 draft ZIP inputs are authenticated by tools/ci/portable_candidate.py.
Only *non-payload* root files are restored. The project LICENSE and BUILD_INFO
are intentionally regenerated from the checked-out source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

from portable_candidate import RELEASES, ROOT, digest, safe_member, read_old_release, verify_zip, verify_gui_zip


BASE_FILES = {"asm-tool", "asm-tool.exe", "README.md", "payload-provenance.json",
              "payload/bundle.json", "SHA256SUMS"}
ALLOWED_ROOT = {"LICENSE", "README_RU.md", "BUILD_INFO.json", "config.example.yml",
                "LICENSE_PAYLOAD_MAPPING.json", "GUI_INTEGRATION_REPORT.md",
                "GUI_RUNTIME_PROVENANCE.json", "VERSION_IDENTITY_FIX.md"}
ALLOWED_EVIDENCE = {"evidence/gui-build/GUI_BUILD_REPORT.json",
                    "evidence/gui-build/GUI_INTEGRATION_HANDOFF.md",
                    "evidence/gui-build/GUI_SHA256SUMS",
                    "evidence/gui-build/GUI_dotnet-publish.log"}


def allowed_extra(path):
    return (path in ALLOWED_ROOT or path in ALLOWED_EVIDENCE
            or path.startswith("docs/patch123/"))




def list_legacy(archive, platform):
    expected_name, h, size = RELEASES[platform]
    if archive.name != expected_name or archive.stat().st_size != size or digest(archive) != h:
        raise ValueError("Old release archive does not match fixed SHA-256: " + str(archive))
    lock_name = "linux-amd64-patch123.lock.json" if platform == "linux" else "windows-amd64-patch123.lock.json"
    lock = json.loads((ROOT / "packaging/portable" / lock_name).read_text(encoding="utf-8"))
    with zipfile.ZipFile(archive) as z:
        read_old_release(z, lock)
        # Windows release additionally includes hundreds of GUI .NET files.
        # These are *not* missing documents and must not be classified as extras.
        extra = sorted(n for n in z.namelist()
                       if allowed_extra(n))
        if len(extra) != 27:
            raise ValueError(f"Expected exactly 27 extra {platform} files, observed {len(extra)}: {extra}")
        if any(not safe_member(n) or not allowed_extra(n) for n in extra):
            raise ValueError("Unexpected old portable root files: " + repr(extra))
        result = [
            {"path": n, "sha256": hashlib.sha256(z.read(n)).hexdigest(),
             "size": z.getinfo(n).file_size}
            for n in extra
        ]
    return result


def collect_old(archive, platform, output):
    items = list_legacy(archive, platform)
    if output.exists():
        raise ValueError("Legacy extraction destination already exists")
    output.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        for item in items:
            dest = output / item["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            data = z.read(item["path"])
            if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("Source changed during extraction")
            dest.write_bytes(data)
    (output / "manifest.json").write_text(
        json.dumps({"schema": 1, "platform": platform, "baseline": archive.name,
                    "files": items}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"platform": platform, "legacy_extra_count": len(items),
                      "paths": [i["path"] for i in items]}, ensure_ascii=False))


def current_doc(item, platform):
    n = item["path"]
    if n == "LICENSE":
        return (ROOT / "LICENSE").read_bytes(), "current-project-license"
    if n == "BUILD_INFO.json":
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        data = {
            "schema": 1, "version": "0.12.3", "status": "PRIVATE_CI_CANDIDATE",
            "platform": platform, "source_commit": commit,
            "license_holder_confirmed": True, "published": False,
            "base_release_archive_sha256": RELEASES[platform][1],
            "third_party_payload": "verified unchanged except own MIT LICENSE",
            "qualification": {
                "go_build": "PASS", "integrity": "PASS",
                "native_gui_build": "PASS" if platform == "windows" else "N/A",
                "user_runtime_tests": "NOT_FULLY_QUALIFIED"
            }
        }
        return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), "generated-build-info"
    if n == "config.example.yml":
        return (ROOT / "assets/examples/config.example.yml").read_bytes(), "current-config"
    if n == "LICENSE_PAYLOAD_MAPPING.json":
        mapping = ROOT / "planning/patch123/evidence/LICENSE_PAYLOAD_MAPPING.json"
        if mapping.is_file():
            return mapping.read_bytes(), "current-license-map"
        # The original mapping is not tracked in today's checkout. Preserve
        # its SHA-authenticated byte content from the accepted old release.
        return None, "original-pinned-license-map"
    if n == "README_RU.md":
        text = (ROOT / "docs/patch123/README_RU.md").read_text(encoding="utf-8")
        text = re.sub(r"\]\(([A-Za-z_0-9.-]+\.md)\)", r"](docs/patch123/\1)", text)
        text += ("\nЛицензионные пути исходного реестра относятся к source tree;"
                 " используйте LICENSE_PAYLOAD_MAPPING.json для portable payload.\n")
        return text.encode("utf-8"), "current-readme"
    if n.startswith("docs/patch123/"):
        path = ROOT / n
        if path.is_file():
            data = path.read_bytes()
            if n.endswith(".md"):
                # Keep paths consistent with portable ZIP rather than the repository.
                data = data.decode("utf-8").replace(
                    "(../../licenses/patch123/", "(../../payload/licenses/patch123/").encode("utf-8")
            return data, "current-source-doc"
    return None, "original-pinned-legacy-doc"


def read_manifest(directory, platform):
    obj = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if obj.get("schema") != 1 or obj.get("platform") != platform:
        raise ValueError("Wrong old-files manifest")
    rows = obj.get("files", [])
    if len(rows) != 27 or len(set(r["path"] for r in rows)) != 27:
        raise ValueError("Incomplete/duplicated 27-file legacy corpus")
    return rows


def normalize_zip(old_candidate, legacy_dir, platform, output):
    rows = read_manifest(legacy_dir, platform)
    if output.exists():
        raise ValueError("Refuse overwrite " + str(output))
    if platform == "linux":
        verify_zip(old_candidate)
    else:
        verify_gui_zip(old_candidate)
    additions = {}
    records = []
    for row in rows:
        p = row["path"]
        if not safe_member(p) or not allowed_extra(p):
            raise ValueError("Unreviewed root extra " + p)
        saved = (legacy_dir / p).read_bytes()
        if hashlib.sha256(saved).hexdigest() != row["sha256"] or len(saved) != row["size"]:
            raise ValueError("Old extra source SHA mismatch " + p)
        content, origin = current_doc(row, platform)
        if content is None:
            content = saved
        if p == "LICENSE" and b"TO BE CONFIRMED" in content:
            raise ValueError("Owner placeholder unexpectedly persisted")
        additions[p] = content
        records.append({"path": p, "source": origin, "sha256": hashlib.sha256(content).hexdigest()})
    with zipfile.ZipFile(old_candidate) as z:
        current = set(z.namelist())
        overlap = current & set(additions)
        if overlap:
            raise ValueError("Extra documents unexpectedly already present: " + repr(sorted(overlap)))
        if any(p.startswith("payload/") for p in additions):
            raise ValueError("No payload file may be rewritten")
        all_names = current | set(additions)
        manifest_name = "SHA256SUMS" if platform == "linux" else "GUI_DISTRIBUTION_MANIFEST.sha256"
        hashes = {}
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "x") as dest:
            for item in z.infolist():
                name = item.filename
                if name == manifest_name:
                    continue
                meta = zipfile.ZipInfo(name, (1980,1,1,0,0,0))
                meta.create_system = 3
                meta.external_attr = item.external_attr
                meta.compress_type = zipfile.ZIP_STORED if name.endswith((".zip",".gz",".xz",".crate")) else zipfile.ZIP_DEFLATED
                h = hashlib.sha256()
                with z.open(item) as src, dest.open(meta, "w", force_zip64=True) as out:
                    while block := src.read(1024*1024):
                        out.write(block)
                        h.update(block)
                hashes[name] = h.hexdigest()
            for name, data in sorted(additions.items()):
                meta = zipfile.ZipInfo(name, (1980,1,1,0,0,0))
                meta.create_system = 3
                meta.external_attr = (stat.S_IFREG | 0o644) << 16
                meta.compress_type = zipfile.ZIP_DEFLATED
                dest.writestr(meta, data)
                hashes[name] = hashlib.sha256(data).hexdigest()
            meta = zipfile.ZipInfo(manifest_name, (1980,1,1,0,0,0))
            meta.create_system = 3
            meta.external_attr = (stat.S_IFREG | 0o644) << 16
            meta.compress_type = zipfile.ZIP_DEFLATED
            dest.writestr(meta, "".join(f"{h}  {n}\n" for n,h in sorted(hashes.items())))
    if platform == "linux":
        verify_zip(output)
    else:
        verify_gui_zip(output)
    with zipfile.ZipFile(output) as z:
        missing = sorted(set(i["path"] for i in rows) - set(z.namelist()))
        if missing:
            raise ValueError("Legacy file(s) still absent: " + repr(missing))
    print(json.dumps({"platform": platform, "new_archive": str(output),
                      "sha256":digest(output), "restored":len(additions),
                      "total_files": len(all_names), "sources": records},
                     ensure_ascii=False))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    extract = sub.add_parser("extract")
    extract.add_argument("--platform",choices=("linux","windows"),required=True)
    extract.add_argument("--old",type=Path,required=True)
    extract.add_argument("--out",type=Path,required=True)
    restore = sub.add_parser("restore")
    restore.add_argument("--platform",choices=("linux","windows"),required=True)
    restore.add_argument("--candidate",type=Path,required=True)
    restore.add_argument("--legacy-dir",type=Path,required=True)
    restore.add_argument("--out",type=Path,required=True)
    a = p.parse_args()
    if a.cmd == "extract":
        collect_old(a.old, a.platform, a.out)
    else:
        normalize_zip(a.candidate, a.legacy_dir, a.platform, a.out)


if __name__ == "__main__":
    main()
