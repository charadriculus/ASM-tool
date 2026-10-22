#!/usr/bin/env python3
"""Verify ASM Tool 0.12.3 ZIP contents without executing bundled programs.

Integrity and V8 archive inspection are evidence, NOT redistribution permission.
"""
import argparse
import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

PINNED = {
    "linux": ("695d48df48d8b840f5e8ac240b3a29a025d61b85511b8458fa9de5246d19046a", 296102932),
    "windows": ("6dc9b4e8289453a598982d957e952b930b448ac0e6d95da3a2619151816d710b", 239602994),
}


def sha256_stream(f):
    h = hashlib.sha256()
    while True:
        data = f.read(1024 * 1024)
        if not data:
            break
        h.update(data)
    return h.hexdigest()


def audit_zip(zip_path, lock_path, platform):
    output = {"archive": str(zip_path), "platform": platform, "verified": False, "errors": []}
    with zip_path.open("rb") as f:
        output["archive_sha256"] = sha256_stream(f)
    expected_sha, expected_size = PINNED[platform]
    output["archive_size"] = zip_path.stat().st_size
    output["expected_archive_sha256"] = expected_sha
    if output["archive_sha256"] != expected_sha:
        output["errors"].append("ARCHIVE_SHA256_MISMATCH")
    if output["archive_size"] != expected_size:
        output["errors"].append("ARCHIVE_SIZE_MISMATCH")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    output["lock"] = str(lock_path)
    if ("linux" if platform == "linux" else "windows") not in lock.get("platform", "").lower():
        output["errors"].append("WRONG_PLATFORM_LOCK")
    entries = lock.get("files", [])
    failures, matched = [], 0
    with zipfile.ZipFile(zip_path) as z:
        members = [n for n in z.namelist() if not n.endswith("/")]
        seen, duplicates = set(), set()
        for n in members:
            if n in seen:
                duplicates.add(n)
            seen.add(n)
        if duplicates:
            output["errors"].append("DUPLICATE_ZIP_MEMBER")
        for ent in entries:
            name = ent["path"].lstrip("/")
            # A single enclosing directory is allowed. Ambiguous matches fail.
            hits = [n for n in members if n == name or n.endswith("/" + name)]
            if len(hits) != 1:
                failures.append({"path": name, "reason": "NOT_UNIQUE_OR_MISSING", "matches": len(hits)})
                continue
            with z.open(hits[0]) as f:
                actual = sha256_stream(f)
            if actual != ent["sha256"]:
                failures.append({"path": name, "reason": "SHA256_MISMATCH", "sha256": actual})
            else:
                matched += 1
        output["total_zip_files"] = len(members)
        expected_names = {ent["path"].lstrip("/") for ent in entries}
        output["unlocked_file_count"] = sum(
            not any(n == k or n.endswith("/" + k) for k in expected_names)
            for n in members
        )
    output["matched_lock_files"] = matched
    output["total_lock_files"] = len(entries)
    output["file_failures"] = failures[:50]
    output["file_failures_total"] = len(failures)
    if failures:
        output["errors"].append("LOCK_FILE_MISMATCH")
    output["verified"] = not output["errors"]
    return output


def inspect_ar(archive):
    result = {
        "archive": str(archive), "status": "INCONCLUSIVE",
        "relevance": "not established that the supplied V8 static archive was linked into the shipped Obscura",
        "matched_glibc_members": []
    }
    with archive.open("rb") as f:
        result["sha256"] = sha256_stream(f)
    with tempfile.TemporaryDirectory(prefix="asm-v8-") as t:
        target = Path(t) / "v8.a"
        with (gzip.open(archive, "rb") if archive.suffix == ".gz" else archive.open("rb")) as src, target.open("wb") as dst:
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                dst.write(block)
        try:
            p = subprocess.run(["ar", "t", str(target)], capture_output=True, text=True, timeout=60, check=True)
        except (FileNotFoundError, subprocess.SubprocessError) as e:
            result["error"] = str(e)
            return result
        names = p.stdout.splitlines()
        result["object_count"] = len(names)
        needles = ("branred", "s_sin", "s_cos", "sincostab", "s_sincos", "k_sin", "k_cos", "e_rem_pio2")
        result["matched_glibc_members"] = [n for n in names if any(s in n.lower() for s in needles)][:50]
        result["status"] = "MATCHED_POTENTIAL_GLIBC_OBJECTS" if result["matched_glibc_members"] else "NO_NAME_MATCH_NOT_PROOF_OF_ABSENCE"
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--linux", type=Path)
    p.add_argument("--windows", type=Path)
    p.add_argument("--linux-lock", type=Path, default=Path("packaging/portable/linux-amd64-patch123.lock.json"))
    p.add_argument("--windows-lock", type=Path, default=Path("packaging/portable/windows-amd64-patch123.lock.json"))
    p.add_argument("--v8-static", type=Path, help="exact rusty_v8 static .a/.lib (optionally gzip-compressed)")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    if not a.linux and not a.windows:
        p.error("specify at least one actual release archive")
    report = {
        "schema": 1, "project": "ASM Tool", "version": "0.12.3",
        "audit_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "technical": {},
        "legal_gates": {
            "copyright_holder": "CONFIRMED_OWNER_STATEMENT",
            "microsoft_crt_redist_entitlement": "NOT_ESTABLISHED",
            "v8_lgpl_binary_relink": "NOT_ESTABLISHED",
            "complete_binary_notice_closure": "NOT_ESTABLISHED"
        },
        "public_redistribution_ready": False
    }
    for platform in ("linux", "windows"):
        archive = getattr(a, platform)
        if archive:
            try:
                report["technical"][platform] = audit_zip(archive, getattr(a, platform + "_lock"), platform)
            except (OSError, ValueError, zipfile.BadZipFile, KeyError) as e:
                report["technical"][platform] = {"verified": False, "errors": [f"AUDIT_EXCEPTION: {e}"]}
    if a.v8_static:
        try:
            report["technical"]["v8_static_archive"] = inspect_ar(a.v8_static)
        except (OSError, ValueError) as e:
            report["technical"]["v8_static_archive"] = {"status": "INCONCLUSIVE", "error": str(e)}
    report["technical_integrity_pass"] = all(
        r.get("verified") for k, r in report["technical"].items() if k in ("linux", "windows")
    )
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "technical_integrity_pass": report["technical_integrity_pass"],
        "public_redistribution_ready": False,
        "report": str(a.out)
    }))
    return 3 if report["technical_integrity_pass"] else 2


if __name__ == "__main__":
    sys.exit(main())
