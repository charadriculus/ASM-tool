#!/usr/bin/env python3
"""CI staging from SHA-256-pinned PRIVATE draft ZIPs; never executes vendored tools.

The baseline archives are authenticated byte inputs for third-party payloads.
Go CLI and WinUI GUI are built from checkout sources by the CI workflow.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile

RELEASES = {
    "linux": ("ASM_Tool_0.12.3-linux-x86_64.zip",
              "695d48df48d8b840f5e8ac240b3a29a025d61b85511b8458fa9de5246d19046a",
              296102932),
    "windows": ("ASM_Tool_0.12.3-windows-x64.zip",
                "6dc9b4e8289453a598982d957e952b930b448ac0e6d95da3a2619151816d710b",
                239602994),
}
ROOT = Path(__file__).resolve().parents[2]


def digest(file):
    with open(file, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def member_hash(z, name):
    with z.open(name) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_member(name):
    return (name and not name.endswith("/") and not name.startswith("/")
            and "\\" not in name and ":" not in name
            and all(piece not in ("", ".", "..") for piece in name.split("/")))


def read_old_release(z, old_lock):
    files = {f["path"]: f for f in old_lock["files"]}
    seen, names = set(), set()
    for item in z.infolist():
        name = item.filename
        if not safe_member(name):
            raise ValueError("Unsafe/non-file baseline ZIP entry: " + name)
        if name.casefold() in seen:
            raise ValueError("Duplicated/case-colliding ZIP entry: " + name)
        seen.add(name.casefold())
        names.add(name)
        if (item.external_attr >> 16) & stat.S_IFMT(0o170000) == stat.S_IFLNK:
            raise ValueError("Symlink in source ZIP: " + name)
    if not set(files).issubset(names):
        raise ValueError("Baseline ZIP misses locked payload: " + str(sorted(set(files)-names)[:6]))
    if "SHA256SUMS" not in names:
        raise ValueError("Baseline ZIP has no SHA256SUMS")
    # Audit all ZIP data, not only the copied payload members.
    recorded = {}
    for line in z.read("SHA256SUMS").decode("utf-8").splitlines():
        h, sep, p = line.partition("  ")
        if not sep or not safe_member(p) or p in recorded or len(h) != 64:
            raise ValueError("Invalid original SHA256SUMS line")
        recorded[p] = h
    if set(recorded) != names - {"SHA256SUMS"}:
        raise ValueError("Original ZIP closed-inventory mismatch")
    for p, h in recorded.items():
        if member_hash(z, p) != h:
            raise ValueError("Original ZIP SHA256SUMS mismatch: " + p)
    for p, f in files.items():
        if recorded[p] != f["sha256"]:
            raise ValueError("Original packaging lock disagrees with ZIP: " + p)
        if z.getinfo(p).file_size != f["size"]:
            raise ValueError("Original payload size mismatch: " + p)


def prepare(platform, archive, out_lock):
    if platform not in RELEASES:
        raise ValueError("Unknown platform")
    name, expected_sha, expected_size = RELEASES[platform]
    if archive.name != name or archive.stat().st_size != expected_size or digest(archive) != expected_sha:
        raise ValueError("Untrusted baseline release ZIP: " + str(archive))
    lock = json.loads((ROOT / "packaging/portable" / (
        "linux-amd64-patch123.lock.json" if platform == "linux"
        else "windows-amd64-patch123.lock.json")).read_text(encoding="utf-8"))
    with zipfile.ZipFile(archive) as z:
        read_old_release(z, lock)
    release_path = os.path.relpath(archive.resolve(), out_lock.parent.resolve()).replace(os.sep, "/")
    license_path = os.path.relpath((ROOT / "LICENSE").resolve(), out_lock.parent.resolve()).replace(os.sep, "/")
    lic_sha = digest(ROOT / "LICENSE")
    lic_size = (ROOT / "LICENSE").stat().st_size
    if "TO BE CONFIRMED" in (ROOT / "LICENSE").read_text(encoding="utf-8"):
        raise ValueError("The root LICENSE contains an unresolved placeholder")
    lock["sources"] = [
        {"id": "ci-pinned-prior-release", "path": release_path,
         "sha256": expected_sha, "archive": True, "version": "0.12.3 accepted artifact",
         "license": "Component-specific unmodified third-party notices; see source corpus"},
        {"id": "ci-current-project-license", "path": license_path,
         "sha256": lic_sha, "archive": False, "version": "MIT current checkout",
         "license": "MIT"},
    ]
    replacements = 0
    for item in lock["files"]:
        if item["path"] == "payload/licenses/asm-tool/LICENSE":
            item.update(source="ci-current-project-license", sha256=lic_sha, size=lic_size)
            item.pop("member", None)
            replacements += 1
        else:
            item["source"] = "ci-pinned-prior-release"
            item["member"] = item["path"]
    if replacements != 1:
        raise ValueError("Expected exactly one own-license payload entry")
    out_lock.parent.mkdir(parents=True, exist_ok=True)
    if out_lock.exists():
        raise ValueError("Refusing to replace generated lock")
    out_lock.write_text(json.dumps(lock, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"platform":platform, "baseline_sha256":expected_sha,
                      "new_mit_sha256":lic_sha, "files":len(lock["files"]),
                      "generated_lock":str(out_lock)}))


def extract_fonts(archive, out):
    """Copy the exact pinned font fixture bytes for deterministic offline tests."""
    name, expected_sha, expected_size = RELEASES["linux"]
    if archive.name != name or archive.stat().st_size != expected_size or digest(archive) != expected_sha:
        raise ValueError("Cannot extract fixtures from untrusted archive")
    lock = json.loads((ROOT / "packaging/portable/linux-amd64-patch123.lock.json").read_text())
    font_names = {"DejaVuSans.ttf", "DejaVuSans-Bold.ttf",
                  "DejaVuSans-Oblique.ttf", "DejaVuSans-BoldOblique.ttf"}
    records = [f for f in lock["files"] if f["path"].startswith("payload/fonts/dejavu/")]
    if {Path(f["path"]).name for f in records} != font_names:
        raise ValueError("Font fixture lock does not contain exactly the required font set")
    out.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        for item in records:
            name = item["path"]
            content = z.read(name)
            h = hashlib.sha256(content).hexdigest()
            if h != item["sha256"] or len(content) != item["size"]:
                raise ValueError("Pinned font hash mismatch: " + name)
            (out / Path(name).name).write_bytes(content)
    print(json.dumps({"font_fixture_count":len(records), "out":str(out)}))


def sums_for_dir(root):
    files = sorted(p for p in root.rglob("*") if p.is_file())
    out = {}
    for p in files:
        name = p.relative_to(root).as_posix()
        if not safe_member(name) or name == "SHA256SUMS":
            raise ValueError("Invalid/unexpected stage file: " + name)
        if p.is_symlink():
            raise ValueError("Untrusted stage link " + name)
        out[name] = digest(p)
    return out


def write_sums(root):
    out = root / "SHA256SUMS"
    if out.exists():
        raise ValueError("Refusing to overwrite SHA256SUMS")
    sums = sums_for_dir(root)
    out.write_text("".join(f"{h}  {name}\n" for name, h in sums.items()), encoding="utf-8")
    print(json.dumps({"stage":str(root), "closed_file_count":len(sums)}))


def verify_zip(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(set(names)) != len(names) or any(not safe_member(n) for n in names):
            raise ValueError("Bad zip member names")
        sums = {}
        for ln in z.read("SHA256SUMS").decode().splitlines():
            h, sep, name = ln.partition("  ")
            if not sep or not safe_member(name) or name in sums:
                raise ValueError("Invalid checksum line")
            sums[name] = h
        if set(sums) != set(names) - {"SHA256SUMS"}:
            raise ValueError("Non-closed ZIP")
        for n, h in sums.items():
            if member_hash(z, n) != h:
                raise ValueError("Archive payload digest mismatch: " + n)
    print(json.dumps({"archive":str(path), "sha256":digest(path), "files":len(names)}))


def zip_tree(source, output):
    if output.exists():
        raise ValueError("Refuse overwrite ZIP")
    if not (source / "SHA256SUMS").is_file():
        raise ValueError("Unsealed tree")
    # Archive never follows symlinks and uses fixed metadata.
    with zipfile.ZipFile(output, "x") as z:
        for p in sorted(source.rglob("*")):
            if not p.is_file():
                continue
            if p.is_symlink():
                raise ValueError("Symlink in stage")
            n = p.relative_to(source).as_posix()
            if not safe_member(n):
                raise ValueError("Unsafe output member")
            info = zipfile.ZipInfo(n, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if os.access(p, os.X_OK) else 0o644)) << 16
            info.compress_type = zipfile.ZIP_STORED if n.endswith((".zip", ".gz", ".xz", ".crate")) else zipfile.ZIP_DEFLATED
            with p.open("rb") as inp, z.open(info, "w", force_zip64=True) as dest:
                while data := inp.read(1024*1024):
                    dest.write(data)
    verify_zip(output)


def verify_gui_zip(path):
    """WinUI archive uses a GUI-wide manifest plus separate Go-only SHA256SUMS."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(set(names)) != len(names) or any(not safe_member(n) for n in names):
            raise ValueError("Unsafe/duplicate GUI ZIP member")
        must_have = {"ASMTool.exe", "asm-tool.exe", "payload/bundle.json",
                     "payload-provenance.json", "SHA256SUMS", "GUI_DISTRIBUTION_MANIFEST.sha256",
                     "payload/licenses/asm-tool/LICENSE"}
        if not must_have.issubset(names):
            raise ValueError("Missing required GUI ZIP members")
        manifest = {}
        for line in z.read("GUI_DISTRIBUTION_MANIFEST.sha256").decode("utf-8").splitlines():
            h, sep, n = line.partition("  ")
            if not sep or not safe_member(n) or n in manifest or len(h) != 64:
                raise ValueError("Invalid GUI manifest entry")
            manifest[n] = h.lower()
        if set(manifest) != set(names) - {"GUI_DISTRIBUTION_MANIFEST.sha256"}:
            raise ValueError("GUI closure has missing or extra files")
        for n, h in manifest.items():
            if member_hash(z, n) != h:
                raise ValueError("GUI file hash mismatch: " + n)
        go_sums = {}
        for line in z.read("SHA256SUMS").decode("utf-8").splitlines():
            h, sep, n = line.partition("  ")
            if not sep or not safe_member(n) or n in go_sums or len(h) != 64:
                raise ValueError("Invalid Go-only manifest entry")
            go_sums[n] = h.lower()
        go_names = {n for n in names if n.startswith("payload/")}
        go_names.update({"asm-tool.exe", "README.md", "payload-provenance.json"})
        if set(go_sums) != go_names:
            raise ValueError("Go-only manifest does not cover the Go bundle")
        for n, h in go_sums.items():
            if member_hash(z, n) != h:
                raise ValueError("Go file hash mismatch: " + n)
        if member_hash(z, "payload/licenses/asm-tool/LICENSE") != digest(ROOT/"LICENSE"):
            raise ValueError("Release has stale MIT project LICENSE")
        if any(p.casefold().split("/")[-1].startswith("nmap") for p in names):
            raise ValueError("Nmap is forbidden in ASM Tool portable")
    print(json.dumps({"gui_archive":str(path), "sha256":digest(path),
                      "total_files":len(names), "go_files":len(go_sums)}))


def combine(linux, windows, output):
    # Wrapper archive: retains both complete, closed platform ZIPs, no inference of native PASS.
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError("Refuse overwrite combined ZIP")
    verify_zip(linux)
    verify_gui_zip(windows)
    entries = {
        "linux-x86_64/" + linux.name: linux,
        "windows-x64/" + windows.name: windows,
        "LICENSE": ROOT / "LICENSE",
    }
    entries["README.md"] = None
    readme = ("ASM Tool 0.12.3 CI candidate.\n"
              "Contains hash-verified platform ZIPs and current MIT LICENSE.\n"
              "This is a private qualification artifact, not a published release.\n").encode()
    checksums = {name: digest(p) for name, p in entries.items() if p is not None}
    checksums["README.md"] = hashlib.sha256(readme).hexdigest()
    with zipfile.ZipFile(output, "x") as z:
        for n, p in sorted(entries.items()):
            info = zipfile.ZipInfo(n, (1980,1,1,0,0,0))
            info.create_system=3
            info.external_attr=(stat.S_IFREG|0o644)<<16
            info.compress_type=zipfile.ZIP_STORED if n.endswith(".zip") else zipfile.ZIP_DEFLATED
            with z.open(info,"w",force_zip64=True) as dst:
                if p is None:
                    dst.write(readme)
                else:
                    with p.open("rb") as src:
                        while part:=src.read(1024*1024):
                            dst.write(part)
        info=zipfile.ZipInfo("SHA256SUMS",(1980,1,1,0,0,0))
        info.create_system=3
        info.external_attr=(stat.S_IFREG|0o644)<<16
        info.compress_type=zipfile.ZIP_DEFLATED
        z.writestr(info,"".join(f"{h}  {n}\n" for n,h in sorted(checksums.items())))
    verify_zip(output)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="command",required=True)
    a=sub.add_parser("prepare-lock")
    a.add_argument("--platform",required=True,choices=RELEASES)
    a.add_argument("--archive",required=True,type=Path)
    a.add_argument("--out",required=True,type=Path)
    fonts=sub.add_parser("extract-fonts")
    fonts.add_argument("--archive",required=True,type=Path)
    fonts.add_argument("--out",required=True,type=Path)
    b=sub.add_parser("seal")
    b.add_argument("--root",required=True,type=Path)
    zr=sub.add_parser("zip-root")
    zr.add_argument("--root",required=True,type=Path)
    zr.add_argument("--out",required=True,type=Path)
    vg=sub.add_parser("verify-gui")
    vg.add_argument("--archive",required=True,type=Path)
    v=sub.add_parser("verify")
    v.add_argument("--archive",required=True,type=Path)
    c=sub.add_parser("combine")
    c.add_argument("--linux",required=True,type=Path)
    c.add_argument("--windows",required=True,type=Path)
    c.add_argument("--out",required=True,type=Path)
    q=p.parse_args()
    if q.command=="prepare-lock":
        prepare(q.platform,q.archive,q.out)
    elif q.command=="extract-fonts":
        extract_fonts(q.archive,q.out)
    elif q.command=="seal":
        write_sums(q.root)
    elif q.command=="zip-root":
        zip_tree(q.root,q.out)
    elif q.command=="verify":
        verify_zip(q.archive)
    elif q.command=="verify-gui":
        verify_gui_zip(q.archive)
    else:
        combine(q.linux,q.windows,q.out)


if __name__=="__main__":
    main()
