#!/usr/bin/env python3
"""Prepare the user-approved Windows Nmap/WOW64 candidate lock offline.

This script only reads the already pinned development ZIP and the existing
Windows no-Nmap lock. It verifies the whole-archive pin and each selected Nmap
member against WINDOWS_MANIFEST.sha256, then writes a new lock; it never
extracts files or executes payload binaries.
"""
import hashlib
import json
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path('/home/charadriculus/Projects/asm_tool/asm-tool-0113-audit')
ZIP_PATH = AUDIT / 'asm_tool_0.11.3-win64/dist/ASM_Tool_0.11.3-win64-development.zip'
ZIP_SHA256 = 'c45b1218ca200ae9bd13a0aa7bc507403b3635e79b0418178f6a9454d731b99c'
PREFIX = 'ASM_Tool_0.11.3-win64-development/'
EMBEDDED_MANIFEST_SHA256 = 'fb7feb85ec10c7a04add29138a916e35f9f0adc9ffc8eaedcb5470d9e53b3d93'
BASE_LOCK = ROOT / 'packaging/portable/windows-amd64-no-nmap-notices.lock.json'
OUTPUT = ROOT / 'packaging/portable/windows-amd64-approved.lock.json'
USER_APPROVAL = 'approved for development and local tests by user 2026-10-14; authentic source notices preserved'


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def parse_manifest(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in data.decode('utf-8').splitlines():
        fields = line.split(None, 1)
        if len(fields) != 2 or len(fields[0]) != 64:
            continue
        digest, name = fields[0].lower(), fields[1].lstrip('*')
        try:
            int(digest, 16)
        except ValueError:
            continue
        if name in result:
            raise SystemExit(f'duplicate path in embedded manifest: {name}')
        result[name] = digest
    if len(result) != 1950:
        raise SystemExit(f'unexpected embedded manifest entry count: {len(result)}')
    return result


def main() -> None:
    if source_sha256(ZIP_PATH) != ZIP_SHA256:
        raise SystemExit('pinned Windows development ZIP SHA-256 mismatch')
    base = json.loads(BASE_LOCK.read_text(encoding='utf-8'))
    if base.get('schema_version') != 1 or base.get('platform') != 'windows/amd64':
        raise SystemExit('unexpected base lock schema or platform')
    if OUTPUT.exists():
        raise SystemExit(f'refusing to overwrite existing candidate lock: {OUTPUT}')

    with zipfile.ZipFile(ZIP_PATH) as archive:
        members = archive.namelist()
        if len(members) != len(set(members)):
            raise SystemExit('duplicate ZIP member names')
        manifest_data = archive.read(PREFIX + 'WINDOWS_MANIFEST.sha256')
        if sha256(manifest_data) != EMBEDDED_MANIFEST_SHA256:
            raise SystemExit('embedded Windows manifest digest mismatch')
        pins = parse_manifest(manifest_data)
        nmap_prefix = PREFIX + '.tools/nmap/'
        nmap_names = sorted(name for name in members if name.startswith(nmap_prefix) and not name.endswith('/'))
        if not nmap_names:
            raise SystemExit('Nmap subtree is empty')

        seen_outputs: set[str] = set()
        nmap_files = []
        nmap_bytes = 0
        for archive_name in nmap_names:
            relative = archive_name[len(PREFIX):]
            if relative not in pins:
                raise SystemExit(f'Nmap member missing from embedded manifest: {relative}')
            output_relative = 'payload/bin/nmap/' + relative.removeprefix('.tools/nmap/')
            path = PurePosixPath(output_relative)
            if path.is_absolute() or '..' in path.parts or '\\' in output_relative:
                raise SystemExit(f'unsafe Nmap output path: {output_relative}')
            folded = output_relative.casefold()
            if folded in seen_outputs:
                raise SystemExit(f'case-colliding Nmap output path: {output_relative}')
            seen_outputs.add(folded)
            info = archive.getinfo(archive_name)
            if info.file_size > 64 * 1024 * 1024:
                raise SystemExit(f'Nmap member exceeds per-file bound: {relative}')
            data = archive.read(archive_name)
            if len(data) != info.file_size or sha256(data) != pins[relative]:
                raise SystemExit(f'Nmap member digest/size mismatch: {relative}')
            nmap_bytes += len(data)
            nmap_files.append({
                'path': output_relative,
                'source': 'windows-development-archive',
                'member': archive_name,
                'sha256': pins[relative],
                'size': len(data),
                'executable': relative == '.tools/nmap/nmap.exe',
            })
        if nmap_bytes > 128 * 1024 * 1024:
            raise SystemExit('Nmap subtree exceeds total size bound')
        if 'payload/bin/nmap/nmap.exe' not in seen_outputs:
            raise SystemExit('pinned Nmap executable missing')

    lock = base
    for source in lock['sources']:
        if source['id'] == 'windows-development-archive':
            if source['sha256'] != ZIP_SHA256:
                raise SystemExit('base lock archive pin differs from approved source')
            source['license'] = USER_APPROVAL
            break
    else:
        raise SystemExit('base lock lacks the pinned development ZIP source')

    # The user's final decision resolves the development/local-test use gate;
    # original notices and license manifests remain byte-for-byte included.
    for source in lock['sources']:
        if 'PENDING' in source.get('license', '') or 'REVIEW_REQUIRED' in source.get('license', ''):
            source['license'] = USER_APPROVAL
    for item in lock['files']:
        if item['path'] == 'payload/licenses/windows-development-license-manifest.json':
            # The original manifest is retained as provenance; it does not
            # override the user's explicit authorization for this local task.
            continue
    for tool in lock['tools']:
        if tool['name'] == 'typst':
            tool['license'] = USER_APPROVAL + '; original Apache notice included'
        elif tool['name'] == 'subfaster':
            tool['license'] = USER_APPROVAL + '; original MIT notice included'
    lock['files'].extend(nmap_files)
    lock['files'].sort(key=lambda item: item['path'].casefold())
    lock['tools'].append({
        'name': 'nmap',
        'executable': 'payload/bin/nmap/nmap.exe',
        'version': '7.991',
        'usage': 'qualification-only',
        'capabilities': [
            'x86 PE executed through Windows WOW64; no native x64 executable available',
            'Nmap DLLs and version-matched data files bundled under payload/bin/nmap/',
            'only nmap.exe is invoked; other bundled PE files are adjacent runtime/data inputs',
            'real native qualification NOT_RUN',
        ],
        'license': USER_APPROVAL + '; original Nmap notices included',
        'dependencies': [
            'WOW64 on x64 Windows',
            'adjacent x86 DLL closure and Nmap data tree under payload/bin/nmap/',
            'Windows OS API/UCRT imports; minimum OS/runtime qualification NOT_RUN',
        ],
    })
    lock['tools'].sort(key=lambda tool: tool['name'])
    data = (json.dumps(lock, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    OUTPUT.write_bytes(data)
    print(json.dumps({
        'output': str(OUTPUT),
        'sha256': sha256(data),
        'nmap_files': len(nmap_files),
        'nmap_bytes': nmap_bytes,
        'embedded_manifest_sha256': EMBEDDED_MANIFEST_SHA256,
        'platform': lock['platform'],
        'nmap_version': '7.991',
        'architecture': 'x86 via WOW64; Windows x64 host',
    }, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
