#!/usr/bin/env python3
"""Repack the accepted GUI candidate with version-identity-corrected Go CLIs only.
No native payload, GUI, historical archive, or scan result is executed or changed.
"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
import struct
import zipfile
from contextlib import ExitStack
from pathlib import Path

spec = importlib.util.spec_from_file_location('composition', Path(__file__).with_name('assemble.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
ROOT = m.ROOT
INPUT = ROOT / 'dist/ASM_Tool_0.12.3-final-20261022-01'
INPUTS = {
    'linux': ('ASM_Tool_0.12.3-linux-x86_64.zip', 'ad60de40e3a62bfb5f93d97a0ffc746c6cf244bdc7af315cbf79e9132fb6f708'),
    'windows': ('ASM_Tool_0.12.3-windows-x64.zip', 'eabcc32b5ba2905c168c386bdf17555950ca14f5f4cb74133ce024d0c29ee3b7'),
}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def zip_hash(z, name):
    with z.open(name) as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-root', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    build = Path(args.build_root).resolve()
    out = Path(args.output).absolute()
    m.require(not out.exists(), 'output must be new')
    m.require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() == args.source_commit, 'source commit mismatch')
    for name, expected in INPUTS.values():
        m.require(m.sha(INPUT / name) == expected, 'accepted input archive changed: ' + name)
    info = json.loads((INPUT / 'BUILD_INFO.json').read_text())
    info['previous_build_source_commit'] = info['source_commit']
    info['source_commit'] = args.source_commit
    info['packaging_tool_sha256'] = m.sha(Path(__file__))
    info['packaging_update'] = 'VERSION_IDENTITY_FIX_2026-10-22'
    info['version_identity_fix'] = {
        'shared_source': 'internal/version/version.go',
        'consumer_identity_validation': 'UNCHANGED_STRICT',
        'past_scan_results_modified': False,
        'gui_rebuilt': False,
        'native_runtime': 'NOT_RUN',
        'offline_evidence': 'planning/patch123/evidence/version-fix-*',
    }
    for platform in INPUTS:
        app = 'asm-tool.exe' if platform == 'windows' else 'asm-tool'
        pin = info['platforms'][platform + '/amd64']
        binary = (build / app).read_bytes()
        m.require(pin['bundle_sha256'].encode('ascii') in binary, 'CLI missing retained bundle anchor')
        if platform == 'linux':
            m.require(binary[:6] == b'\x7fELF\x02\x01' and binary[18:20] == b'\x3e\x00', 'expected ELF amd64 CLI')
        else:
            m.require(binary[:2] == b'MZ' and len(binary) >= 64, 'expected PE CLI')
            offset = struct.unpack_from('<I', binary, 0x3c)[0]
            m.require(binary[offset:offset+6] == b'PE\0\0\x64\x86', 'expected PE amd64 CLI')
        pin['application_sha256'] = m.digest(binary)
        info['platforms'][platform + '/amd64']['reproducibility'] = 'NOT_REPEATED_TARGETED_CORRECTION_BUILD'
    fix_report = ROOT / 'docs/patch123/VERSION_IDENTITY_FIX.md'
    readme = ('Исправление идентификатора версии, 22 октября 2026: см. VERSION_IDENTITY_FIX.md. '
              'Go CLI пересобран; GUI и native payload сохранены. Старые scan results не изменялись.\n\n').encode() + (INPUT / 'README_RU.md').read_bytes()
    out.mkdir(mode=0o700)
    results = {}
    preservation = {}
    combined = {'README_RU.md': readme, 'BUILD_INFO.json': encoded(info), 'VERSION_IDENTITY_FIX.md': fix_report}
    combined_exec = set()
    with ExitStack() as stack:
        for platform, (filename, _) in INPUTS.items():
            old = stack.enter_context(zipfile.ZipFile(INPUT / filename))
            app = 'asm-tool.exe' if platform == 'windows' else 'asm-tool'
            entries = {i.filename: (old, i) for i in old.infolist() if i.filename not in ('SHA256SUMS', 'GUI_DISTRIBUTION_MANIFEST.sha256')}
            entries.update({app: build / app, 'README_RU.md': readme,
                            'BUILD_INFO.json': encoded(info), 'VERSION_IDENTITY_FIX.md': fix_report})
            if platform == 'windows':
                entries['GUI_DISTRIBUTION_MANIFEST.sha256'] = ''.join(m.item_hash(v) + '  ' + n + '\n' for n, v in sorted(entries.items())).encode()
            executable = {i.filename for i in old.infolist() if i.external_attr >> 16 & 0o111}
            m.write_zip(out / filename, m.closed_entries(entries), executable)
            results[filename] = m.verify_zip(out / filename)
            new = stack.enter_context(zipfile.ZipFile(out / filename))
            changed = [n for n in old.namelist() if zip_hash(old, n) != zip_hash(new, n)]
            expected = {app, 'README_RU.md', 'BUILD_INFO.json', 'SHA256SUMS'}
            if platform == 'windows':
                expected.add('GUI_DISTRIBUTION_MANIFEST.sha256')
            m.require(set(changed) == expected, 'unexpected old member change: ' + str(changed))
            m.require(set(new.namelist()) - set(old.namelist()) == {'VERSION_IDENTITY_FIX.md'}, 'unexpected added member')
            pin = info['platforms'][platform + '/amd64']
            m.require(zip_hash(new, app) == pin['application_sha256'], 'CLI identity mismatch')
            m.require(zip_hash(new, 'payload/bundle.json') == pin['bundle_sha256'], 'payload anchor changed')
            m.require(zip_hash(new, 'payload-provenance.json') == pin['provenance_sha256'], 'payload provenance changed')
            preservation[platform] = {'changed_members': changed, 'all_other_original_members': 'BYTE_IDENTICAL', 'new_members': ['VERSION_IDENTITY_FIX.md']}
            prefix = 'windows-x64/' if platform == 'windows' else 'linux-x86_64/'
            for i in new.infolist():
                combined[prefix + i.filename] = (new, i)
                if platform == 'linux' and i.external_attr >> 16 & 0o111:
                    combined_exec.add(prefix + i.filename)
        filename = 'ASM_Tool_0.12.3-Linux-Windows.zip'
        m.write_zip(out / filename, m.closed_entries(combined), combined_exec)
        results[filename] = m.verify_zip(out / filename)
    evidence = {'exit_code': 0, 'source_commit': args.source_commit,
                'command': ['python3', 'tools/patch123/package-version-fix.py', '--build-root', args.build_root, '--output', args.output, '--source-commit', args.source_commit],
                'inputs': {p: {'filename': n, 'sha256': h} for p, (n, h) in INPUTS.items()},
                'preservation': preservation, 'artifacts': results, 'native_runtime': 'NOT_RUN', 'gui_rebuilt': False}
    (out / 'BUILD_INFO.json').write_bytes(encoded(info))
    (out / 'README_RU.md').write_bytes(readme)
    (out / 'SHA256SUMS').write_text(''.join(v['sha256'] + '  ' + n + '\n' for n, v in sorted(results.items())))
    (out / 'PACKAGING_EVIDENCE.json').write_bytes(encoded(evidence))
    print(json.dumps(evidence, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
