#!/usr/bin/env python3
"""Developer-only RC metadata overlay on two independently verified base ZIPs.
No payload execution, downloads or edits; fresh output required. Not a release gate.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[2]
COMMIT = 'c0a91beecc6623d5ce14baea39f622207d1d135b'
SDK_SHA = '29e6e0b8be61beb1489ceae62b304343566de8a1dc700af74bde7aeb9c80ad45'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()

def load_zip(path):
    entries = {}
    folded = set()
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError('CRC failure: ' + str(path))
        for info in archive.infolist():
            name = info.filename
            parts = PurePosixPath(name).parts
            mode = info.external_attr >> 16
            if (not parts or name.startswith('/') or '\\' in name or ':' in name
                or any(p in ('', '.', '..') for p in name.split('/'))
                or name.casefold() in folded or not stat.S_ISREG(mode)):
                raise ValueError('unsafe/duplicate/non-regular entry: ' + name)
            folded.add(name.casefold())
            entries[name] = (archive.read(info), stat.S_IMODE(mode))
    return entries

def inventory(entries):
    return [{'path': name, 'sha256': digest(data), 'size': len(data), 'mode': oct(mode)}
            for name, (data, mode) in sorted(entries.items())]

def write_zip(path, entries):
    # Fresh parent is owned by this run; never replace a prior deliverable.
    with path.open('xb') as stream, zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, (data, mode) in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, data)
    actual = load_zip(path)
    if actual != entries:
        raise ValueError('archive readback differs')

def metadata(entries, platform, base):
    manifest = {'schema_version': 1, 'candidate': '0.12.0-rc1', 'source_commit': COMMIT,
                'platform': platform, 'go_sdk_sha256': SDK_SHA,
                'base_archive_sha256': base.get('archive_sha256'),
                'bundle_sha256': base.get('bundle_sha256'),
                'product_changes': 'NONE', 'native_runtime': 'NOT_RUN',
                'browser': 'BLOCKED; candidate31 FAIL',
                'historical_linux_network': 'FAIL', 'windows_strict_network': 'NOT_RUN',
                'windows11_runtime': 'NOT_RUN', 'g28_full_equivalence': 'NOT_ESTABLISHED; known divergences retained',
                'inventory_exclusions': ['RC_MANIFEST.json', 'SHA256SUMS'], 'files': inventory(entries)}
    entries['RC_MANIFEST.json'] = (encoded(manifest), 0o644)
    entries['SHA256SUMS'] = (''.join(f'{digest(data)}  {name}\n' for name, (data, _) in sorted(entries.items())).encode(), 0o644)
    return manifest

def assert_base(entries, base, platform):
    app = 'asm-tool.exe' if platform == 'windows' else 'asm-tool'
    for path, expected in [(app, base['application_sha256']), ('payload/bundle.json', base['bundle_sha256']),
                           ('payload-provenance.json', base['provenance_sha256'])]:
        if digest(entries[path][0]) != expected:
            raise ValueError('base anchor differs: ' + path)
    bundle = json.loads(entries['payload/bundle.json'][0])
    expected = {app, 'README.md', 'payload-provenance.json', 'payload/bundle.json'}
    for item in bundle['files']:
        name = 'payload/' + item['path']
        expected.add(name)
        if digest(entries[name][0]) != item['sha256']:
            raise ValueError('payload digest differs: ' + name)
    if set(entries) != expected or bundle['platform'] != platform + '/amd64':
        raise ValueError('base closure/platform mismatch')
    # Independent static architecture check; does not execute a payload.
    checked = []
    for name in [app] + ['payload/' + tool['executable'] for tool in bundle['tools']]:
        data = entries[name][0]
        if platform == 'linux':
            valid = data[:6] == b'\x7fELF\x02\x01' and int.from_bytes(data[18:20], 'little') == 62
            machine = 'ELF64 x86-64'
        else:
            offset = int.from_bytes(data[60:64], 'little')
            arch = int.from_bytes(data[offset + 4:offset + 6], 'little')
            valid = data[:2] == b'MZ' and data[offset:offset + 4] == b'PE\0\0' and arch == (0x14c if name.endswith('/nmap.exe') else 0x8664)
            machine = 'PE x86/WOW64 approved' if arch == 0x14c else 'PE x64'
        if not valid:
            raise ValueError('architecture mismatch: ' + name)
        checked.append({'path': name, 'architecture': machine, 'sha256': digest(data)})
    if base['bundle_sha256'].encode() not in entries[app][0]:
        raise ValueError('embedded bundle anchor missing')
    return checked

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--checks', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    summary = json.loads((args.build / 'evidence/summary.json').read_text())
    if summary['go_sdk']['sha256'] != SDK_SHA or summary['source_before'] != summary['source_after']:
        raise ValueError('build SDK/source guard mismatch')
    args.output.mkdir(mode=0o700)
    records = []
    for result in summary['results']:
        platform = result['platform'].split('/')[0]
        hashes = []
        arch = None
        for base in result['builds']:
            source = Path(base['archive'])
            if digest(source.read_bytes()) != base['archive_sha256']:
                raise ValueError('base ZIP digest mismatch')
            entries = load_zip(source)
            arch = assert_base(entries, base, platform)
            entries['RELEASE_NOTES.md'] = ((ROOT / 'docs/packaging/rc1/RELEASE_NOTES.md').read_bytes(), 0o644)
            entries['NATIVE_QUALIFICATION.md'] = ((ROOT / 'planning/progress/rc1-native-handoff.md').read_bytes(), 0o644)
            metadata(entries, result['platform'], base)
            suffix = 'linux-x86_64' if platform == 'linux' else 'windows-x64'
            name = f'ASM_Tool_0.12.0-rc1-{suffix}.zip'
            path = args.output / (name if base['attempt'] == 'A' else name + '.repro-B')
            write_zip(path, entries)
            hashes.append(digest(path.read_bytes()))
        if hashes[0] != hashes[1]:
            raise ValueError('RC reproducibility failure: ' + platform)
        records.append({'archive': name, 'sha256': hashes[0], 'reproducibility': 'PASS_TWO_LOCAL_BUILDS',
                        'files': len(entries), 'architecture': arch, 'bundle_sha256': base['bundle_sha256'], 'rc_manifest_sha256': digest(entries['RC_MANIFEST.json'][0]), 'sha256sums_sha256': digest(entries['SHA256SUMS'][0])})
    checks = {}
    test_architectures = []
    anchors = {r['platform'].split('/')[0]: r['builds'][0]['bundle_sha256'] for r in summary['results']}
    for name in ['linux-native.test', 'windows-native.test.exe']:
        first = (args.checks / (name + '-A')).read_bytes()
        second = (args.checks / (name + '-B')).read_bytes()
        if first != second:
            raise ValueError('test executable reproducibility failure: ' + name)
        if name.startswith('linux'):
            valid = first[:6] == b'\x7fELF\x02\x01' and int.from_bytes(first[18:20], 'little') == 62
            platform = 'linux'
        else:
            offset = int.from_bytes(first[60:64], 'little')
            valid = first[:2] == b'MZ' and first[offset:offset + 4] == b'PE\0\0' and int.from_bytes(first[offset + 4:offset + 6], 'little') == 0x8664
            platform = 'windows'
        if not valid or anchors[platform].encode() not in first:
            raise ValueError('test executable architecture/anchor mismatch: ' + name)
        test_architectures.append({'path': name, 'platform': platform + '/amd64', 'sha256': digest(first), 'bundle_anchor': anchors[platform], 'two_builds_equal': True})
        checks[name] = (first, 0o755)
    checks['NATIVE_QUALIFICATION.md'] = ((ROOT / 'planning/progress/rc1-native-handoff.md').read_bytes(), 0o644)
    metadata(checks, 'linux+windows/amd64 developer-only checks; NOT_READY unsupervised', {})
    name = 'ASM_Tool_0.12.0-rc1-native-checks.zip'
    write_zip(args.output / name, checks)
    records.append({'archive': name, 'sha256': digest((args.output / name).read_bytes()),
                    'native_runtime': 'NOT_RUN', 'unsupervised_execution': 'NOT_READY', 'test_executables': test_architectures})
    (args.output / 'artifacts.json').write_bytes(encoded({'source_commit': COMMIT, 'artifacts': records}))
    (args.output / 'SHA256SUMS').write_text(''.join(f"{r['sha256']}  {r['archive']}\n" for r in records))
    print(json.dumps(records, indent=2))

if __name__ == '__main__':
    main()
