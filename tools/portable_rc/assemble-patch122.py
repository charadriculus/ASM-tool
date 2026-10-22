#!/usr/bin/env python3
"""Developer-only assembly/inspection of already built 0.12.2 portable ZIPs; no payload execution."""
import argparse, hashlib, json, shutil, stat, struct, zipfile
from contextlib import ExitStack
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STAMP = (1980, 1, 1, 0, 0, 0)
SOURCE_COMMIT = 'a6360b1f1d472332815113fcb713603eee148ee5'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def digest(data):
    return hashlib.sha256(data).hexdigest()

def inspect_zip(path, expected_platform, build):
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None, 'CRC failure'
        names = archive.namelist()
        assert len(names) == len(set(n.lower() for n in names)), 'duplicate/colliding path'
        assert all(not n.startswith('/') and '\\' not in n and '..' not in Path(n).parts for n in names)
        assert all(stat.S_ISREG(x.external_attr >> 16) for x in archive.infolist())
        assert not any('nmap' in Path(n).name.lower() for n in names)
        suffix = '.exe' if expected_platform.startswith('windows') else ''
        assert all('payload/bin/'+name+suffix in names for name in ['obscura','obscura-worker','subfaster','typst'])
        manifest = json.loads(archive.read('payload/bundle.json'))
        assert manifest['platform'] == expected_platform
        app_name = 'asm-tool.exe' if expected_platform.startswith('windows') else 'asm-tool'
        expected = {'README.md', 'payload-provenance.json', 'payload/bundle.json', app_name}
        expected |= {'payload/' + row['path'] for row in manifest['files']}
        assert set(names) == expected, 'closed-tree inventory mismatch'
        assert digest(archive.read('payload/bundle.json')) == build['bundle_sha256']
        assert digest(archive.read('payload-provenance.json')) == build['provenance_sha256']
        for row in manifest['files']:
            assert digest(archive.read('payload/' + row['path'])) == row['sha256']
        app = archive.read(app_name)
        assert digest(app) == build['application_sha256']
        assert build['bundle_sha256'].encode('ascii') in app, 'embedded digest absent'
        if expected_platform.startswith('windows'):
            assert app[:2] == b'MZ'
            pe = struct.unpack_from('<I', app, 0x3c)[0]
            assert app[pe:pe+4] == b'PE\0\0' and struct.unpack_from('<H', app, pe+4)[0] == 0x8664
        else:
            assert app[:5] == b'\x7fELF\x02' and struct.unpack_from('<H', app, 18)[0] == 62
            assert (archive.getinfo(app_name).external_attr >> 16) & 0o111
        return {'files': len(names), 'crc': 'PASS', 'closed_tree_and_payload_hashes': 'PASS',
                'embedded_anchor_static_check': 'PASS', 'app_architecture': 'amd64', 'native_runtime': 'NOT_RUN'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-root', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    build_root = Path(args.build_root).resolve()
    output = Path(args.output).absolute()
    output.mkdir(mode=0o700)  # New output only; never replaces an accepted archive.
    summary = json.loads((build_root/'evidence/summary.json').read_text())
    assert summary['source_before'] == summary['source_after']
    for relative, expected in summary['source_after'].items():
        assert sha(ROOT/relative) == expected, 'build source changed after compilation'
    labels = ['sdk-version', 'build-stager']
    labels += [platform+'-'+attempt+'-'+step for platform in ['linux', 'windows']
               for attempt in ['A', 'B'] for step in ['stage', 'app-build', 'verify', 'archive', 'build-info']]
    assert len(labels) == summary['command_count']
    for label in labels:
        record_path = build_root/'evidence'/(label+'.json')
        record = json.loads(record_path.read_text())
        assert record['exit_code'] == 0 and not record['timeout']
        assert sha(record_path.with_suffix('.log')) == record['log_sha256']
    info = {'version': '0.12.2-go', 'product_source_base_commit': SOURCE_COMMIT, 'product_source_commit': args.source_commit,
            'go_sdk': summary['go_sdk'], 'developer_builder_sha256': sha(ROOT/'tools/portablepayload/build-approved.py'),
            'assembler_sha256': sha(Path(__file__)), 'platforms': {},
            'status': {'native_linux': 'NOT_RUN', 'native_windows10': 'NOT_RUN', 'native_windows11': 'NOT_RUN',
                       'browser': 'RESTORED_OWNER_TRIALS_NOT_SECURITY_QUALIFIED', 'subfaster': 'RESTORED_STARTUP_UDP_RISK_UNRESOLVED',
                       'candidate31': 'FAIL', 'historical_linux_network': 'FAIL', 'windows_strict_network': 'NOT_RUN',
                       'robots_G28_01': 'DEFERRED'}}
    inventory = {}
    with ExitStack() as stack:
        entries = {}
        for result in summary['results']:
            a, b = result['builds']
            for key in ['archive_sha256', 'application_sha256', 'bundle_sha256', 'provenance_sha256']:
                assert a[key] == b[key]
            platform = result['platform']
            prefix = 'windows-x64' if platform.startswith('windows') else 'linux-x86_64'
            filename = 'ASM_Tool_0.12.2-' + prefix + '.zip'
            source = Path(a['archive']).resolve()
            assert source.is_relative_to(build_root) and sha(source) == a['archive_sha256']
            repeat_archive = Path(b['archive']).resolve()
            assert repeat_archive.is_relative_to(build_root) and sha(repeat_archive) == b['archive_sha256']
            shutil.copyfile(source, output/filename)
            assert sha(output/filename) == a['archive_sha256']
            inventory[filename] = inspect_zip(output/filename, platform, a)
            info['platforms'][platform] = {key: a[key] for key in ['application_sha256', 'bundle_sha256', 'provenance_sha256', 'lock_sha256', 'archive_sha256']}
            info['platforms'][platform].update(archive=filename, reproducibility='PASS_TWO_LOCAL_BUILDS')
            archive = stack.enter_context(zipfile.ZipFile(output/filename))
            for member in archive.infolist():
                entries[prefix+'/'+member.filename] = (archive, member, member.external_attr)
        docs = {'README_RU.md': (ROOT/'docs/patch122/PORTABLE_README_RU.md').read_bytes(),
                'config.example.yml': (ROOT/'assets/examples/config.example.yml').read_bytes(),
                'BUILD_INFO.json': (json.dumps(info, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode(),
                'LICENSE_REVIEW.md': (ROOT/'newdocs/licenses/patch122-license-review.md').read_bytes()}
        source_zip = output/'ASM_Tool_0.12.2-source.zip'
        source_paths = sorted({p for prefix in ['cmd','internal','assets','testdata','tools/portablepayload','tools/portable_rc','packaging/portable','docs/patch122','newdocs/licenses'] for p in (ROOT/prefix).rglob('*') if p.is_file() and not p.is_symlink() and p.suffix not in ['.pyc','.exe','.zip','.gz'] and '__pycache__' not in p.parts} | {ROOT/'go.mod',ROOT/'go.sum'})
        with source_zip.open('xb') as stream, zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
            for p in source_paths:
                header=zipfile.ZipInfo(str(p.relative_to(ROOT)),STAMP);header.create_system=3;header.external_attr=(stat.S_IFREG|0o644)<<16
                archive.writestr(header,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
        with zipfile.ZipFile(source_zip) as archive: assert archive.testzip() is None
        inventory[source_zip.name]={'files':len(source_paths),'crc':'PASS','scope':'current Go source/resources/developer packaging; historical reference snapshots and dependency caches excluded'}
        docs['SOURCE_CODE.zip']=source_zip.read_bytes()
        hashes = {name: digest(data) for name, data in docs.items()}
        hashes.update({name: digest(archive.read(member)) for name, (archive, member, _) in entries.items()})
        docs['SHA256SUMS'] = ''.join(hashes[name]+'  '+name+'\n' for name in sorted(hashes)).encode()
        def write_delivery(path):
            with path.open('xb') as stream, zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for name in sorted(set(entries)|set(docs)):
                    header = zipfile.ZipInfo(name, STAMP)
                    header.create_system = 3
                    header.compress_type = zipfile.ZIP_DEFLATED
                    header.external_attr = entries[name][2] if name in entries else (stat.S_IFREG|0o644) << 16
                    if name in docs:
                        archive.writestr(header, docs[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
                    else:
                        source, member, _ = entries[name]
                        with source.open(member) as incoming, archive.open(header, 'w') as target:
                            shutil.copyfileobj(incoming, target)
        delivery = output/'ASM_Tool_0.12.2-portable-Linux-Windows.zip'
        write_delivery(delivery)
        repeat = build_root/'delivery-repeat.zip'
        write_delivery(repeat)
        assert sha(delivery) == sha(repeat), 'delivery ZIP reproducibility failure'
        with zipfile.ZipFile(delivery) as archive:
            assert archive.testzip() is None
            assert set(archive.namelist()) == set(hashes)|{'SHA256SUMS'}
            for name, expected in hashes.items():
                assert digest(archive.read(name)) == expected
            inventory[delivery.name] = {'files': len(archive.namelist()), 'crc': 'PASS', 'file_hashes': 'PASS', 'reproducibility': 'PASS_TWO_LOCAL_ASSEMBLIES'}
        (output/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(output.glob('*.zip'))))
        (output/'README_RU.md').write_bytes(docs['README_RU.md'])
        (output/'BUILD_INFO.json').write_bytes(docs['BUILD_INFO.json'])
    result = {'archives': {p.name: {'sha256': sha(p), 'bytes': p.stat().st_size, **inventory[p.name]} for p in sorted(output.glob('*.zip'))},
              'source_product_unchanged_since_build': True, 'payload_execution': 'NOT_RUN'}
    (build_root/'evidence/archive-inspection.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
