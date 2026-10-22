#!/usr/bin/env python3
"""Developer-only deterministic G16 kit packager. Never executes input binaries."""
import argparse, hashlib, json, os, shutil, stat, struct, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
BASE = '7edcf3b6712cfc1844db89dd08ecb0bebfc2ba2d'
BASE_SNAPSHOT_SHA256 = 'beb2bbc94d924be2421485ac25f8b00c198a433458a0ed7158cfa38aac726174'
PINS = {'linux': '86c83b34d7d62caae5f1a7e8fb54b8163b8df05e7009ef4993ae446296fd2e41', 'windows': 'c26c75208ddd40f3999abbeef4591a0ac6c7f1953a983e396d02895a7f4db479'}

def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def regular(path):
    path = Path(path).absolute()
    for p in [path, *path.parents]:
        if p.is_symlink():
            raise ValueError('symlink input: '+str(p))
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('regular input file required: '+str(path))
    return path

def machine(path, platform):
    with regular(path).open('rb') as f:
        header = f.read(64)
        if platform == 'linux':
            if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', header, 18)[0] != 62:
                raise ValueError('ELF x86-64 required: '+str(path))
        else:
            if len(header) != 64 or header[:2] != b'MZ':
                raise ValueError('PE x64 required: '+str(path))
            offset = struct.unpack_from('<I', header, 60)[0]
            if offset > Path(path).stat().st_size - 6:
                raise ValueError('PE offset outside file')
            f.seek(offset)
            if f.read(6) != b'PE\0\0\x64\x86':
                raise ValueError('PE x64 required: '+str(path))

def reject_symlink_ancestors(path):
    for p in [Path(path).absolute(), *Path(path).absolute().parents]:
        if p.is_symlink():
            raise ValueError("symlink output ancestor: "+str(p))

def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n', encoding='utf-8')

def unchanged_base(path):
    if sha(regular(path)) != BASE_SNAPSHOT_SHA256:
        raise ValueError('unapproved base source snapshot identity')
    data = json.loads(Path(path).read_text())
    if not data.get('files'):
        raise ValueError('empty base source snapshot')
    if data['base_commit'] != BASE:
        raise ValueError('wrong frozen product base')
    for name, digest in data['files'].items():
        if sha(regular(ROOT/name)) != digest:
            raise ValueError('base source changed: '+name)
    return data

def stage(args):
    base = unchanged_base(args.base_snapshot)
    out = Path(args.out).absolute()
    reject_symlink_ancestors(out)
    if out.exists():
        raise ValueError('output must be fresh')
    suffix = '.exe' if args.platform == 'windows' else ''
    inputs = [('asm-tool', regular(args.app)), ('g16-native.test', regular(args.harness))]
    for _, p in inputs:
        machine(p, args.platform)
    sources = {str(p.relative_to(ROOT)): sha(p) for p in sorted(ROOT.glob('internal/app/g16*test.go'))}
    sources.update({str(p.relative_to(ROOT)): sha(p) for p in sorted(ROOT.glob('tools/g16check/*.go'))})
    for name in ['package-g16-kit.py','build-g16-kit.py','test_g16_kit_packaging.py']:
        p=ROOT/'tools/portablepayload'/name
        sources[str(p.relative_to(ROOT))]=sha(p)
    if not sources:
        raise ValueError('missing G16 harness/tool source')
    out.mkdir(parents=True, exist_ok=False)
    checks = out/'checks'
    (checks/'bin').mkdir(parents=True)
    for name, source in inputs:
        dest = checks/'bin'/(name+suffix)
        shutil.copyfile(source, dest)
        dest.chmod(0o755 if args.platform == 'linux' else 0o644)
    (checks/'product-source.sha256').write_text(''.join(h+'  '+p+'\n' for p,h in sorted(base['files'].items())), encoding='utf-8')
    write_json(checks/'SOURCE.json', {'base_commit': BASE, 'platform': args.platform+'/amd64', 'payload_anchor': PINS[args.platform], 'base_product_files': len(base['files']), 'base_manifest_sha256': sha(checks/'product-source.sha256'), 'developer_sources': sources, 'native_execution': 'NOT_RUN', 'subfaster': 'NOT_EXECUTED', 'browser': 'BLOCKED_candidate31_FAIL', 'linux_strict_network': 'HISTORICAL_FAIL_PRESERVED', 'windows11': 'NOT_RUN_SEPARATE'})
    files = [{'path': p.relative_to(checks).as_posix(), 'sha256': sha(p)} for p in sorted(checks.rglob('*')) if p.is_file()]
    manifest = {'schema_version': 1, 'platform': args.platform+'/amd64', 'files': files, 'tools': [{'name': name, 'executable': 'bin/'+name+suffix, 'version': '0.12.0-go'} for name,_ in inputs]}
    write_json(checks/'bundle.json', manifest)
    print(json.dumps({'out':str(out), 'checks_manifest_sha256':sha(checks/'bundle.json'), 'files':len(files)}))

def verify_checks(root):
    checks = root/'checks'
    manifest = json.loads(regular(checks/'bundle.json').read_text())
    expected = {x['path']: x['sha256'] for x in manifest['files']}
    if len(expected) != len(manifest['files']):
        raise ValueError('duplicate manifest path')
    found = {}
    for p in sorted(checks.rglob('*')):
        if p.is_symlink():
            raise ValueError('symlink kit member')
        if p.is_file() and p.name != 'bundle.json':
            found[p.relative_to(checks).as_posix()] = sha(regular(p))
    if found != expected:
        raise ValueError('kit closed-tree/hash mismatch')
    return manifest

def archive(args):
    root = Path(args.root).absolute()
    platform = args.platform
    suffix = '.exe' if platform == 'windows' else ''
    manifest = verify_checks(root)
    if manifest['platform'] != platform+'/amd64':
        raise ValueError('wrong kit platform')
    runner = regular(args.runner)
    machine(runner, platform)
    readme = regular(args.readme)
    output = Path(args.out).absolute()
    reject_symlink_ancestors(output)
    allowed = {'checks'}
    if {p.name for p in root.iterdir()} != allowed:
        raise ValueError('archive requires fresh staged root; refuses overwriting kit')
    if output.exists():
        raise ValueError('archive output exists')
    dest = root/('g16check'+suffix)
    shutil.copyfile(runner, dest)
    dest.chmod(0o755 if platform == 'linux' else 0o644)
    shutil.copyfile(readme, root/'README.md')
    files = sorted(p for p in root.rglob('*') if p.is_file())
    (root/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.relative_to(root).as_posix()+'\n' for p in files), encoding='utf-8')
    files.append(root/'SHA256SUMS');files.sort()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in files:
            name = p.relative_to(root).as_posix()
            i = zipfile.ZipInfo(name, date_time=(1980,1,1,0,0,0)); i.create_system=3
            mode = 0o755 if platform=='linux' and (name=='g16check' or name.startswith('checks/bin/')) else 0o644
            i.external_attr=(stat.S_IFREG|mode)<<16;i.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(i,p.read_bytes(),compresslevel=9)
    with zipfile.ZipFile(output) as z:
        if z.testzip() is not None or len(z.namelist()) != len(files):
            raise ValueError('ZIP integrity failure')
        for p in files:
            if hashlib.sha256(z.read(p.relative_to(root).as_posix())).hexdigest()!=sha(p):
                raise ValueError('ZIP member hash mismatch')
    print(json.dumps({'path':str(output), 'sha256':sha(output), 'bytes':output.stat().st_size, 'files':len(files), 'checks_manifest_sha256':sha(root/'checks/bundle.json'), 'runner_sha256':sha(dest), 'native_execution':'NOT_RUN'}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    s=sub.add_parser('stage');s.add_argument('--platform',choices=PINS,required=True);s.add_argument('--app',required=True);s.add_argument('--harness',required=True);s.add_argument('--base-snapshot',required=True);s.add_argument('--out',required=True)
    a=sub.add_parser('archive');a.add_argument('--platform',choices=PINS,required=True);a.add_argument('--root',required=True);a.add_argument('--runner',required=True);a.add_argument('--readme',required=True);a.add_argument('--out',required=True)
    args=parser.parse_args()
    try:
        (stage if args.command=='stage' else archive)(args)
    except (OSError,ValueError,KeyError) as e:
        parser.exit(1,'g16-kit: '+str(e)+'\n')
if __name__=='__main__':main()
