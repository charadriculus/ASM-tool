#!/usr/bin/env python3
"""Build source-pinned developer check kits offline; never run their binaries."""
import argparse, hashlib, json, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
GO=Path('/home/charadriculus/opt/go1.26.6/bin/go')
GO_SHA='29e6e0b8be61beb1489ceae62b304343566de8a1dc700af74bde7aeb9c80ad45'
BASE='7edcf3b6712cfc1844db89dd08ecb0bebfc2ba2d'
PINS={'linux':'86c83b34d7d62caae5f1a7e8fb54b8163b8df05e7009ef4993ae446296fd2e41','windows':'c26c75208ddd40f3999abbeef4591a0ac6c7f1953a983e396d02895a7f4db479'}

def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def build(work,evidence):
    if not work.is_absolute() or not evidence.is_absolute():raise ValueError('absolute local output/evidence paths required')
    if work.is_symlink() or any(p.is_symlink() for p in work.parents):raise ValueError('linked output root')
    if work.exists() and any(work.iterdir()):raise ValueError('work directory must be fresh/empty; keep previous outputs')
    if sha(GO)!=GO_SHA:raise ValueError('Go toolchain SHA mismatch')
    work.mkdir(parents=True,exist_ok=True)
    record=evidence/'kit-summary.json'
    if record.exists():raise ValueError('summary already exists; no overwrite')
    base=evidence/'base-source.json'
    immutable=json.loads((evidence/'immutable-inputs-before.json').read_text())
    developer_paths = [ROOT/'internal/app/g16_native_check_test.go', *sorted((ROOT/'tools/g16check').glob('*.go')), *[ROOT/'tools/portablepayload'/name for name in ['build-g16-kit.py','package-g16-kit.py','test_g16_kit_packaging.py']], evidence/'run-check.py', ROOT/'planning/progress/g16-kit-handoff.md']
    developer_sources = {str(p.relative_to(ROOT)):sha(p) for p in developer_paths}
    def check_immutable():
        for p,h in developer_sources.items():
            if sha(ROOT/p)!=h:raise ValueError('developer build input changed: '+p)
        snap=json.loads(base.read_text());assert snap['base_commit']==BASE
        for p,h in snap['files'].items():
            if sha(ROOT/p)!=h:raise ValueError('frozen base changed: '+p)
        for p,h in immutable.items():
            if sha(ROOT/p)!=h:raise ValueError('old archive changed: '+p)
    check_immutable()
    runner=evidence/'run-check.py'
    package=ROOT/'tools/portablepayload/package-g16-kit.py'
    readme=ROOT/'planning/progress/g16-kit-handoff.md'
    summary={'base_commit':BASE,'native_execution':'NOT_RUN','windows11':'NOT_RUN_SEPARATE','go_sha256':GO_SHA,'platforms':{},'developer_sources':developer_sources}
    def invoke(label,argv):
        command=[sys.executable,str(runner),label,*map(str,argv)]
        completed=subprocess.run(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        print(completed.stdout,flush=True)
        if completed.returncode!=0:raise ValueError('STOP check failed: '+label+' exit '+str(completed.returncode))
        check_immutable()
    for platform,pin in PINS.items():
        suffix='.exe' if platform=='windows' else ''
        binaries={}
        for copy in ['A','B']:
            app=work/(platform+'-app-'+copy+suffix);test=work/(platform+'-harness-'+copy+suffix)
            flags='-s -w -buildid= -X asmtool/internal/app.BundleManifestSHA256='+pin
            invoke(platform+'-app-'+copy,[GO,'build','-buildvcs=false','-ldflags',flags,'-o',app,'./cmd/asm-tool'])
            invoke(platform+'-harness-'+copy,[GO,'test','-c','-buildvcs=false','-ldflags',flags,'-o',test,'./internal/app'])
            binaries[copy]={'app':app,'harness':test}
        for kind in ['app','harness']:
            if sha(binaries['A'][kind])!=sha(binaries['B'][kind]):raise ValueError('paired '+kind+' build mismatch: '+platform)
        roots={copy:work/(platform+'-'+copy) for copy in ['A','B']}
        for copy in ['A','B']:
            invoke(platform+'-stage-'+copy,[sys.executable,package,'stage','--platform',platform,'--app',binaries[copy]['app'],'--harness',binaries[copy]['harness'],'--base-snapshot',base,'--out',roots[copy]])
        checks_hash=sha(roots['A']/'checks/bundle.json')
        if checks_hash!=sha(roots['B']/'checks/bundle.json'):raise ValueError('checks manifest mismatch')
        for copy in ['A','B']:
            target=work/(platform+'-runner-'+copy+suffix)
            invoke(platform+'-runner-'+copy,[GO,'build','-buildvcs=false','-ldflags','-s -w -buildid= -X main.kitManifestSHA256='+checks_hash,'-o',target,'./tools/g16check'])
            binaries[copy]['runner']=target
        if sha(binaries['A']['runner'])!=sha(binaries['B']['runner']):raise ValueError('paired runner mismatch')
        for kind,path in binaries['A'].items():
            invoke(platform+'-build-info-'+kind,[GO,'version','-m',path])
            expected=checks_hash if kind=='runner' else pin
            # trimpath builds omit linker flags in build-info; inspect embedded bytes without execution.
            if expected.encode('ascii') not in path.read_bytes():raise ValueError('compiled manifest anchor absent from binary: '+kind)
        archives=[]
        final_name='g16-linux-check' if platform=='linux' else 'g16-windows10-check'
        for copy in ['A','B']:
            archive=work/(final_name+('' if copy=='A' else '-repeat')+'.zip')
            invoke(platform+'-archive-'+copy,[sys.executable,package,'archive','--platform',platform,'--root',roots[copy],'--runner',binaries[copy]['runner'],'--readme',readme,'--out',archive])
            archives.append({'path':str(archive),'sha256':sha(archive),'bytes':archive.stat().st_size})
        if archives[0]['sha256']!=archives[1]['sha256']:raise ValueError('paired ZIP mismatch')
        source=json.loads((roots['A']/'checks/SOURCE.json').read_text())
        if source['base_product_files']!=237:raise ValueError('unexpected product snapshot completeness')
        summary['platforms'][platform]={'archives':archives,'checks_manifest_sha256':checks_hash,'root':str(roots['A']),'binaries':{kind:{'path':str(path),'sha256':sha(path),'bytes':path.stat().st_size} for kind,path in binaries['A'].items()},'builds_byte_identical':True,'archives_byte_identical':True,'files':{p.relative_to(roots['A']).as_posix():sha(p) for p in sorted(roots['A'].rglob('*')) if p.is_file()},'native_execution':'NOT_RUN'}
    check_immutable()
    summary['immutable_inputs']=immutable
    record.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    sums=''
    for platform in PINS:
        a=summary['platforms'][platform]['archives'][0];sums+=a['sha256']+'  '+Path(a['path']).name+'\n'
    for p,h in immutable.items():sums+=h+'  '+Path(p).name+'\n'
    (work/'TRANSFER_SHA256SUMS').write_text(sums)
    print(json.dumps({'summary':str(record),'transfer_sha256':sha(work/'TRANSFER_SHA256SUMS'),'status':'PREPARED_NOT_RUN'}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',required=True);p.add_argument('--evidence',required=True);a=p.parse_args()
    try:build(Path(a.work).absolute(),Path(a.evidence).absolute())
    except (ValueError,OSError,KeyError,AssertionError) as e:p.exit(1,'g16-build: '+str(e)+'\n')
