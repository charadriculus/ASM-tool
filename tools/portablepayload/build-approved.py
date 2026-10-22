#!/usr/bin/env python3
"""Developer-only offline double build; produces local preparation candidates, not a release.
Use a new private --output directory. Existing candidates/evidence are never replaced.
"""
import argparse, hashlib, json, os, signal, subprocess, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
GO=Path('/home/charadriculus/opt/go1.26.6/bin/go')
EXPECTED_GO_SHA256='29e6e0b8be61beb1489ceae62b304343566de8a1dc700af74bde7aeb9c80ad45'

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def source_hashes():
 paths=sorted({*ROOT.joinpath('internal').rglob('*.go'),*ROOT.joinpath('internal').rglob('*.json'),*ROOT.joinpath('cmd').rglob('*.go'),*ROOT.joinpath('assets').rglob('*.*'),*ROOT.joinpath('tools/portablepayload').glob('*.*'),*ROOT.joinpath('packaging/portable').glob('*.*'),ROOT/'go.mod',ROOT/'go.sum'})
 return {str(p.relative_to(ROOT)):sha(p) for p in paths if p.is_file()}

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True);parser.add_argument('--linux-lock',default='linux-amd64-approved.lock.json');parser.add_argument('--windows-lock',default='windows-amd64-approved.lock.json');parser.add_argument('--cache-root',default='tmp/integration-6-8',help='existing local Go cache root under this worktree');args=parser.parse_args()
 if sha(GO)!=EXPECTED_GO_SHA256:raise SystemExit('Go toolchain SHA-256 mismatch; no build started')
 cache=(ROOT/args.cache_root).resolve()
 if not cache.is_relative_to(ROOT) or not (cache/'modcache').is_dir():raise SystemExit('cache root must be an existing worktree-local cache with modcache')
 for name in ['home','cache','tmp']:(cache/name).mkdir(parents=True,exist_ok=True)
 out=Path(args.output).absolute();out.mkdir(mode=0o700) # fail if present
 evidence=out/'evidence';evidence.mkdir(mode=0o700)
 env={'PATH':str(GO.parent)+':/usr/bin:/bin','HOME':str(cache/'home'),'GOWORK':'off','GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOTELEMETRY':'off','GOENV':'off','GOFLAGS':'-mod=readonly -p=1 -trimpath','GOMAXPROCS':'2','CGO_ENABLED':'0','GOOS':'linux','GOARCH':'amd64','GOAMD64':'v1','GOMODCACHE':str(cache/'modcache'),'GOCACHE':str(cache/'cache'),'GOTMPDIR':str(cache/'tmp'),'TMPDIR':str(cache/'tmp')}
 before=source_hashes();records=[]
 def command(label,argv,overrides=None):
  settings=env| (overrides or {});start=time.time();log=evidence/(label+'.log')
  with log.open('xb') as f:
   p=subprocess.Popen([str(a) for a in argv],cwd=ROOT,env=settings,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   try:code=p.wait(timeout=120);timed_out=False
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait();code=124;timed_out=True
  record={'label':label,'command':[str(a) for a in argv],'cwd':str(ROOT),'environment':settings,'exit_code':code,'timeout':timed_out,'timeout_seconds':120,'wall_seconds':time.time()-start,'log_sha256':sha(log)}
  (evidence/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n');records.append(record)
  print(json.dumps({'label':label,'exit_code':code}),flush=True)
  if code:raise SystemExit('STOP on failed offline preparation step: '+label)
  return log.read_text()
 command('sdk-version',[GO,'version'])
 builder=out/'portablepayload-builder'
 command('build-stager',[GO,'build','-buildvcs=false','-ldflags=-buildid=','-o',builder,'./tools/portablepayload'])
 results=[]
 for platform,lock_name in [('linux',args.linux_lock),('windows',args.windows_lock)]:
  pair=[];lock=ROOT/'packaging/portable'/lock_name
  for attempt in ['A','B']:
   label=platform+'-'+attempt;stage=out/('ASM-'+platform+'-проверка-'+attempt)
   info=json.loads(command(label+'-stage',[builder,'stage','--lock',lock,'--out',stage]))
   app=stage/('asm-tool.exe' if platform=='windows' else 'asm-tool')
   flags='-s -w -buildid= -X asmtool/internal/app.BundleManifestSHA256='+info['bundle_sha256']
   command(label+'-app-build',[GO,'build','-buildvcs=false','-ldflags',flags,'-o',app,'./cmd/asm-tool'],{'GOOS':platform,'GOARCH':'amd64'})
   app_hash=sha(app);verify_args=['--root',stage,'--app-sha256',app_hash,'--bundle-sha256',info['bundle_sha256'],'--provenance-sha256',info['provenance_sha256']]
   command(label+'-verify',[builder,'verify',*verify_args]);archive=out/(label+'-preparation.zip')
   command(label+'-archive',[builder,'archive',*verify_args,'--out',archive])
   command(label+'-build-info',[GO,'version','-m',app])
   pair.append({'attempt':attempt,'root':str(stage),'archive':str(archive),'archive_sha256':sha(archive),'application_sha256':app_hash,'bundle_sha256':info['bundle_sha256'],'provenance_sha256':info['provenance_sha256'],'lock_sha256':sha(lock)})
  for field in ['archive_sha256','application_sha256','bundle_sha256','provenance_sha256']:
   if pair[0][field]!=pair[1][field]:raise SystemExit('reproducibility FAIL: '+platform+' '+field)
  results.append({'platform':platform+'/amd64','reproducibility':'PASS_TWO_LOCAL_BUILDS','candidate_scope':'approved existing native payload; local functional qualification','builds':pair,'native_runtime':'NOT_RUN'})
 after=source_hashes()
 if before!=after:raise SystemExit('source changed during build; evidence invalid')
 summary={'status':'EXISTING_COMPONENTS_PREPARED_OFFLINE','go_sdk':{'path':str(GO),'sha256':sha(GO)},'builder_sha256':sha(builder),'source_before':before,'source_after':after,'results':results,'command_count':len(records),'browser':'RESTORED_OWNER_TRIALS_NOT_SECURITY_QUALIFIED','qualification':'NOT_RUN','warnings':['Subfaster and Obscura execution restored for owner trials; network safety not qualified','candidate31 FAIL and historical Linux network FAIL preserved','Subfaster startup UDP probe not fixed','Windows10/11 native runtime NOT_RUN for 0.12.2','Linux Obscura direct host ABI prerequisites apply','robots.txt G28-01 deferred; no full Python/Go equivalence claim','No public release authorization'], 'component_use':'approved by final user decision2026-10-14'}
 (evidence/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'summary':str(evidence/'summary.json'),'status':summary['status'],'results':[{'platform':x['platform'],'reproducibility':x['reproducibility']} for x in results]},ensure_ascii=False))
if __name__=='__main__':main()
