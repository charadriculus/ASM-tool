#!/usr/bin/env python3
"""Copy no originals: derive a new lock for user-approved existing Linux assets.
Static readelf/ldconfig metadata only; no payload execution, downloads or system changes.
"""
import hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
AUDIT=Path('/home/charadriculus/Projects/asm_tool/asm-tool-0113-audit')
EVIDENCE=ROOT/'planning/progress/approved-portable-evidence'
APPROVED={'nmap':(Path('/usr/bin/nmap'),'dfdfb438e214b82f1a8701d9ca94eca0156c710a663261f1bd595f98a53662fc','7.98+dfsg-1'),'subfaster':(AUDIT/'asm_tool_0113/.tools/bin/subfaster','bbbe5e8c4adeb71d94e209bf5c9e269b90dbbe2ac63ff7497bac4c4fc830bd30','2.18.0')}
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def command(argv):
 p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
 if p.returncode:raise SystemExit(f'static metadata failed {argv}: {p.stderr.decode()}')
 return p.stdout.decode()
def needed(p):return re.findall(r'\(NEEDED\).*\[(.*?)\]',command(['/usr/bin/readelf','-d',str(p)]))
def main():
 out=ROOT/'packaging/portable/linux-amd64-approved.lock.json'
 if out.exists():raise SystemExit('refuse to replace existing approved lock')
 lock=json.loads((ROOT/'packaging/portable/linux-amd64-report-only.lock.json').read_text())
 for src in lock['sources']:src['license']='Existing component use approved by user2026-10-14; original notices retained'
 for tool in lock['tools']:tool['license']='Existing component use approved by user2026-10-14';tool['dependencies']=[d for d in tool.get('dependencies',[]) if 'LICENSE' not in d]
 metadata=[]
 def add(id,source,dest,version,executable=False,pin=None):
  real=source.resolve(strict=True)
  if not real.is_file():raise SystemExit('nonregular source '+str(real))
  digest=sha(real)
  if pin and digest!=pin:raise SystemExit('approved source bytes changed '+str(real))
  lock['sources'].append({'id':id,'path':str(real),'sha256':digest,'archive':False,'version':version,'license':'Existing component/libraries approved by user2026-10-14'})
  lock['files'].append({'path':'payload/'+dest,'source':id,'sha256':digest,'size':real.stat().st_size,'executable':executable})
  metadata.append({'source':str(real),'destination':'payload/'+dest,'sha256':digest,'size':real.stat().st_size})
 cache={}
 for line in command(['/usr/sbin/ldconfig','-p']).splitlines():
  m=re.match(r'\s*(\S+) \(([^)]*)\) => (\S+)',line)
  if m and 'x86-64' in m[2]:cache.setdefault(m[1],Path(m[3]))
 loader=Path('/lib64/ld-linux-x86-64.so.2').resolve(strict=True)
 libraries={'ld-linux-x86-64.so.2':loader};queue=[]
 for name,(source,pin,version) in APPROVED.items():
  add('approved-linux-'+name,source,'bin/'+name,version,True,pin);queue.append(source.resolve())
  lock['tools'].append({'name':name,'executable':'payload/bin/'+name,'version':'2.18.0' if name=='subfaster' else '7.98','usage':'qualification-only','capabilities':['existing approved native; local functional qualification only'],'license':'Existing component use approved by user2026-10-14','dependencies':['bundled matching linux-runtime loader/DT_NEEDED closure']})
 seen=set()
 while queue:
  obj=queue.pop(0)
  if obj in seen:continue
  seen.add(obj)
  for soname in needed(obj):
   if '/' in soname:raise SystemExit('unsupported path dependency '+soname)
   if soname not in libraries:
    if soname not in cache:raise SystemExit('unresolved local dependency '+soname)
    libraries[soname]=cache[soname].resolve(strict=True);queue.append(libraries[soname])
 for index,(soname,p) in enumerate(sorted(libraries.items())):add('linux-runtime-'+str(index),p,'bin/linux-runtime/'+soname,'existing matching Linux amd64 runtime',soname=='ld-linux-x86-64.so.2')
 # Same approved system Nmap package datasets, adjacent to executable; fixed --datadir .
 data=Path('/usr/share/nmap')
 for index,p in enumerate(sorted(data.rglob('*'))):
  if p.is_file():add('nmap-data-'+str(index),p,'bin/'+p.relative_to(data).as_posix(),'7.98+dfsg-1 matching nmap-common')
 lock['linux_runtime']={'loader':'bin/linux-runtime/ld-linux-x86-64.so.2','library_dir':'bin/linux-runtime','tools':['nmap','subfaster']}
 lock['files'].sort(key=lambda x:x['path']);lock['sources'].sort(key=lambda x:x['id']);lock['tools'].sort(key=lambda x:x['name'])
 raw=(json.dumps(lock,ensure_ascii=False,indent=2)+'\n').encode();out.write_bytes(raw)
 report={'approval':'user final decision2026-10-14','lock_sha256':hashlib.sha256(raw).hexdigest(),'loader':str(loader),'runtime_libraries':[{'soname':name,'source':str(p),'sha256':sha(p),'needed':needed(p)} for name,p in sorted(libraries.items())],'files':metadata,'native_qualification':'NOT_RUN','license_review':'NOT_REOPENED','system_configuration':'UNCHANGED'}
 (EVIDENCE/'linux-inputs.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'lock':str(out),'files':len(lock['files']),'runtime_libraries':len(libraries),'sha256':report['lock_sha256']}))
if __name__=='__main__':main()
