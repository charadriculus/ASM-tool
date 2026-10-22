#!/usr/bin/env python3
"""Add available authenticated Subfaster dependency notices to a NEW Windows lock.
H1 is recomputed from module ZIP bytes and compared with the build-info of the
independently pinned Windows binary. This never downloads or executes Subfaster.
"""
import base64,hashlib,json,re,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
CACHE=Path('/home/charadriculus/Projects/asm_tool/asm-tool-0113-audit/qualification/en/home/go/pkg/mod/cache/download')
def escape(s):return ''.join('!'+c.lower() if 'A'<=c<='Z' else c for c in s)
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 evidence=ROOT/'planning/progress/portable-payload-evidence'
 inventory_bytes=(evidence/'static-inventory.json').read_bytes()
 # Pin the reviewed inventory that contains the previously read binary build-info.
 if sha(inventory_bytes)!='11a5899e020145fdffb762ab7769830cc6f6269f4fa8455bb0439bb4bb9cc2e0':raise SystemExit('reviewed static inventory identity changed')
 inventory=json.loads(inventory_bytes)
 info=next(c['output'] for c in inventory['commands'] if c['label']=='windows-subfaster-build-info')
 deps=re.findall(r'^\s*dep\s+(\S+)\s+(\S+)\s+(\S+)',info,re.M)
 if len(deps)!=107:raise SystemExit('unexpected Subfaster dependency inventory')
 lock_path=ROOT/'packaging/portable/windows-amd64-no-nmap.lock.json'
 lock=json.loads(lock_path.read_text());missing=[];found=[]
 for index,(mod,version,expected) in enumerate(deps):
  path=CACHE/escape(mod)/'@v'/(escape(version)+'.zip')
  if not path.exists():missing.append({'module':mod,'version':version,'h1':expected,'status':'BLOCKED_MISSING_SOURCE_AND_NOTICE'});continue
  if path.is_symlink() or not path.is_file() or path.stat().st_size>512<<20:raise SystemExit('unsafe module ZIP')
  with path.open('rb') as stream:zip_sha=hashlib.file_digest(stream,'sha256').hexdigest()
  with zipfile.ZipFile(path) as archive:
   members=archive.infolist()
   if len(members)>5000 or sum(m.file_size for m in members)>512<<20:raise SystemExit('module archive exceeds preparation bounds')
   names=[m.filename for m in members]
   if len(set(names))!=len(names) or any('\n' in n for n in names):raise SystemExit('invalid Hash1 names')
   checksum=hashlib.sha256();license_members=[]
   for member in sorted(members,key=lambda m:m.filename):
    with archive.open(member) as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    checksum.update((digest+'  '+member.filename+'\n').encode())
    basename=Path(member.filename).name.lower()
    if not member.is_dir() and any(t in basename for t in ['license','licence','copying','copyright','notice']):license_members.append((member,digest))
   actual='h1:'+base64.b64encode(checksum.digest()).decode()
   if actual!=expected:raise SystemExit('H1 mismatch: '+mod)
   if not license_members:raise SystemExit('no notice in module '+mod)
   source_id='subfaster-module-'+str(index)
   lock['sources'].append({'id':source_id,'path':str(path),'sha256':zip_sha,'archive':True,'version':version,'license':'authentic notices; module bytes verified against pinned binary build-info '+expected})
   for member,digest in license_members:
    prefix=mod+'@'+version+'/'
    if not member.filename.startswith(prefix):raise SystemExit('unexpected module archive root')
    relative=member.filename[len(prefix):]
    lock['files'].append({'path':'payload/licenses/subfaster-deps/'+mod+'@'+version+'/'+relative,'source':source_id,'member':member.filename,'sha256':digest,'size':member.file_size,'executable':False})
   found.append({'module':mod,'version':version,'h1':actual,'zip_sha256':zip_sha,'zip_path':str(path),'notices':[m.filename for m,h in license_members]})
 lock['sources'].sort(key=lambda s:s['id']);lock['files'].sort(key=lambda f:f['path'])
 name='windows-amd64-no-nmap-notices.lock.json';out=ROOT/'packaging/portable'/name
 data=(json.dumps(lock,ensure_ascii=False,indent=2)+'\n').encode()
 with out.open('xb') as stream:stream.write(data)
 report={'inventory_sha256':sha(inventory_bytes),'new_lock':name,'new_lock_sha256':sha(data),'dependencies':107,'matched_h1':len(found),'missing':missing,'available':found,'status':'PARTIAL_NOTICES; 2 dependencies BLOCKED','native_subfaster_execution':'NOT_RUN','external_network':'NOT_USED'}
 with (evidence/'subfaster-notices.json').open('x') as stream:stream.write(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'found':len(found),'missing':missing,'files':len(lock['files']),'sources':len(lock['sources']),'lock':str(out)}))
if __name__=='__main__':main()
