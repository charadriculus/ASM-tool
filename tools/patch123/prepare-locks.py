#!/usr/bin/env python3
"""Developer-only composition of existing payload locks and recorded license/source inputs.
Does not execute payload binaries. Existing locks are immutable; new locks must be absent.
"""
import hashlib, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 report={}
 for plat in ['linux','windows']:
  original=ROOT/f'packaging/portable/{plat}-amd64-patch122.lock.json'
  lock=json.loads(original.read_text());mapping=[]
  # This historical aggregate mentions components no longer distributed. Original notices remain.
  lock['files']=[f for f in lock['files'] if f['path']!='payload/licenses/windows-development-license-manifest.json']
  bypath={f['path']:f for f in lock['files']}
  files=[p for p in (ROOT/'licenses/patch123').rglob('*') if p.is_file()]
  files.append(ROOT/'LICENSE')
  for p in sorted(files):
   if p.is_symlink():raise ValueError('linked input')
   rel=str(p.relative_to(ROOT));dest='payload/'+rel;distribute=True
   if rel.startswith('licenses/patch123/microsoft/') and plat!='windows':distribute=False
   if rel.startswith('licenses/patch123/go-runtime/linux-runtime/') and plat!='linux':distribute=False
   if rel.startswith('licenses/patch123/go-runtime/subfaster/linux/') and plat!='linux':distribute=False
   if rel.startswith('licenses/patch123/go-runtime/subfaster/windows/') and plat!='windows':distribute=False
   if rel=='LICENSE':dest='payload/licenses/asm-tool/LICENSE'
   prefix='licenses/patch123/go-runtime/subfaster/common/'
   if rel.startswith(prefix):dest='payload/licenses/subfaster-deps/'+rel.removeprefix(prefix)
   if rel=='licenses/patch123/go-runtime/subfaster/LICENSE.md':dest='payload/licenses/subfaster/LICENSE.md'
   if rel in ['licenses/patch123/rust/typst/LICENSE','licenses/patch123/rust/typst/NOTICE']:
    dest='payload/licenses/typst/'+p.name
   digest=sha(p)
   row={'input':rel,'sha256':digest,'payload_path':dest if distribute else None,'status':'INCLUDED' if distribute else 'OTHER_PLATFORM_SOURCE_RECORD_ONLY'}
   mapping.append(row)
   if not distribute:continue
   if dest in bypath:
    if bypath[dest]['sha256']!=digest:raise ValueError('notice collision: '+dest)
    row['status']='REUSED_IDENTICAL_EXISTING_NOTICE';continue
   identity='patch123-'+hashlib.sha256(rel.encode()).hexdigest()[:20]
   lock['sources'].append({'id':identity,'path':'../../'+rel,'sha256':digest,'archive':False,'version':'0.12.3 license corpus; exact upstream versions in original metadata','license':'Original unmodified notices/source; terms and known gaps in docs/patch123'})
   f={'path':dest,'source':identity,'sha256':digest,'size':p.stat().st_size,'executable':False};lock['files'].append(f);bypath[dest]=f
  used={f['source'] for f in lock['files']};lock['sources']=[s for s in lock['sources'] if s['id'] in used]
  for tool in lock['tools']:
   tool['license']='Original notices/source and applicability limits: docs/patch123; public redistribution NOT_CONFIRMED'
   if plat=='linux' and tool['name'] in ['obscura','obscura-worker']:
    tool['dependencies']=['Direct host ABI; bundled Subfaster loader does not apply; native compatibility NOT_RUN']
  total=sum(f['size'] for f in lock['files'])
  assert total<=512*1024*1024 and len(lock['files'])<=5000
  out=ROOT/f'packaging/portable/{plat}-amd64-patch123.lock.json'
  with out.open('x') as f:json.dump(lock,f,ensure_ascii=False,indent=2);f.write('\n')
  report[plat]={'base_lock_sha256':sha(original),'new_lock_sha256':sha(out),'files':len(lock['files']),'payload_bytes':total,'mapping':mapping}
 out=ROOT/'planning/patch123/evidence/LICENSE_PAYLOAD_MAPPING.json'
 with out.open('x') as f:json.dump(report,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps({k:{f:v for f,v in row.items() if f!='mapping'} for k,row in report.items()},indent=2))
if __name__=='__main__':main()
