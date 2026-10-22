#!/usr/bin/env python3
"""Read existing approved inputs; create explicit preparation locks, no execution/downloads.
Absolute source paths describe this machine. Review this script and its inputs before use.
"""
import hashlib, json, re, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
AUDIT=Path('/home/charadriculus/Projects/asm_tool/asm-tool-0113-audit')
ZIP=AUDIT/'asm_tool_0.11.3-win64/dist/ASM_Tool_0.11.3-win64-development.zip'
ZIP_SHA='c45b1218ca200ae9bd13a0aa7bc507403b3635e79b0418178f6a9454d731b99c'
PREFIX='ASM_Tool_0.11.3-win64-development/'
FONTS={'DejaVuSans.ttf':'b4c632e3cdf9acc7f28758fb5a323c8524d7fc6660d46904d9b6cbe2809c419c','DejaVuSans-Bold.ttf':'e1d733afbbfce842a1b43dced0c9885a76a4e67290dc7e690c4e9b76ebfc7d23','DejaVuSans-Oblique.ttf':'e6bb3d31b3afd8070753da4bac76ac6f97d99743d0bf070d7fe01336a1f1ae42','DejaVuSans-BoldOblique.ttf':'db536b2436d5823489aec205adfaee70629633dbe6c5c2d135ac6934e522e905'}
def sha(data):return hashlib.sha256(data).hexdigest()
def file_sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,obj):
 data=(json.dumps(obj,ensure_ascii=False,indent=2)+'\n').encode()
 if p.exists() and p.read_bytes()!=data:raise SystemExit('refuse to replace changed lock: '+str(p))
 p.write_bytes(data)
def main():
 if file_sha(ZIP)!=ZIP_SHA:raise SystemExit('original Windows development ZIP digest mismatch')
 z=zipfile.ZipFile(ZIP)
 manifest_bytes=z.read(PREFIX+'WINDOWS_MANIFEST.sha256')
 pins={}
 for line in manifest_bytes.decode().splitlines():
  parts=line.split(None,1)
  if len(parts)==2 and len(parts[0])==64:pins[parts[1].lstrip('*')]=parts[0].lower()
 # The original archive digest is independently pinned; every selected member must also match its embedded per-file manifest.
 def member(rel):
  b=z.read(PREFIX+rel)
  if pins.get(rel)!=sha(b):raise SystemExit('manifest member mismatch: '+rel)
  return b
 absent_modules=[]
 locks={p:{'schema_version':1,'platform':p,'sources':[],'files':[],'tools':[]} for p in ['linux/amd64','windows/amd64']}
 for lock in locks.values():lock['sources'].append({'id':'windows-development-archive','path':str(ZIP),'sha256':ZIP_SHA,'archive':True,'version':'0.11.3-win64 development NOT_ACCEPTED','license':'per-member licenses; CRT redistribution LICENSE_REVIEW_REQUIRED'})
 def zip_file(lock,rel,dest,exe=False):
  b=member(rel);lock['files'].append({'path':'payload/'+dest,'source':'windows-development-archive','member':PREFIX+rel,'sha256':sha(b),'size':len(b),'executable':exe})
 def source_file(lock,id,p,dest,version,license,expected=None,exe=False):
  b=p.read_bytes();digest=sha(b)
  if expected and digest!=expected:raise SystemExit('source digest mismatch: '+str(p))
  lock['sources'].append({'id':id,'path':str(p),'sha256':digest,'archive':False,'version':version,'license':license})
  lock['files'].append({'path':'payload/'+dest,'source':id,'sha256':digest,'size':len(b),'executable':exe})
 linux=locks['linux/amd64'];windows=locks['windows/amd64']
 source_file(linux,'linux-typst',AUDIT/'asm_tool_0113/.tools/bin/typst','bin/typst','0.15.1 (accepted replay pin)','Apache-2.0','29273eaa04f6d00edd0c2bec578f565fc9c65be856bfbffc894567c68ed0b237',True)
 for name,pin in FONTS.items():
  source_file(linux,'font-'+name.replace('.','-'),Path('/usr/share/fonts/truetype/dejavu')/name,'fonts/dejavu/'+name,'DejaVu 2.37','Bitstream Vera/DejaVu font license',pin)
  zip_file(windows,'fonts/'+name,'fonts/dejavu/'+name)
 for lock in locks.values():
  for rel,dest in [('licenses/typst/LICENSE','licenses/typst/LICENSE'),('licenses/typst/NOTICE','licenses/typst/NOTICE'),('licenses/fonts/copyright','licenses/fonts/copyright')]:zip_file(lock,rel,dest)
 zip_file(windows,'.tools/bin/typst.exe','bin/typst.exe',True)
 zip_file(windows,'.tools/bin/subfaster.exe','bin/subfaster.exe',True)
 zip_file(windows,'runtime/vcruntime140.dll','bin/vcruntime140.dll')
 zip_file(windows,'licenses/subfaster/LICENSE.md','licenses/subfaster/LICENSE.md')
 # Preserve authentic archive notices as license evidence; absence of an explicit CRT grant remains a blocker.
 zip_file(windows,'WINDOWS_LICENSE_MANIFEST.json','licenses/windows-development-license-manifest.json')
 windows['tools'].append({'name':'subfaster','executable':'payload/bin/subfaster.exe','version':'2.18.0','usage':'qualification-only','capabilities':['passive JSONL -d/-s/-oJ/-cs; native probe NOT_RUN'],'license':'MIT; transitive module notices completeness PENDING','dependencies':['x64 Kernel32 OS import; CGO disabled historical build metadata']})
 for platform,lock in locks.items():
  source_file(lock,'go-sdk-license',Path('/home/charadriculus/opt/go1.26.6/LICENSE'),'licenses/go/stdlib-LICENSE','go1.26.6','BSD-3-Clause')
  lock['tools'].append({'name':'typst','executable':'payload/bin/typst'+('.exe' if platform.startswith('windows') else ''),'version':'0.15.1','usage':'qualification-only','capabilities':['offline PDF; native integrated execution NOT_RUN'],'license':'Apache-2.0 (LICENSE and NOTICE included)','dependencies':['VCRUNTIME140.dll x64; OS UCRT/API sets, native minimum OS NOT_RUN'] if platform.startswith('windows') else ['static PIE ELF x86-64, no DT_NEEDED']})
  # Current application's module notices from the existing worktree cache. Root dependency locks remain unchanged.
  for mod,ver in re.findall(r'^\s*([^\s()]+)\s+(v[^\s]+)',(ROOT/'go.mod').read_text(),re.M):
   src=ROOT/'tmp/integration-6-8/modcache'/f'{mod}@{ver}'
   if not src.is_dir():
    absent_modules.append(mod+'@'+ver);continue
   notices=[p for p in src.iterdir() if p.is_file() and any(x in p.name.lower() for x in ['license','copying','copyright','notice'])]
   if not notices:raise SystemExit('module license missing: '+mod)
   for i,p in enumerate(sorted(notices)):
    source_file(lock,'module-'+mod.replace('/','-').replace('.','-')+'-'+str(i),p,'licenses/go/'+mod+'@'+ver+'/'+p.name,ver,'authentic module notice; final legal review PENDING')
  lock['files'].sort(key=lambda x:x['path']);lock['sources'].sort(key=lambda x:x['id']);lock['tools'].sort(key=lambda x:x['name'])
  save(ROOT/'packaging/portable'/('linux-amd64-report-only.lock.json' if platform.startswith('linux') else 'windows-amd64-no-nmap.lock.json'),lock)
 save(ROOT/'planning/progress/portable-payload-evidence/selected-inputs.json',{'windows_source_zip':{'path':str(ZIP),'sha256':ZIP_SHA,'status':'NOT_ACCEPTED development source'},'windows_embedded_manifest_sha256':sha(manifest_bytes),'excluded':{'linux_subfaster':'current pin differs from accepted replay; source rebuild or explicit pin approval required','linux_nmap':'no trusted portable input; system ELF dependencies not packaged','windows_nmap':'7.991 x86 not authorized for x64 bundle','browser':'production security BLOCKED; candidate31 FAIL','httpx':'native HTTPX1.8.1 BLOCKED'},'declared_modules_without_local_notices':sorted(set(absent_modules)),'locks':{p:sha((json.dumps(lock,ensure_ascii=False,indent=2)+'\n').encode()) for p,lock in locks.items()}})
 print(json.dumps({p:{'files':len(v['files']),'sources':len(v['sources'])} for p,v in locks.items()}))
if __name__=='__main__':main()
