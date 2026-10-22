#!/usr/bin/env python3
"""Static local binary/dependency inventory; no bundled executable is launched."""
import hashlib,json,re,struct,subprocess,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
AUDIT=Path('/home/charadriculus/Projects/asm_tool/asm-tool-0113-audit')
ZIP=AUDIT/'asm_tool_0.11.3-win64/dist/ASM_Tool_0.11.3-win64-development.zip'
PREFIX='ASM_Tool_0.11.3-win64-development/'
GO='/home/charadriculus/opt/go1.26.6/bin/go'
records=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def static_command(label,args):
 p=subprocess.run(args,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60,check=False)
 records.append({'label':label,'command':args,'exit_code':p.returncode,'output':p.stdout.decode(errors='replace')})
 if p.returncode:raise SystemExit('static command failed: '+label)
 return p.stdout.decode(errors='replace')
def elf(p):
 b=p.read_bytes();dyn=static_command(p.name+'-dynamic',['/usr/bin/readelf','-d',str(p)]);ver=static_command(p.name+'-versions',['/usr/bin/readelf','--version-info',str(p)])
 versions=set(re.findall(r'GLIBC_(\d+(?:\.\d+)*)',ver));maxv=max(versions,key=lambda x:tuple(map(int,x.split('.')))) if versions else None
 return {'path':str(p),'sha256':sha(b),'format':'ELF','machine':int.from_bytes(b[18:20],'little'),'dt_needed':re.findall(r'\(NEEDED\).*\[(.+?)\]',dyn),'highest_required_GLIBC':maxv}
def pe(b):
 off=struct.unpack_from('<I',b,0x3c)[0]
 if b[off:off+4]!=b'PE\x00\x00':raise ValueError('not PE')
 machine,count=struct.unpack_from('<HH',b,off+4);optsize=struct.unpack_from('<H',b,off+20)[0];opt=off+24;magic=struct.unpack_from('<H',b,opt)[0]
 sections=[]
 for i in range(count):
  s=opt+optsize+40*i;vsize,rva,size,raw=struct.unpack_from('<IIII',b,s+8);sections.append((rva,max(vsize,size),raw))
 def ptr(rva):
  for start,size,raw in sections:
   if start<=rva<start+size:return raw+rva-start
  raise ValueError('invalid PE RVA')
 base=opt+(112 if magic==0x20b else 96);import_rva=struct.unpack_from('<I',b,base+8)[0];imports=[]
 if import_rva:
  s=ptr(import_rva)
  for _ in range(256):
   row=struct.unpack_from('<IIIII',b,s)
   if not any(row):break
   p=ptr(row[3]);imports.append(b[p:b.index(b'\x00',p)].decode('ascii'));s+=20
  else:raise ValueError('unbounded import table')
 return {'sha256':sha(b),'size':len(b),'format':'PE32+' if magic==0x20b else 'PE32','machine':hex(machine),'imports':imports}
def main():
 zip_digest=hashlib.file_digest(ZIP.open('rb'),'sha256').hexdigest()
 if zip_digest!='c45b1218ca200ae9bd13a0aa7bc507403b3635e79b0418178f6a9454d731b99c':raise SystemExit('ZIP identity changed')
 z=zipfile.ZipFile(ZIP)
 windows={rel:pe(z.read(PREFIX+rel)) for rel in ['.tools/bin/typst.exe','.tools/bin/subfaster.exe','runtime/vcruntime140.dll','runtime/vcruntime140_1.dll','.tools/nmap/nmap.exe','.tools/nmap/vcruntime140.dll','.tools/nmap/msvcp140.dll']}
 linux={name:elf(p) for name,p in {'typst':AUDIT/'asm_tool_0113/.tools/bin/typst','subfaster':AUDIT/'asm_tool_0113/.tools/bin/subfaster','nmap':Path('/usr/bin/nmap')}.items()}
 static_command('linux-subfaster-build-info',[GO,'version','-m',str(AUDIT/'asm_tool_0113/.tools/bin/subfaster')])
 candidate=ROOT/'tmp/portable-payload-candidate-01/ASM-windows-проверка-A/payload/bin/subfaster.exe'
 static_command('windows-subfaster-build-info',[GO,'version','-m',str(candidate)])
 static_command('system-package-versions',['/usr/bin/dpkg-query','-W','nmap','nmap-common','fonts-dejavu-core','fonts-dejavu-extra'])
 nmap_provenance=AUDIT/'asm_tool_0.11.3-win64/.windows-inputs/nmap/NMAP_INPUT_PROVENANCE.json'
 installer=AUDIT/'asm_tool_0.11.3-win64/.windows-inputs/nmap/nmap-7.991-setup.exe'
 pins={str(p):hashlib.file_digest(p.open('rb'),'sha256').hexdigest() for p in [nmap_provenance,installer]}
 if pins[str(nmap_provenance)]!='3c4ebcbb3f1c7d17c5d7ddfec9d27dd889be8bdc15dd242c91cf1940b706dd70' or pins[str(installer)]!='93bfd37bdb31a7adfd932beb5dbce06025da691d01a0939e806ea704f7367657':raise SystemExit('user supplied Nmap provenance identity changed')
 actual=ROOT/'planning/progress/portable-payload-evidence/reproducible/summary.json';summary=json.loads(actual.read_text());license_check=[]
 for result in summary['results']:
  label=result['platform'].split('/')[0]+'-A';info=(actual.parent/(label+'-build-info.log')).read_text();modules=re.findall(r'^\s*dep\s+(\S+)\s+(\S+)\s+(\S+)',info,re.M)
  notices=Path(result['builds'][0]['root'])/'payload/licenses/go'
  missing=[mod+'@'+ver for mod,ver,digest in modules if not (notices/(mod+'@'+ver)).is_dir()]
  if missing:raise SystemExit('actual linked module notices missing: '+str(missing))
  license_check.append({'platform':result['platform'],'linked_modules':[{'path':m,'version':v,'go_sum':h} for m,v,h in modules],'all_linked_modules_have_local_notices':True,'final_redistribution_review':'PENDING'})
 output={'static_only':True,'native_executable_invocations':0,'linux':linux,'windows':windows,'original_windows_zip_sha256':zip_digest,'nmap_input_sha256':pins,'linked_go_module_notice_check':license_check,'commands':records,'blocked':{'linux_subfaster':'current binary is not accepted-replay identity; omitted','nmap':'Linux not portable; Windows x86 not authorized for x64 payload; both omitted','crt_redistribution':'LICENSE_REVIEW_REQUIRED','production_browser':'BLOCKED; candidate31 FAIL'}}
 out=ROOT/'planning/progress/portable-payload-evidence/static-inventory.json'
 with out.open('x') as f:f.write(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'inventory':str(out),'static_only':True,'linux':{k:{'sha256':v['sha256'],'dt_needed':v['dt_needed'],'highest_required_GLIBC':v['highest_required_GLIBC']} for k,v in linux.items()},'windows':{k:{'sha256':v['sha256'],'machine':v['machine']} for k,v in windows.items()}}))
if __name__=='__main__':main()
