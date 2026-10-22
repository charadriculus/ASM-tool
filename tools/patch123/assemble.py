#!/usr/bin/env python3
"""Developer-only deterministic 0.12.3 composition. Never executes native payload or old GUI.
Consumes verified build-approved.py output. Only fresh output directories are accepted.
"""
import argparse, hashlib, importlib.util, json, re, shutil, stat, subprocess, zipfile
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
ROOT=Path(__file__).resolve().parents[2]
STAMP=(1980,1,1,0,0,0)
LINUX='ASM_Tool_0.12.3-linux-x86_64.zip'
WINDOWS='ASM_Tool_0.12.3-windows-x64-CLI-GUI-BUILD-BLOCKED.zip'
KIT='ASM_Tool_0.12.3-Windows-GUI-build-kit.zip'
SOURCE='ASM_Tool_0.12.3-source.zip'
COMBINED='ASM_Tool_0.12.3-preparation-Linux-Windows.zip'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def digest(b):return hashlib.sha256(b).hexdigest()
def require(test,msg):
 if not test:raise ValueError(msg)
def safe_name(s):
 p=PurePosixPath(s)
 return bool(s) and not p.is_absolute() and '\\' not in s and ':' not in s and all(x not in ('','.','..') for x in s.split('/'))
def file_bytes(value):
 if isinstance(value,bytes):return value
 if isinstance(value,Path):return value.read_bytes()
 z,m=value;return z.read(m)
def item_hash(value):
 if isinstance(value,Path):return sha(value)
 return digest(file_bytes(value))
def write_zip(dest,entries,executable=()):
 require(not dest.exists(),'output exists: '+str(dest))
 require(len(entries)==len({s.lower() for s in entries}),'case collision')
 for name in entries:require(safe_name(name),'unsafe ZIP member: '+name)
 with dest.open('xb') as f,zipfile.ZipFile(f,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
  for name,value in sorted(entries.items()):
   mode=0o755 if name in executable else 0o644
   h=zipfile.ZipInfo(name,STAMP);h.create_system=3;h.external_attr=(stat.S_IFREG|mode)<<16
   # Already-compressed archives need no recompression. All timestamps are fixed.
   h.compress_type=zipfile.ZIP_STORED if name.endswith(('.zip','.crate','.gz','.xz')) else zipfile.ZIP_DEFLATED
   with z.open(h,'w',force_zip64=True) as target:
    if isinstance(value,Path):
     with value.open('rb') as incoming:shutil.copyfileobj(incoming,target,1024*1024)
    elif isinstance(value,bytes):target.write(value)
    else:
     source,member=value
     with source.open(member) as incoming:shutil.copyfileobj(incoming,target,1024*1024)
def closed_entries(entries):
 require('SHA256SUMS' not in entries,'self-referential sums')
 return entries|{'SHA256SUMS':''.join(item_hash(v)+'  '+k+'\n' for k,v in sorted(entries.items())).encode()}
def verify_zip(path):
 with zipfile.ZipFile(path) as z:
  names=z.namelist();require(len(names)==len(set(n.lower() for n in names)),'duplicate ZIP member')
  require(all(safe_name(n) for n in names),'unsafe ZIP member')
  require(all(stat.S_ISREG(i.external_attr>>16) for i in z.infolist()),'nonregular ZIP member')
  require(z.testzip() is None,'CRC failure')
  expected={}
  for line in z.read('SHA256SUMS').decode('utf-8').splitlines():
   h,n=line.split('  ',1);require(safe_name(n) and n not in expected and len(h)==64 and all(c in '0123456789abcdef' for c in h),'invalid sums line')
   expected[n]=h
  require(set(names)==set(expected)|{'SHA256SUMS'},'unmanifested ZIP content')
  for n,h in expected.items():
   with z.open(n) as f:require(hashlib.file_digest(f,'sha256').hexdigest()==h,'hash mismatch: '+n)
  return {'files':len(names),'bytes':path.stat().st_size,'sha256':sha(path),'crc':'PASS','closed_inventory_sha256':'PASS'}
def distribution_docs(payload_prefix=''):
 entries={}
 for p in (ROOT/'docs/patch123').rglob('*'):
  if not p.is_file():continue
  name=str(p.relative_to(ROOT));value=p.read_bytes()
  if p.suffix=='.md':
   value=value.decode().replace('(../../licenses/patch123/','(../../'+payload_prefix+'payload/licenses/patch123/').encode()
  entries[name]=value
 text=(ROOT/'docs/patch123/README_RU.md').read_text()
 text=re.sub(r'\]\(([A-Za-z_0-9.-]+\.md)\)',r'](docs/patch123/\1)',text)
 text+='\nЛицензионные пути в отчётах и SPDX-матрице относятся к исходному дереву Source ZIP; для соответствия portable-путям используйте LICENSE_PAYLOAD_MAPPING.json. Источники из CORPUS.SHA256SUMS относятся ко всему исходному корпусу, а не к отдельной платформе.\n'
 entries['README_RU.md']=text.encode()
 return entries
def combined_docs():
 # The wrapper contains platform ZIPs, not an extracted payload tree.
 entries=distribution_docs()
 for name,value in entries.items():
  if not name.endswith('.md'):continue
  text=value.decode()
  text,count=re.subn(r'\]\(../../payload/licenses/patch123/[^)]+\)','](../../'+SOURCE+')',text)
  if count:text+='\nВ объединённом комплекте ссылки на индексы лицензий ведут к Source ZIP. Распакуйте его и откройте исходный индекс по указанному в документе пути licenses/patch123/.\n'
  entries[name]=text.encode()
 return entries

def source_files():
 prefixes=['cmd','internal','assets','testdata','ui/windows','tools/patch123','tools/portablepayload','tools/portable_rc','packaging/portable','docs/patch123','licenses/patch123','planning/patch123']
 paths={ROOT/'LICENSE',ROOT/'go.mod',ROOT/'go.sum',ROOT/'AGENTS.md',ROOT/'planning/CODEX_ENTRY.md'}
 for prefix in prefixes:
  for p in (ROOT/prefix).rglob('*'):
   if not p.is_file() or '__pycache__' in p.parts or p.suffix in ('.pyc','.exe','.dll','.so','.dylib','.test') or any(x in ('bin','obj','.vs','.toolchain') for x in p.relative_to(ROOT/prefix).parts):continue
   require(not p.is_symlink(),'source symlink')
   paths.add(p)
 return {str(p.relative_to(ROOT)):p for p in sorted(paths)}
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--build-root',required=True);ap.add_argument('--output',required=True);ap.add_argument('--source-commit',required=True);args=ap.parse_args()
 b=Path(args.build_root).resolve();out=Path(args.output).absolute();out.mkdir(mode=0o700)
 require(subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==args.source_commit,'source commit mismatch')
 summary=json.loads((b/'evidence/summary.json').read_text());require(summary['source_before']==summary['source_after'],'build source drift')
 for name,h in summary['source_after'].items():require(sha(ROOT/name)==h,'source drift after build '+name)
 for record in (b/'evidence').glob('*.json'):
  d=json.loads(record.read_text())
  if 'exit_code' in d:require(d['exit_code']==0 and not d['timeout'] and sha(record.with_suffix('.log'))==d['log_sha256'],'failed/altered build evidence')
 # Reuse the existing strict platform/anchor inspection, without executing its main().
 sp=importlib.util.spec_from_file_location('existing_inspector',ROOT/'tools/portable_rc/assemble-patch122.py');old=importlib.util.module_from_spec(sp);sp.loader.exec_module(old)
 info={'version':'0.12.3-go','base_commit':'1476e6f0bed747f1080b0e12c6eb65f979c7328f','source_commit':args.source_commit,'go_sdk':summary['go_sdk'],'platforms':{},'gates':{'linux_cli_preparation':'PREPARED_NOT_NATIVE_QUALIFIED','windows_cli_preparation':'PREPARED_CROSS_COMPILED','windows_gui':'BLOCKED_NO_WINDOWS_BUILDER','development_owner_trial':'PARTIAL_WINDOWS_GUI_BUILD_AND_RUNTIME_NOT_RUN','public_redistribution':'NOT_CONFIRMED'},'status':{'csharp_release_x64':'NOT_RUN','gui_runtime':'NOT_RUN','windows10_native':'NOT_RUN','windows11_native':'NOT_RUN','browser':'RESTORED_OWNER_TRIALS_NOT_SECURITY_QUALIFIED','candidate31':'FAIL','historical_linux_network':'FAIL','windows_strict_network':'NOT_RUN','subfaster_startup_udp':'UNRESOLVED','linux_worker_authenticity':'AUTHENTICITY_NOT_VERIFIED','copyright_holder':'UNCONFIRMED','crt_redistribution':'LICENSING_NOT_CLEARED','rust_actual_binary_closure':'UNKNOWN'},'no_release':True}
 for result in summary['results']:
  a,repeat=result['builds'];require(all(a[k]==repeat[k] for k in ['archive_sha256','application_sha256','bundle_sha256','provenance_sha256']),'double build differs')
  for row in (a,repeat):
   p=Path(row['archive']).resolve();require(p.is_relative_to(b) and sha(p)==row['archive_sha256'],'input archive hash/root mismatch');old.inspect_zip(p,result['platform'],row)
  info['platforms'][result['platform']]={k:a[k] for k in ['application_sha256','bundle_sha256','provenance_sha256','lock_sha256']}
  info['platforms'][result['platform']]['reproducibility']='PASS_TWO_LOCAL_CLI_BUILDS'
 info_bytes=(json.dumps(info,ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode()
 common=distribution_docs()|{'LICENSE':ROOT/'LICENSE','BUILD_INFO.json':info_bytes,'config.example.yml':ROOT/'assets/examples/config.example.yml','LICENSE_PAYLOAD_MAPPING.json':ROOT/'planning/patch123/evidence/LICENSE_PAYLOAD_MAPPING.json'}
 inventory={}
 with ExitStack() as stack:
  for result in summary['results']:
   a=result['builds'][0];z=stack.enter_context(zipfile.ZipFile(a['archive']));entries={m.filename:(z,m) for m in z.infolist()};require(not set(entries)&set(common),'root composition collision')
   entries|=common;name=WINDOWS if result['platform'].startswith('windows') else LINUX
   executable={m.filename for m in z.infolist() if m.external_attr>>16&0o111}
   # No native tool/hash changes are allowed during composition.
   write_zip(out/name,closed_entries(entries),executable)
   inventory[name]=verify_zip(out/name)
  source_entries=source_files()|{'BUILD_INFO.json':info_bytes}
  write_zip(out/SOURCE,closed_entries(source_entries));inventory[SOURCE]=verify_zip(out/SOURCE)
  kit={str(p.relative_to(ROOT)):p for p in (ROOT/'ui/windows').rglob('*') if p.is_file() and '__pycache__' not in p.parts}
  windows_archive=stack.enter_context(zipfile.ZipFile(out/WINDOWS))
  kit|={key:value for key,value in common.items() if not key.startswith('docs/') and key!='README_RU.md'}
  kit|=distribution_docs('GoBundle/')|{'GoBundle/'+m.filename:(windows_archive,m) for m in windows_archive.infolist()}
  kit['WINDOWS_BUILD_STEPS.md']=ROOT/'docs/patch123/WINDOWS_BUILD_STEPS.md'
  write_zip(out/KIT,closed_entries(kit));inventory[KIT]=verify_zip(out/KIT)
  combined=common|combined_docs()|{LINUX:out/LINUX,KIT:out/KIT,SOURCE:out/SOURCE}
  write_zip(out/COMBINED,closed_entries(combined));inventory[COMBINED]=verify_zip(out/COMBINED)
  # Second composition checks exact ZIP reproducibility, not just input equality.
  repeat=b/(out.name+'-composition-repeat.zip');write_zip(repeat,closed_entries(combined));require(sha(repeat)==sha(out/COMBINED),'composition reproducibility failure')
  inventory[COMBINED]['reproducibility']='PASS_TWO_LOCAL_ASSEMBLIES'
 (out/'BUILD_INFO.json').write_bytes(info_bytes)
 (out/'SHA256SUMS').write_text(''.join(v['sha256']+'  '+n+'\n' for n,v in sorted(inventory.items())))
 (out/'README_RU.md').write_bytes(common['README_RU.md'])
 report={'archives':inventory,'build_command_count':summary['command_count'],'source_product_unchanged_since_build':True,'payload_execution':'NOT_RUN','windows_gui':'BLOCKED_NO_WINDOWS_BUILDER','gates':info['gates']}
 (b/'evidence/patch123-archive-inspection.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps(report,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
