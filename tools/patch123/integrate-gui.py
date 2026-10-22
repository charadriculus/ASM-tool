#!/usr/bin/env python3
"""Integrate the owner's already-built GUI. No compiler, native tool or network is run.
Uses the reviewed deterministic ZIP helpers; previous candidates are read-only inputs.
"""
import argparse, hashlib, importlib.util, json, re, stat, struct
from contextlib import ExitStack
from pathlib import Path
sp=importlib.util.spec_from_file_location('previous_composition',Path(__file__).with_name('assemble.py'))
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
ROOT=m.ROOT
PREP=ROOT/'dist/ASM_Tool_0.12.3-preparation-20261021-02'
GUIROOT=ROOT/'dist/ASM_Tool_0.12.3_GUI_win-x64'
GUIZIP=PREP/'ASM_Tool_0.12.3_GUI_win-x64.zip'
GUI_SHA='0961a89a1254ee2f3e86b39584d5044d3ffc39b701a18d33feeefcf633bd1675'
INPUTS={'linux':('ASM_Tool_0.12.3-linux-x86_64.zip','0ba329c844ccaaa10acf9cd9cf872821be3e8bb744f17622c0afb804db0f304a'), 'windows':('ASM_Tool_0.12.3-windows-x64-CLI-GUI-BUILD-BLOCKED.zip','a17a413e92743ad7aba3810a73f2ab217ef84aea3aa8675adde01f02a1da9e1c')}
WINDOWS='ASM_Tool_0.12.3-windows-x64.zip'
LINUX=INPUTS['linux'][0]
COMBINED='ASM_Tool_0.12.3-Linux-Windows.zip'
def encoded(d):return (json.dumps(d,ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode()
def require(ok,why):m.require(ok,why)
def filehash(z,member):
 with z.open(member) as f:return hashlib.file_digest(f,'sha256').hexdigest()
def canonical_gui_path(name):
 name=name.replace('\\','/')
 require(m.safe_name(name) and all(ord(c)>=32 for c in name),'unsafe GUI path '+name)
 for segment in name.split('/'):
  require(not re.search(r'[<>"|?*]',segment) and not segment.endswith((' ','.')),'unsafe Windows path '+name)
  require(not re.fullmatch(r'(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?',segment,re.I),'reserved Windows name '+name)
 return name
def pe_summary(data):
 require(data[:2]==b'MZ' and len(data)>=64,'not PE')
 offset=struct.unpack_from('<I',data,60)[0];require(offset+24<=len(data) and data[offset:offset+4]==b'PE\0\0','invalid PE')
 result={'machine':hex(struct.unpack_from('<H',data,offset+4)[0])}
 marker=data.find(b'\xbd\x04\xef\xfe')
 if marker>=0 and marker+16<=len(data):
  _,_,a,b=struct.unpack_from('<4I',data,marker);result['file_version']='.'.join(map(str,[a>>16,a&65535,b>>16,b&65535]))
 return result

def inspect_gui(z):
 report=json.loads((PREP/'GUI_BUILD_REPORT.json').read_text(encoding='utf-8-sig'))
 require(report['archive_sha256']==GUI_SHA and report['status']=='BUILD_PASS' and report['version']=='0.12.3' and report['target']=='win-x64','handoff metadata mismatch')
 require((PREP/'GUI_SHA256SUMS').read_text().strip()==GUI_SHA+'  '+GUIZIP.name,'GUI handoff checksum mismatch')
 members=z.infolist();require(0<len(members)<=5000 and sum(x.file_size for x in members)<=512<<20,'GUI input exceeds bounds')
 entries={};hashes={};original_names={}
 for i in members:
  require(not i.is_dir(),'unexpected directory member')
  name=canonical_gui_path(i.filename);kind=stat.S_IFMT(i.external_attr>>16)
  require(kind in (0,stat.S_IFREG),'nonregular GUI member')
  require(i.file_size<=128<<20 and not i.flag_bits&1,'oversized/encrypted GUI member')
  require(name.casefold() not in {n.casefold() for n in entries},'duplicate/case-colliding GUI path')
  entries[name]=(z,i);hashes[name]=filehash(z,i);original_names[name]=i.filename # also checks CRC
 require(GUIROOT.is_dir() and not GUIROOT.is_symlink(),'GUI directory missing/linked')
 disk={}
 for p in GUIROOT.rglob('*'):
  require(not p.is_symlink(),'GUI directory contains symlink')
  if p.is_file():
   name=canonical_gui_path(str(p.relative_to(GUIROOT)))
   require(name.casefold() not in {n.casefold() for n in disk},'directory case/canonical path collision')
   disk[name]=m.sha(p)
  else:require(p.is_dir(),'nonregular GUI directory entry')
 require(disk==hashes,'transferred GUI directory differs from ZIP')
 required=['ASMTool.exe','ASMTool.dll','ASMTool.deps.json','ASMTool.runtimeconfig.json','App.xbf','MainWindow.xbf','ASMTool.pri','coreclr.dll','hostfxr.dll','hostpolicy.dll','System.Private.CoreLib.dll','Microsoft.ui.xaml.dll','DirectML.dll','onnxruntime.dll','onnxruntime_providers_shared.dll','WebView2Loader.dll']
 require(all(name in entries and z.getinfo(name).file_size>0 for name in required),'required GUI runtime/resource missing')
 exe=pe_summary(z.read('ASMTool.exe'));dll=pe_summary(z.read('ASMTool.dll'))
 require(exe['machine']=='0x8664' and exe.get('file_version')=='0.12.3.0' and dll.get('file_version')=='0.12.3.0','wrong GUI architecture/version')
 deps=json.loads(z.read('ASMTool.deps.json'));runtime=json.loads(z.read('ASMTool.runtimeconfig.json'))
 require(deps['runtimeTarget']['name'].endswith('/win-x64') and 'ASMTool/0.12.3' in deps['libraries'],'wrong GUI deps target')
 require(runtime['runtimeOptions'].get('includedFrameworks')==[{'name':'Microsoft.NETCore.App','version':'10.0.13'}],'unexpected bundled framework')
 asset_count=0
 for lib,row in deps['targets'][deps['runtimeTarget']['name']].items():
  for kind in ('runtime','native','resources'):
   for asset in row.get(kind,{}):
    if asset.endswith('/_._'):continue
    target='/'.join(asset.split('/')[-2:]) if kind=='resources' else Path(asset).name
    require(target in entries,'missing deps asset '+lib+': '+asset);asset_count+=1
 inventory=json.loads((ROOT/'licenses/patch123/microsoft/PACKAGE_INVENTORY.json').read_text())
 known={a['package'].casefold():a['version'] for a in inventory['records']};package_rows=[]
 for name,data in deps['libraries'].items():
  package,version=name.rsplit('/',1);key=package.removeprefix('runtimepack.').casefold()
  if key in known:
   require(known[key]==version,'unexpected existing package version '+name)
   status='EXACT_VERSION_MATCH_EXISTING_NOTICE_INPUT'
  else:status='APP_OR_DERIVED_PROJECTION_ASSEMBLY_NOT_SEPARATE_NUGET_CLAIM'
  package_rows.append({'name':package,'version':version,'type':data.get('type'),'notice_mapping':status})
 return entries,{'gui_zip_sha256':GUI_SHA,'gui_files':hashes,'archive_member_names':original_names,'gui_file_count':len(hashes),'uncompressed_bytes':sum(i.file_size for i in members),'directory_matches_zip':True,'crc_all_members':'PASS','required_runtime_resources':'PRESENT','deps_asset_count':asset_count,'deps_assets':'ALL_PRESENT','pe':{'ASMTool.exe':exe,'ASMTool.dll':dll},'runtime_options':runtime,'actual_deps_libraries':package_rows,'owner_build_report':report,'windows_build_exit_code':'NOT_RECORDED_IN_HANDOFF','source_archive_digest':report['source_sha256'],'source_archive_match':'NOT_VERIFIED_TRANSFER_SOURCE_ARCHIVE_NOT_PROVIDED','gui_runtime':'NOT_RUN','csharp_tests':'NOT_RUN','publisher_signature':'NOT_VERIFIED'}

README='''# ASM Tool 0.12.3 — Linux и Windows portable candidate

В Windows-комплекте запускайте ASMTool.exe для GUI или asm-tool.exe для CLI. В Linux — ./asm-tool; существующий интерактивный построчный режим сохранён. Не перемещайте executable отдельно от payload и runtime-файлов.

GUI получен готовым после Windows10 build (.NET SDK10.0.402), не пересобирался. Bundled runtime10.0.13 и WinUI ресурсы включены; структура не требует пользовательской установки Go/Python/Node/.NET SDK/WSL. GUI startup/Windows10 и Windows11 runtime, unit/integration/UIAutomation и cleanup здесь NOT_RUN: сборка и упаковка не доказывают работоспособность на чистой ОС.

Перед распаковкой сверяйте SHA-256 архива с внешним списком. SHA256SUMS внутри каждого платформенного каталога перечисляет все его файлы кроме себя. В Windows PowerShell можно читать строки вида `<hash>  <relative path>` и сравнивать Get-FileHash -Algorithm SHA256; на Linux используйте sha256sum -c SHA256SUMS. Это integrity checks, не подпись издателя. Для GUI-launch не требуется PowerShell.

GUI_BUILD_FILES.sha256 идентифицирует переданные GUI-файлы. GUI_DISTRIBUTION_MANIFEST.sha256 исключает себя и корневой SHA256SUMS; итоговый SHA256SUMS включает этот manifest. CLI payload/bundle.json, provenance и embedded anchor не изменены. Готовый GUI и CLI находятся рядом; никакие blocked backend не заменялись скрытым fallback.

Browser восстановлен для owner trials, но NOT_SECURITY_QUALIFIED. Candidate31 FAIL и исторический Linux network FAIL сохранены. Subfaster startup UDP, robots.txt и redirects ограничения не устранены. Windows strict network и Windows11 qualification NOT_RUN. Использовать только авторизованные цели; этот этап не проводил scans/native checks.

Linux Obscura сохраняет host-ABI требования; bundled Linux loader предназначен только для Subfaster. Nmap и старый Python runtime отсутствуют. Исходные лицензии/соответствующие GNU source archives сохранены. PUBLIC_REDISTRIBUTION_READY остаётся NOT_CONFIRMED: MIT holder/CRT rights/Rust-V8 closure/worker authenticity не закрываются готовой GUI-сборкой.

Актуальное состояние: GUI_INTEGRATION_REPORT.md и BUILD_INFO.json. Старые документы docs/patch123 и payload license indexes сохранены как датированные evidence предыдущей подготовки; текущий GUI inventory — GUI_RUNTIME_PROVENANCE.json (Windows). Оригинальные source/GUI/input ZIP и результаты прошлых проверок не перезаписаны. Это подготовка кандидата, не публикация release.
'''.encode()

def updated_entries(z,info,provenance):
 entries={i.filename:(z,i) for i in z.infolist() if i.filename!='SHA256SUMS'}
 # Only package-facing metadata changes; executable/payload bytes remain untouched.
 for name,value in list(entries.items()):
  if name.startswith('docs/patch123/') and name.endswith('.md'):
   header='> Обновление 2026-10-22: GUI0.12.3 получен после Windows10 BUILD_PASS; runtime/tests NOT_RUN. Ниже сохранён исторический документ подготовки 21 октября. Актуально: ../../GUI_INTEGRATION_REPORT.md и ../../BUILD_INFO.json.\n\n'
   entries[name]=header.encode()+m.file_bytes(value)
 entries['README_RU.md']=README
 entries['BUILD_INFO.json']=encoded(info)
 entries['GUI_INTEGRATION_REPORT.md']=ROOT/'docs/patch123/GUI_HANDOFF_INTEGRATION.md'
 for name in ['GUI_INTEGRATION_HANDOFF.md','GUI_BUILD_REPORT.json','GUI_dotnet-publish.log','GUI_SHA256SUMS']:
  entries['evidence/gui-build/'+name]=PREP/name
 entries['GUI_RUNTIME_PROVENANCE.json']=encoded(provenance)
 return entries

def main():
 import zipfile
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True);args=ap.parse_args()
 out=Path(args.output).absolute();require(not out.exists(),'new output directory required')
 require(m.sha(GUIZIP)==GUI_SHA,'GUI ZIP hash mismatch')
 for _,(name,h) in INPUTS.items():require(m.sha(PREP/name)==h,'accepted Go ZIP changed '+name)
 info=json.loads((PREP/'BUILD_INFO.json').read_text());old_info=json.loads(json.dumps(info))
 evidence={'commands':{'assembly':'python3 tools/patch123/integrate-gui.py --output '+args.output},'gui_executed':False,'compilers_executed':False,'old_regression_tests_repeated':False,'input_gui_sha256':GUI_SHA,'input_go_sha256':{k:v[1] for k,v in INPUTS.items()},'old_build_info_sha256':m.sha(PREP/'BUILD_INFO.json')}
 with ExitStack() as stack:
  gui_zip=stack.enter_context(zipfile.ZipFile(GUIZIP));gui,provenance=inspect_gui(gui_zip)
  info['previous_preparation_source_commit']=info['source_commit'];info['packaging_update']='GUI_HANDOFF_INTEGRATED_2026-10-22'
  info['gui_build']={'status':'BUILD_PASS_REPORTED_BY_OWNER','host':'Windows10 10.0.19045.0','dotnet_sdk':'10.0.402','runtime':provenance['runtime_options'],'archive_sha256':GUI_SHA,'source_archive_sha256_reported':provenance['source_archive_digest'],'source_archive_match':provenance['source_archive_match'],'build_exit_code':'NOT_RECORDED_IN_HANDOFF','gui_runtime':'NOT_RUN'}
  info['gates'].update(windows_gui='BUILT_AND_PACKAGED_RUNTIME_NOT_RUN',development_owner_trial='PACKAGING_COMPLETE_RUNTIME_PENDING')
  info['status']['csharp_release_x64']='BUILD_PASS_REPORTED_BY_OWNER';info['status']['gui_runtime']='NOT_RUN'
  info['packaging_tool_sha256']=m.sha(Path(__file__))
  out.mkdir(mode=0o700);result={};combined={'README_RU.md':README,'BUILD_INFO.json':encoded(info),'GUI_INTEGRATION_REPORT.md':ROOT/'docs/patch123/GUI_HANDOFF_INTEGRATION.md'}
  for platform,(name,_) in INPUTS.items():
   z=stack.enter_context(zipfile.ZipFile(PREP/name));entries=updated_entries(z,info,provenance)
   executable={i.filename for i in z.infolist() if i.external_attr>>16&0o111}
   if platform=='windows':
    require(not set(entries)&set(gui),'GUI/CLI output collision')
    entries|=gui
    entries['GUI_BUILD_FILES.sha256']=''.join(h+'  '+n+'\n' for n,h in sorted(provenance['gui_files'].items())).encode()
    entries['GUI_DISTRIBUTION_MANIFEST.sha256']=''.join(m.item_hash(v)+'  '+n+'\n' for n,v in sorted(entries.items())).encode()
   require(not any(Path(n).name.casefold() in ('nmap','nmap.exe','python.exe','pythonw.exe','bootstrap.py') for n in entries),'forbidden runtime entry')
   filename=WINDOWS if platform=='windows' else LINUX
   m.write_zip(out/filename,m.closed_entries(entries),executable);result[filename]=m.verify_zip(out/filename)
   packaged=stack.enter_context(zipfile.ZipFile(out/filename))
   app='asm-tool.exe' if platform=='windows' else 'asm-tool';pin=old_info['platforms'][platform+'/amd64']
   require(filehash(packaged,app)==pin['application_sha256'],'Go CLI changed')
   require(filehash(packaged,'payload/bundle.json')==pin['bundle_sha256'],'payload anchor changed')
   require(filehash(packaged,'payload-provenance.json')==pin['provenance_sha256'],'payload provenance changed')
   if platform=='windows':
    for n,h in provenance['gui_files'].items():require(filehash(packaged,n)==h,'GUI binary/resource changed '+n)
   prefix='windows-x64/' if platform=='windows' else 'linux-x86_64/'
   for i in packaged.infolist():combined[prefix+i.filename]=(packaged,i)
  combined_exec={'linux-x86_64/'+i.filename for i in stack.enter_context(zipfile.ZipFile(out/LINUX)).infolist() if i.external_attr>>16&0o111}
  m.write_zip(out/COMBINED,m.closed_entries(combined),combined_exec);result[COMBINED]=m.verify_zip(out/COMBINED)
  evidence.update({'exit_code':0,'input_gui':provenance,'artifacts':result,'gates':info['gates'],'native_runtime':'NOT_RUN','reproducibility':'FIXED_ZIP_METADATA_SINGLE_COMPOSITION_NO_REDUNDANT_REPEAT'})
  (out/'BUILD_INFO.json').write_bytes(encoded(info));(out/'README_RU.md').write_bytes(README)
  (out/'SHA256SUMS').write_text(''.join(row['sha256']+'  '+name+'\n' for name,row in sorted(result.items())))
  (out/'INTEGRATION_EVIDENCE.json').write_bytes(encoded(evidence))
  target=ROOT/'planning/patch123/gui-handoff-20261022/INTEGRATION_EVIDENCE.json';require(not target.exists(),'evidence already exists');target.write_bytes(encoded(evidence))
 print(json.dumps({'exit_code':0,'output':str(out),'gui_files':provenance['gui_file_count'],'deps_assets':provenance['deps_asset_count'],'artifacts':result,'gates':info['gates']},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
