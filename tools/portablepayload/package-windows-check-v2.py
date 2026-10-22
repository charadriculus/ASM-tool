#!/usr/bin/env python3
"""Package already cross-built EXEs and source-reviewed scripts; no EXE execution."""
import argparse,hashlib,json,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',required=True);p.add_argument('--summary-label',default='kit-summary');args=p.parse_args();work=Path(args.work).absolute();kit=work/'kit'
if not args.summary_label.replace('-','').isalnum():raise SystemExit('unsafe summary label')
summary_path=ROOT/('planning/progress/windows-check-kit-v2-evidence/'+args.summary_label+'.json')
if summary_path.exists():raise SystemExit('refusing existing evidence')
expected_inputs={'approved-windows-native.test.exe','windows-local-check-v2.ps1','windows10-preflight-v2.ps1'}
if {q.name for q in kit.iterdir()}!=expected_inputs:raise SystemExit('use a fresh kit with exactly the three approved input files')
a=work/'windows-A.test.exe';b=work/'windows-B.test.exe'
if sha(a)!=sha(b):raise SystemExit('cross-build reproducibility mismatch')
if sha(kit/'approved-windows-native.test.exe')!=sha(a):raise SystemExit('kit EXE differs')
(kit/'README.md').write_bytes((ROOT/'planning/progress/windows-check-kit-v2-handoff.md').read_bytes())
files={q.name:sha(q) for q in sorted(kit.iterdir()) if q.is_file()}
manifest={'kit_version':2,'scope':'Windows10 local functional trial; Windows11 separate NOT_RUN','files':files,'test_exe_sha256':sha(a),'harness_source_sha256':sha(ROOT/'internal/app/native_portable_qualification_test.go'),'subfaster_runtime':'NOT_RUN_MANIFEST_ONLY','bundle_anchor':'c26c75208ddd40f3999abbeef4591a0ac6c7f1953a983e396d02895a7f4db479','portable_application_sha256':'4e5f35efc9f6dec065a655570ab9c61926e7063a2736365e75078b5483b811e1','native_execution':'NOT_RUN','linux_network_gate':'FAIL_PRESERVED','browser':'BLOCKED_candidate31_FAIL'}
(kit/'MANIFEST.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
(kit/'SHA256SUMS').write_text(''.join(sha(q)+'  '+q.name+'\n' for q in sorted(kit.iterdir()) if q.is_file() and q.name!='SHA256SUMS'))
archives=[]
for name in ['windows-local-check-v2.zip','windows-local-check-v2-repeat.zip']:
 archive=work/name
 with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for q in sorted(kit.iterdir()):
   i=zipfile.ZipInfo(q.name,date_time=(1980,1,1,0,0,0));i.create_system=3;i.external_attr=0o100644<<16;i.compress_type=zipfile.ZIP_DEFLATED;z.writestr(i,q.read_bytes(),compresslevel=9)
 with zipfile.ZipFile(archive) as z:
  if z.testzip() is not None:raise SystemExit('bad ZIP CRC')
  for q in kit.iterdir():
   if hashlib.sha256(z.read(q.name)).hexdigest()!=sha(q):raise SystemExit('ZIP entry mismatch')
 archives.append({'path':str(archive),'sha256':sha(archive),'bytes':archive.stat().st_size})
if archives[0]['sha256']!=archives[1]['sha256']:raise SystemExit('ZIP reproducibility mismatch')
portable=ROOT/'tmp/approved-portable-candidate-03/windows-A-preparation.zip';expected='2de7dc0477d454f01029d702f4d5215c45cffa061a13ad55dbc070c91855c907'
if sha(portable)!=expected:raise SystemExit('old portable ZIP changed')
(work/'TRANSFER_SHA256SUMS').write_text(expected+'  windows-A-preparation.zip\n'+archives[0]['sha256']+'  windows-local-check-v2.zip\n')
summary={'archives':archives,'test_exe_A_sha256':sha(a),'test_exe_B_sha256':sha(b),'exe_reproducibility':'PASS_BYTE_IDENTICAL','zip_reproducibility':'PASS_BYTE_IDENTICAL','kit_files':{q.name:sha(q) for q in sorted(kit.iterdir()) if q.is_file()},'portable_zip':str(portable),'portable_sha256':expected,'transfer_sums_sha256':sha(work/'TRANSFER_SHA256SUMS'),'windows_native':'NOT_RUN','powershell_runtime':'NOT_RUN','subfaster_runtime':'NOT_RUN_MANIFEST_ONLY'}
summary_path.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'zip_sha256':archives[0]['sha256'],'test_exe_sha256':sha(a),'files':len(summary['kit_files']),'exe_bytes':a.stat().st_size}))
