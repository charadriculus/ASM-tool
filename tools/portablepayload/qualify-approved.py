#!/usr/bin/env python3
"""Approved bounded loopback functional qualification. No external targets/browser.
Input is a previously built candidate root; exact commands, SHA, trace and cleanup
are recorded. A new --label keeps every prior attempt/evidence immutable.
"""
import argparse,hashlib,json,os,signal,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
GO=Path('/home/charadriculus/opt/go1.26.6/bin/go')
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def sources():return {p.relative_to(ROOT).as_posix():sha(p) for directory in ['internal','cmd','tools/portablepayload'] for p in (ROOT/directory).rglob('*.go')}
def proc_info(pid):
 try:
  stat=Path('/proc')/str(pid)/'stat';body=stat.read_text();start=body[body.rfind(')')+2:].split()[19]
  cmd=(stat.parent/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace');ppid=int(body[body.rfind(')')+2:].split()[1]);return start,cmd,ppid
 except (OSError,IndexError):return None

def extend_owned(owned,snapshot):
 """Only parent ancestry with matching PID start identities grants ownership."""
 changed=True
 while changed:
  changed=False
  for pid,info in snapshot.items():
   if pid in owned:continue
   parent=info[2];parent_info=snapshot.get(parent)
   if parent in owned and parent_info and parent_info[0]==owned[parent]:
    owned[pid]=info[0];changed=True
 return owned

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--candidate',required=True);parser.add_argument('--label',required=True);args=parser.parse_args()
 if not args.label.replace('-','').isalnum():raise SystemExit('unsafe evidence label')
 candidate=Path(args.candidate).absolute();summary=json.loads((candidate/'evidence/summary.json').read_text());linux=next(x for x in summary['results'] if x['platform']=='linux/amd64')['builds'][0]
 root=Path(linux['root']);bundle=root/'payload';anchor=linux['bundle_sha256']
 if sha(root/'asm-tool')!=linux['application_sha256'] or sha(bundle/'bundle.json')!=anchor:raise SystemExit('preflight SHA mismatch')
 evidence=ROOT/'planning/progress/approved-portable-evidence'/args.label;evidence.mkdir(mode=0o700)
 env={'PATH':str(GO.parent)+':/usr/bin:/bin','HOME':str(ROOT/'tmp/integration-6-8/home'),'GOWORK':'off','GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOTELEMETRY':'off','GOENV':'off','GOFLAGS':'-mod=readonly -p=1 -trimpath','GOMAXPROCS':'2','CGO_ENABLED':'0','GOMODCACHE':str(ROOT/'tmp/integration-6-8/modcache'),'GOCACHE':str(ROOT/'tmp/integration-6-8/cache'),'GOTMPDIR':str(ROOT/'tmp/integration-6-8/tmp'),'TMPDIR':str(ROOT/'tmp/integration-6-8/tmp')}
 records=[]
 def command(label,cmd,settings=None,cwd=None,timeout=120,observe=False):
  settings=env | (settings or {});before=sources();log=evidence/(label+'.log');start=time.time();owned={};maps={}
  with log.open('xb') as f:
   p=subprocess.Popen([str(x) for x in cmd],cwd=cwd or ROOT,env=settings,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   timed_out=False
   root_info=proc_info(p.pid)
   if root_info:owned[p.pid]=root_info[0]
   while p.poll() is None:
    if observe:
     snapshot={}
     for item in Path('/proc').iterdir():
      if item.name.isdigit():
       info=proc_info(int(item.name))
       if info:snapshot[int(item.name)]=info
     extend_owned(owned,snapshot)
     for pid in owned:
      info=snapshot.get(pid)
      if info and info[0]==owned[pid] and str(bundle/'bin') in info[1]:
       try:maps[pid]=(Path('/proc')/str(pid)/'maps').read_text()
       except OSError:pass
    if time.time()-start>timeout:
     timed_out=True
     os.killpg(p.pid,signal.SIGKILL)
     for pid,identity in owned.items():
      current=proc_info(pid)
      if current and current[0]==identity:
       try:os.kill(pid,signal.SIGKILL)
       except ProcessLookupError:pass
     break
    time.sleep(.03)
   p.wait()
  survivors=[pid for pid,identity in owned.items() if (proc_info(pid) or (None,'',None))[0]==identity]
  for pid,body in maps.items():(evidence/(label+'-maps-'+str(pid)+'.txt')).write_text(body)
  record={'command':[str(x) for x in cmd],'cwd':str(cwd or ROOT),'environment':settings,'exit_code':124 if timed_out else p.returncode,'timeout':timed_out,'timeout_seconds':timeout,'wall_seconds':time.time()-start,'log_sha256':sha(log),'source_before':before,'source_after':sources(),'observed_owned_processes':list(owned),'survivors':survivors,'uid':os.getuid()}
  (evidence/(label+'.json')).write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n');records.append(record)
  print(json.dumps({'label':label,'exit_code':record['exit_code'],'survivors':survivors}),flush=True)
  if record['exit_code'] or survivors or before!=record['source_after']:raise SystemExit('STOP on qualification failure: '+label)
  return log.read_text()
 # No user SDK/Python needed by the separate application runtime; this is developer qualification.
 command('cli-help',[root/'asm-tool','--help'],settings={'PATH':'/nonexistent'})
 command('cli-version',[root/'asm-tool','--version'],settings={'PATH':'/nonexistent'})
 exe=candidate/(args.label+'-linux.test')
 command('test-compile',[GO,'test','-c','-buildvcs=false','-ldflags','-buildid= -X asmtool/internal/app.BundleManifestSHA256='+anchor,'-o',exe,'./internal/app'])
 native_dir=evidence/'artifacts'
 trace=evidence/'native.strace'
 command('native-test',['/usr/bin/strace','-f','-s','512','-e','trace=network,execve,openat,chdir','-o',trace,exe,'-test.run','^TestApprovedNativePortableQualification$','-test.v','-test.timeout','150s'],settings={'ASM_APPROVED_NATIVE_PAYLOAD':str(bundle),'ASM_APPROVED_NATIVE_BUNDLE_SHA256':anchor,'ASM_APPROVED_NATIVE_EVIDENCE_DIR':str(native_dir)},cwd=ROOT/'internal/app',timeout=180,observe=True)
 result=json.loads((native_dir/'qualification-result.json').read_text())
 if result['status']!='PASS':raise SystemExit('native evidence not PASS')
 text=trace.read_text(errors='replace');bad=[];contacts=[]
 import re
 for line in text.splitlines():
  if 'connect(' not in line and 'sendto(' not in line:continue
  ips=re.findall(r'inet_addr\("([^"]+)"\)',line)+re.findall(r'inet_pton\(AF_INET6, "([^"]+)"',line)
  for ip in ips:
   contacts.append(ip)
   if ip not in ['127.0.0.1','::1']:bad.append(line)
 host_data=[line for line in text.splitlines() if '/usr/share/nmap/' in line and 'openat(' in line and not '= -1' in line]
 mapped=[];host_libs=[]
 for file in evidence.glob('native-test-maps-*.txt'):
  for line in file.read_text().splitlines():
   parts=line.split(maxsplit=5)
   if len(parts)==6 and '.so' in Path(parts[5]).name:
    mapped.append(parts[5])
    if not parts[5].startswith(str(bundle/'bin/linux-runtime')+'/'):host_libs.append(parts[5])
 proof={'status':'PASS' if not bad and not host_data and not host_libs else 'FAIL','observed_destination_ips':sorted(set(contacts)),'unexpected_contacts':bad,'successful_host_nmap_data_reads':host_data,'mapped_native_libraries':sorted(set(mapped)),'unexpected_mapped_host_libraries':sorted(set(host_libs)),'trace_sha256':sha(trace),'qualification_result_sha256':sha(native_dir/'qualification-result.json'),'test_executable_sha256':sha(exe),'tool_hashes':{t.name:sha(t) for t in (bundle/'bin').iterdir() if t.is_file() and t.name in ['nmap','subfaster','typst']},'browser':'BLOCKED candidate31 FAIL','external_dns_providers':'NOT_RUN','windows10':'NOT_RUN','windows11':'NOT_RUN'}
 (evidence/'trace-analysis.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'status':proof['status'],'evidence':str(evidence),'mapped_libraries':len(proof['mapped_native_libraries'])}))
 if proof['status']!='PASS':raise SystemExit('STOP unexpected native trace behavior')
if __name__=='__main__':main()
