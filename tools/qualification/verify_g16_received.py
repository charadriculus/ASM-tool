"""Developer-only static inspection of received evidence. Never runs native programs."""
import argparse,datetime,hashlib,ipaddress,json,re,sqlite3,sys,tarfile,tempfile,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[2]
INPUTS={'linux':('tmp/G16 Linux проверка-01/g16-linux-native-evidence-01.tar.gz','d611050c2686f93dc41d1ba7e0bc29cbb2c2c51805602287f192b97e32ab910b'),'windows':('tmp/g16-windows10-native-evidence-mainchat-01/g16-windows10-native-evidence-01.zip','ba54c72ad642382294456b7044e42018c82b4e26fc0c6ca03772ad44f8c157dd')}
CASES={'arrival_budget','backpressure_cancel_partial_persistence','batch_ranked_pipeline','loopback_http_crawler','payload_identity_only','shared_http_page_budgets','streaming_pipeline'}
def sha(b):return hashlib.sha256(b).hexdigest()
def read_archive(path):
    result={}
    def add(name,b):
        n=name.replace('\\','/');p=PurePosixPath(n)
        assert not p.is_absolute() and '..' not in p.parts and ':' not in n and n not in result,n
        assert len(b)<32<<20,n
        result[n]=b
    if path.suffix=='.zip':
        with zipfile.ZipFile(path) as a:
            assert a.testzip() is None
            for i in a.infolist():
                assert ((i.external_attr>>16)&0o170000)!=0o120000
                if not i.filename.endswith(('/','\\')):add(i.filename,a.read(i))
    else:
        with tarfile.open(path) as a:
            for m in a:
                assert m.isdir() or m.isfile(),m.name
                if m.isfile():add(m.name,a.extractfile(m).read())
    return result

def inspect(platform,path,pin,kit):
    b=path.read_bytes();assert sha(b)==pin
    d=read_archive(path)
    def load(n):return json.loads(d[n].decode('utf-8-sig'))
    checks={}
    for prefix in ['preflight-evidence','native-evidence']:
        manifest=load(prefix+'/evidence-manifest.json');expected={x['path'] for x in manifest}
        found={n[len(prefix)+1:] for n in d if n.startswith(prefix+'/') and n!=prefix+'/evidence-manifest.json'}
        assert expected==found and len(expected)==len(manifest)
        for x in manifest:
            data=d[prefix+'/'+x['path']];assert sha(data)==x['sha256'] and len(data)==x['size']
        checks[prefix+'_manifest_files']=len(manifest)
    pre=load('preflight-evidence/runner-result.json');run=load('native-evidence/runner-result.json');g=load('native-evidence/artifacts/g16-result.json')
    assert pre['status']=='PREFLIGHT_PASS' and pre['commands']==[]
    assert run['status']==g['status']=='PASS_FUNCTIONAL_ONLY' and not run['elevated']
    assert run['kit_manifest_sha256']==pre['kit_manifest_sha256']==kit['checks_manifest_sha256']
    assert run['portable_manifest_sha256']==g['bundle_manifest_sha256']
    assert set(run['scenarios'])==set(g['scenarios'])==CASES and set(run['scenarios'].values())=={'PASS'}
    for n in CASES:assert g['scenarios'][n]['status']=='PASS'
    for k,v in run['kit_executables'].items():
        key='app' if k=='asm-tool' else 'harness';assert v['sha256']==kit['binaries'][key]['sha256']
    assert [c['name'] for c in run['commands']]==['app-help','app-version','g16-native-local-fixtures']
    for c in run['commands']:
        assert c['exit_code']==0 and not c['timed_out'] and not c['output_limit_exceeded']
        for stream in ['stdout','stderr']:
            names=[n for n in d if n.startswith('native-evidence/logs/') and n.endswith('-'+c['name']+'.'+stream+'.log')];assert len(names)==1
            data=d[names[0]];assert len(data)==c[stream+'_bytes'] and sha(data)==c[stream+'_sha256']
    testlog=next(v.decode() for n,v in d.items() if n.endswith('-g16-native-local-fixtures.stdout.log'))
    assert '--- PASS: TestG16NativeCheckKit ' in testlog and 'SKIP' not in testlog and 'FAIL' not in testlog
    assert g['artifact_preservation'] is True
    for a in g['artifacts'].values():assert sha(d['native-evidence/'+a['path']])==a['sha256']
    c=g['scenarios'];assert c['arrival_budget']['details']['validation_start_sequence']==['example.test','z.example.test']
    assert c['batch_ranked_pipeline']['details']['selected']==['example.test','a.example.test']
    assert c['shared_http_page_budgets']['details']['remaining_total_page_limits']==[8,7,6]
    w=c['backpressure_cancel_partial_persistence']['details'];assert w['workers_joined'] and w['active_dns_workers_after_return']==0 and not w['duplicate_dns'] and w['emitted_before_cancel']<=12
    h=c['loopback_http_crawler']['details'];assert h['listener_closed'] and h['loopback_requests']==3 and h['crawler_pages']==2
    dbs={}
    with tempfile.TemporaryDirectory(prefix='g16-evidence-read-',dir=ROOT/'tmp') as temp:
        for case in sorted(CASES-{'payload_identity_only'}):
            prefix='native-evidence/artifacts/runs/'+case+'/'
            p=Path(temp)/(case+'.sqlite3');p.write_bytes(d[prefix+'asm.sqlite3'])
            con=sqlite3.connect(p.as_uri()+'?mode=ro&immutable=1',uri=True)
            try:
                assert con.execute('pragma quick_check').fetchone()[0]=='ok'
                con.row_factory=sqlite3.Row;rows=list(con.execute('select * from events'))
                events=[json.loads(line) for line in d[prefix+'events/run.jsonl'].splitlines() if line.strip()]
                ids=[ev['event_id'] for ev in events];assert len(ids)==len(set(ids))==len(rows)
                byid={row['event_id']:row for row in rows};assert set(ids)==set(byid)
                for ev in events:
                    row=byid[ev['event_id']]
                    for field in ['event_type','module','scope_status']:
                        assert row[field]==ev.get(field),(case,field)
                    for field in ['raw_value','normalized_value','metadata','evidence','relations']:assert json.loads(row[field])==ev[field],(case,field)
                status=json.loads(d[prefix+'run_status.json'])
                dbs[case]={'events':len(events),'sqlite_quick_check':'ok','ids_unique_equal':True,'stored_semantic_fields_equal':True,'run_status':status}
            finally:con.close()
    result={'status':'PASS_FUNCTIONAL_ONLY','archive_sha256':pin,'files':len(d),'host':{k:run[k] for k in ['machine_name','os_version','platform','elevated']},'manifest_checks':checks,'commands':run['commands'],'scenarios':g['scenarios'],'database_checks':dbs,'artifact_preservation':True,'limitations':run['limitations'],'historical':g['historical'],'not_run':g['not_run']}
    if platform=='windows':
        transfer=load('EVIDENCE_TRANSFER_MANIFEST.json');assert len(transfer['files'])==45
        for f in transfer['files']:assert len(d[f['path']])==f['size'] and sha(d[f['path']])==f['sha256']
        result['account_caveat']={k:transfer[k] for k in ['admin_group_member','effective_token_elevated','strict_network_gate','windows11','attempts']}
        result['standard_nonadmin_account_qualified']=False
    else:
        assert d['native-command.exit'].strip()==d['preflight-command.exit'].strip()==b'0'
        trace=d['native.strace'].decode();lines=trace.splitlines();execs=[];net=[]
        for line in lines:
            m=re.search(r'execve\("((?:\\.|[^"\\])*)"',line)
            if m:
                raw=m[1];decoded=re.sub(r'\\([0-7]{3})',lambda x:chr(int(x[1],8)),raw).encode('latin1').decode('utf-8');execs.append(decoded)
            if re.search(r'\b(connect|bind|sendto|sendmsg|sendmmsg)\(',line):
                addresses=re.findall(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"',line)
                for pair in addresses:
                    ip=ipaddress.ip_address(next(x for x in pair if x));assert ip.is_loopback or getattr(ip,'ipv4_mapped',None) and ip.ipv4_mapped.is_loopback,line
                assert addresses or 'AF_UNIX' in line,line
                net.append(line)
        assert execs==[run['kit_root']+'/g16check',*[c['executable'] for c in run['commands']]]
        pids=set(re.findall(r'^(\d+) ',trace,re.M));exited=set(re.findall(r'^(\d+) +\+\+\+ exited with 0 \+\+\+',trace,re.M));assert pids==exited
        result['linux_trace']={'sha256':sha(d['native.strace']),'lines':len(lines),'execve_allowlist':execs,'checked_destination_calls':net,'traced_ids':len(pids),'all_traced_ids_exit0':True,'unclassified_trace_lines':[{'line':i+1,'text':line} for i,line in enumerate(lines) if '???(' in line], 'scope':'OBSERVED_RECOGNIZED_LOCAL_SUBSET_EXHAUSTIVE_STRICT_CLASSIFICATION_INCOMPLETE','historical_linux_gate':'FAIL_PRESERVED','postcheck_caveat':'Original postcheck truncates escaped Unicode targets; complete raw trace parsed independently.'}
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    assert not args.out.exists(),'fresh output required';args.out.mkdir(parents=True)
    kit=json.loads((ROOT/'planning/progress/g16-kit-evidence/build-02/kit-summary.json').read_text())
    result={'verification_command':sys.argv,'verifier_sha256':sha(Path(__file__).read_bytes()),'new_native_execution':'NOT_RUN','platforms':{}}
    for platform,(name,pin) in INPUTS.items():result['platforms'][platform]=inspect(platform,ROOT/name,pin,kit['platforms'][platform])
    (args.out/'inspection.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({p:{'status':x['status'],'files':x['files'],'cases':len(x['scenarios']),'dbs':len(x['database_checks'])} for p,x in result['platforms'].items()}))
if __name__=='__main__':main()
