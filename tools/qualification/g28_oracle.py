"""Reuse accepted source functions and existing fixtures offline; no application/native run."""
import argparse,ast,dataclasses,hashlib,http,importlib.util,json,sys,tempfile,types
from pathlib import Path
from http import HTTPStatus
from urllib.parse import urljoin,urlsplit
from urllib.robotparser import RobotFileParser
ROOT=Path(__file__).resolve().parents[2];LINUX=ROOT/'reference/linux-0.11.3-accepted';OUT=None;sys.dont_write_bytecode=True

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def block_io(event,args):
    if event.startswith('socket.') or event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork'}:
        raise RuntimeError('G28 forbidden network/process operation: '+event)
sys.addaudithook(block_io)
def write(name,obj):
    p=OUT/name
    if p.exists():raise ValueError('no overwrite: '+str(p))
    p.write_text(json.dumps(obj,ensure_ascii=False,sort_keys=True,indent=2,default=str)+'\n')
def builder(number,scratch):
    path=ROOT/'scripts'/('build_phase2_fixture.py' if number==2 else f'build_phase{number}_fixtures.py')
    tree=ast.parse(path.read_text());body=[]
    for node in tree.body:
        # Suppress only builder scratch setup; preserve all fixture-producing functions.
        if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute) and node.value.func.attr=='mkdir':continue
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Attribute) and t.attr=='tempdir' for t in node.targets):continue
        body.append(node)
    mod=types.ModuleType('g28_phase'+str(number));mod.__file__=str(path);sys.modules[mod.__name__]=mod
    exec(compile(ast.Module(body=body,type_ignores=[]),str(path),'exec'),mod.__dict__)
    mod.WIN=LINUX if number==2 else LINUX/'asm_tool'
    mod.TEMP_ROOT=scratch;mod.SCRATCH=scratch;tempfile.tempdir=str(scratch)
    if number==3:
        return legacy_nmap()
    value=mod.build()
    if number==2:
        value.pop('synthetic_sqlite_run_sql');actual=value;expected=json.loads((ROOT/'testdata/phase2/legacy_contract.json').read_text())
    else:
        value=value['fixtures/contracts.json'] if number==3 else value['contracts.json'] if number==4 else value
        actual=json.loads(value);expected=json.loads((ROOT/f'testdata/phase{number}/fixtures/contracts.json').read_text())
    actual.pop('source',None);expected.pop('source',None)
    # source/provenance only is excluded; every semantic fixture input/output stays.
    differences=[]
    def diff(a,b,path=''):
        if type(a)!=type(b):differences.append({'path':path,'python_linux':a,'existing_fixture':b});return
        if isinstance(a,dict):
            for k in sorted(set(a)|set(b)):
                if k not in a or k not in b:differences.append({'path':path+'/'+k,'python_linux':a.get(k),'existing_fixture':b.get(k)})
                else:diff(a[k],b[k],path+'/'+k)
        elif isinstance(a,list):
            if len(a)!=len(b):differences.append({'path':path,'python_linux_length':len(a),'existing_length':len(b)})
            else:
                for i,(x,y) in enumerate(zip(a,b)):diff(x,y,path+'/'+str(i))
        elif a!=b:differences.append({'path':path,'python_linux':a,'existing_fixture':b})
    diff(actual,expected)
    write(f'accepted-linux-phase{number}.json',{'oracle':'actual accepted Linux definitions on reused scripted fixtures','builder_sha256':sha(path),'excluded_nonsemantic_field':'top-level source provenance only','semantic_groups':len(actual.get('outputs',actual.get('groups',actual))),'differences_from_existing_fixture':differences,'actual':actual})
    return {'phase':number,'differences':len(differences),'status':'MATCH_SELECTED_SOURCE_CONTRACTS' if not differences else 'DIFF','builder':str(path.relative_to(ROOT))}


def legacy_nmap():
    import xml.etree.ElementTree as ET
    ns={'Path':Path,'Any':object,'ET':ET}
    source_defs(LINUX/'asm_tool/wrappers/nmap.py',{'parse_nmap_xml'},ns)
    fixture=json.loads((ROOT/'testdata/phase3/fixtures/contracts.json').read_text());cases={}
    for name,inp in fixture['inputs']['nmap.parse'].items():
        path=ROOT/'testdata/phase3'/inp['xml_fixture'] if inp['xml_fixture'] else OUT/'missing.xml'
        try:cases[name]={'rows':ns['parse_nmap_xml'](path),'error':None}
        except Exception as exc:cases[name]={'rows':None,'error':type(exc).__name__+': '+str(exc)}
    write('accepted-linux-phase3.json',{'oracle':'accepted parse_nmap_xml only; original Windows builder parse_nmap_result does not exist in accepted Linux','inputs':fixture['inputs']['nmap.parse'],'cases':cases})
    return {'phase':3,'status':'SOURCE_SHAPE_DIFFERENCE_EXPLICIT_LINUX_PARSER_RUN','cases':len(cases)}

def config_module():
    import yaml
    norm={};path=LINUX/'asm_tool/core/normalization.py';exec(compile(path.read_text(),str(path),'exec'),norm)
    path=LINUX/'asm_tool/config.py';tree=ast.parse(path.read_text());tree.body=[n for n in tree.body if not isinstance(n,ast.ImportFrom) or not n.level]
    m=types.ModuleType('g28_accepted_config');m.__dict__.update(__version__='0.11.3',normalize_domain=norm['normalize_domain']);sys.modules[m.__name__]=m
    exec(compile(tree,str(path),'exec'),m.__dict__)
    backend=types.ModuleType('asm_tool.evidence.backend');backend.validate_configured_backends=lambda _:None;sys.modules[backend.__name__]=backend
    ser=types.ModuleType('asm_tool.backends.serialization');ser.configure_serialization_backend=lambda _:None;sys.modules[ser.__name__]=ser
    return m

def source_defs(path,names,ns):
    tree=ast.parse(path.read_text());nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names];assert len(nodes)==len(names)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),ns)

def presentation():
    ns={'Any':object,'HTTPStatus':HTTPStatus,'Translator':object}
    path=LINUX/'asm_tool/utils/redaction.py';exec(compile(path.read_text(),str(path),'exec'),ns)
    source_defs(LINUX/'asm_tool/reporting/pdf.py',{'_pdf_source_health','_http_error_label','_cache_age_label','_pdf_limitations','_humanize_limitation'},ns)
    report={'metadata':{},'summary':{'discovered_subdomains':0,'dns_validated_subdomains':0,'ips':0,'ports_total':0},'source_health':[{'source':'crt.sh','label':'crt.sh','status':'partial','items':2,'http_attempts':3,'last_http_status':503,'cache_stale':True,'cache_age_seconds':7200,'errors':['fixture failure']}],'limitations':[{'reason':'fixture warning','data':{'source_tool':'fixture','metadata':{}}},{'reason':'fixture warning','data':{'source_tool':'fixture','metadata':{}}},{'reason':'503 transport issue','data':{'source_tool':'crt.sh','metadata':{}}}],'assets':{'domains':[],'ips':[],'asn':[],'cidrs':[]},'web':[],'crawler':[],'screenshots':[],'related_domains':[],'source_failures':[],'reporting':{}}
    write('shared-report-input.json',{'input':{'TargetDomain':'example.test','Version':'0.12.0-go','Profile':'passive'},'report':report})
    for lang in ['en','ru']:
        tree=ast.parse((LINUX/f'asm_tool/i18n/{lang}.py').read_text());catalog=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='STRINGS' for t in n.targets)))
        class Translator:
            def text(self,key,**values):return catalog[key].format(**values)
        tr=Translator();write('python-view-'+lang+'.json',{'health':ns['_pdf_source_health'](report,tr),'limitations':ns['_pdf_limitations'](report,[],tr)})

def robots_reference():
    import time
    from collections import defaultdict
    class Session:
        def __init__(self):self.headers={};self.paths=[]
        def get(self,url,**kw):
            p=urlsplit(url).path;self.paths.append(p)
            return types.SimpleNamespace(status_code=302 if p=='/robots.txt' else 200,headers={'location':'/policy/robots.txt'} if p=='/robots.txt' else {},is_redirect=p=='/robots.txt',is_permanent_redirect=False,text='' if p=='/robots.txt' else 'User-agent: *\nDisallow: /private\n')
    ns={'time':time,'defaultdict':defaultdict,'urljoin':urljoin,'urlsplit':urlsplit,'requests':types.SimpleNamespace(Session=Session,Response=object),'ScopeChecker':object,'RobotFileParser':RobotFileParser,'robots_url_for':lambda org:org.rstrip('/')+'/robots.txt'}
    source_defs(LINUX/'asm_tool/active/http/client.py',{'LowNoiseHttpClient','RequestBudgetExceeded','TargetBackoff'},ns)
    source_defs(LINUX/'asm_tool/active/crawler/engine.py',{'_robots_for_origin'},ns)
    cl=ns['LowNoiseHttpClient']('fixture',0,50,[]);scope=types.SimpleNamespace(check_url=lambda _:types.SimpleNamespace(status='in_scope',reason='fixture'))
    parser,url,body,error=ns['_robots_for_origin'](cl,scope,'http://example.test');assert parser is not None and not parser.can_fetch('fixture','http://example.test/private')
    write('python-robots-redirect.json',{'source':'unchanged LowNoiseHttpClient.get + _robots_for_origin','transport':'scripted Session; zero socket calls','paths':cl.session.paths,'robots_error':error,'private_allowed':parser.can_fetch('fixture','http://example.test/private'),'body':body})

def main():
    global OUT
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();OUT=args.out.absolute()
    OUT.mkdir(parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='g28-oracle-',dir=ROOT/'tmp') as td:
        scratch=Path(td);summary=[]
        for n in [2,3,4,5]:summary.append(builder(n,scratch))
        cfg=config_module();projection={k:dataclasses.asdict(getattr(cfg,k)()) for k in ['RateLimits','CollectionPolicy','Modules','ReportingConfig','BackendsConfig']}
        for values in projection.values():
            for key in list(values):
                if key.startswith('research_') or key=='ai_review':del values[key]
        write('python-defaults.json',projection)
        configs={}
        bodies={'base':'','resource_monitor':'resource_monitor: {enabled: true}\n','external_tools':'external_tools: {subfaster: /fixture/subfaster}\n','unknown':'legacy_extension: true\n','ai_removed':'modules: {ai_review: false}\n'}
        for name,body in bodies.items():
            p=scratch/(name+'.yml');p.write_text('target_domain: example.test\nallowed_domains: [example.test]\n'+body)
            try:
                c=cfg.load_config(p);configs[name]={'parsed':True,'profile':c.profile,'resource_monitor_enabled':c.resource_monitor.enabled,'external_tools':c.external_tools}
            except Exception as exc:configs[name]={'parsed':False,'error':str(exc)}
        write('python-config-cases.json',{'boundary':'actual load_config validation except backend availability/serialization configuration are inert infrastructure stubs; no backend probe','cases':configs})
        presentation();robots_reference()
        write('oracle-summary.json',{'python':sys.version,'source':'accepted Linux0.11.3; NOT Windows acceptance','phase_contracts':summary,'network_and_subprocess':'audit-hook DENY; no native execution','full_cli_browser_pdf_runtime':'NOT_RUN','scope':'selected source definitions; reused scripted fixture transports and capture sinks; not entire Python application','config_stubs':['validate_configured_backends','configure_serialization_backend']})
        print(json.dumps(summary))
if __name__=='__main__':main()
