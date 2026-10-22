"""Compare recorded local observations without executing product/native code."""
import importlib.util,json,hashlib,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];E=ROOT/'planning/progress/g28-evidence';O=E/'oracle-02';G=E/'go-01'
spec=importlib.util.spec_from_file_location('g28_source_oracle',ROOT/'tools/qualification/g28_oracle.py');oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
def load(p):return json.loads(p.read_text())
def save(n,d):
 p=E/n
 if p.exists():raise ValueError('fresh result required')
 p.write_text(json.dumps(d,ensure_ascii=False,indent=2,default=str)+'\n')
def main():
 g=load(G/'g28-go-observations.json');py=load(O/'python-defaults.json');mapping={'RateLimits':'rate_limits','CollectionPolicy':'collection_policy','Modules':'modules','ReportingConfig':'reporting','BackendsConfig':'backends'}
 defaults=[]
 for cls,key in mapping.items():
  got=g['config_projection'][key];want=py[cls]
  defaults.append({'group':cls,'equal':got==want,'python':want,'go':got})
 cfg=oracle.config_module();cases=[]
 for i,observed in enumerate(g['prepare_cases']):
  path=G/f'case-{i:02d}.yaml';body=path.read_text()
  try:c=cfg.load_config(path);p={'accepted':True,'profile':c.profile,'external_tools':c.external_tools,'resource_monitor_enabled':c.resource_monitor.enabled}
  except Exception as exc:p={'accepted':False,'error':str(exc)}
  cases.append({'name':observed['name'],'fixture':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(body.encode()).hexdigest(),'python_load_config':p,'go_prepare':observed,'boundary':'Python backend availability/configuration stubbed, Go Prepare preflight only; no backend/native run'})
 parser=load(O/'accepted-linux-phase3.json');parsed=g['nmap_fixture_parse']['actual'];nmap=[]
 assert parser['inputs']==g['nmap_fixture_parse']['inputs']
 for key,p in parser['cases'].items():
  go=parsed[key];nmap.append({'case':key,'python':p,'go':go,'same_rows':p['rows']==(go.get('rows') or []),'classification':'Same normal parser rows where equal; Go issues/filtering against planned targets are required fail-closed semantic extensions, not hidden normalization'})
 views={}
 for lang in ['en','ru']:
  expected=load(O/('python-view-'+lang+'.json'));variants={}
  for mode in ['bounded','full']:
   view=load(O/f'go-view-{lang}-{mode}.json');health=next(s for s in view['Sections'] if s['Key']=='report.section.source_health');cells=health['Rows'][0]['Cells']
   # Compare observable facts in rendered Cells, not unused convenience Sources fields.
   labels=load(ROOT/f'internal/i18n/{lang}.json')
   for field,value in [('source.items','2'),('source.http_attempts','3'),('source.stale_cache',labels['common.yes']),('source.cache_age',labels['source.cache_age_value'].format(hours=2,minutes=0))]:
    assert labels[field]+': '+value in cells[2],(lang,field,cells)
   assert '503' in cells[2]
   html=(O/f'go-view-{lang}-{mode}.html').read_text();typ=(O/f'go-view-{lang}-{mode}.typ').read_text()
   assert cells[2] in html and cells[2] in typ
   variants[mode]={'source_health_cells':cells,'source_health_facts_preserved':True,'limitations':view['Limitations'],'python_limitation_count':len(expected['limitations']),'go_limitation_count':len(view['Limitations']),'html_and_typst_include_shared_health_facts':True,'pdf_execution':'NOT_RUN'}
  views[lang]={'python':expected,'go':variants}
 robots=load(O/'python-robots-redirect.json');assert robots['paths']==['/robots.txt','/policy/robots.txt'] and robots['private_allowed'] is False
 assert '/robots.txt' in g['crawler']['requests'] and '/policy/robots.txt' not in g['crawler']['requests'] and '/private' in g['crawler']['requests']
 cfg=oracle.config_module();ns=dict(cfg.__dict__)
 ns['normalize_report_language']=lambda value:value
 oracle.source_defs(oracle.LINUX/'asm_tool/interactive.py',{'_build_config'},ns)
 python_modes={}
 for profile in ['passive','verify','full']:
  c=ns['_build_config']('example.test',[80,443],E/'never-executed',profile,False,profile!='passive')
  python_modes[profile]={'config':oracle.dataclasses.asdict(c),'execution':'NOT_RUN; actual _build_config only'}
 existing_modes=E/'python-mode-plans.json'
 if existing_modes.exists():assert load(existing_modes)==json.loads(json.dumps(python_modes,default=str)), 'historical mode fixture changed'
 else:save('python-mode-plans.json',python_modes)
 go_modes=load(O/'go-mode-plans.json')
 mode_diffs={}
 for mode, row in python_modes.items():
  before=row['config'];after=go_modes[mode]['config'];mode_diffs[mode]={group:{k:{'python':v,'go':after[group][k]} for k,v in before[group].items() if k in after[group] and v!=after[group][k]} for group in ['rate_limits','collection_policy','modules']}
 summary={'comparison_status':'DIFFERENCES_CONFIRMED; FULL_G28_NOT_QUALIFIED','same_fixture_scope':'selected accepted Linux definitions, reused phase2/4/5 contracts +12 XML +exact Go YAML cases +shared report JSON; Python robot transport scripted vs actual Go loopback','defaults':defaults,'mode_plan_differences':mode_diffs,'mode_execution':'NOT_RUN; actual config builders/plans only','config_cases':cases,'nmap':nmap,'presentation':views,'robots_redirect':{'python':robots,'go_request_paths':g['crawler']['requests'],'go_results':g['crawler']['results'],'go_terminal_status_counts':g['crawler']['terminal_status_counts']},'normalization':'Only top-level source provenance excluded from reused fixture equality; no statuses/counts/errors/scope/provenance records dropped. Empty Go rows interpreted as empty sequence only for parser-row comparison; raw outputs retained. Event IDs/times/dynamic loopback ports are not cross-runtime equality targets.','not_run':['Whole Python/Go CLI passive/verify/full side-by-side','Browser rendered navigation/DOM/screenshots','Same-fixture native Nmap','New PDF/native Typst comparison','Windows G28','Performance/throughput'],'python_config_infrastructure_stubs':['validate_configured_backends','configure_serialization_backend']}
 save('comparison-final.json',summary)
 print(json.dumps({'defaults_groups_equal':sum(x['equal'] for x in defaults),'config_cases':len(cases),'nmap_cases':len(nmap),'nmap_same_rows':sum(x['same_rows'] for x in nmap),'view_variants':4,'robots_policy_mismatch':True,'full_g28':'NOT_QUALIFIED'}))
if __name__=='__main__':main()
