#!/usr/bin/env python3
"""Read existing native02 artifacts; no native scanner, browser or network calls."""
import argparse, hashlib, html.parser, json, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
E=ROOT/'planning/progress/approved-portable-evidence'
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--label',default='artifact-check-final');args=parser.parse_args()
if not args.label.replace('-','').isalnum():raise SystemExit('unsafe evidence label')
OUT=E/args.label
OUT.mkdir(exist_ok=False)
def sha(p): return hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
class Text(html.parser.HTMLParser):
 def __init__(self): super().__init__(); self.parts=[]
 def handle_data(self,s): self.parts.append(s)
record={'scope':'existing small loopback fixture only; not complete historical equivalence','commands':[],'artifact_hashes':{},'json_differences':{},'status':'RUNNING'}
try:
 native=json.loads((E/'native-linux-02/artifacts/qualification-result.json').read_text())
 reports=native['reports'];docs={}
 for name,items in reports.items():
  for fmt in ['json','html','pdf','typst','manifest']:
   p=Path(items[fmt+'_path']);digest=sha(p)
   if digest!=items[fmt]: raise ValueError('artifact digest mismatch '+str(p))
   record['artifact_hashes'][str(p.relative_to(ROOT))]=digest
  docs[name]=json.loads(Path(items['json_path']).read_text())
 base=docs['full-en-bounded']
 allowed={'report_language','report_mode','human_subdomain_row_limit'}
 for name in ['ru-bounded','en-full','ru-full']:
  other=docs[name]
  if base.keys()!=other.keys():raise ValueError('JSON keys differ '+name)
  differences=[k for k in base if base[k]!=other[k]]
  if differences!=['reporting']:raise ValueError('unexpected JSON differences '+repr(differences))
  if base['reporting'].keys()!=other['reporting'].keys():raise ValueError('reporting JSON keys differ '+name)
  diff=[k for k in base['reporting'] if base['reporting'][k]!=other['reporting'].get(k)]
  if not set(diff)<=allowed:raise ValueError('unexpected presentation differences '+repr(diff))
  language='ru' if name.startswith('ru') else 'en';mode='bounded' if name.endswith('bounded') else 'full'
  if other['reporting']['report_language']!=language or other['reporting']['report_mode']!=mode:raise ValueError('wrong language/mode')
  record['json_differences'][name]={'top_level':differences,'reporting_fields':diff}
 if base['summary']['ports_actively_confirmed']!=1 or base['summary']['crawler_pages']!=2 or base['summary']['web_pages_loaded']!=3:raise ValueError('fixture counts differ')
 record['json_semantic_scope']='All non-reporting fields identical across four full-run variants. Only three explicit presentation fields may differ; no timestamp/event/provenance normalization.'
 ip=native['http']['bound_host'];port=str(native['http']['open_port']);domain=native['http']['domain']
 record['human_selected_content']={}
 for name in ['full-en-bounded','ru-bounded','en-full','ru-full']:
  p=Path(reports[name]['pdf_path']);cmd=['/usr/bin/pdftotext','-layout',str(p),'-'];x=subprocess.run(cmd,capture_output=True)
  record['commands'].append({'command':cmd,'exit_code':x.returncode,'stdout_sha256':hashlib.sha256(x.stdout).hexdigest(),'stderr':x.stderr.decode(errors='replace')})
  if x.returncode:raise ValueError('PDF extraction failed')
  (OUT/(name+'.txt')).write_bytes(x.stdout);pdf=x.stdout.decode('utf-8');parser=Text();parser.feed(Path(reports[name]['html_path']).read_text());text=' '.join(parser.parts)
  terms=[ip,port,domain,'candidate31','Nmap']
  if name.startswith('ru'):terms+=['Порты и сетевые сервисы','Покрытие веб-проверкой','Скриншоты']
  else:terms+=['Ports and network services','Web assessment coverage','Screenshots']
  for term in terms:
   if term not in pdf or term not in text:raise ValueError('missing HTML/PDF term '+name+' '+term)
  record['human_selected_content'][name]=terms
 for name in ['full-en-bounded','ru-full']:
  p=Path(reports[name]['pdf_path']);prefix=OUT/name;cmd=['/usr/bin/pdftoppm','-f','1','-l','2','-r','90','-png',str(p),str(prefix)];x=subprocess.run(cmd,capture_output=True)
  record['commands'].append({'command':cmd,'exit_code':x.returncode,'stderr':x.stderr.decode(errors='replace')})
  if x.returncode:raise ValueError('PDF rendering failed')
 record['status']='PASS_SELECTED_FIXTURE_CONTENT';record['visual_review']='PENDING_MANUAL_INSPECTION';record['complete_semantic_equivalence']='NOT_RUN'
finally:
 (OUT/'result.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'status':record['status'],'artifacts_verified':len(record['artifact_hashes']),'output':str(OUT)},ensure_ascii=False))
