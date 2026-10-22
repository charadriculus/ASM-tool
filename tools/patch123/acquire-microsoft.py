#!/usr/bin/env python3
"""Acquire pinned package metadata/notices only; never restore, install or run packages."""
import base64, concurrent.futures, hashlib, json, os, re, time, urllib.request, zipfile
from pathlib import Path
from xml.etree import ElementTree as ET
ROOT=Path(__file__).resolve().parents[2]
CACHE=ROOT/'tmp/patch123-license-cache/microsoft'
OUT=ROOT/'licenses/patch123/microsoft'
CACHE.mkdir(parents=True,exist_ok=True); OUT.mkdir(parents=True,exist_ok=True)
CONTROL=json.loads((CACHE/'control-ASMTool.deps.json').read_text())
packages={tuple(k.rsplit('/',1)): v.get('sha512','') for k,v in CONTROL['libraries'].items() if v['type']=='package'}
packages[('Microsoft.Windows.SDK.BuildTools','10.0.26100.4654')]=''
# Exact extra packages declared by the pinned WindowsAppSDK nuspec; not inferred new binaries.
packages[('Microsoft.WindowsAppSDK.Base','1.8.250831001')]=''
packages[('Microsoft.WindowsAppSDK.DWrite','1.8.25090401')]=''
packages[('Microsoft.WindowsAppSDK.Runtime','1.8.250916003')]=''
packages[('Microsoft.NETCore.App.Runtime.win-x64','10.0.13')]=''
packages[('Microsoft.Windows.SDK.BuildTools.MSIX','1.7.20250829.1')]=''
packages[('Microsoft.Windows.SDK.NET.Ref','10.0.19041.57')]=''

def acquire(item):
 (name,version),expected=item; key=name.lower()+'.'+version
 url=f'https://api.nuget.org/v3-flatcontainer/{name.lower()}/{version}/{key}.nupkg'
 p=CACHE/(key+'.nupkg'); record={'package':name,'version':version,'source_url':url,'scope':'GUI historical reference/package license investigation; new GUI build NOT_RUN','expected_control_sha512':expected or None,'files':[]}
 start=time.time()
 try:
  if not p.exists():
   partial=p.with_suffix('.partial')
   with urllib.request.urlopen(url,timeout=30) as response, partial.open('xb') as out:
    if response.geturl().split('/')[2].lower() not in ['api.nuget.org','globalcdn.nuget.org']:raise ValueError('unexpected download host')
    total=0
    while data:=response.read(1<<20):
     total+=len(data)
     if total>384<<20:raise ValueError('package exceeds bounded 384MiB source-inspection limit')
     out.write(data)
   partial.rename(p)
  with p.open('rb') as f: sha=hashlib.file_digest(f,'sha256').hexdigest()
  with p.open('rb') as f: sha512=base64.b64encode(hashlib.file_digest(f,'sha512').digest()).decode()
  record.update(archive_sha256=sha,archive_sha512=sha512,bytes=p.stat().st_size,raw_sha512_equals_control_content_hash=(expected=='sha512-'+sha512) if expected else None, control_content_hash_verification='NOT_VERIFIED: NuGet contentHash excludes signing metadata; raw archive SHA512 is a different value')
  dest=OUT/(name+'@'+version);dest.mkdir(exist_ok=True)
  with zipfile.ZipFile(p) as archive:
   names=archive.namelist();nuspec=[n for n in names if n.endswith('.nuspec') and '/' not in n]
   if len(nuspec)!=1:raise ValueError('expected one root nuspec')
   data=archive.read(nuspec[0]);tree=ET.fromstring(data);ns={'n':'http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd'}
   # Nuspec namespaces vary; use local element names instead of assuming a revision.
   metadata=next(x for x in tree if x.tag.split('}')[-1]=='metadata')
   props={x.tag.split('}')[-1]:x for x in metadata}
   if props['id'].text.lower()!=name.lower() or props['version'].text!=version:raise ValueError('nuspec requested ID/version mismatch')
   license_node=props.get('license');license_path=license_node.text.strip() if license_node is not None and license_node.attrib.get('type')=='file' and license_node.text else None
   record['license_declaration']={'type':license_node.attrib.get('type'),'value':license_node.text} if license_node is not None else {'url':props['licenseUrl'].text if 'licenseUrl' in props else None}
   record['dependencies']=[{'id':x.attrib.get('id'),'version':x.attrib.get('version')} for x in metadata.iter() if x.tag.split('}')[-1]=='dependency']
   chosen=[n for n in names if n==nuspec[0] or n==license_path or re.search(r'(^|/)(license[^/]*|notice[^/]*|third[-_ ]?party[^/]*|redist[^/]*)(\.(txt|md|rtf|html))?$',n,re.I)]
   total=0;seen=set()
   for member in sorted(chosen):
    parts=Path(member).parts
    if member.endswith('/') or member.startswith('/') or '..' in parts or '\\' in member or any(':' in x for x in parts):continue
    if member.casefold() in seen:raise ValueError('colliding notice path')
    seen.add(member.casefold());info=archive.getinfo(member)
    if info.file_size>8<<20:raise ValueError('notice exceeds8MiB')
    total+=info.file_size
    if total>32<<20:raise ValueError('notice total exceeds32MiB')
    content=archive.read(member);target=dest/member;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
    record['files'].append({'path':str(target.relative_to(ROOT)),'member':member,'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()})
  record['status']='PACKAGE_NOTICES_ACQUIRED_BINARY_CLOSURE_NOT_VERIFIED'
 except Exception as error:record.update(status='ACQUISITION_NOT_COMPLETED',error=f'{type(error).__name__}: {error}')
 record['wall_seconds']=time.time()-start
 print(json.dumps({'package':name,'version':version,'status':record['status'],'error':record.get('error')},ensure_ascii=False),flush=True)
 return record
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:records=list(pool.map(acquire,packages.items()))
(OUT/'PACKAGE_INVENTORY.json').write_text(json.dumps({'new_gui_build':'NOT_RUN','historical_control_archive_sha256':'be79a6c5b1a332eef1d3bc2c5db27a2f467528ba77d4a872bc35c1d18e5eaae8','records':records},ensure_ascii=False,indent=2)+'\n')
