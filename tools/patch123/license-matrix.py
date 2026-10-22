#!/usr/bin/env python3
"""Compose a review matrix from existing evidence, not a binary-completeness assertion."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(p):return json.loads((ROOT/p).read_text())
def main():
 rows=[{'component':'ASM Tool own code','version':'0.12.3','spdx':'MIT','evidence':'LICENSE','status':'OWNER_SELECTED_HOLDER_UNCONFIRMED'}, {'component':'GNU glibc shared runtime','version':'2.43-2ubuntu2.4','spdx':'LGPL-2.1-or-later','per_file_exceptions':True,'evidence':'licenses/patch123/go-runtime/LINUX_RUNTIME_PROVENANCE.json','status':'EXACT_SOURCE_AND_NOTICES_INCLUDED_REPLACEMENT_NOT_RUNTIME_TESTED'}, {'component':'libgcc_s.so.1','version':'16-20260322-1ubuntu1','spdx':'GPL-3.0-or-later WITH GCC-exception-3.1','evidence':'licenses/patch123/go-runtime/linux-runtime/notices/libgcc-s1-copyright','status':'SOURCE_AND_TERMS_INCLUDED_NOT_LEGAL_APPROVAL'}, {'component':'Microsoft CRT x64','version':'14.51.36247.0','spdx':'LicenseRef-Microsoft-VisualStudio-REDIST','evidence':'licenses/patch123/microsoft/GO_PAYLOAD_CRT_PROVENANCE.json','status':'LICENSING_NOT_CLEARED'}, {'component':'DejaVu Sans','version':'2.37','spdx':'LicenseRef-DejaVu-Bitstream','evidence':'packaging/portable/linux-amd64-patch123.lock.json','status':'ORIGINAL_COPYRIGHT_PRESERVED_IN_PAYLOAD'}, {'component':'Subfaster','version':'2.18.0','spdx':'MIT','evidence':'licenses/patch123/go-runtime/subfaster/LICENSE.md','status':'BINARY_BUILD_INFO_INSPECTED_WINDOWS_MAIN_H1_ABSENT'}]
 s=load('licenses/patch123/go-runtime/SUBFASTER_PROVENANCE.json')
 for group in ['common_dependency_modules','linux_only_modules','windows_only_modules']:
  for m in s[group]:rows.append({'component':m['module'],'version':m['version'],'spdx_expressions':m.get('detected_notice_spdx_expressions') or ['NOASSERTION'],'scope':group,'evidence':'licenses/patch123/go-runtime/SUBFASTER_PROVENANCE.json','status':'BUILD_INFO_GRAPH_AND_NOTICE_BYTES_VERIFIED_NOT_MACHINE_CODE_CLOSURE'})
 for a in load('licenses/patch123/rust/licenses-index.json')['artifacts']:
  rows.append({'component':a.get('component',a['name']),'source_artifact':a['name'],'version':a.get('version','source artifact'),'spdx':a.get('spdx_or_license_expression','NOASSERTION'),'source_url':a.get('source_url',a.get('url')),'sha256':a['sha256'],'evidence':'licenses/patch123/rust/licenses-index.json','status':'SOURCE_EVIDENCE_ONLY_ACTUAL_BINARY_INCLUSION_UNKNOWN'})
 for a in load('licenses/patch123/microsoft/PACKAGE_INVENTORY.json')['records']:
  dec=a['license_declaration'];decl=dec.get('value',dec.get('url'));spdx=decl if dec.get('type')=='expression' else ('LicenseRef-Microsoft-WebView2' if 'WebView2' in a['package'] else 'LicenseRef-Microsoft-Package-Terms')
  rows.append({'component':a['package'],'version':a['version'],'spdx':spdx,'original_declaration':decl,'source_url':a['source_url'],'sha256':a['archive_sha256'],'evidence':'licenses/patch123/microsoft/PACKAGE_INVENTORY.json','status':'ORIGINAL_EXACT_PACKAGE_TERMS_NEW_GUI_NOT_BUILT'})
 # Preserve the actual file-level expressions rather than collapsing a multilicensed crate.
 for a in load('licenses/patch123/rust/licenses-index.json')['records']:
  rows.append({'component':'Rust source/notice file: '+a['path'],'version':a['version_or_revision'],'spdx':a['spdx_or_license_expression'],'sha256':a['sha256'],'evidence':'licenses/patch123/rust/licenses-index.json','status':'FILE_LEVEL_LICENSE_EVIDENCE_BINARY_INCLUSION_UNKNOWN'})
 for row in rows:
  if not (ROOT/row['evidence']).is_file():raise ValueError('missing evidence '+row['evidence'])
 result={'format':'Review matrix with SPDX/LicenseRef values, not a complete binary SPDX SBOM','public_redistribution':'NOT_CONFIRMED','rows':rows,'core_go_deps':'Exact versions and original terms in platform locks and payload/licenses/go. modernc libc is not GNU glibc.'}
 (ROOT/'docs/patch123/SPDX_MATRIX.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(len(rows),'review matrix records')
if __name__=='__main__':main()
