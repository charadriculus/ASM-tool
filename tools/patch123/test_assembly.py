"""Targeted offline checks of the new composition layer; no native execution."""
import hashlib, importlib.util, json, posixpath, re, stat, tempfile, unittest, zipfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('composition',Path(__file__).with_name('assemble.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class CompositionTests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def test_roundtrip_and_repeat(self):
  data=m.closed_entries({'asm-tool':b'fake app bytes','docs/Русский.txt':'Unicode'.encode()})
  a=self.root/'a.zip';b=self.root/'b.zip'
  m.write_zip(a,data,{'asm-tool'});m.write_zip(b,data,{'asm-tool'})
  self.assertEqual(m.sha(a),m.sha(b));self.assertEqual(m.verify_zip(a)['files'],3)
  with zipfile.ZipFile(a) as z:self.assertTrue((z.getinfo('asm-tool').external_attr>>16)&0o111)
 def test_packaged_document_links_resolve(self):
  for plat,prefix in [('linux',''),('windows',''),('windows','GoBundle/'),('linux','combined')]:
   with self.subTest(platform=plat,prefix=prefix):
    docs=m.combined_docs() if prefix=='combined' else m.distribution_docs(prefix)
    lock=json.loads((m.ROOT/f'packaging/portable/{plat}-amd64-patch123.lock.json').read_text())
    paths=set(docs)|({m.SOURCE} if prefix=='combined' else {prefix+f['path'] for f in lock['files']})
    for name,value in docs.items():
     if not name.endswith('.md'):continue
     for target in re.findall(r'\]\(([^)]+)\)',value.decode()):
      if target.startswith(('https:','http:','#')):continue
      resolved=posixpath.normpath(posixpath.join(posixpath.dirname(name),target))
      exists=resolved in paths or (target.endswith('/') and any(p.startswith(resolved+'/') for p in paths))
      self.assertTrue(exists,f'{name}: {target} -> {resolved}')
 def test_tampered_content_rejected(self):
  data=m.closed_entries({'file.txt':b'original'});data['file.txt']=b'modified'
  p=self.root/'bad.zip';m.write_zip(p,data)
  with self.assertRaisesRegex(ValueError,'hash mismatch'):m.verify_zip(p)
 def test_unlisted_content_rejected(self):
  data=m.closed_entries({'file.txt':b'original'});data['extra.txt']=b'extra'
  p=self.root/'extra.zip';m.write_zip(p,data)
  with self.assertRaisesRegex(ValueError,'unmanifested'):m.verify_zip(p)
 def test_traversal_and_absolute_rejected_before_write(self):
  for n in ['../escape','/absolute','a/../b','a\\b','C:/file','a//b']:
   with self.subTest(n=n):
    p=self.root/'unsafe.zip'
    with self.assertRaisesRegex(ValueError,'unsafe'):m.write_zip(p,{n:b'x'})
    self.assertFalse(p.exists())
 def test_case_collisions_rejected(self):
  with self.assertRaisesRegex(ValueError,'case collision'):m.write_zip(self.root/'case.zip',{'A':b'a','a':b'a'})
 def test_previous_output_preserved(self):
  p=self.root/'previous.zip';p.write_bytes(b'previous result')
  with self.assertRaisesRegex(ValueError,'output exists'):m.write_zip(p,{'new':b'x'})
  self.assertEqual(p.read_bytes(),b'previous result')
 def test_link_member_rejected(self):
  p=self.root/'link.zip'
  with zipfile.ZipFile(p,'w') as z:
   info=zipfile.ZipInfo('link');info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(info,'target')
   z.writestr('SHA256SUMS',hashlib.sha256(b'target').hexdigest()+'  link\n')
  with self.assertRaisesRegex(ValueError,'nonregular'):m.verify_zip(p)
if __name__=='__main__':unittest.main(verbosity=2)
