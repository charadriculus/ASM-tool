"""Offline checks of final kit and refusal to overwrite it. Never starts a PE."""
import hashlib,json,subprocess,sys,unittest,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/'tmp/windows-check-kit-v2-corrective-02'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
class KitIntegrity(unittest.TestCase):
 def test_manifest_archive_and_flat_payload_layout(self):
  summary=json.loads((ROOT/'planning/progress/windows-check-kit-v2-evidence/kit-final-summary-02.json').read_text())
  for item in summary['archives']:
   archive=Path(item['path']);self.assertEqual(sha(archive),item['sha256'])
   with zipfile.ZipFile(archive) as z:
    self.assertIsNone(z.testzip());self.assertEqual(set(z.namelist()),set(summary['kit_files']))
    for name,digest in summary['kit_files'].items():self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(),digest)
    manifest=json.loads(z.read('MANIFEST.json'))
    self.assertEqual(manifest['subfaster_runtime'],'NOT_RUN_MANIFEST_ONLY')
    self.assertNotIn('MANIFEST.json',manifest['files']);self.assertNotIn('SHA256SUMS',manifest['files'])
    for name,digest in manifest['files'].items():self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(),digest)
  with zipfile.ZipFile(summary['portable_zip']) as z:
   self.assertIn('asm-tool.exe',z.namelist());self.assertIn('payload/bundle.json',z.namelist())
  self.assertEqual(sha(WORK/'windows-A.test.exe'),sha(WORK/'windows-B.test.exe'))
 def test_repack_refuses_existing_kit_without_mutation(self):
  before={p.name:sha(p) for p in (WORK/'kit').iterdir()};label='negative-repack-unused'
  output=ROOT/('planning/progress/windows-check-kit-v2-evidence/'+label+'.json')
  self.assertFalse(output.exists())
  cmd=[sys.executable,str(ROOT/'tools/portablepayload/package-windows-check-v2.py'),'--work',str(WORK),'--summary-label',label]
  result=subprocess.run(cmd,capture_output=True,text=True)
  self.assertEqual(result.returncode,1);self.assertIn('use a fresh kit',result.stderr)
  self.assertEqual(before,{p.name:sha(p) for p in (WORK/'kit').iterdir()});self.assertFalse(output.exists())
  print(json.dumps({'negative_command':cmd,'expected_exit_code':1,'actual_exit_code':result.returncode,'kit_unchanged':True}))
if __name__=='__main__':unittest.main()
