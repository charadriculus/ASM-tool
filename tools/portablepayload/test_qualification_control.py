import importlib.util, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('qualify',Path(__file__).with_name('qualify-approved.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Ownership(unittest.TestCase):
 def test_same_candidate_path_is_not_ownership(self):
  rows={10:('100','strace',1),11:('101','native-test',10),12:('102','candidate/nmap',11),99:('099','candidate/nmap --other-user-inspection',1)}
  self.assertEqual(module.extend_owned({10:'100'},rows),{10:'100',11:'101',12:'102'})
 def test_reused_parent_pid_is_not_ownership(self):
  rows={10:('200','unrelated',1),11:('201','candidate/nmap',10)}
  self.assertEqual(module.extend_owned({10:'100'},rows),{10:'100'})
if __name__=='__main__':unittest.main()
