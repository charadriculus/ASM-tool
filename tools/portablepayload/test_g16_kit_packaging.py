"""Offline synthetic packaging invariants. Never executes ELF/PE inputs."""
import argparse, hashlib, importlib.util, json, tempfile, unittest, zipfile
from unittest.mock import patch
from pathlib import Path
SPEC=importlib.util.spec_from_file_location('g16_package',Path(__file__).with_name('package-g16-kit.py'))
PKG=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(PKG)

def elf(path):
    b=bytearray(64);b[:6]=b'\x7fELF\x02\x01';b[18:20]=b'\x3e\0';path.write_bytes(b)

class Packaging(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.app=self.root/'app';self.harness=self.root/'test';self.runner=self.root/'runner'
        for p in [self.app,self.harness,self.runner]:elf(p)
        self.readme=self.root/'README.input';self.readme.write_text('Fixture only; NOT_RUN native.\n')
        self.base=self.root/'base.json';self.base.write_text(json.dumps({'base_commit':PKG.BASE,'files':{'go.mod':PKG.sha(PKG.ROOT/'go.mod')}}))
        self.pin=patch.object(PKG,'BASE_SNAPSHOT_SHA256',PKG.sha(self.base));self.pin.start();self.addCleanup(self.pin.stop)
    def stage(self,name):
        out=self.root/name
        PKG.stage(argparse.Namespace(base_snapshot=self.base,out=out,platform='linux',app=self.app,harness=self.harness))
        return out
    def archive(self,out,name):
        path=self.root/name
        PKG.archive(argparse.Namespace(root=out,platform='linux',runner=self.runner,readme=self.readme,out=path))
        return path
    def test_reproducible_archives_and_modes_closed_tree(self):
        a=self.stage('A');b=self.stage('B')
        za=self.archive(a,'A.zip');zb=self.archive(b,'B.zip')
        self.assertEqual(PKG.sha(za),PKG.sha(zb))
        with zipfile.ZipFile(za) as z:
            self.assertIsNone(z.testzip())
            expected={'g16check','README.md','SHA256SUMS','checks/bundle.json','checks/SOURCE.json','checks/product-source.sha256','checks/bin/asm-tool','checks/bin/g16-native.test'}
            self.assertEqual(set(z.namelist()),expected)
            for line in z.read('SHA256SUMS').decode().splitlines():
                digest,name=line.split('  ',1);self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(),digest)
            self.assertEqual((z.getinfo('g16check').external_attr>>16)&0o777,0o755)
            self.assertEqual((z.getinfo('README.md').external_attr>>16)&0o777,0o644)
    def test_no_overwrite_no_mutation(self):
        a=self.stage('A');archive=self.archive(a,'A.zip')
        before={str(p.relative_to(a)):PKG.sha(p) for p in a.rglob('*') if p.is_file()};sha=PKG.sha(archive)
        with self.assertRaisesRegex(ValueError,'fresh|overwrit'):
            self.archive(a,'new.zip')
        self.assertEqual(before,{str(p.relative_to(a)):PKG.sha(p) for p in a.rglob('*') if p.is_file()})
        self.assertEqual(sha,PKG.sha(archive));self.assertFalse((self.root/'new.zip').exists())
    def test_tampered_or_unlisted_member_refused_before_archive(self):
        for name in ['tamper','extra']:
            with self.subTest(name=name):
                a=self.stage(name)
                if name=='tamper':(a/'checks/bin/asm-tool').write_bytes(b'changed')
                else:(a/'checks/extra').write_bytes(b'unknown')
                with self.assertRaisesRegex(ValueError,'closed-tree'):
                    self.archive(a,name+'.zip')
                self.assertFalse((self.root/(name+'.zip')).exists())
    def test_symlink_and_wrong_architecture_refused(self):
        self.runner.write_bytes(b'MZ'+b'\0'*62)
        a=self.stage('A')
        with self.assertRaisesRegex(ValueError,'ELF'):
            self.archive(a,'A.zip')
        self.assertFalse((self.root/'A.zip').exists())
        link=self.root/'link';link.symlink_to(self.app)
        with self.assertRaisesRegex(ValueError,'symlink'):
            PKG.machine(link,'linux')
    def test_windows_pe64_archive_and_x86_refusal(self):
        for p in [self.app,self.harness,self.runner]:
            b=bytearray(70);b[:2]=b'MZ';b[60:64]=(64).to_bytes(4,'little');b[64:70]=b'PE\0\0\x64\x86';p.write_bytes(b)
        out=self.root/'Win'
        PKG.stage(argparse.Namespace(base_snapshot=self.base,out=out,platform='windows',app=self.app,harness=self.harness))
        archive=self.root/'Win.zip'
        PKG.archive(argparse.Namespace(root=out,platform='windows',runner=self.runner,readme=self.readme,out=archive))
        with zipfile.ZipFile(archive) as z:
            self.assertIn('g16check.exe',z.namelist());self.assertIn('checks/bin/asm-tool.exe',z.namelist())
            self.assertTrue(all(((i.external_attr>>16)&0o777)==0o644 for i in z.infolist()))
        b=bytearray(self.runner.read_bytes());b[68:70]=b'\x4c\x01';self.runner.write_bytes(b)
        with self.assertRaisesRegex(ValueError,'PE x64'):
            PKG.machine(self.runner,'windows')
    def test_empty_or_wrong_source_snapshot_is_not_approved(self):
        self.base.write_text(json.dumps({'base_commit':PKG.BASE,'files':{}}))
        with self.assertRaisesRegex(ValueError,'unapproved'):
            self.stage('unapproved')
        with patch.object(PKG,'BASE_SNAPSHOT_SHA256',PKG.sha(self.base)):
            with self.assertRaisesRegex(ValueError,'empty'):
                self.stage('empty')
        self.assertFalse((self.root/'empty').exists())
    def test_base_mutation_refused_before_output(self):
        self.base.write_text(json.dumps({'base_commit':PKG.BASE,'files':{'go.mod':'0'*64}}))
        with self.assertRaisesRegex(ValueError,'unapproved base source snapshot'):
            self.stage('A')
        self.assertFalse((self.root/'A').exists())

if __name__=='__main__':unittest.main()
