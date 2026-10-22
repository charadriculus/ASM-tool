#!/usr/bin/env python3
"""Read executable headers/import tables only; never execute a payload."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

root = Path.cwd()
build = Path(sys.argv[1])
out = Path(sys.argv[2])
records = []
for platform in ['linux', 'windows']:
    stage = build / ('ASM-' + platform + '-проверка-A')
    payload = stage / 'payload'
    names = {p.name.lower() for p in payload.rglob('*') if p.is_file()}
    for path in sorted(stage.rglob('*')):
        if not path.is_file():
            continue
        with path.open('rb') as stream:
            magic = stream.read(4)
        if magic == b'\x7fELF':
            command = ['/usr/bin/readelf', '-d', '-l', str(path)]
        elif magic[:2] == b'MZ':
            command = ['/usr/bin/objdump', '-p', str(path)]
        else:
            continue
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        text = completed.stdout.decode(errors='replace')
        needed = re.findall(r'Shared library: \[([^]]+)\]', text) if platform == 'linux' else re.findall(r'DLL Name: (\S+)', text)
        unbundled = [name for name in needed if name.lower() not in names]
        record = {'path': str(path.relative_to(stage)), 'platform': platform, 'command': command,
                  'exit_code': completed.returncode, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                  'imports': needed, 'not_bundled_imports': unbundled, 'static_tool_output': text}
        records.append(record)
        if completed.returncode or platform == 'linux' and unbundled:
            raise SystemExit('static ELF closure/header check FAIL: ' + str(path))
report = {'scope': 'static header/import inventory; native loading NOT_RUN', 'files': records,
          'windows_note': 'Unbundled imports are recorded explicitly; Windows OS/API-set loader behavior requires separate Windows10/11 native checks. Existing approved DLLs are unchanged.'}
with out.open('x') as stream:
    json.dump(report, stream, ensure_ascii=False, indent=2)
    stream.write('\n')
print(json.dumps({'static_files': len(records), 'linux_unbundled': sorted({n for r in records if r['platform']=='linux' for n in r['not_bundled_imports']}), 'windows_unbundled': sorted({n for r in records if r['platform']=='windows' for n in r['not_bundled_imports']})}, ensure_ascii=False))
