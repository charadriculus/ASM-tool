import os, sys, json, subprocess, time, signal, hashlib
from pathlib import Path
root=Path.cwd(); evidence=root/"planning/patch123/evidence"; label=sys.argv[1]; cmd=sys.argv[2:]
env={"PATH":"/home/charadriculus/opt/go1.26.6/bin:/usr/bin:/bin","HOME":str(root/"tmp/patch123/home"),"GOWORK":"off","GOTOOLCHAIN":"local","GOPROXY":"off","GOSUMDB":"off","GOTELEMETRY":"off","GOENV":"off","GOFLAGS":"-mod=readonly -p=1 -trimpath","GOMAXPROCS":"2","CGO_ENABLED":"0","GOOS":"linux","GOARCH":"amd64","GOMODCACHE":str(root/"tmp/patch123/modcache"),"GOCACHE":str(root/"tmp/patch123/cache"),"GOTMPDIR":str(root/"tmp/patch123/tmp"),"TMPDIR":str(root/"tmp/patch123/tmp")}
if label.startswith("race"):env.update(CGO_ENABLED="1",CC="/usr/bin/gcc")
if label.startswith("windows"):env.update(GOOS="windows",GOARCH="amd64",CGO_ENABLED="0")
for name in ["HOME","GOTMPDIR","GOCACHE"]:Path(env[name]).mkdir(parents=True,exist_ok=True)
def hashes():return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(list((root/"internal").rglob("*.go"))+list((root/"cmd").rglob("*.go"))+list((root/"tools").rglob("*.go"))+[root/"go.mod",root/"go.sum"]+list((root/"internal").rglob("*.json"))+list((root/"packaging/portable").glob("*patch122.lock.json"))+list((root/"assets").rglob("*.*"))+list((root/"testdata").rglob("*.*")))}
before=hashes(); start=time.time(); log=evidence/(label+".log")
if log.exists():raise SystemExit("evidence label already exists")
with log.open("wb") as f:
 proc=subprocess.Popen(cmd,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
 try:code=proc.wait(timeout=120);timeout=False
 except subprocess.TimeoutExpired:
  os.killpg(proc.pid,signal.SIGKILL);proc.wait();code=124;timeout=True
record={"command":cmd,"cwd":str(root),"environment":env,"exit_code":code,"timeout":timeout,"timeout_seconds":120,"wall_seconds":time.time()-start,"log_sha256":hashlib.sha256(log.read_bytes()).hexdigest(),"source_before":before,"source_after":hashes()}
(evidence/(label+".json")).write_text(json.dumps(record,ensure_ascii=False,indent=2)+"\n")
print(json.dumps({k:record[k] for k in ["command","exit_code","timeout","wall_seconds","log_sha256"]}));print(log.read_text(errors="replace")[-12000:]);sys.exit(code)
