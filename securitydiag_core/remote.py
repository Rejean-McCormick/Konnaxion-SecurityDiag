from __future__ import annotations
import re, shutil, subprocess, time
from pathlib import Path
from .util import redact, tail_text

class RemoteBlocked(RuntimeError): pass
SAFE_HOST=re.compile(r"^[A-Za-z0-9._:\-\[\]]+$")
SAFE_USER=re.compile(r"^[A-Za-z0-9._-]+$")

def remote_ready(cfg):
    if not cfg.get("execution",{}).get("allow_network",False):
        return False,"Network execution is disabled."
    r=cfg.get("remote",{})
    if not r.get("enabled",False): return False,"Remote VPS checks are disabled."
    if not shutil.which("ssh"): return False,"ssh executable was not found."
    host=str(r.get("host","")).strip(); user=str(r.get("user","")).strip()
    if not host or not SAFE_HOST.fullmatch(host): return False,"remote.host is missing or unsafe."
    if not user or not SAFE_USER.fullmatch(user): return False,"remote.user is missing or unsafe."
    return True,""

def ssh_argv(cfg):
    ok,msg=remote_ready(cfg)
    if not ok: raise RemoteBlocked(msg)
    r=cfg["remote"]; host=str(r["host"]); user=str(r["user"]); port=int(r.get("port",22))
    argv=["ssh","-p",str(port),"-o","BatchMode=yes",
          "-o",f"ConnectTimeout={int(r.get('connect_timeout_seconds',10))}",
          "-o",f"StrictHostKeyChecking={r.get('strict_host_key_checking','yes')}"]
    if r.get("identity_file"):
        argv += ["-i",str(Path(r["identity_file"]).expanduser())]
    if r.get("known_hosts_file"):
        argv += ["-o",f"UserKnownHostsFile={Path(r['known_hosts_file']).expanduser()}"]
    argv += [f"{user}@{host}"]
    return argv

def run_script(cfg, script, *, privileged=False, timeout_seconds=90):
    r=cfg.get("remote",{})
    if privileged:
        if r.get("sudo_mode","none")!="noninteractive":
            raise RemoteBlocked("Privileged remote evidence requires remote.sudo_mode=noninteractive.")
        remote_cmd="sudo -n bash -s"
    else:
        remote_cmd="bash -s"
    argv=ssh_argv(cfg)+[remote_cmd]
    started=time.monotonic()
    try:
        cp=subprocess.run(argv,input=script,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,encoding="utf-8",errors="replace",
                          timeout=timeout_seconds,shell=False,check=False)
        return {"exit_code":cp.returncode,"timed_out":False,
                "duration_seconds":round(time.monotonic()-started,3),
                "stdout_tail":tail_text(redact(cp.stdout or ""),256*1024),
                "stderr_tail":tail_text(redact(cp.stderr or ""),128*1024)}
    except subprocess.TimeoutExpired as e:
        out=e.stdout.decode("utf-8","replace") if isinstance(e.stdout,bytes) else (e.stdout or "")
        err=e.stderr.decode("utf-8","replace") if isinstance(e.stderr,bytes) else (e.stderr or "")
        return {"exit_code":None,"timed_out":True,
                "duration_seconds":round(time.monotonic()-started,3),
                "stdout_tail":tail_text(redact(out),256*1024),
                "stderr_tail":tail_text(redact(err),128*1024)}
