from __future__ import annotations
import os, shlex, subprocess, time
from pathlib import Path
from .util import redact, tail_text

def normalize_command(command):
    if isinstance(command,str):
        return shlex.split(command,posix=(os.name!="nt"))
    if isinstance(command,list) and all(isinstance(x,str) for x in command):
        return command
    raise ValueError("command must be string or list[str]")

def run_command(command, *, cwd: Path, timeout_seconds=120, capture_limit_kb=256,
                env=None, input_text=None):
    argv=normalize_command(command)
    started=time.monotonic()
    try:
        cp=subprocess.run(argv,cwd=str(cwd),env=env,stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                          input=input_text,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,encoding="utf-8",errors="replace",
                          timeout=timeout_seconds,shell=False,check=False)
        timed_out=False; code=cp.returncode; out=cp.stdout or ""; err=cp.stderr or ""
    except subprocess.TimeoutExpired as e:
        timed_out=True; code=None
        out=e.stdout.decode("utf-8","replace") if isinstance(e.stdout,bytes) else (e.stdout or "")
        err=e.stderr.decode("utf-8","replace") if isinstance(e.stderr,bytes) else (e.stderr or "")
    limit=int(capture_limit_kb)*1024
    return {
        "argv":argv,
        "exit_code":code,
        "timed_out":timed_out,
        "duration_seconds":round(time.monotonic()-started,3),
        "stdout_tail":tail_text(redact(out),limit),
        "stderr_tail":tail_text(redact(err),limit),
    }
