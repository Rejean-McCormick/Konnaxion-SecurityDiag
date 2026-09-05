from __future__ import annotations
import re
from pathlib import Path
from securitydiag_core.scanner import bounded_text
from securitydiag_core.commands import run_command

def check_text(report,path,text,fid,pattern,message_ok,message_bad,verdict_bad="FAIL",recommendation=None):
    ok=bool(re.search(pattern,text,re.I|re.M))
    report.add(fid,"PASS" if ok else verdict_bad,"application_security",message_ok if ok else message_bad,
               path=path,recommendation=None if ok else recommendation)
    return ok

def run(cfg,report):
    root=Path(cfg["_target_root"]); app=cfg.get("application",{})
    prod=root/app.get("django_production_settings","backend/config/settings/production.py")
    if prod.exists():
        text=bounded_text(prod,1024*1024) or ""
        check_text(report,prod,text,"app.django.secret_key.external",r'SECRET_KEY\s*=\s*env\(',
                   "Django SECRET_KEY is sourced from environment.","Django SECRET_KEY is not clearly sourced from environment.",
                   recommendation="Load production SECRET_KEY from an environment/secret store.")
        check_text(report,prod,text,"app.django.allowed_hosts.external",r'ALLOWED_HOSTS\s*=\s*env\.list\(',
                   "ALLOWED_HOSTS is environment-driven.","ALLOWED_HOSTS is not clearly environment-driven.")
        check_text(report,prod,text,"app.django.ssl_redirect",r'SECURE_SSL_REDIRECT\s*=\s*(?:env\.bool\([^\n]+default\s*=\s*True|True)',
                   "HTTPS redirect is enabled/default-on.","SECURE_SSL_REDIRECT is not clearly enabled.",recommendation="Enable HTTPS redirect in production.")
        check_text(report,prod,text,"app.django.session_cookie_secure",r'SESSION_COOKIE_SECURE\s*=\s*True',
                   "Session cookie is Secure.","SESSION_COOKIE_SECURE=True was not found.")
        check_text(report,prod,text,"app.django.csrf_cookie_secure",r'CSRF_COOKIE_SECURE\s*=\s*True',
                   "CSRF cookie is Secure.","CSRF_COOKIE_SECURE=True was not found.")
        check_text(report,prod,text,"app.django.hsts",r'SECURE_HSTS_SECONDS\s*=\s*[1-9]\d*',
                   "HSTS is enabled.","HSTS is not clearly enabled.",verdict_bad="WARN")
    else:
        report.add("app.django.production_settings","BLOCKED","application_security","Django production settings file was not found.",path=prod)

    compose=root/app.get("production_compose","backend/docker-compose.production.yml")
    if compose.exists():
        text=bounded_text(compose,1024*1024) or ""
        published=[]
        for i,line in enumerate(text.splitlines(),1):
            if re.search(r'["\']?(?:0\.0\.0\.0:)?(\d+):(\d+)["\']?',line):
                m=re.search(r'(?:0\.0\.0\.0:)?(\d+):(\d+)',line)
                if m: published.append({"line":i,"host_port":int(m.group(1)),"container_port":int(m.group(2))})
        forbidden=set(cfg.get("remote",{}).get("forbidden_public_ports",[]))
        bad=[x for x in published if x["host_port"] in forbidden]
        report.add("app.compose.public_ports","FAIL" if bad else "PASS","network",
                   "Production compose publishes forbidden internal ports." if bad else "Production compose does not publish configured forbidden internal ports.",
                   evidence={"published":published,"forbidden_matches":bad})
        flower_public=any(x["host_port"]==5555 for x in published)
        report.add("app.flower.public_exposure","FAIL" if flower_public else "PASS","network",
                   "Flower is publicly published." if flower_public else "Flower is not publicly published by production compose.")
    else:
        report.add("app.compose.production","BLOCKED","application_security","Production compose file was not found.",path=compose)

    nextcfg=root/app.get("frontend_next_config","frontend/next.config.ts")
    if nextcfg.exists():
        text=bounded_text(nextcfg,1024*1024) or ""
        prod_local=bool(re.search(r"NODE_ENV\s*===\s*['\"]production['\"][\\s\\S]{0,250}localhost",text,re.I))
        report.add("app.frontend.production_localhost","WARN" if prod_local else "PASS","application_security",
                   "Production branch appears to reference localhost." if prod_local else "No obvious production-only localhost API fallback found.",
                   path=nextcfg,recommendation="Use same-origin or explicit production API origin." if prod_local else None)

    dj=app.get("django_check",{})
    if dj.get("enabled",False):
        cwd=(root/dj.get("cwd","backend")).resolve(strict=False)
        if not cwd.is_relative_to(root):
            report.add("app.django.check_deploy","CONFIG_ERROR","application_security","Django check cwd escapes repository.")
        else:
            r=run_command(dj.get("command"),cwd=cwd,timeout_seconds=int(dj.get("timeout_seconds",180)))
            report.add("app.django.check_deploy","PASS" if r["exit_code"]==0 else "FAIL","application_security",
                       "Django check --deploy passed." if r["exit_code"]==0 else "Django check --deploy failed.",
                       evidence={"exit_code":r["exit_code"],"stdout_tail":r["stdout_tail"][-8000:],"stderr_tail":r["stderr_tail"][-8000:]})
    else:
        required=cfg.get("phase")=="production" and app.get("require_django_check_in_production",True)
        report.add("app.django.check_deploy","BLOCKED" if required else "SKIP","application_security",
                   "Django check --deploy is required in production but disabled." if required else "Runtime Django production check is disabled in config.",
                   recommendation="Enable application.django_check with a reviewed production-settings command/environment before release." if required else None)
