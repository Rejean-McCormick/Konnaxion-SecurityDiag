from __future__ import annotations
import os
import re
from pathlib import Path
from securitydiag_core.scanner import bounded_text
from securitydiag_core.commands import run_command

def check_text(report,path,text,fid,pattern,message_ok,message_bad,verdict_bad="FAIL",recommendation=None):
    ok=bool(re.search(pattern,text,re.I|re.M))
    report.add(fid,"PASS" if ok else verdict_bad,"application_security",message_ok if ok else message_bad,
               path=path,recommendation=None if ok else recommendation)
    return ok



def _read(root: Path, rel: str) -> tuple[Path, str]:
    path = root / rel
    return path, (bounded_text(path, 1024 * 1024) or "") if path.exists() else ""




def _django_check_environment(dj: dict) -> dict[str, str]:
    """Build the subprocess environment for the local Django deploy check.

    Values declared in SecurityDiag config are intended to be synthetic,
    check-only values. They override the current process environment without
    mutating it.
    """
    configured = dj.get("environment", {})
    if configured is None:
        configured = {}
    if not isinstance(configured, dict):
        raise ValueError("application.django_check.environment must be an object of string values")

    env = os.environ.copy()
    for key, value in configured.items():
        if not isinstance(key, str) or not key or "\x00" in key or "=" in key:
            raise ValueError("application.django_check.environment contains an invalid variable name")
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError(
                f"application.django_check.environment[{key!r}] must be a string"
            )
        env[key] = value
    return env

def _check_common_auth_contract(cfg, report, root: Path, app: dict) -> None:
    base_path, base = _read(root, app.get("django_base_settings", "backend/config/settings/base.py"))
    prod_path, prod = _read(root, app.get("django_production_settings", "backend/config/settings/production.py"))
    urls_path, urls = _read(root, app.get("django_urls", "backend/config/urls.py"))
    models_path, models = _read(root, app.get("django_user_model", "backend/konnaxion/users/models.py"))
    adapters_path, adapters = _read(root, app.get("django_user_adapters", "backend/konnaxion/users/adapters.py"))
    requirements_path, requirements = _read(root, app.get("backend_requirements", "backend/requirements/base.txt"))
    frontend_env_path, frontend_env = _read(root, app.get("frontend_production_env", "frontend/env.production.example"))
    frontend_pkg_path, frontend_pkg = _read(root, app.get("frontend_package", "frontend/package.json"))

    oidc_capable = (
        "allauth.socialaccount.providers.openid_connect" in base
        and bool(re.search(r'["\']uid_field["\']\s*:\s*["\']sub["\']', base))
        and bool(re.search(r"COMMON_OIDC_ENABLED\s*=\s*env\.bool\(", base))
    )
    report.add(
        "app.auth.oidc_capability",
        "PASS" if oidc_capable else "FAIL",
        "authentication",
        "Optional django-allauth OpenID Connect capability uses subject (`sub`) as the provider UID."
        if oidc_capable
        else "Konnaxion common OIDC capability is missing or does not clearly use `sub` as the provider UID.",
        path=base_path,
    )

    local_login = bool(re.search(r"SOCIALACCOUNT_ONLY\s*=\s*False", base))
    report.add(
        "app.auth.local_login_preserved",
        "PASS" if local_login else "FAIL",
        "authentication",
        "Local django-allauth login remains enabled alongside optional federation."
        if local_login
        else "Local login preservation is not explicit (SOCIALACCOUNT_ONLY=False missing).",
        path=base_path,
    )

    no_email_autolink = bool(
        re.search(r"SOCIALACCOUNT_EMAIL_AUTHENTICATION\s*=\s*False", base)
        and re.search(r"SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT\s*=\s*False", base)
    )
    report.add(
        "app.auth.no_email_auto_link",
        "PASS" if no_email_autolink else "FAIL",
        "authentication",
        "Federated accounts are not silently linked by email."
        if no_email_autolink
        else "Email-based federated-account authentication/auto-connect is not clearly disabled.",
        path=base_path,
    )

    accounts_route = bool(
        re.search(
            r"path\(\s*[\"']accounts/[\"']\s*,\s*include\(\s*[\"']allauth\.urls[\"']\s*\)",
            urls,
        )
    )
    legacy_token = bool(re.search(r"\bobtain_auth_token\b|api/auth-token", urls, re.I))
    report.add(
        "app.auth.accounts_route",
        "PASS" if accounts_route else "FAIL",
        "authentication",
        "Canonical /accounts/ django-allauth route is present."
        if accounts_route
        else "Canonical /accounts/ django-allauth route is missing.",
        path=urls_path,
    )
    report.add(
        "app.auth.legacy_drf_token_endpoint",
        "FAIL" if legacy_token else "PASS",
        "authentication",
        "Legacy DRF username/password auth-token endpoint is exposed."
        if legacy_token
        else "Legacy DRF username/password auth-token endpoint is absent.",
        path=urls_path,
    )

    interactive_policy = (
        "def can_interactive_login" in models
        and "user.can_interactive_login" in adapters
    )
    report.add(
        "app.auth.interactive_account_policy",
        "PASS" if interactive_policy else "FAIL",
        "authentication",
        "Human/service/klone interactive-login policy is represented in the user model and enforced by the allauth adapter."
        if interactive_policy
        else "Interactive-login restrictions for service/klone accounts are incomplete.",
        evidence={
            "model_policy": "def can_interactive_login" in models,
            "adapter_enforcement": "user.can_interactive_login" in adapters,
        },
        path=models_path,
    )

    csrf_ok = bool(
        re.search(r"CSRF_COOKIE_SECURE\s*=\s*True", prod)
        and re.search(r"CSRF_COOKIE_HTTPONLY\s*=\s*False", prod)
        and re.search(r"CSRF_COOKIE_NAME\s*=\s*['\"]csrftoken['\"]", prod)
    )
    admin_allauth = bool(re.search(r"DJANGO_ADMIN_FORCE_ALLAUTH\s*=\s*True", prod))
    report.add(
        "app.auth.browser_csrf_contract",
        "PASS" if csrf_ok else "FAIL",
        "authentication",
        "Production CSRF cookie contract matches the browser session client."
        if csrf_ok
        else "Production CSRF cookie contract is inconsistent with the browser session client.",
        path=prod_path,
    )
    report.add(
        "app.auth.admin_allauth",
        "PASS" if admin_allauth else "FAIL",
        "authentication",
        "Production Django admin login is forced through allauth."
        if admin_allauth
        else "Production Django admin is not clearly forced through allauth.",
        path=prod_path,
    )

    same_origin = bool(
        re.search(r"^\s*NEXT_PUBLIC_API_BASE\s*=\s*/api\s*$", frontend_env, re.M)
    )
    report.add(
        "app.auth.same_origin_api",
        "PASS" if same_origin else "WARN",
        "authentication",
        "Frontend production example uses same-origin /api."
        if same_origin
        else "Frontend production API base is not clearly same-origin /api.",
        path=frontend_env_path,
        recommendation=None if same_origin else "Prefer NEXT_PUBLIC_API_BASE=/api for the documented same-origin production topology.",
    )

    oidc_requirements = bool(
        re.search(r"django-allauth\[[^\]]*socialaccount[^\]]*\]", requirements, re.I)
    )
    report.add(
        "app.auth.oidc_dependencies",
        "PASS" if oidc_requirements else "FAIL",
        "supply_chain",
        "django-allauth socialaccount dependencies are declared for OIDC."
        if oidc_requirements
        else "django-allauth socialaccount dependency extra is not declared.",
        path=requirements_path,
    )

    auth0_residue = []
    for rel in (
        "frontend/lib/auth0.ts",
        "frontend/components/auth0-components/index.tsx",
        "frontend/app/providers/AuthProvider.tsx",
    ):
        if (root / rel).exists():
            auth0_residue.append(rel)
    if "@auth0/" in frontend_pkg:
        auth0_residue.append("frontend/package.json:@auth0")
    report.add(
        "app.auth.legacy_auth0_residue",
        "WARN" if auth0_residue else "PASS",
        "authentication",
        "Legacy Auth0 frontend residue remains."
        if auth0_residue
        else "Legacy Auth0 frontend scaffolding/dependencies are absent.",
        evidence=auth0_residue or None,
        path=frontend_pkg_path,
    )


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

    _check_common_auth_contract(cfg, report, root, app)

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
            try:
                check_env = _django_check_environment(dj)
            except ValueError as exc:
                report.add(
                    "app.django.check_deploy",
                    "CONFIG_ERROR",
                    "application_security",
                    str(exc),
                )
            else:
                r=run_command(
                    dj.get("command"),
                    cwd=cwd,
                    timeout_seconds=int(dj.get("timeout_seconds",180)),
                    env=check_env,
                )
                report.add("app.django.check_deploy","PASS" if r["exit_code"]==0 else "FAIL","application_security",
                           "Django check --deploy passed." if r["exit_code"]==0 else "Django check --deploy failed.",
                           evidence={
                               "exit_code":r["exit_code"],
                               "stdout_tail":r["stdout_tail"][-8000:],
                               "stderr_tail":r["stderr_tail"][-8000:],
                               "configured_environment_keys":sorted(dj.get("environment",{}).keys()),
                           })
    else:
        required=cfg.get("phase")=="production" and app.get("require_django_check_in_production",True)
        report.add("app.django.check_deploy","BLOCKED" if required else "SKIP","application_security",
                   "Django check --deploy is required in production but disabled." if required else "Runtime Django production check is disabled in config.",
                   recommendation="Enable application.django_check with a reviewed production-settings command/environment before release." if required else None)
