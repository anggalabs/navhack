"""Network adapters: liveness, port scan, banner grab.  No raw sockets."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple

from .. import httpio, util
from ..data import COMMON_PORTS, HTTP_PORTS
from ..models import Fog, Kind, PlanStep, StepResult
from .. import platform_compat as plat
from .base import ExecCtx, adapter, needs_tool, not_in_dry_run, upsert_edge


@adapter("net.probe_host")
def probe_host(ctx: ExecCtx, step: PlanStep) -> StepResult:
    host = step.target_key
    probe_ports = [80, 443, 22, 445, 8080, 3389, 21, 25, 53, 8000]
    opened: List[int] = []
    errors: List[str] = []
    for port in probe_ports:
        ok, elapsed, error = httpio.probe_tcp(host, port, policy=ctx.policy, timeout=1.5)
        if ok:
            opened.append(port)
        elif error:
            errors.append("%s:%s" % (port, error))
        if len(opened) >= 3:
            break
        if ctx.policy.aborted:
            break
    if not opened:
        detail = errors[-1] if errors else "no response"
        node = ctx.node(Kind.HOST.value, host, confidence=0.3, fog=Fog.SEEN.value, attrs={"alive": False})
        return StepResult(False, "closed/filtered (%s)" % util.clip(detail, 80), nodes=[node])
    node = ctx.node(
        Kind.HOST.value,
        host,
        confidence=0.9,
        fog=Fog.CHARTED.value,
        attrs={"alive": True, "open": opened},
    )
    for port in opened:
        port_node = ctx.node(
            Kind.PORT.value,
            "%s:%d" % (host, port),
            confidence=0.85,
            attrs={"host": host, "port": port},
        )
        upsert_edge(ctx, node, port_node, "exposes", 0.9)
    return StepResult(True, "open: %s" % ", ".join(map(str, opened)), nodes=[node])


def _scan(ctx: ExecCtx, host: str, ports: List[int]) -> List[int]:
    open_ports: List[int] = []
    workers = max(1, min(ctx.policy.budget.concurrency, 32))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(httpio.probe_tcp, host, port, policy=ctx.policy, timeout=1.2): port
            for port in ports
        }
        for future in futures:
            port = futures[future]
            try:
                ok, _elapsed, _error = future.result()
            except Exception:
                ok = False
            if ok:
                open_ports.append(port)
            if ctx.policy.aborted:
                break
    return sorted(open_ports)


@adapter("net.scan_ports")
def scan_ports(ctx: ExecCtx, step: PlanStep) -> StepResult:
    host = step.target_key
    extra = list(step.move.__dict__.get("extra_ports") or [])
    ports = list(dict.fromkeys(COMMON_PORTS + extra))
    skip = ctx.store.find_nodes(kinds=[Kind.PORT.value], min_confidence=0.5, limit=200)
    known = {n.attrs.get("port") for n in skip if n.attrs.get("host") == host}
    ports = [p for p in ports if p not in known]
    if not ports:
        return StepResult(True, "already scanned")
    started = time.monotonic()
    found = _scan(ctx, host, ports)
    host_node = ctx.node(Kind.HOST.value, host, confidence=0.9, fog=Fog.CHARTED.value)
    for port in found:
        port_node = ctx.node(
            Kind.PORT.value, "%s:%d" % (host, port), confidence=0.9, attrs={"host": host, "port": port}
        )
        upsert_edge(ctx, host_node, port_node, "exposes", 0.9)
    ctx.policy.spend(noise=2)
    detail = "open %d/%d: %s" % (len(found), len(ports), ", ".join(map(str, found)) or "-")
    return StepResult(bool(found), detail, elapsed=time.monotonic() - started, nodes=[host_node])


@adapter("net.grab_banner")
def grab_banner(ctx: ExecCtx, step: PlanStep) -> StepResult:
    node = ctx.store.node_by_key(Kind.PORT.value, step.target_key)
    if node is None:
        return StepResult(False, "unknown port %s" % step.target_key)
    host = str(node.attrs.get("host") or step.target_key.split(":")[0])
    port = int(node.attrs.get("port") or step.target_key.rsplit(":", 1)[-1])
    if node.kind != Kind.PORT.value:
        return StepResult(False, "not a port node")
    ctx.policy.gate_host(host, port)
    banner = b""
    error = ""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=3.0)
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        sock.settimeout(2.5)
        try:
            banner = sock.recv(1024)
        except socket.timeout:
            banner = b""
    except OSError as exc:
        error = str(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    if not banner and error:
        return StepResult(False, "no banner: %s" % util.clip(error, 80))
    text = util.printable(banner, 800)
    server = ""
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    guess = "http" if ("HTTP/" in text or port in HTTP_PORTS) else (server or "unknown")
    service = ctx.node(
        Kind.SERVICE.value,
        "%s:%d/%s" % (host, port, guess),
        confidence=0.75,
        attrs={"host": host, "port": port, "service": guess, "server": server, "banner": util.clip(text, 400)},
    )
    upsert_edge(ctx, node, service, "runs", 0.8)
    if server:
        tech = ctx.node(Kind.TECH.value, server, confidence=0.7, attrs={"host": host})
        upsert_edge(ctx, service, tech, "powered_by", 0.7)
    return StepResult(True, "banner: %s" % util.clip(text.replace("\r", " ").replace("\n", " "), 100), nodes=[service])


@adapter("net.snmp_read")
def snmp_read(ctx: ExecCtx, step: PlanStep) -> StepResult:
    if plat.which("snmpwalk") is None:
        return needs_tool("snmpwalk", "install net-snmp; pkg install net-snmp on Termux")
    from .. import platform_compat

    code, out, err = platform_compat.run_capture(
        ["snmpwalk", "-v2c", "-c", "public", "-t", "2", "-r", "1", step.target_key, "1.3.6.1.2.1.1"],
        timeout=25,
    )
    if code != 0:
        return StepResult(False, util.clip(err or "snmp failed", 160))
    node = ctx.node(Kind.HOST.value, step.target_key, confidence=0.7, attrs={"snmp": True})
    ctx.store.grant_tag("cred:community")
    return StepResult(True, "sysDescr: %s" % util.clip(out, 160), nodes=[node])


@adapter("net.pivot")
def pivot(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(
        "ssh|chisel|ligolo",
        "start a tunnel, then `navhack scope add <internal-cidr>` and run recon through it",
    )


__all__ = ["probe_host", "scan_ports", "grab_banner", "snmp_read", "pivot", "Tuple"]
