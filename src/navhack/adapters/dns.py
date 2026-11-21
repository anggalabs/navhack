"""DNS adapter: resolution plus scope sanity on the answers."""

from __future__ import annotations

import socket

from .. import util
from ..models import Fog, Kind, PlanStep, StepResult
from .base import ExecCtx, adapter, upsert_edge


@adapter("dns.resolve")
def resolve(ctx: ExecCtx, step: PlanStep) -> StepResult:
    host = step.target_key
    try:
        answers = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return StepResult(False, "resolve failed: %s" % exc)
    addresses = sorted({info[4][0] for info in answers})
    host_node = ctx.node(Kind.HOST.value, host, confidence=0.95, fog=Fog.CHARTED.value, attrs={"resolved": addresses})
    inside, outside = [], []
    for address in addresses:
        ok, _ = ctx.policy.scope.check(address)
        (inside if ok else outside).append(address)
        dns_node = ctx.node(
            Kind.DNS.value, "%s->%s" % (host, address), confidence=0.95, attrs={"host": host, "ip": address, "in_scope": ok}
        )
        upsert_edge(ctx, host_node, dns_node, "resolves", 0.95)
    note = "%d address(es)" % len(addresses)
    if outside:
        note += "; out of scope: %s" % ", ".join(outside[:4])
        ctx.scope_notes.append("%s resolves outside scope: %s" % (host, ", ".join(outside)))
    return StepResult(True, note, nodes=[host_node])


__all__ = ["resolve"]
