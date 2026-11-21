"""Engagement scope enforcement.

Every network operation funnels through :meth:`Scope.check`, so an accidental
third-party redirect or a pivot to a CDN host cannot silently leave scope.

Accepted entry syntax::

    example.com            apex + any subdomain
    *.example.com          subdomains only
    corp.example.com:8443  single host, port pinned
    10.10.0.0/16           CIDR
    10.10.0.5-10.10.0.40   IP range
    https://app.example.com/portal

Rule: a host is in scope when it *equals* a host entry, is a subdomain of a
bare domain entry, matches a wildcard, or falls inside a network range.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlsplit


class ScopeError(RuntimeError):
    pass


def _strip_host(raw: str) -> str:
    text = (raw or "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        text = urlsplit(text).netloc or ""
    if text.startswith("["):  # [v6]:port
        close = text.find("]")
        return text[1:close] if close > 0 else text
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text.rstrip(".")


@dataclass
class Rule:
    raw: str
    kind: str  # domain | wildcard | cidr | range | ip
    value: object
    port: Optional[int] = None

    def matches(self, host: str, port: Optional[int] = None) -> bool:
        if self.port is not None and port is not None and port != self.port:
            return False
        target = host.lower().rstrip(".")
        if self.kind == "domain":
            return target == self.value or target.endswith("." + str(self.value))
        if self.kind == "wildcard":
            return target != self.value and target.endswith("." + str(self.value))
        if self.kind == "ip":
            try:
                return ipaddress.ip_address(target) == self.value
            except ValueError:
                return False
        if self.kind == "cidr":
            try:
                return ipaddress.ip_address(target) in self.value
            except ValueError:
                return False
        if self.kind == "range":
            try:
                return self.value[0] <= ipaddress.ip_address(target) <= self.value[1]
            except ValueError:
                return False
        return False

    def describe(self) -> str:
        suffix = ":%d" % self.port if self.port else ""
        return "%s (%s)%s" % (self.raw, self.kind, suffix)


def parse_rule(raw: str) -> Rule:
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty scope entry")
    port: Optional[int] = None
    candidate = text
    if "://" in candidate:
        parts = urlsplit(candidate)
        candidate = parts.netloc
        if parts.port:
            port = parts.port
    if candidate.startswith("[") and "]" in candidate:
        host_part, _, rest = candidate[1:].partition("]")
        candidate = host_part
        if rest.startswith(":"):
            port = int(rest[1:])
    elif candidate.count(":") == 1:
        left, _, right = candidate.partition(":")
        if right.isdigit():
            candidate, port = left, int(right)

    candidate = candidate.lower().rstrip(".")
    if candidate.startswith("*."):
        base = candidate[2:]
        if not _is_domain(base):
            raise ValueError("bad wildcard entry: %r" % raw)
        return Rule(raw=raw, kind="wildcard", value=base, port=port)
    if "/" in candidate:
        return Rule(raw=raw, kind="cidr", value=ipaddress.ip_network(candidate, strict=False), port=port)
    if "-" in candidate and candidate.count("-") == 1:
        left, _, right = candidate.partition("-")
        try:
            start = ipaddress.ip_address(left)
            end = ipaddress.ip_address(right)
            return Rule(raw=raw, kind="range", value=(start, end), port=port)
        except ValueError:
            pass
    try:
        return Rule(raw=raw, kind="ip", value=ipaddress.ip_address(candidate), port=port)
    except ValueError:
        pass
    if _is_domain(candidate):
        return Rule(raw=raw, kind="domain", value=candidate, port=port)
    raise ValueError("cannot interpret scope entry: %r" % raw)


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value)) or value in ("localhost",)


@dataclass
class Scope:
    rules: List[Rule] = field(default_factory=list)

    @classmethod
    def parse(cls, entries: List[str]) -> "Scope":
        return cls(rules=[parse_rule(entry) for entry in entries if entry.strip()])

    def add(self, entry: str) -> Rule:
        rule = parse_rule(entry)
        if all(existing.raw != rule.raw for existing in self.rules):
            self.rules.append(rule)
        return rule

    def check(self, host: str, port: Optional[int] = None) -> Tuple[bool, str]:
        target = _strip_host(host)
        if not target:
            return False, "empty host"
        if not self.rules:
            return False, "scope is empty (add entries with `navhack scope add`)"
        for rule in self.rules:
            if rule.matches(target, port):
                return True, rule.describe()
        return False, "%s not covered by %d scope rule(s)" % (
            target if port is None else "%s:%s" % (target, port),
            len(self.rules),
        )

    def require(self, host: str, port: Optional[int] = None) -> str:
        ok, reason = self.check(host, port)
        if not ok:
            raise ScopeError(reason)
        return reason

    def entries(self) -> List[str]:
        return [rule.raw for rule in self.rules]

    def describe(self) -> str:
        return ", ".join(rule.describe() for rule in self.rules) or "(empty)"

    def __len__(self) -> int:
        return len(self.rules)
