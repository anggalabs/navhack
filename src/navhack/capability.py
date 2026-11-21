"""Capability engine: what the tool can actually do *right now*.

The planner is only allowed to use moves whose preconditions are backed by real
capabilities.  Capabilities are derived from the world model (never guessed),
plus explicit ``--grant`` tags for things a human knows (a valid credential,
a VPN position, an existing session).

Tag namespace produced here::

    host:up, port:tcp, service:*, url:base, url:params, path:known,
    tech:known, auth:session, cred:*, primitive:*, source:code, identity:*,
    network:internal, objective:*
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from .models import Finding, FindingStatus, Fog, Kind, Node
from .store import Store

USABLE_FOG = (Fog.SEEN.value, Fog.CHARTED.value, Fog.VERIFIED.value)

FINDING_TAG = {
    "file_read": "primitive:file_read",
    "file_write": "primitive:file_write",
    "rce": "primitive:rce",
    "exec": "primitive:exec",
    "db_read": "primitive:db_read",
    "exec_client": "primitive:exec_client",
    "ssrf": "network:internal",
    "open_redirect": "primitive:redirect",
    "exposure": "finding:exposure",
    "xss": "finding:xss",
    "sqli": "finding:sqli",
    "lfi": "finding:lfi",
}

SERVICE_TAGS = {
    "http": "service:http",
    "https": "service:http",
    "ssl/http": "service:http",
    "smb": "service:smb",
    "microsoft-ds": "service:smb",
    "ssh": "service:ssh",
    "smtp": "service:smtp",
    "ftp": "service:ftp",
    "mysql": "service:mysql",
    "postgresql": "service:postgres",
    "redis": "service:redis",
    "snmp": "service:snmp",
    "rdp": "service:rdp",
    "ldap": "service:ldap",
}


@dataclass
class Capabilities:
    tags: Set[str] = field(default_factory=set)
    targets: Dict[str, List[Node]] = field(default_factory=dict)
    sources: Dict[str, str] = field(default_factory=dict)

    def add_tag(self, tag: str, source: str = "derived") -> None:
        if tag and tag not in self.tags:
            self.tags.add(tag)
            self.sources[tag] = source

    def add_node(self, tag: str, node: Node, source: str = "derived") -> None:
        self.add_tag(tag, source)
        bucket = self.targets.setdefault(tag, [])
        if all(existing.node_id != node.node_id for existing in bucket):
            bucket.append(node)

    def has(self, tag: str) -> bool:
        return tag in self.tags

    def missing(self, tags) -> List[str]:
        return [tag for tag in tags if tag not in self.tags]

    def candidates(self, kind: str, tag_hint: str = "") -> List[Node]:
        bucket = list(self.targets.get(tag_hint, [])) if tag_hint else []
        if bucket:
            return bucket
        return []

    def summary(self) -> Dict[str, object]:
        return {
            "tags": sorted(self.tags),
            "targets": {tag: [n.key for n in nodes] for tag, nodes in self.targets.items()},
        }


def _node_tag(node: Node) -> List[str]:
    tags: List[str] = []
    if node.kind == Kind.HOST.value:
        tags.append("host:up")
        if node.attrs.get("owned"):
            tags.append("host:owned")
    elif node.kind == Kind.PORT.value:
        tags.append("port:tcp")
        tags.append("port:%s" % node.attrs.get("port", node.key))
    elif node.kind == Kind.SERVICE.value:
        name = str(node.attrs.get("service") or node.key).lower()
        if name in SERVICE_TAGS:
            tags.append(SERVICE_TAGS[name])
        elif name.startswith("http"):
            tags.append("service:http")
    elif node.kind == Kind.URL.value:
        tags.append("url:base")
        if node.attrs.get("params"):
            tags.append("url:params")
    elif node.kind == Kind.PATH.value:
        tags.append("path:known")
    elif node.kind == Kind.TECH.value:
        tags.append("tech:known")
    elif node.kind == Kind.CRED.value:
        subtype = str(node.attrs.get("subtype") or "secret")
        tags.append("cred:%s" % subtype)
        tags.append("cred:any")
    elif node.kind == Kind.IDENTITY.value:
        tags.append("identity:%s" % (node.attrs.get("level") or node.key))
        tags.append("auth:session")
    elif node.kind == Kind.DNS.value:
        tags.append("host:resolved")
    elif node.kind == Kind.SHARE.value:
        tags.append("share:known")
    elif node.kind == Kind.FINDING.value:
        primitive = str(node.attrs.get("primitive") or "")
        if primitive and node.confidence >= 0.7:
            mapped = FINDING_TAG.get(primitive)
            if mapped:
                tags.append(mapped)
    elif node.attrs.get("internal"):
        tags.append("network:internal")
    return tags


def collect(
    store: Store,
    *,
    granted: List[str] = (),
    entry_hosts: List[str] = (),
) -> Capabilities:
    caps = Capabilities()
    for entry in entry_hosts:
        caps.add_tag("entry", "scope")
        caps.add_tag("host:resolved", "scope")
        caps.add_node("host:resolved", Node(kind=Kind.HOST.value, key=entry, provenance="scope"))
    for tag in granted:
        caps.add_tag(tag.strip(), "grant")

    for node in store.find_nodes(fog=USABLE_FOG, min_confidence=0.25, limit=2000):
        for tag in _node_tag(node):
            caps.add_node(tag, node, node.provenance)

    for finding in store.findings(status=FindingStatus.CONFIRMED.value, limit=500):
        tag = FINDING_TAG.get(finding.primitive)
        if tag:
            caps.add_tag(tag, "finding:%d" % (finding.finding_id or 0))

    for tag in store.tags():
        caps.add_tag(tag, "tag")

    # Derived closures: a charted URL implies a host that is up and a service.
    for tag in list(caps.tags):
        if tag == "url:base":
            caps.add_tag("service:http", "closure")
            caps.add_tag("host:up", "closure")
        if tag == "path:known":
            caps.add_tag("service:http", "closure")
            caps.add_tag("url:base", "closure")
        if tag.startswith("primitive:"):
            caps.add_tag("host:up", "closure")
        if tag == "auth:session":
            caps.add_tag("url:base", "closure")
        if tag == "share:known":
            caps.add_tag("service:smb", "closure")
        if tag == "source:code":
            caps.add_tag("primitive:file_read", "closure")
    return caps


def finding_tags(finding: Finding) -> List[str]:
    tags = []
    tag = FINDING_TAG.get(finding.primitive)
    if tag:
        tags.append(tag)
    return tags
