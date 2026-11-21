"""Domain adapters that delegate to well-known external tools.

These do not pretend: when the tool is missing they return ``needs_tool`` with
the command the operator should run.  ``navhack doctor`` shows which are
installed, and every report step keeps the exact recipe.
"""

from __future__ import annotations

import shutil
from typing import Dict, List

from .. import util
from ..models import Kind, PlanStep, StepResult
from .base import ExecCtx, adapter, needs_tool

TOOL_HINTS = {
    "ad.smb_enum": ("smbclient|netexec", "pkg install samba on Termux; pipx install netexec"),
    "ad.read_share": ("smbclient", "pkg install samba"),
    "ad.kerberoast": ("impacket-GetUserSPNs", "pip install impacket"),
    "ad.pass_the_hash": ("netexec", "pipx install netexec"),
    "ad.secretsdump": ("impacket-secretsdump", "pip install impacket"),
    "ad.dcsync": ("impacket-secretsdump", "pip install impacket"),
    "ad.adcs_esc1": ("certipy", "pipx install certipy-ad"),
    "cloud.imds_ssrf": ("curl", "pkg install curl"),
    "cloud.enumerate_iam": ("aws", "pip install awscli"),
    "cloud.assume_role": ("aws", "pip install awscli"),
    "cloud.s3_enum": ("aws", "pip install awscli"),
    "cloud.s3_read": ("aws", "pip install awscli"),
    "linux.enum_privesc": ("sh", "built-in; run the printed commands in the shell you hold"),
    "generic.exfiltrate": ("tar|base64", "built-in via the shell you hold"),
}


def _first_tool(spec: str):
    for candidate in spec.split("|"):
        found = shutil.which(candidate)
        if found:
            return candidate, found
    return None, None


@adapter("ad.smb_enum")
def smb_enum(ctx: ExecCtx, step: PlanStep) -> StepResult:
    tool, path = _first_tool("smbclient")
    if path is None:
        return needs_tool(*TOOL_HINTS["ad.smb_enum"])
    from .. import platform_compat

    host = step.target_key
    code, out, err = platform_compat.run_capture(["smbclient", "-L", "//%s" % host, "-N"], timeout=30)
    if code != 0:
        return StepResult(False, util.clip(err or out, 200))
    node = ctx.node(Kind.SERVICE.value, "%s/smb" % host, confidence=0.8, attrs={"host": host, "service": "smb"})
    return StepResult(True, util.clip(out, 300), nodes=[node])


@adapter("ad.read_share")
def read_share(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["ad.read_share"])


@adapter("ad.kerberoast")
def kerberoast(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["ad.kerberoast"])


@adapter("ad.pass_the_hash")
def pass_the_hash(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["ad.pass_the_hash"])


@adapter("ad.secretsdump")
def secretsdump(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["ad.secretsdump"])


@adapter("ad.dcsync")
def dcsync(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["ad.dcsync"])


@adapter("ad.adcs_esc1")
def adcs_esc1(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["ad.adcs_esc1"])


@adapter("cloud.imds_ssrf")
def imds_ssrf(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["cloud.imds_ssrf"])


@adapter("cloud.enumerate_iam")
def enumerate_iam(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["cloud.enumerate_iam"])


@adapter("cloud.assume_role")
def assume_role(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["cloud.assume_role"])


@adapter("cloud.s3_enum")
def s3_enum(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["cloud.s3_enum"])


@adapter("cloud.s3_read")
def s3_read(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(*TOOL_HINTS["cloud.s3_read"])


@adapter("linux.enum_privesc")
def enum_privesc(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool(
        "sudo",
        "run: sudo -l ; find / -perm -4000 -type f 2>/dev/null ; getcap -r / 2>/dev/null",
    )


@adapter("generic.exfiltrate")
def exfiltrate(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return needs_tool("tar", TOOL_HINTS["generic.exfiltrate"][1])


__all__ = list(TOOL_HINTS)
