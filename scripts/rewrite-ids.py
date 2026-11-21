"""Rewrite all commits to the anggalabs identity without a shell.

Git for Windows' MSYS sh is broken in this sandbox, so rebase/filter-branch
(which shell out) cannot be used.  Plumbing only: commit-tree + reset.

History is linear, so each rewritten commit gets the *previous rewritten*
commit as parent (using the original parent would leave the old chain attached).
"""

from __future__ import annotations

import os
import subprocess

NAME = "anggalabs"
EMAIL = "341025173+anggalabs@users.noreply.github.com"


def sh(*args: str) -> str:
    return subprocess.run(list(args), capture_output=True, text=True, check=True).stdout


head = sh("git", "rev-parse", "HEAD").strip()
tree_head = sh("git", "rev-parse", "HEAD^{tree}").strip()
commits = sh("git", "rev-list", "--reverse", "--topo-order", "HEAD").split()
print("rewriting", len(commits), "commits")

parent = None
for sha in commits:
    tree = sh("git", "rev-parse", sha + "^{tree}").strip()
    message = sh("git", "log", "-1", "--format=%B", sha)
    when = sh("git", "log", "-1", "--format=%aI", sha).strip()

    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": NAME,
            "GIT_AUTHOR_EMAIL": EMAIL,
            "GIT_AUTHOR_DATE": when,
            "GIT_COMMITTER_NAME": NAME,
            "GIT_COMMITTER_EMAIL": EMAIL,
            "GIT_COMMITTER_DATE": when,
        }
    )
    args = ["git", "commit-tree", tree]
    if parent:
        args += ["-p", parent]
    parent = subprocess.run(
        args, input=message, capture_output=True, text=True, env=env, check=True
    ).stdout.strip()

assert parent is not None
subprocess.run(["git", "reset", "--hard", parent], check=True, capture_output=True)

tree_new = sh("git", "rev-parse", "HEAD^{tree}").strip()
print("tree unchanged:", tree_head == tree_new)
print("commits now:", len(sh("git", "rev-list", "HEAD").split()))
print("new head:", parent)
