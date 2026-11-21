"""Adapter registry."""

from __future__ import annotations

from .base import ADAPTERS, AdapterFn, ExecCtx, register_all

register_all()

__all__ = ["ADAPTERS", "AdapterFn", "ExecCtx", "register_all", "available"]


def available() -> list:
    return sorted(ADAPTERS)
