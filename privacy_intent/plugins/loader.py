
"""Optional plugin discovery and execution."""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Callable

from privacy_intent.models import ScanReport

PluginFunc = Callable[[ScanReport], list]


def load_plugins(group: str = "privacyintent.plugins") -> list[PluginFunc]:
    loaded: list[PluginFunc] = []
    try:
        eps = entry_points()
        selected = eps.select(group=group) if hasattr(eps, "select") else eps.get(group, [])
    except Exception:
        return loaded

    for ep in selected:
        try:
            candidate = ep.load()
            if callable(candidate):
                loaded.append(candidate)
        except Exception:
            continue
    return loaded


def apply_plugins(report: ScanReport) -> list:
    findings = []
    for plugin in load_plugins():
        try:
            result = plugin(report)
            if isinstance(result, list):
                findings.extend(result)
        except Exception:
            continue
    return findings


