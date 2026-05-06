from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from app.services.mapping_loader import load_mapping

mapping = load_mapping()


def is_valid(val: Any) -> bool:
    if val is None:
        return False
    text = str(val).strip()
    return bool(text) and text.lower() not in {"-", "unknown", "system"}


def normalize_field(event: Dict[str, Any], aliases: Iterable[str]) -> Optional[str]:
    for key in aliases:
        val = event.get(key)
        if is_valid(val):
            return str(val).strip()
    return None


class NormalizedEvent:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.user = normalize_field(raw, mapping["user"])
        self.src = normalize_field(raw, mapping["src"])
        self.dest = normalize_field(raw, mapping["dest"])
