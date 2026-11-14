"""Shared helpers for the SE05x figures: read enumerations and constants from the frozen headers in inc/.

Every helper raises when the code no longer looks the way a figure expects, so a figure fails to build instead of
drawing something the code does not do.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIRE = "inc/se05x_wire.hpp"
T1 = "inc/se05x_t1.hpp"
CONFIRM = "inc/se05x_confirm.hpp"
LIFECYCLE = "inc/se05x_lifecycle.hpp"
IDS = "inc/se05x_ids.hpp"
TYPES = "inc/se05x_types.hpp"
POLICY = "inc/se05x_policy_types.hpp"
HROT = "inc/se05x_hrot.hpp"
SE052_PINS = "docs/diagrams/data/se052-pins.json"


def read(rel: str) -> str:
    return (ROOT / rel).read_text()


def need(pattern: str, text: str, what: str, flags: int = re.S) -> re.Match:
    m = re.search(pattern, text, flags)
    if not m:
        raise SystemExit(f"figure source drift: {what} not found (pattern {pattern!r})")
    return m


def enumerators(rel: str, name: str) -> list[str]:
    """The enumerator names of ``enum class <name>`` in order."""
    body = need(rf"enum class (?:\[\[nodiscard\]\] )?{name} : \w+ \{{(.*?)\n\}};", read(rel), f"enum {name}").group(1)
    return re.findall(r"^\s+(\w+)(?: =[^,\n]*)?,", body, re.M)


def constant(rel: str, name: str) -> int:
    """The value of ``inline constexpr <type> <name> = <number>;`` (hex or decimal)."""
    m = need(rf"inline constexpr \w+ {name} =\s*(0x[0-9A-Fa-f']+|[0-9']+)U?", read(rel), f"constant {name}")
    return int(m.group(1).replace("'", ""), 0)


def frame(rel: str, name: str) -> dict:
    """``inline constexpr FrameFormat <name>{.nad_host_to_se = .., .nad_se_to_host = .., .len_bytes = ..,
    .max_len = ..};`` (designated initialisers)."""
    m = need(rf"inline constexpr FrameFormat {name}\{{\s*\.nad_host_to_se = (0x[0-9A-F]+)U,\s*"
             rf"\.nad_se_to_host = (0x[0-9A-F]+)U,\s*\.len_bytes = (\d+)U,\s*\.max_len = (0x[0-9A-F]+)U\}}",
             read(rel), f"frame format {name}")
    return {"nad_out": int(m.group(1), 16), "nad_in": int(m.group(2), 16), "len_bytes": int(m.group(3)),
            "max_inf": int(m.group(4), 16)}


def structs_with_phrase(rel: str) -> list[str]:
    """The operation tags of se05x_confirm.hpp: every struct that carries a ``kPhrase``."""
    return re.findall(r"struct (\w+) \{\n\s+static constexpr Phrase kPhrase", read(rel))


def json_data(rel: str) -> dict:
    return json.loads(read(rel))
