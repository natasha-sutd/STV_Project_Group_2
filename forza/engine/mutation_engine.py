"""
engine/mutation_engine.py

AFL-style weighted mutation engine.
- Each strategy starts with an equal base weight.
- When a mutation strategy finds new coverage, its weight is boosted (energy recalibration).
- Strategy is selected via weighted random each iteration.
- Format-aware strategies are applied only when input_format matches (set in YAML).

No external libraries used — all mutation logic written from scratch.
"""

import random
import string
import subprocess


# ── Constants ────────────────────────────────────────────────────────────────

# Characters commonly used to break parsers
SPECIAL_CHARS = [
    "\x00",         # null byte
    "\xff",         # max byte
    "\n", "\r",     # newlines
    "\\",           # backslash
    "\"", "'",      # quotes
    "{", "}", "[", "]",  # brackets
    "<", ">",       # angle brackets (XML/HTML confusion)
    "/../",         # path traversal
    "%00",          # URL-encoded null
    "&&", "||",     # shell injection
    "999999999999999999999999",  # integer overflow bait
]

# JSON-specific edge case values
JSON_EDGE_VALUES = [
    "null", "true", "false",
    "0", "-1", "1e308", "-1e308",   # numeric edges
    '""',                            # empty string
    '" "',                           # whitespace string
    '"' + "A" * 10000 + '"',         # very long string
    "[]", "{}",                      # empty containers
    "[" + ",".join(["0"] * 1000) + "]",  # large array
]

# IP/CIDR edge case values
IP_EDGE_VALUES = [
    "0.0.0.0", "255.255.255.255",
    "256.0.0.1", "999.999.999.999",  # out of range octets
    "192.168.1",                      # missing octet
    "192.168.1.1.1",                  # extra octet
    "::1", "::",                      # IPv6 loopback / unspecified
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  # IPv6 max
    "192.168.1.0/33", "10.0.0.0/0",  # bad/edge CIDR prefix lengths
    "0.0.0.0/0",                      # default route
    "",                               # empty
    " ",                              # whitespace
]


# ── Individual mutation strategies ───────────────────────────────────────────

def bit_flip(data: str) -> str:
    """Flip a random bit in a random character of the input."""
    if not data:
        return data
    idx = random.randint(0, len(data) - 1)
    char_code = ord(data[idx])
    bit = 1 << random.randint(0, 7)
    flipped = chr(char_code ^ bit)
    return data[:idx] + flipped + data[idx + 1:]


def truncate(data: str) -> str:
    """Cut the input short at a random position."""
    if len(data) <= 1:
        return data
    cut = random.randint(0, len(data) - 1)
    return data[:cut]


def insert_special_char(data: str) -> str:
    """Insert a special/bad character at a random position."""
    if not data:
        return random.choice(SPECIAL_CHARS)
    idx = random.randint(0, len(data))
    char = random.choice(SPECIAL_CHARS)
    return data[:idx] + char + data[idx:]


def repeat_chunk(data: str) -> str:
    """Duplicate a random slice of the input (stress-tests length handling)."""
    if len(data) < 2:
        return data * 2
    start = random.randint(0, len(data) - 1)
    end = random.randint(start + 1, len(data))
    chunk = data[start:end]
    repeat = random.randint(2, 10)
    return data[:start] + chunk * repeat + data[end:]


def byte_insert(data: str) -> str:
    """Insert a random printable ASCII character at a random position."""
    idx = random.randint(0, len(data))
    char = random.choice(string.printable)
    return data[:idx] + char + data[idx:]


def swap_chars(data: str) -> str:
    """Swap two random characters in the input."""
    if len(data) < 2:
        return data
    i, j = random.sample(range(len(data)), 2)
    lst = list(data)
    lst[i], lst[j] = lst[j], lst[i]
    return "".join(lst)


# ── Format-aware strategies ──────────────────────────────────────────────────

def json_aware_mutate(data: str) -> str:
    """
    Apply JSON-structure-aware mutations.
    Targets common JSON parser failure points:
      - Missing closing brackets/braces
      - Injected edge values
      - Deeply nested structures
      - Duplicate keys
    """
    strategies = [
        _json_drop_closing,
        _json_inject_edge_value,
        _json_deep_nest,
        _json_duplicate_key,
        _json_inject_unicode,
    ]
    return random.choice(strategies)(data)


def _json_drop_closing(data: str) -> str:
    """Remove a random closing bracket or brace."""
    closers = [i for i, c in enumerate(data) if c in "]}"]
    if not closers:
        return data + "{"   # append unclosed brace
    idx = random.choice(closers)
    return data[:idx] + data[idx + 1:]


def _json_inject_edge_value(data: str) -> str:
    """Replace the whole input with a JSON edge-case value."""
    return random.choice(JSON_EDGE_VALUES)


def _json_deep_nest(data: str) -> str:
    """Wrap input in deeply nested objects (stack overflow bait)."""
    depth = random.randint(50, 200)
    return "{\"a\":" * depth + "1" + "}" * depth


def _json_duplicate_key(data: str) -> str:
    """Inject a duplicate key into a JSON object."""
    if not data.startswith("{"):
        return data
    return data[:-1] + ', "a": 1, "a": 2}'


def _json_inject_unicode(data: str) -> str:
    """Inject a unicode escape sequence into the input."""
    idx = random.randint(0, len(data))
    unicode_seq = "\\u" + format(random.randint(0, 0xFFFF), "04x")
    return data[:idx] + unicode_seq + data[idx:]


def ip_aware_mutate(data: str) -> str:
    """
    Apply IP/CIDR-aware mutations.
    Targets common IP parser failure points:
      - Out-of-range octets
      - Wrong number of octets
      - Bad CIDR prefix lengths
      - Mixed IPv4/IPv6 confusion
    """
    strategies = [
        _ip_replace_with_edge,
        _ip_overflow_octet,
        _ip_add_extra_octet,
        _ip_bad_cidr_prefix,
        _ip_mixed_format,
    ]
    return random.choice(strategies)(data)


def _ip_replace_with_edge(data: str) -> str:
    """Replace with a known IP edge-case value."""
    return random.choice(IP_EDGE_VALUES)


def _ip_overflow_octet(data: str) -> str:
    """Replace one octet with an out-of-range value."""
    parts = data.split(".")
    if len(parts) < 2:
        return data
    idx = random.randint(0, len(parts) - 1)
    parts[idx] = str(random.choice([256, 999, -1, 99999]))
    return ".".join(parts)


def _ip_add_extra_octet(data: str) -> str:
    """Append an extra octet to confuse the parser."""
    return data + ".1"


def _ip_bad_cidr_prefix(data: str) -> str:
    """Append or replace a CIDR prefix with an invalid value."""
    base = data.split("/")[0]
    bad_prefix = random.choice([-1, 33, 128, 999, 0])
    return f"{base}/{bad_prefix}"


def _ip_mixed_format(data: str) -> str:
    """Mix IPv4 and IPv6 notation to confuse parsers."""
    return "::ffff:" + data.split("/")[0]

# ── Radamsa mutation ─────────────────────────────────────────────────────────

def radamsa_mutate(data: str) -> str:
    """Mutate data using external Radamsa."""
    try:
        p = subprocess.Popen(["radamsa"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, _ = p.communicate(data.encode())
        return out.decode(errors="ignore")
    except Exception:
        return data


# ── Strategy registry ────────────────────────────────────────────────────────
# Each entry: (name, function, base_weight, applicable_formats)
# applicable_formats: list of input_format values this strategy applies to,
#                     or ["*"] for all formats.

STRATEGIES = [
    ("bit_flip",            bit_flip,             1.0, ["*"]),
    ("truncate",            truncate,             1.0, ["*"]),
    ("insert_special_char", insert_special_char,  1.0, ["*"]),
    ("repeat_chunk",        repeat_chunk,         1.0, ["*"]),
    ("byte_insert",         byte_insert,          1.0, ["*"]),
    ("swap_chars",          swap_chars,           1.0, ["*"]),
    ("json_aware_mutate",   json_aware_mutate,    1.5, ["json"]),
    ("ip_aware_mutate",     ip_aware_mutate,      1.5, ["ip", "cidr", "ipv4", "ipv6"]),
    ("radamsa",             radamsa_mutate,       2.0, ["*"]),
]


# ── MutationEngine class ─────────────────────────────────────────────────────

class MutationEngine:
    """
    AFL-style weighted mutation engine.

    Usage:
        engine = MutationEngine(input_format="json")
        mutated = engine.mutate('{"key": "value"}')
        engine.boost("json_aware_mutate")   # call when a strategy finds new coverage
    """

    def __init__(self, input_format: str = "*"):
        """
        Parameters
        ----------
        input_format : the input_format value from the target YAML config
                       (e.g. "json", "ip", "cidr", or "*" for generic)
        """
        self.input_format = input_format

        # Build the active strategy list filtered by input_format
        self.strategies = [
            {"name": name, "fn": fn, "weight": weight}
            for name, fn, weight, formats in STRATEGIES
            if "*" in formats or input_format in formats
        ]

    def mutate(self, seed: str) -> str:
        """
        Pick a strategy via weighted random selection (AFL-style)
        and return a mutated version of the seed.
        """
        chosen = self._weighted_choice()
        try:
            return chosen["fn"](seed)
        except Exception:
            # If a strategy fails on an unusual input, fall back to truncation
            return truncate(seed) if seed else seed

    def boost(self, strategy_name: str, factor: float = 1.5) -> None:
        """
        Boost the weight of a strategy that found new coverage.
        Called by coverage_tracker when a mutated input increases coverage.

        Parameters
        ----------
        strategy_name : name of the strategy to boost
        factor        : multiplier applied to the current weight
        """
        for s in self.strategies:
            if s["name"] == strategy_name:
                s["weight"] *= factor
                return

    def decay(self, factor: float = 0.95) -> None:
        """
        Slightly decay all weights each iteration to prevent
        one strategy dominating forever (AFL-style energy decay).
        """
        for s in self.strategies:
            s["weight"] = max(0.1, s["weight"] * factor)

    def get_last_strategy(self) -> str:
        """Return the name of the last strategy used (for coverage_tracker to call boost)."""
        # return self._last_strategy
        return getattr(self, "_last_strategy", "unknown")

    def _weighted_choice(self) -> dict:
        """Select a strategy using weighted random sampling."""
        total = sum(s["weight"] for s in self.strategies)
        pick = random.uniform(0, total)
        cumulative = 0.0
        for s in self.strategies:
            cumulative += s["weight"]
            if pick <= cumulative:
                self._last_strategy = s["name"]
                return s
        self._last_strategy = self.strategies[-1]["name"]
        return self.strategies[-1]


# ── Quick manual test ────────────────────────────────────────────────────────
# Run directly to see mutations in action:
#   python engine/mutation_engine.py

if __name__ == "__main__":
    print("=== JSON mutations ===")
    engine = MutationEngine(input_format="json")
    seed = '{"name": "alice", "age": 30}'
    for i in range(8):
        mutated = engine.mutate(seed)
        print(f"[{engine.get_last_strategy():25s}] {repr(mutated)}")
        engine.decay()

    print("\n=== IP mutations ===")
    engine = MutationEngine(input_format="ip")
    seed = "192.168.1.1"
    for i in range(8):
        mutated = engine.mutate(seed)
        print(f"[{engine.get_last_strategy():25s}] {repr(mutated)}")
        engine.decay()

    print("\n=== Weight boosting demo ===")
    engine = MutationEngine(input_format="json")
    print("Before boost:", {s["name"]: round(s["weight"], 2) for s in engine.strategies})
    engine.boost("json_aware_mutate")
    engine.boost("json_aware_mutate")
    print("After 2x boost:", {s["name"]: round(s["weight"], 2) for s in engine.strategies})