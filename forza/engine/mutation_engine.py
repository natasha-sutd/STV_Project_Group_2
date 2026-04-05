"""
engine/mutation_engine.py

AFL-style weighted mutation engine with grammar-aware mutation support.

Each strategy starts with an equal base weight. When a strategy finds new
coverage, its weight is boosted (AFL-style energy recalibration). All
weights decay slightly each iteration to prevent one strategy dominating.

Two tiers of mutation
---------------------
Generic (format-agnostic):
    bit_flip, truncate, insert_special_char, repeat_chunk,
    byte_insert, swap_chars, radamsa

Grammar-aware (uses YAML input: spec — enabled when grammar_spec provided):
    grammar_mutate       — calls mutate_from_spec() for structurally valid variants
                           (boundary values, component swaps, fresh generation)
    constraint_violation — calls violate_constraints() to intentionally break
                           grammar rules (wrong octet range, bad field count, etc.)
                           High weight (2.0) because it directly targets logic bugs.

No external libraries required for core mutations.
"""

from __future__ import annotations

import random
import string
import subprocess

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SPECIAL_CHARS = [
    "\x00",                      # null byte
    "\xff",                      # max byte
    "\n", "\r",                  # newlines
    "\\",                        # backslash
    "\"", "'",                   # quotes
    "{", "}", "[", "]",          # brackets
    "<", ">",                    # angle brackets
    "/../",                      # path traversal
    "%00",                       # URL-encoded null
    "&&", "||",                  # shell injection
    "999999999999999999999999",  # integer overflow bait
]

# ---------------------------------------------------------------------------
# Generic mutation strategies
# ---------------------------------------------------------------------------
def bit_flip(data: str) -> str:
    """Flip a random bit in a random character of the input."""
    if not data:
        return data
    idx = random.randint(0, len(data) - 1)
    flipped = chr(ord(data[idx]) ^ (1 << random.randint(0, 7)))
    return data[:idx] + flipped + data[idx + 1:]

def truncate(data: str) -> str:
    """Cut the input short at a random position."""
    if len(data) <= 1:
        return data
    return data[:random.randint(0, len(data) - 1)]

def insert_special_char(data: str) -> str:
    """Insert a special/bad character at a random position."""
    if not data:
        return random.choice(SPECIAL_CHARS)
    idx = random.randint(0, len(data))
    return data[:idx] + random.choice(SPECIAL_CHARS) + data[idx:]

def repeat_chunk(data: str) -> str:
    """Duplicate a random slice of the input (stress-tests length handling)."""
    if len(data) < 2:
        return data * 2
    start = random.randint(0, len(data) - 1)
    end = random.randint(start + 1, len(data))
    chunk = data[start:end]
    return data[:start] + chunk * random.randint(2, 10) + data[end:]

def byte_insert(data: str) -> str:
    """Insert a random printable ASCII character at a random position."""
    idx = random.randint(0, len(data))
    return data[:idx] + random.choice(string.printable) + data[idx:]

def swap_chars(data: str) -> str:
    """Swap two random characters in the input."""
    if len(data) < 2:
        return data
    i, j = random.sample(range(len(data)), 2)
    lst = list(data)
    lst[i], lst[j] = lst[j], lst[i]
    return "".join(lst)

def radamsa_mutate(data: str) -> str:
    """Mutate using external Radamsa (skipped silently if not installed)."""
    try:
        p = subprocess.Popen(["radamsa"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, _ = p.communicate(data.encode())
        return out.decode(errors="ignore")
    except Exception:
        return data

# ---------------------------------------------------------------------------
# Strategy registry
# grammar_mutate and constraint_violation are added dynamically in __init__
# when a grammar_spec is provided.
# ---------------------------------------------------------------------------
STRATEGIES = [
    ("bit_flip",            bit_flip,            1.0, ["*"]),
    ("truncate",            truncate,            1.0, ["*"]),
    ("insert_special_char", insert_special_char, 1.0, ["*"]),
    ("repeat_chunk",        repeat_chunk,        1.0, ["*"]),
    ("byte_insert",         byte_insert,         1.0, ["*"]),
    ("swap_chars",          swap_chars,          1.0, ["*"]),
    ("radamsa",             radamsa_mutate,      2.0, ["*"]),
]

# ---------------------------------------------------------------------------
# MutationEngine
# ---------------------------------------------------------------------------
class MutationEngine:
    """
    AFL-style weighted mutation engine.

    Initialise with a grammar spec to enable grammar-aware mutation:

        engine = MutationEngine(
            input_format = "json",
            grammar_spec = config.get("input"),
        )

    Without a grammar spec, only generic format-agnostic mutations are used.
    """
    def __init__(
        self,
        input_format : str = "*",
        grammar_spec : dict | None = None
    ) -> None:
        self.input_format = input_format
        self._grammar_spec = grammar_spec or {}
        self._last_strategy = "unknown"

        # Build active strategy list
        self.strategies = [
            {"name": name, "fn": fn, "weight": weight}
            for name, fn, weight, formats in STRATEGIES
            if "*" in formats or input_format in formats
        ]

        # Add grammar-aware strategies when a spec is available
        if self._grammar_spec:
            self.strategies.append({
                "name"  : "grammar_mutate",
                "fn"    : self._grammar_mutate,
                "weight": 1.5,
            })
            self.strategies.append({
                "name"  : "constraint_violation",
                "fn"    : self._constraint_violation,
                "weight": 2.0,  # High weight — directly targets logic bugs
            })

    # ── Public interface ──────────────────────────────────────────────────
    def mutate(self, seed: str) -> str:
        """Pick a strategy via weighted random selection and return a mutated seed."""
        chosen = self._weighted_choice()
        try:
            result = chosen["fn"](seed)
            return str(result) if result else seed
        except Exception:
            return truncate(seed) if seed else seed

    def boost(self, strategy_name: str, factor: float = 1.5) -> None:
        """Increase weight of a strategy that found new coverage."""
        for s in self.strategies:
            if s["name"] == strategy_name:
                s["weight"] *= factor
                return

    def decay(self, factor: float = 0.95) -> None:
        """Decay all weights slightly to prevent one strategy dominating."""
        for s in self.strategies:
            s["weight"] = max(0.1, s["weight"] * factor)

    def get_last_strategy(self) -> str:
        """Return the name of the strategy used in the last mutate() call."""
        return self._last_strategy

    def strategy_weights(self) -> dict[str, float]:
        """Return current weights for all strategies (useful for debugging)."""
        return {s["name"]: round(s["weight"], 3) for s in self.strategies}

    # ── Grammar-aware strategies ──────────────────────────────────────────
    def _grammar_mutate(self, seed: str) -> str:
        """
        Structurally valid mutation using the YAML grammar spec.
        Produces boundary values, component swaps, or fresh generation.
        """
        try:
            from engine.seed_generator import mutate_from_spec
            return mutate_from_spec(seed, self._grammar_spec)
        except Exception:
            return insert_special_char(seed)

    def _constraint_violation(self, seed: str) -> str:
        """
        Intentionally violate the grammar's constraints to probe logic bugs.
        E.g. IP octet > 255, wrong field count, non-numeric where int expected.
        """
        try:
            from engine.seed_generator import violate_constraints
            return violate_constraints(seed, self._grammar_spec)
        except Exception:
            return insert_special_char(seed)

    # ── Internal ──────────────────────────────────────────────────────────
    def _weighted_choice(self) -> dict:
        """Select a strategy using weighted random sampling."""
        total      = sum(s["weight"] for s in self.strategies)
        pick       = random.uniform(0, total)
        cumulative = 0.0
        for s in self.strategies:
            cumulative += s["weight"]
            if pick <= cumulative:
                self._last_strategy = s["name"]
                return s
        self._last_strategy = self.strategies[-1]["name"]
        return self.strategies[-1]

# ---------------------------------------------------------------------------
# Quick manual test — python3 engine/mutation_engine.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import yaml
    from pathlib import Path

    print("=== Generic mutations ===")
    engine = MutationEngine(input_format="*")
    seed   = '{"name": "alice", "age": 30}'
    for _ in range(6):
        mutated = engine.mutate(seed)
        print(f"[{engine.get_last_strategy():25s}] {repr(mutated[:60])}")

    print("\n=== Grammar-aware mutations ===")
    yaml_path = Path("targets/json_decoder.yaml")
    if yaml_path.exists():
        with open(yaml_path) as f:
            cfg = yaml.safe_load(f)
        engine = MutationEngine(
            input_format = "json",
            grammar_spec = cfg.get("input"),
        )
        seed = '{"a": 1}'
        for _ in range(10):
            mutated = engine.mutate(seed)
            print(f"[{engine.get_last_strategy():25s}] {repr(mutated[:60])}")
        print("\nWeights:", engine.strategy_weights())
    else:
        print("[skip] targets/json_decoder.yaml not found")