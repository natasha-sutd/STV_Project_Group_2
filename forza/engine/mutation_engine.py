"""
AFL-style weighted mutation engine with grammar-aware mutation support.

Mutation strategues:
    - Generic (format-agnostic):
        - bit_flip, truncate, insert_special_char, repeat_chunk, byte_insert, swap_chars, radamsa
    - Grammar-aware:
        - grammar_mutate, constraint_violation
"""

from __future__ import annotations

import random
import string
import subprocess

SPECIAL_CHARS = [
    "\x00",  # null byte
    "\xff",  # max byte
    "\n",
    "\r",  # newlines
    "\\",  # backslash
    '"',
    "'",  # quotes
    "{",
    "}",
    "[",
    "]",  # brackets
    "<",
    ">",  # angle brackets
    "/../",  # path traversal
    "%00",  # URL-encoded null
    "&&",
    "||",  # shell injection
    "999999999999999999999999",  # integer overflow bait
]


# generic mutations
def bit_flip(data: str) -> str:
    if not data:
        return data
    idx = random.randint(0, len(data) - 1)
    flipped = chr(ord(data[idx]) ^ (1 << random.randint(0, 7)))
    return data[:idx] + flipped + data[idx + 1 :]


def truncate(data: str) -> str:
    if len(data) <= 1:
        return data
    return data[: random.randint(0, len(data) - 1)]


def insert_special_char(data: str) -> str:
    if not data:
        return random.choice(SPECIAL_CHARS)
    idx = random.randint(0, len(data))
    return data[:idx] + random.choice(SPECIAL_CHARS) + data[idx:]


def repeat_chunk(data: str) -> str:
    if len(data) < 2:
        return data * 2
    start = random.randint(0, len(data) - 1)
    end = random.randint(start + 1, len(data))
    chunk = data[start:end]
    return data[:start] + chunk * random.randint(2, 10) + data[end:]


def byte_insert(data: str) -> str:
    idx = random.randint(0, len(data))
    return data[:idx] + random.choice(string.printable) + data[idx:]


def swap_chars(data: str) -> str:
    if len(data) < 2:
        return data
    i, j = random.sample(range(len(data)), 2)
    lst = list(data)
    lst[i], lst[j] = lst[j], lst[i]
    return "".join(lst)


def radamsa_mutate(data: str) -> str:
    try:
        p = subprocess.Popen(
            ["radamsa"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        try:
            out, _ = p.communicate(data.encode(), timeout=2.0)
            return out.decode(errors="ignore")

        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            return data

    except (FileNotFoundError, PermissionError):
        return data
    except Exception:
        return data


STRATEGIES = [
    ("bit_flip", bit_flip, 1.0, ["*"]),
    ("truncate", truncate, 1.0, ["*"]),
    ("insert_special_char", insert_special_char, 1.0, ["*"]),
    ("repeat_chunk", repeat_chunk, 1.0, ["*"]),
    ("byte_insert", byte_insert, 1.0, ["*"]),
    ("swap_chars", swap_chars, 1.0, ["*"]),
    ("radamsa", radamsa_mutate, 2.0, ["*"]),
]


class MutationEngine:
    def __init__(
        self,
        input_format: str = "*",
        grammar_spec: dict | None = None,
        mutation_dictionary: list[str] | None = None,
        enabled_strategies: list[str] | None = None,
        disabled_strategies: list[str] | None = None,
    ) -> None:
        self.input_format = input_format
        self._grammar_spec = grammar_spec or {}
        self._dictionary_tokens = self._normalize_dictionary_tokens(mutation_dictionary)
        self._last_strategy = "unknown"

        # Build active strategy list
        self.strategies = [
            {"name": name, "fn": fn, "weight": weight}
            for name, fn, weight, formats in STRATEGIES
            if "*" in formats or input_format in formats
        ]

        # Add grammar-aware strategies when a spec is available
        if self._grammar_spec:
            self.strategies.append(
                {
                    "name": "grammar_mutate",
                    "fn": self._grammar_mutate,
                    "weight": 1.5,
                }
            )
            self.strategies.append(
                {
                    "name": "constraint_violation",
                    "fn": self._constraint_violation,
                    "weight": 2.0,  # High weight — directly targets logic bugs
                }
            )

        if self._dictionary_tokens:
            self.strategies.append(
                {
                    "name": "insert_dictionary_token",
                    "fn": self._insert_dictionary_token,
                    "weight": 1.6,
                }
            )

        if enabled_strategies:
            allowed = {
                str(name).strip() for name in enabled_strategies if str(name).strip()
            }
            self.strategies = [s for s in self.strategies if s["name"] in allowed]

        if disabled_strategies:
            blocked = {
                str(name).strip() for name in disabled_strategies if str(name).strip()
            }
            self.strategies = [s for s in self.strategies if s["name"] not in blocked]

        if not self.strategies:
            self.strategies = [{"name": "bit_flip", "fn": bit_flip, "weight": 1.0}]

    # Public API
    def mutate(self, seed: str) -> str:
        """Pick a strategy via weighted random selection and return a mutated seed."""
        chosen = self._weighted_choice()
        try:
            result = chosen["fn"](seed)
            return str(result) if result is not None else seed
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

    # Grammar-aware strategies
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
            from engine.seed_generator import (
                parse_string_to_tree,
                violate_tree,
                tree_to_string,
            )

            tree = parse_string_to_tree(seed, self._grammar_spec)
            return tree_to_string(violate_tree(tree))
        except Exception:
            return insert_special_char(seed)

    def _insert_dictionary_token(self, seed: str) -> str:
        """Insert a target-specific dictionary token at a random offset."""
        if not self._dictionary_tokens:
            return insert_special_char(seed)
        token = random.choice(self._dictionary_tokens)
        idx = random.randint(0, len(seed))
        return seed[:idx] + token + seed[idx:]

    @staticmethod
    def _normalize_dictionary_tokens(raw_tokens: list[str] | None) -> list[str]:
        if not isinstance(raw_tokens, list):
            return []
        tokens: list[str] = []
        seen: set[str] = set()
        for raw in raw_tokens:
            token = str(raw).strip()
            if not token or token in seen:
                continue
            seen.add(token)
            tokens.append(token)
        return tokens

    # Internal
    def _weighted_choice(self) -> dict:
        """Select a strategy using weighted random sampling."""
        total = sum(s["weight"] for s in self.strategies)
        if total <= 1e-6:
            chosen = random.choice(self.strategies)
            self._last_strategy = chosen["name"]
            return chosen
        pick = random.uniform(0, total)
        cumulative = 0.0
        for s in self.strategies:
            cumulative += s["weight"]
            if pick <= cumulative:
                self._last_strategy = s["name"]
                return s
        self._last_strategy = self.strategies[-1]["name"]
        return self.strategies[-1]
