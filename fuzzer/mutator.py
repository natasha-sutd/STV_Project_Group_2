# -*- coding: utf-8 -*-
"""
MutationEngine: generates mutants from a seed.

Strategies are arranged in two tiers:

  Tier 1 — Grammar-aware (IP-specific):
    These understand what a valid/invalid IPv4 or IPv6 string looks like and
    generate mutations that exercise parser edge cases:
      - octet boundary values (0, 255, 256, -1)
      - leading-zero variants
      - group count changes
      - double-colon position changes
      - IPv4-suffix injection/removal in IPv6
      - hex group width changes (1..4 digits)

  Tier 2 — Generic (bit/byte-level):
    These operate on the raw bytes and do not know about IP syntax:
      - bit flips
      - byte replacements with random or interesting values
      - insertion / deletion of bytes
      - seed splicing (crossover)

The engine picks a strategy with probability proportional to its weight.
Grammar-aware strategies are weighted higher for better early coverage.
"""

import random
import string
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Interesting constants
# ---------------------------------------------------------------------------

# Byte-level interesting values (overflow boundaries)
INTERESTING_BYTES = [
    b"\x00", b"\x01", b"\x7f", b"\x80", b"\xfe", b"\xff",
]

# Full interesting strings covering IPv4 parser edge cases
INTERESTING_IPV4_OCTETS = [
    "0", "1", "9", "10", "99", "100", "127", "128",
    "200", "254", "255", "256", "257", "300", "999",
    "00", "01", "001", "0000",
]

# Interesting hex groups for IPv6
INTERESTING_HEX_GROUPS = [
    "0", "1", "f", "ff", "fff", "ffff", "10000",
    "fffff", "0000", "FFFF", "g", "gg", "z",
]

# Interesting IPv6 prefixes / known tricky patterns
IPV6_SEEDS = [
    "::", "::1", "::0", "::ffff:0:0",
    "fe80::", "fc00::", "ff02::1",
    "2001:db8::", "2001::", "2002::",
    ":1", "1:", ":::", "1::2::3",
]

SPECIAL_CHARS = list(":./ \\@#![]{}|")


# ---------------------------------------------------------------------------
# Base strategy
# ---------------------------------------------------------------------------

class MutationStrategy(ABC):
    """A mutation strategy transforms input bytes into a mutant."""

    @abstractmethod
    def mutate(self, data: bytes) -> bytes: ...

    @property
    @abstractmethod
    def weight(self) -> float: ...

    @property
    @abstractmethod
    def name(self) -> str: ...


# ===========================================================================
# Generic strategies
# ===========================================================================

class BitFlip(MutationStrategy):
    """Flip between 1 and 4 consecutive bits at a random position."""

    @property
    def weight(self) -> float: return 1.0

    @property
    def name(self) -> str: return "bit_flip"

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data
        ba = bytearray(data)
        pos = random.randrange(len(ba))
        n_bits = random.choice([1, 2, 4])
        shift = random.randint(0, 8 - n_bits)
        mask = ((1 << n_bits) - 1) << shift
        ba[pos] ^= mask
        return bytes(ba)


class ByteReplace(MutationStrategy):
    """Replace 1–4 bytes with random or interesting values."""

    @property
    def weight(self) -> float: return 1.5

    @property
    def name(self) -> str: return "byte_replace"

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data
        ba = bytearray(data)
        count = random.randint(1, min(4, len(ba)))
        start = random.randrange(len(ba) - count + 1)
        if random.random() < 0.3:
            # Use interesting bytes
            replacement = bytes([
                random.choice(INTERESTING_BYTES)[0]
                for _ in range(count)
            ])
        else:
            replacement = bytes(random.randint(0, 255) for _ in range(count))
        ba[start : start + count] = replacement
        return bytes(ba)


class ByteInsertion(MutationStrategy):
    """Insert 1–3 random bytes (or interesting bytes) at a random position."""

    @property
    def weight(self) -> float: return 0.8

    @property
    def name(self) -> str: return "byte_insert"

    def mutate(self, data: bytes) -> bytes:
        ba = bytearray(data)
        pos = random.randint(0, len(ba))
        count = random.randint(1, 3)
        insert = bytes(random.randint(0, 255) for _ in range(count))
        ba[pos:pos] = insert
        return bytes(ba)


class ByteDeletion(MutationStrategy):
    """Delete 1–4 bytes at a random position."""

    @property
    def weight(self) -> float: return 0.8

    @property
    def name(self) -> str: return "byte_delete"

    def mutate(self, data: bytes) -> bytes:
        if len(data) <= 1:
            return data
        ba = bytearray(data)
        count = random.randint(1, min(4, len(ba) - 1))
        start = random.randrange(len(ba) - count + 1)
        del ba[start : start + count]
        return bytes(ba)


class SpecialCharInsertion(MutationStrategy):
    """Insert a special character (delimiter/operator) at a random position."""

    @property
    def weight(self) -> float: return 1.2

    @property
    def name(self) -> str: return "special_char"

    def mutate(self, data: bytes) -> bytes:
        ba = bytearray(data)
        pos = random.randint(0, len(ba))
        char = random.choice(SPECIAL_CHARS).encode()
        ba[pos:pos] = char
        return bytes(ba)


class SpliceMutation(MutationStrategy):
    """
    Crossover: split data at a random midpoint and append a suffix
    stored from a previous call (lazy; stores its own pool).
    """

    def __init__(self) -> None:
        self._pool: List[bytes] = []

    def feed(self, data: bytes) -> None:
        """Accumulate data segments for future splicing."""
        if data:
            self._pool.append(data)
            if len(self._pool) > 500:
                self._pool.pop(0)

    @property
    def weight(self) -> float: return 0.5

    @property
    def name(self) -> str: return "splice"

    def mutate(self, data: bytes) -> bytes:
        if not self._pool or len(data) < 2:
            return data
        mid = random.randint(1, len(data) - 1)
        donor = random.choice(self._pool)
        if len(donor) < 2:
            return data
        donor_mid = random.randint(1, len(donor) - 1)
        return data[:mid] + donor[donor_mid:]


# ===========================================================================
# Grammar-aware IPv4 strategies
# ===========================================================================

class IPv4OctetBoundary(MutationStrategy):
    """Replace one octet with a boundary value (0, 1, 127, 128, 254, 255, 256…)."""

    @property
    def weight(self) -> float: return 3.0

    @property
    def name(self) -> str: return "ipv4_octet_boundary"

    def mutate(self, data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        parts = text.split(".")
        if len(parts) != 4:
            # Not a clean IPv4 string; fall back to appending a valid one.
            return random.choice([
                b"0.0.0.0", b"127.0.0.1", b"255.255.255.255",
                b"256.0.0.0", b"0.0.0.256",
            ])
        idx = random.randrange(4)
        parts[idx] = random.choice(INTERESTING_IPV4_OCTETS)
        return ".".join(parts).encode()


class IPv4LeadingZero(MutationStrategy):
    """Add / remove leading zeros in an octet."""

    @property
    def weight(self) -> float: return 2.0

    @property
    def name(self) -> str: return "ipv4_leading_zero"

    def mutate(self, data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        parts = text.split(".")
        if len(parts) != 4:
            return data
        idx = random.randrange(4)
        action = random.choice(["add", "remove", "pad2", "pad3"])
        try:
            val = int(parts[idx].lstrip("0") or "0")
        except ValueError:
            return data
        if action == "add":
            parts[idx] = "0" + parts[idx]
        elif action == "remove":
            parts[idx] = str(val)
        elif action == "pad2":
            parts[idx] = f"{val:02d}"
        else:
            parts[idx] = f"{val:03d}"
        return ".".join(parts).encode()


class IPv4OctetCountChange(MutationStrategy):
    """Add or drop an octet entirely."""

    @property
    def weight(self) -> float: return 2.0

    @property
    def name(self) -> str: return "ipv4_octet_count"

    def mutate(self, data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        parts = text.split(".")
        action = random.choice(["drop", "duplicate", "add"])
        if action == "drop" and len(parts) > 1:
            idx = random.randrange(len(parts))
            del parts[idx]
        elif action == "duplicate" and parts:
            idx = random.randrange(len(parts))
            parts.insert(idx, parts[idx])
        else:
            parts.append(random.choice(["0", "1", "255", "256"]))
        return ".".join(parts).encode()


class IPv4SeparatorMutation(MutationStrategy):
    """Replace a '.' separator with another character."""

    @property
    def weight(self) -> float: return 1.5

    @property
    def name(self) -> str: return "ipv4_separator"

    def mutate(self, data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        dots = [i for i, c in enumerate(text) if c == "."]
        if not dots:
            return data
        pos = random.choice(dots)
        replacement = random.choice([",", "/", ":", " ", "", "-", "_"])
        return (text[:pos] + replacement + text[pos + 1:]).encode()


# ===========================================================================
# Grammar-aware IPv6 strategies
# ===========================================================================

class IPv6GroupBoundary(MutationStrategy):
    """Replace one hex group with a boundary/interesting value."""

    @property
    def weight(self) -> float: return 3.0

    @property
    def name(self) -> str: return "ipv6_group_boundary"

    def mutate(self, data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        # Split on ':' but be careful around '::'
        if "::" in text:
            left, _, right = text.partition("::")
            side = random.choice(["left", "right"])
            target = left if side == "left" else right
            groups = target.split(":") if target else []
            if not groups or groups == [""]:
                return data
            idx = random.randrange(len(groups))
            groups[idx] = random.choice(INTERESTING_HEX_GROUPS)
            if side == "left":
                return ((".".join([]) if not groups else ":".join(groups)) + "::" + right).encode()
            left_part = left
            new_right = ":".join(groups)
            return f"{left_part}::{new_right}".encode()
        else:
            groups = text.split(":")
            if not groups:
                return data
            idx = random.randrange(len(groups))
            groups[idx] = random.choice(INTERESTING_HEX_GROUPS)
            return ":".join(groups).encode()


class IPv6DoubleColonManipulation(MutationStrategy):
    """Add, move, duplicate or remove the '::' abbreviation."""

    @property
    def weight(self) -> float: return 2.5

    @property
    def name(self) -> str: return "ipv6_double_colon"

    def mutate(self, data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        action = random.choice(["add_extra", "remove", "duplicate", "move"])

        if action == "add_extra":
            # Insert a second '::', making it invalid
            if "::" in text:
                pos = random.randint(0, len(text))
                return (text[:pos] + "::" + text[pos:]).encode()
            else:
                pos = random.randint(0, len(text))
                return (text[:pos] + "::" + text[pos:]).encode()

        elif action == "remove":
            return text.replace("::", ":").encode()

        elif action == "duplicate":
            # Replace '::' with ':::'
            return text.replace("::", ":::").encode()

        else:  # move
            text2 = text.replace("::", "")
            pos = random.randint(0, len(text2))
            return (text2[:pos] + "::" + text2[pos:]).encode()


class IPv6GroupCountChange(MutationStrategy):
    """Add or remove one hex group."""

    @property
    def weight(self) -> float: return 2.0

    @property
    def name(self) -> str: return "ipv6_group_count"

    def mutate(self, data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        action = random.choice(["add", "drop"])
        parts = text.split(":")
        if action == "drop" and len(parts) > 1:
            idx = random.randrange(len(parts))
            del parts[idx]
        else:
            idx = random.randint(0, len(parts))
            parts.insert(idx, random.choice(["0", "ffff", "1", "abcd"]))
        return ":".join(parts).encode()


class IPv6IPv4SuffixManipulation(MutationStrategy):
    """
    Append an IPv4 suffix to a plain IPv6 address, or corrupt an
    existing IPv4 suffix by changing an octet's value.
    """

    @property
    def weight(self) -> float: return 2.5

    @property
    def name(self) -> str: return "ipv6_ipv4_suffix"

    # Match last IPv4-like suffix, e.g. '::ffff:192.168.1.1'
    _V4_SUFFIX = r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"

    def mutate(self, data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        import re
        m = re.search(self._V4_SUFFIX, text)
        if m:
            # Corrupt one octet
            octets = list(m.groups())
            idx = random.randrange(4)
            octets[idx] = random.choice(INTERESTING_IPV4_OCTETS)
            new_suffix = ".".join(octets)
            return (text[: m.start()] + new_suffix).encode()
        else:
            # Append a new IPv4 suffix
            suffix = random.choice([
                "192.168.1.1", "0.0.0.0", "255.255.255.255",
                "256.0.0.1", "1.2.3.4", "::127.0.0.1",
            ])
            # Try appending after last group
            if text.endswith("::") or ":" not in text:
                return (text + suffix).encode()
            return (text + ":" + suffix).encode()


class IPv6CaseChange(MutationStrategy):
    """Toggle upper/lower case of hex digits."""

    @property
    def weight(self) -> float: return 1.0

    @property
    def name(self) -> str: return "ipv6_case"

    def mutate(self, data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        action = random.choice(["upper", "lower", "random"])
        if action == "upper":
            return text.upper().encode()
        elif action == "lower":
            return text.lower().encode()
        else:
            return "".join(
                c.upper() if random.random() < 0.5 else c.lower()
                for c in text
            ).encode()


class IPv6InterestingReplace(MutationStrategy):
    """Replace the entire input with a known interesting IPv6 pattern."""

    @property
    def weight(self) -> float: return 1.5

    @property
    def name(self) -> str: return "ipv6_interesting_replace"

    def mutate(self, data: bytes) -> bytes:
        return random.choice(IPV6_SEEDS).encode()


# ===========================================================================
# MutationEngine
# ===========================================================================

class MutationEngine:
    """
    Dispatches mutations using weighted-random strategy selection.

    `target` controls which strategies are included:
      - 'ipv4' : generic + IPv4-specific strategies
      - 'ipv6' : generic + IPv6-specific strategies
      - 'generic' : only generic strategies (for unstructured targets)
    """

    def __init__(self, target: str = "generic") -> None:
        self._splice = SpliceMutation()
        self._strategies: List[MutationStrategy] = self._build(target)
        self.mutation_counts: dict = {s.name: 0 for s in self._strategies}

    def _build(self, target: str) -> List[MutationStrategy]:
        generic = [
            BitFlip(),
            ByteReplace(),
            ByteInsertion(),
            ByteDeletion(),
            SpecialCharInsertion(),
            self._splice,
        ]
        ipv4_specific = [
            IPv4OctetBoundary(),
            IPv4LeadingZero(),
            IPv4OctetCountChange(),
            IPv4SeparatorMutation(),
        ]
        ipv6_specific = [
            IPv6GroupBoundary(),
            IPv6DoubleColonManipulation(),
            IPv6GroupCountChange(),
            IPv6IPv4SuffixManipulation(),
            IPv6CaseChange(),
            IPv6InterestingReplace(),
        ]
        if target == "ipv4":
            return generic + ipv4_specific
        elif target == "ipv6":
            return generic + ipv6_specific
        else:
            return generic

    def mutate(self, data: bytes) -> bytes:
        """
        Apply one (or occasionally two) randomly-chosen mutations.
        Returns the mutated bytes.
        """
        # Stacking: with 20% probability, apply a second mutation
        result = self._apply_one(data)
        if random.random() < 0.2:
            result = self._apply_one(result)
        return result

    def _apply_one(self, data: bytes) -> bytes:
        weights = [s.weight for s in self._strategies]
        total = sum(weights)
        r = random.uniform(0, total)
        cumulative = 0.0
        for strategy in self._strategies:
            cumulative += strategy.weight
            if r <= cumulative:
                result = strategy.mutate(data)
                self.mutation_counts[strategy.name] += 1
                return result
        result = self._strategies[-1].mutate(data)
        self.mutation_counts[self._strategies[-1].name] += 1
        return result

    def feed_splice_pool(self, data: bytes) -> None:
        """Give interesting inputs to the splice strategy."""
        self._splice.feed(data)

    def stats(self) -> str:
        total = sum(self.mutation_counts.values())
        if total == 0:
            return "No mutations applied yet."
        lines = [f"{'Strategy':<35} {'Count':>8} {'%':>6}"]
        lines.append("-" * 52)
        for name, count in sorted(
            self.mutation_counts.items(), key=lambda x: -x[1]
        ):
            pct = 100.0 * count / total
            lines.append(f"{name:<35} {count:>8} {pct:>5.1f}%")
        return "\n".join(lines)
