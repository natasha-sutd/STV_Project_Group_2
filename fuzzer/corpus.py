# -*- coding: utf-8 -*-
"""
Seed and SeedCorpus: manages the fuzzer's input queue.

Since we are black-box fuzzing closed binaries, "coverage" is approximated
through behavioral novelty: every unique (bug_category, exc_type, exc_msg)
triple observed for the first time counts as new behavior.  Seeds that
discover new behaviors get boosted energy; seeds that are mined out lose
energy over time (power scheduling).
"""

import random
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

from oracle import BugType, RunResult


@dataclass
class Seed:
    """A single fuzzer input with scheduling metadata."""
    data: bytes

    # Power-scheduling weight; proportional to expected future usefulness.
    energy: float = 1.0

    # How many times this seed has been chosen for mutation.
    times_selected: int = 0

    # How many unique new behaviors this seed (or its mutants) found.
    behaviors_contributed: int = 0

    # Human-readable origin tag for debugging/logging.
    origin: str = "manual"

    def __repr__(self) -> str:
        return (
            f"Seed({self.data!r}, energy={self.energy:.2f}, "
            f"sel={self.times_selected}, contrib={self.behaviors_contributed})"
        )

    def __hash__(self) -> int:
        return hash(self.data)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Seed) and self.data == other.data


class SeedCorpus:
    """
    Manages the set of seeds and decides which seed to mutate next.

    Selection strategy: weighted-random proportional to each seed's energy
    (AFL-style power scheduling).  Seeds that recently triggered new
    behaviors have higher energy; heavily-mined seeds are deprioritised.
    """

    def __init__(self) -> None:
        self._seeds: List[Seed] = []
        # Set of unique (category, exc_type, truncated_msg) tuples seen so far.
        self._seen_behaviors: Set[Tuple[str, str, str]] = set()
        self.total_runs: int = 0
        self.total_new_behaviors: int = 0

    # ------------------------------------------------------------------
    # Corpus management
    # ------------------------------------------------------------------

    def add(self, seed: Seed) -> bool:
        """
        Add a seed to the corpus if its byte content has not been seen before.
        Returns True if the seed was actually added.
        """
        if any(s.data == seed.data for s in self._seeds):
            return False
        self._seeds.append(seed)
        return True

    def add_many(self, seeds: List[Seed]) -> int:
        """Bulk-add; returns the number of seeds that were actually inserted."""
        return sum(1 for s in seeds if self.add(s))

    def size(self) -> int:
        return len(self._seeds)

    def all_seeds(self) -> List[Seed]:
        return list(self._seeds)

    # ------------------------------------------------------------------
    # Power scheduling
    # ------------------------------------------------------------------

    def select(self) -> Seed:
        """
        Select a seed for mutation using weighted-random (energy as weight).
        Raises ValueError if corpus is empty.
        """
        if not self._seeds:
            raise ValueError("Corpus is empty — add seeds before selecting.")

        total_energy = sum(s.energy for s in self._seeds)
        r = random.uniform(0, total_energy)
        cumulative = 0.0
        for seed in self._seeds:
            cumulative += seed.energy
            if r <= cumulative:
                seed.times_selected += 1
                return seed

        # Floating-point edge case: return last seed.
        last = self._seeds[-1]
        last.times_selected += 1
        return last

    def update(self, seed: Seed, result: RunResult) -> bool:
        """
        Record the outcome of a run that originated from `seed`.
        Boosts or decays energy based on whether new behavior was found.
        Returns True if `result` represents previously-unseen behavior.
        """
        self.total_runs += 1
        new = self._record_behavior(result)
        if new:
            seed.behaviors_contributed += 1
            seed.energy = min(seed.energy * 2.0, 200.0)
            self.total_new_behaviors += 1
        else:
            # Gradual energy decay to de-prioritise exhausted seeds.
            seed.energy = max(seed.energy * 0.995, 0.05)
        return new

    # ------------------------------------------------------------------
    # Behavior novelty tracking
    # ------------------------------------------------------------------

    def _record_behavior(self, result: RunResult) -> bool:
        """
        Mark a (bug_type, exc_type, exc_msg) tuple as seen.
        Returns True if this is the first time we observe it.
        """
        if result.bug_key is None:
            # Normal successful parse — not interesting from a bug PoV,
            # but we still use it for energy scheduling.
            return False
        if result.bug_key not in self._seen_behaviors:
            self._seen_behaviors.add(result.bug_key)
            result.is_new_behavior = True
            return True
        return False

    def seen_behavior_count(self) -> int:
        return len(self._seen_behaviors)

    def summarize(self) -> str:
        lines = [
            f"Corpus size       : {self.size()} seeds",
            f"Total runs        : {self.total_runs}",
            f"Unique behaviors  : {self.seen_behavior_count()}",
            f"New behaviors     : {self.total_new_behaviors}",
        ]
        return "\n".join(lines)
