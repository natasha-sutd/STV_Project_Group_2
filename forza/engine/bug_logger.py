"""
Saves every unique bug found to disk and to a CSV file.
"""

# -*- coding: utf-8 -*-
"""
Results logger: writes per-run data and periodic summaries to disk.

Files written to results/<target>/<run_id>/:
  - all_runs.csv    : every execution (input, bug_type, is_new)
  - bugs.csv        : deduplicated unique bugs found
  - stats.csv       : time-series snapshot of coverage/throughput
  - tracebacks.log  : raw stdout for anything that is not NORMAL
"""

import os
import csv
import time
from pathlib import Path
from bug_oracle import BugType, BugResult
from typing import Optional


class FuzzLogger:
    """
    Writes fuzzing results to disk in a structured format.

    Call `record(result)` after every run and `snapshot()` periodically
    (e.g. every 100 runs) to update the stats CSV for graphing.
    """

    RUNS_FIELDS = ["iteration", "timestamp",
                   "input", "bug_type", "is_new", "exit_code"]
    BUGS_FIELDS = ["first_seen_iter", "first_seen_time",
                   "category", "exc_type", "exc_msg", "input"]
    STATS_FIELDS = ["iteration", "elapsed_s", "runs_total",
                    "bugs_unique", "corpus_size", "runs_per_sec"]

    def __init__(self, output_dir: str, target: str) -> None:
        run_id = time.strftime("%Y%m%d_%H%M%S")
        self.out_dir = Path(output_dir) / target / run_id
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self._run_path = self.out_dir / "all_runs.csv"
        self._bug_path = self.out_dir / "bugs.csv"
        self._stat_path = self.out_dir / "stats.csv"
        self._tb_path = self.out_dir / "tracebacks.log"

        self._init_csv(self._run_path, self.RUNS_FIELDS)
        self._init_csv(self._bug_path, self.BUGS_FIELDS)
        self._init_csv(self._stat_path, self.STATS_FIELDS)

        self._iteration = 0
        self._unique_bugs = 0
        self._start_time = time.monotonic()
        self._last_snapshot_iter = 0
        self._snapshot_interval = 50  # write stats row every N runs

        print(f"[logger] Writing results to: {self.out_dir}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, result: BugResult, corpus_size: int = 0) -> None:
        """Record a single run result."""
        self._iteration += 1
        now = time.monotonic() - self._start_time
        input_repr = repr(result.input_data)[:120]

        with open(self._run_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                self._iteration,
                f"{now:.3f}",
                input_repr,
                result.bug_type.value,
                "1" if result.is_new_behavior else "0",
                result.exit_code,
            ])

        if result.is_new_behavior:
            self._unique_bugs += 1
            cat, exc, msg = result.bug_key if result.bug_key else ("", "", "")
            with open(self._bug_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    self._iteration,
                    f"{now:.3f}",
                    cat, exc, msg,
                    input_repr,
                ])

        if result.bug_type not in (BugType.NORMAL,):
            with open(self._tb_path, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(
                    f"Iteration {self._iteration} | {result.bug_type.value} | {now:.1f}s\n")
                f.write(f"Input: {input_repr}\n")
                if result.stdout.strip():
                    f.write(result.stdout.strip() + "\n")
                if result.stderr.strip():
                    f.write("[STDERR]\n" + result.stderr.strip() + "\n")

        if self._iteration - self._last_snapshot_iter >= self._snapshot_interval:
            self.snapshot(corpus_size)

    def snapshot(self, corpus_size: int = 0) -> None:
        """Write one row to stats.csv with the current throughput and coverage."""
        if self._iteration == self._last_snapshot_iter and self._iteration != 0:
            return
        now = time.monotonic() - self._start_time
        runs_per_sec = self._iteration / now if now > 0 else 0.0
        with open(self._stat_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                self._iteration,
                f"{now:.1f}",
                self._iteration,
                self._unique_bugs,
                corpus_size,
                f"{runs_per_sec:.2f}",
            ])
        self._last_snapshot_iter = self._iteration

    def print_status(self, corpus_size: int = 0) -> None:
        """Print a one-line status summary to stdout."""
        now = time.monotonic() - self._start_time
        rps = self._iteration / now if now > 0 else 0.0
        print(
            f"\r[{now:7.1f}s] "
            f"runs={self._iteration:6d}  "
            f"unique_bugs={self._unique_bugs:4d}  "
            f"corpus={corpus_size:4d}  "
            f"rps={rps:5.1f}",
            end="",
            flush=True,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _init_csv(self, path: Path, fields: list) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(fields)

    @property
    def iteration(self) -> int:
        return self._iteration

    @property
    def unique_bugs(self) -> int:
        return self._unique_bugs
