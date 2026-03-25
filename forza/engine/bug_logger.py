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
from engine.types import BugResult, BugType
from typing import Optional
from engine import firestore_client

_ENGINE_DIR  = Path(__file__).resolve().parent
_PROJECT_DIR = _ENGINE_DIR.parent
_RESULTS_DIR = _PROJECT_DIR / "results"
_CRASHES_DIR = _PROJECT_DIR / "crashes"

class FuzzLogger:
    """
    Writes fuzzing results to disk in a structured format.

    Call `record(result)` after every run and `snapshot()` periodically
    (e.g. every 100 runs) to update the stats CSV for graphing.
    """

    RUNS_FIELDS = ["iteration", "timestamp",
                   "input", "bug_type", "is_new", "exit_code"]
    BUGS_FIELDS = ["target", "bug_type", "bug_key", "input_data",
                   "stdout", "stderr", "returncode", "timed_out",
                   "crashed", "strategy", "timestamp"]
    STATS_FIELDS = ["iteration", "elapsed_s", "runs_total",
                    "bugs_unique", "corpus_size", "runs_per_sec"]

    def __init__(self, target: str) -> None:
        run_id = time.strftime("%Y%m%d_%H%M%S")
        self.target = target

        run_dir = _RESULTS_DIR / target / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        self._bug_path  = _RESULTS_DIR / f"{target}_bugs.csv"
        self._run_path  = run_dir / "all_runs.csv"
        self._stat_path = run_dir / "stats.csv"
        self._tb_path   = run_dir / "tracebacks.log"

        self._init_csv(self._run_path, self.RUNS_FIELDS)
        self._init_csv(self._stat_path, self.STATS_FIELDS)
        if not self._bug_path.exists():
            self._init_csv(self._bug_path, self.BUGS_FIELDS)

        self._iteration = 0
        self._unique_bugs = 0
        self._seen_keys: set[str] = set()
        self._start_time = time.monotonic()
        self._last_snapshot_iter = 0
        self._snapshot_interval = 50  # write stats row every N runs
        self._run_id = run_id

        print(f"[logger] Writing results to: {run_dir}")

        # Clear current Firestore database for new run
        firestore_client.clear_current_db(run_id)

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
                result.bug_type.name,
                "1" if result.new_coverage else "0",
                result.returncode,
            ])

        # if result.is_new_behavior:
        #     self._unique_bugs += 1
        #     cat, exc, msg = result.bug_key if result.bug_key else ("", "", "")
        #     with open(self._bug_path, "a", newline="", encoding="utf-8") as f:
        #         writer = csv.writer(f)
        #         writer.writerow([
        #             self._iteration,
        #             f"{now:.3f}",
        #             cat, exc, msg,
        #             input_repr,
        #         ])

        if result.bug_key and result.bug_key not in self._seen_keys:
            self._seen_keys.add(result.bug_key)
            self._unique_bugs += 1
 
            with open(self._bug_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.BUGS_FIELDS)
                writer.writerow({
                    "target"     : self.target,
                    "bug_type"   : result.bug_type.name,
                    "bug_key"    : result.bug_key,
                    "input_data" : result.input_data,
                    "stdout"     : result.stdout[:500],
                    "stderr"     : result.stderr[:500],
                    "returncode" : result.returncode,
                    "timed_out"  : result.timed_out,
                    "crashed"    : result.crashed,
                    "strategy"   : result.strategy,
                    "timestamp"  : time.strftime("%Y-%m-%d %H:%M:%S"),
                })
 
            # Save crash input to crashes/<target>/
            if result.crashed or result.timed_out:
                crash_dir = _CRASHES_DIR / self.target
                crash_dir.mkdir(parents=True, exist_ok=True)
                (crash_dir / f"{result.bug_key}.txt").write_text(
                    result.input_data, encoding="utf-8", errors="replace"
                )

            # Upload to Firestore
            firestore_client.upload_bug(result, run_id=self._run_id)
            if result.crashed or result.timed_out:
                firestore_client.upload_crash(
                    target=self.target,
                    bug_key=result.bug_key,
                    input_data=result.input_data,
                    error_type="TIMEOUT" if result.timed_out else "CRASH",
                )

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

        # Upload stats to Firestore
        firestore_client.upload_stats(
            target=self.target,
            run_id=self._run_id,
            iteration=self._iteration,
            unique_bugs=self._unique_bugs,
            corpus_size=corpus_size,
            elapsed_s=now,
            runs_per_sec=runs_per_sec,
        )

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

    def _bugs_csv_is_stale(self) -> bool:
        """
        Return True if bugs.csv exists but has a different header than
        BUGS_FIELDS — prevents DictWriter from raising ValueError on first
        writerow when the schema changed between runs.
        """
        try:
            with open(self._bug_path, newline="", encoding="utf-8") as f:
                existing_header = next(csv.reader(f), None)
            return existing_header != self.BUGS_FIELDS
        except Exception:
            return True  # unreadable → treat as stale, rewrite

    @property
    def iteration(self) -> int:
        return self._iteration

    @property
    def unique_bugs(self) -> int:
        return self._unique_bugs

# ---------------------------------------------------------------------------
# Module-level interface — called by fuzzer.py
#
# fuzzer.py calls:  bug_logger.log(bug, config)
#                   bug_logger.reset()
#
# A single FuzzLogger instance is created per target and reused across
# all iterations for that target. reset() creates a fresh instance for
# the next target when running --all.
# ---------------------------------------------------------------------------
 
_logger: FuzzLogger | None = None
 
 
def log(bug: BugResult, config: dict) -> None:
    """
    Log one bug result. Creates a FuzzLogger for the target on first call.
    Delegates to FuzzLogger.record() — all the real logic lives there.
    """
    global _logger
    target = bug.target or config.get("name", "unknown")
 
    if _logger is None or _logger.target != target:
        _logger = FuzzLogger(target=target)
 
    _logger.record(bug)
 
 
def reset() -> None:
    """
    Drop the current FuzzLogger instance.
    Call this between targets when running --all so each target gets a
    fresh logger with its own run directory and clean dedup set.
    """
    global _logger
    _logger = None
