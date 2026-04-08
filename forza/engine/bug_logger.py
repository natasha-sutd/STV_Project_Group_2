"""
Saves every unique bug found to disk and to a CSV file.

Files written to results/<target>/<run_id>/:
    - all_runs.csv: every execution (input, bug_type, is_new)
    - bugs.csv: deduplicated unique bugs found
    - stats.csv: time-series snapshot of coverage/throughput
    - tracebacks.log: raw stdout for anything that is not NORMAL
"""

from engine import firestore_client
from engine.types import BugResult, BugType
from pathlib import Path
import time
import csv

_ENGINE_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _ENGINE_DIR.parent
_RESULTS_DIR = _PROJECT_DIR / "results"


class FuzzLogger:
    """
    Writes fuzzing results to disk in a structured format.

    Call 'record(result)' after every run and 'snapshot()' periodically to update the stats CSV for graphing.
    """

    RUNS_FIELDS = ["iteration", "timestamp", "input", "bug_type", "is_new", "exit_code"]
    BUGS_FIELDS = [
        "target",
        "bug_type",
        "bug_key",
        "input_data",
        "stdout",
        "stderr",
        "returncode",
        "timed_out",
        "crashed",
        "strategy",
        "timestamp",
        "is_representative",
    ]
    STATS_FIELDS = [
        "iteration",
        "elapsed_s",
        "runs_total",
        "bugs_unique",
        "corpus_size",
        "runs_per_sec",
    ]

    def __init__(self, target: str) -> None:
        run_id = time.strftime("%Y%m%d_%H%M%S")
        self.target = target

        run_dir = _RESULTS_DIR / target / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        self._bug_path = _RESULTS_DIR / f"{target}_bugs.csv"
        self._run_path = run_dir / "all_runs.csv"
        self._stat_path = run_dir / "stats.csv"
        self._tb_path = run_dir / "tracebacks.log"

        self._init_csv(self._run_path, self.RUNS_FIELDS)
        self._init_csv(self._stat_path, self.STATS_FIELDS)
        if not self._bug_path.exists():
            self._init_csv(self._bug_path, self.BUGS_FIELDS)

        self._iteration = 0
        self._unique_bugs = 0
        self._seen_keys: set[str] = set()
        self._start_time = time.monotonic()
        self._last_snapshot_iter = 0
        self._snapshot_interval = 50
        self._run_id = run_id

        # Stores the FIRST input that triggered each unique BugType (max 11 entries).
        # Only these representative bugs are surfaced in report.html.
        self._first_by_type: dict[BugType, BugResult] = {}

        print(f"[logger] Writing results to: {run_dir}")

        firestore_client.clear_current_db(run_id)

    # Public API
    def record(self, result: BugResult, corpus_size: int = 0) -> None:
        """Record a single run result."""
        self._iteration += 1
        now = time.monotonic() - self._start_time
        input_repr = repr(result.input_data)[:120]

        with open(self._run_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    self._iteration,
                    f"{now:.3f}",
                    input_repr,
                    result.bug_type.name,
                    "1" if result.new_coverage else "0",
                    result.returncode,
                ]
            )

        if result.bug_key and result.bug_key not in self._seen_keys:
            self._seen_keys.add(result.bug_key)
            self._unique_bugs += 1

            with open(self._bug_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.BUGS_FIELDS)
                writer.writerow(
                    {
                        "target": self.target,
                        "bug_type": result.bug_type.name,
                        "bug_key": result.bug_key,
                        "input_data": result.input_data,
                        "stdout": result.stdout[:500],
                        "stderr": result.stderr[:500],
                        "returncode": result.returncode,
                        "timed_out": result.timed_out,
                        "crashed": result.crashed,
                        "strategy": result.strategy,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "is_representative": result.bug_type in self._first_by_type and self._first_by_type[result.bug_type].bug_key == result.bug_key,
                    }
                )

            firestore_client.upload_bug(result, run_id=self._run_id)

        # Track the first-ever input for each BugType (used by report.html).
        # NORMAL results are excluded -- only real bug categories are recorded.
        if (
            result.bug_type is not BugType.NORMAL
            and result.bug_type not in self._first_by_type
        ):
            self._first_by_type[result.bug_type] = result
            firestore_client.upload_bug(
                result, run_id=self._run_id, is_representative=True
            )

        if result.bug_type not in (BugType.NORMAL,):
            with open(self._tb_path, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(
                    f"Iteration {self._iteration} | {result.bug_type.value} | {now:.1f}s\n"
                )
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
            writer.writerow(
                [
                    self._iteration,
                    f"{now:.1f}",
                    self._iteration,
                    self._unique_bugs,
                    corpus_size,
                    f"{runs_per_sec:.2f}",
                ]
            )
        self._last_snapshot_iter = self._iteration

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

    # Helper functions
    def _init_csv(self, path: Path, fields: list) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(fields)

    def _bugs_csv_is_stale(self) -> bool:
        try:
            with open(self._bug_path, newline="", encoding="utf-8") as f:
                existing_header = next(csv.reader(f), None)
            return existing_header != self.BUGS_FIELDS
        except Exception:
            return True  # unreadable, treat as stale, rewrite

    @property
    def iteration(self) -> int:
        return self._iteration

    @property
    def unique_bugs(self) -> int:
        return self._unique_bugs

    @property
    def first_bugs(self) -> dict[BugType, BugResult]:
        """One representative BugResult per BugType, in discovery order.
        
        At most 11 entries (one per category). Use this for report.html
        instead of the full bugs list to avoid duplicates flooding the report.
        """
        return dict(self._first_by_type)


# Singleton logger, reset per target
_logger: FuzzLogger | None = None


def log(bug: BugResult, config: dict) -> None:
    global _logger
    target = bug.target or config.get("name", "unknown")

    if _logger is None or _logger.target != target:
        _logger = FuzzLogger(target=target)

    _logger.record(bug)


def reset() -> None:
    global _logger
    _logger = None