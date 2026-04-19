"""
Coverage tracking for both white-box and black-box fuzz targets.
"""

from __future__ import annotations
import collections
import hashlib
import threading
from engine.types import BugResult
from engine import firestore_client

import csv
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

MAP_SIZE = 65536  # AFL's default shared-memory bitmap size (64 KB)

_ENGINE_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _ENGINE_DIR.parent
_RESULTS_DIR = _PROJECT_DIR / "results"


def get_bucket(count: int) -> int:
    """Map a raw hit count to one of AFL's 8 frequency buckets.

    Bucket | Hit range
    -------|----------
    0      | 1
    1      | 2
    2      | 3
    3      | 4–7
    4      | 8–15
    5      | 16–31
    6      | 32–127
    7      | 128+
    """
    if count <= 1:
        return 0
    if count == 2:
        return 1
    if count == 3:
        return 2
    if 4 <= count <= 7:
        return 3
    if 8 <= count <= 15:
        return 4
    if 16 <= count <= 31:
        return 5
    if 32 <= count <= 127:
        return 6
    return 7


def _hash_edge_to_bitmap_idx(edge_id: str) -> int:
    """Hash an edge identifier to a bitmap index in [0, MAP_SIZE)."""
    h = hashlib.md5(edge_id.encode(errors="replace")).digest()
    return (h[0] | (h[1] << 8)) % MAP_SIZE


@dataclass(frozen=True)
class FuzzIterationPayload:
    """Per-iteration, transport-only data for coverage updates."""

    iteration_id: int
    target_name: str
    strategy_used: str
    bug_key: Optional[str] = None
    execution_metrics: Optional[Any] = None
    input_data: Optional[str] = None
    exec_time_ms: float = 0.0
    input_depth: int = 1
    output_signature: Optional[str] = None


class CoverageTracker:
    """
    Tracks fuzzing progress using behavioral or code-execution semantics.
    """

    valid_modes = {"behavioral", "code_execution"}

    PLATEAU_THRESHOLD = 500

    def __init__(self, config_dict: dict[str, Any]) -> None:
        mode = str(config_dict.get("tracking_mode", "behavioral")).strip().lower()
        if mode not in self.valid_modes:
            raise ValueError(
                "Invalid tracking_mode. Expected one of "
                f"{sorted(self.valid_modes)}, got: {mode!r}"
            )

        self.mode: str = mode
        self.target: str = config_dict.get("name", "unknown")
        self.run_id: str = time.strftime("%Y%m%d_%H%M%S")
        self.start_time: float = time.time()
        self.total_inputs: int = 0

        self.total_edges: int = int(config_dict.get("total_edges", 300))

        # State for black-box novelty tracking (REMOVED support)
        self.seen_bug_keys: set[str] = set()
        self._seen_output_signatures: set[str] = set()

        # State for white-box edge coverage tracking
        self.covered_line_ids: set[str] = set()

        # Dual metrics persisted for Firestore/reporting
        self.behavioral_metric: int = 0
        self.execution_metric: int = 0

        self.current_metric: int = 0
        self.last_iteration_id: int = 0

        # AFL tuple bucketing for count coverage
        self.global_edge_buckets: dict[str, set[int]] = collections.defaultdict(set)

        # AFL 64KB bitmap simulation
        self._bitmap: bytearray = bytearray(MAP_SIZE)
        self._bitmap_virgin: bytearray = bytearray(MAP_SIZE)  # 0 = virgin, 0xFF = seen

        # Coverage stability tracking
        self._edge_stability: dict[str, set[int]] = collections.defaultdict(set)
        self._variable_edges: set[str] = set()

        # Favored input tracking
        self._favored_inputs: dict[str, tuple[str, int, float]] = {}

        # Input-to-coverage association
        self._edge_discoverer: dict[str, str] = {}

        # Plateau detection
        self._iterations_since_new_cov: int = 0
        self._is_plateau: bool = False

        # Bitmap-hash fast path
        self._last_bitmap_hash: str = ""

        # Thread-safe cached metric strings
        self._cached_map_density: str = "0.00%"
        self._cached_count_coverage_bits: str = "1.00 bits/tuple"

        # Real coverage percentages from --show-coverage output (json_decoder)
        self._last_line_cov: float | None = None
        self._last_branch_cov: float | None = None
        self._last_function_cov: float | None = None

        # Current statement coverage (used in map_density calculation)
        self.current_statement_cov: float = 0.0

        # Item geometry tracking (AFL-compatible)
        self._max_depth: int = 0
        self._own_finds: int = 0
        self._pending_total: int = 0
        self._pending_favs: int = 0
        self._imported: int = 0

        # Bitmap snapshot export
        self._snapshot_interval: int = 1000
        self._snapshot_dir = _RESULTS_DIR / "bitmap_snapshots"

        _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        self.coverage_log_path = _RESULTS_DIR / f"{self.target}_coverage.csv"
        self.ensure_log_file()

    def update(self, payload: FuzzIterationPayload) -> bool:
        """Update tracker state using one fuzz iteration payload."""
        new_path_found = False
        new_behavior_found = False
        bucket_novel = False
        self.last_iteration_id = payload.iteration_id
        self.total_inputs += 1

        # Update max depth (item geometry: levels)
        if payload.input_depth > self._max_depth:
            self._max_depth = payload.input_depth

        if payload.bug_key and payload.bug_key not in self.seen_bug_keys:
            self.seen_bug_keys.add(payload.bug_key)
            new_behavior_found = True

        coverage_percentages = self.extract_percentage_metrics(
            payload.execution_metrics
        )

        self.behavioral_metric = len(self.seen_bug_keys)

        if self.mode == "behavioral":
            self.current_metric = self.behavioral_metric

            # Bitmap: mark bug_key slot
            if payload.bug_key:
                self.global_edge_buckets[payload.bug_key].add(0)
                idx = _hash_edge_to_bitmap_idx(payload.bug_key)
                self._bitmap[idx] = max(self._bitmap[idx], 1)

            # Bitmap: mark output-signature slot
            new_sig_found = False
            if payload.output_signature:
                sig = payload.output_signature
                if sig not in self._seen_output_signatures:
                    self._seen_output_signatures.add(sig)
                    sig_idx = _hash_edge_to_bitmap_idx(sig)
                    self._bitmap[sig_idx] = max(self._bitmap[sig_idx], 1)
                    self.global_edge_buckets[sig].add(0)
                    new_sig_found = True

            new_path_found = new_behavior_found or new_sig_found

            statement_coverage = 0.0
            branch_coverage = 0.0
            function_coverage = 0.0

        elif self.mode == "code_execution":
            if coverage_percentages:
                new_statement = coverage_percentages.get("statement", 0.0)
                new_path_found = new_statement > (self._last_line_cov or 0.0)
                self._last_line_cov = max(new_statement, self._last_line_cov or 0.0)
                self._last_branch_cov = max(
                    coverage_percentages.get("branch", 0.0),
                    self._last_branch_cov or 0.0,
                )
                self._last_function_cov = max(
                    coverage_percentages.get("function", 0.0),
                    self._last_function_cov or 0.0,
                )
                self.current_metric = self.execution_metric
            else:
                self.current_metric = self.behavioral_metric
                new_path_found = new_behavior_found
 
            if coverage_percentages:
                statement_coverage = self._last_line_cov if self._last_line_cov is not None else 0.0
                branch_coverage = self._last_branch_cov if self._last_branch_cov is not None else 0.0
                function_coverage = self._last_function_cov if self._last_function_cov is not None else 0.0
            else:
                statement_coverage = self._last_line_cov if self._last_line_cov is not None else 0.0
                branch_coverage = self._last_branch_cov if self._last_branch_cov is not None else 0.0
                function_coverage = self._last_function_cov if self._last_function_cov is not None else 0.0

            # AFL bucket novelty detection via bitmap hash
            bitmap_hash = hashlib.md5(
                str(sorted(coverage_percentages.items())).encode()
            ).hexdigest()

            if bitmap_hash != self._last_bitmap_hash:
                self._last_bitmap_hash = bitmap_hash
                for key, pct in coverage_percentages.items():
                    edge_id = f"cov:{key}"
                    b = get_bucket(int(pct))
                    idx = _hash_edge_to_bitmap_idx(edge_id)
                    self._bitmap[idx] = max(self._bitmap[idx], b + 1)
                    if b not in self.global_edge_buckets[edge_id]:
                        bucket_novel = True
                    self.global_edge_buckets[edge_id].add(b)

            if bucket_novel:
                new_path_found = True

        self.current_statement_cov = statement_coverage

        if new_path_found:
            self._own_finds += 1
            self._iterations_since_new_cov = 0
            self._is_plateau = False
        else:
            self._iterations_since_new_cov += 1
            if self._iterations_since_new_cov >= self.PLATEAU_THRESHOLD:
                self._is_plateau = True

        self._update_cached_metrics()

        if self.total_inputs % self._snapshot_interval == 0:
            self._export_bitmap_snapshot()

        map_density_pct = sum(1 for b in self._bitmap if b > 0) / MAP_SIZE * 100

        self.log_state(
            current_metric=self.current_metric,
            new_path_found=new_path_found,
            behavioral_metric=self.behavioral_metric,
            execution_metric=self.execution_metric,
            statement_coverage=statement_coverage,
            branch_coverage=branch_coverage,
            function_coverage=function_coverage,
            map_density=map_density_pct,
            coverage_source=("instrumented" if coverage_percentages else "proxy"),
        )
        return new_path_found

    @property
    def is_plateau(self) -> bool:
        return self._is_plateau

    @property
    def iterations_since_new_coverage(self) -> int:
        return self._iterations_since_new_cov

    # --- Thread-safe cached metrics ---

    def _update_cached_metrics(self) -> None:
        """Recompute and cache metric strings atomically.
        """
        nonzero = sum(1 for b in self._bitmap if b > 0)
        density = nonzero / MAP_SIZE * 100
        self._cached_map_density = f"{density:.2f}%"

        if not self.global_edge_buckets:
            self._cached_count_coverage_bits = "1.00 bits/tuple"
        else:
            total_bits = sum(len(b) for b in self.global_edge_buckets.values())
            avg = total_bits / len(self.global_edge_buckets)
            self._cached_count_coverage_bits = f"{avg:.2f} bits/tuple"

    @property
    def map_density(self) -> str:
        return self._cached_map_density

    @property
    def count_coverage_bits(self) -> str:
        return self._cached_count_coverage_bits

    # Item geometry properties

    @property
    def levels(self) -> int:
        return max(self._max_depth, 1)

    @property
    def own_finds(self) -> int:
        return self._own_finds

    @property
    def imported(self) -> int:
        return self._imported

    @property
    def stability(self) -> float:
        """Always 100% — stability tracking removed with line frequency extraction."""
        return 100.0

    @property
    def stability_str(self) -> str:
        return f"{self.stability:.2f}%"

    @property
    def bitmap_nonzero(self) -> int:
        return sum(1 for b in self._bitmap if b > 0)

    def update_geometry(self, pending: int, pend_fav: int) -> None:
        """Update pending/pend_fav from the fuzzer main loop."""
        self._pending_total = pending
        self._pending_favs = pend_fav

    @property
    def pending(self) -> int:
        return self._pending_total

    @property
    def pend_fav(self) -> int:
        return self._pending_favs


    def _export_bitmap_snapshot(self) -> None:
        """Save a compressed snapshot of current edge→bucket state."""
        try:
            self._snapshot_dir.mkdir(parents=True, exist_ok=True)
            path = self._snapshot_dir / (f"{self.target}_iter{self.total_inputs}.csv")
            with path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["edge_id", "buckets"])
                for edge_id, buckets in sorted(self.global_edge_buckets.items()):
                    if edge_id.startswith(("line:", "branch:")):
                        continue
                    writer.writerow(
                        [
                            edge_id,
                            "|".join(str(b) for b in sorted(buckets)),
                        ]
                    )
        except Exception:
            pass  # never crash the fuzzer for snapshot failures


    def ensure_log_file(self) -> None:
        # Create the log file with headers if it doesn't already exist
        if self.coverage_log_path.exists():
            return

        with self.coverage_log_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "timestamp",
                    "run_id",
                    "statement_coverage",
                    "branch_coverage",
                    "function_coverage",
                    "map_density",
                    "total_inputs",
                    "coverage_source",
                ]
            )

    def log_state(
        self,
        current_metric: int,
        new_path_found: bool,
        behavioral_metric: int,
        execution_metric: int,
        statement_coverage: float,
        branch_coverage: float,
        function_coverage: float,
        map_density: float,
        coverage_source: str,
    ) -> None:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        with self.coverage_log_path.open("a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(
                [
                    timestamp,
                    self.run_id,
                    statement_coverage,
                    branch_coverage,
                    function_coverage,
                    round(map_density, 4),
                    self.total_inputs,
                    coverage_source,
                ]
            )

        firestore_client.upload_coverage(
            target=self.target,
            run_id=self.run_id,
            iteration=self.last_iteration_id,
            total_inputs=self.total_inputs,
            tracking_mode=self.mode,
            statement_coverage=statement_coverage,
            branch_coverage=branch_coverage,
            function_coverage=function_coverage,
            new_path_found=new_path_found,
            behavioral_metric=float(behavioral_metric),
            execution_metric=float(execution_metric),
            coverage_source=coverage_source,
        )

    def extract_percentage_metrics(
        self, execution_metrics: Optional[Any]
    ) -> dict[str, float]:
        if execution_metrics is None:
            return {}

        if isinstance(execution_metrics, dict):
            raw = execution_metrics.get("coverage_percentages")
            if isinstance(raw, dict):
                out: dict[str, float] = {}
                for key in ("statement", "branch", "function", "combined"):
                    if key in raw:
                        try:
                            out[key] = max(0.0, min(100.0, float(raw[key])))
                        except (TypeError, ValueError):
                            pass
                return out

        return {}


# Singleton tracker, reset per target
_tracker: CoverageTracker | None = None
_iteration: int = 0
_tracker_lock = threading.Lock()


def _extract_output_class(line: str) -> str:
    """Reduce a raw output line to its behavioral CLASS, stripping specific values.

    Examples:
        "Output: [192.168.0.1]"   → "output:bracketed"
        "Reference: Invalid IP"   → "reference:invalid"
        "IPNetwork('1.2.3.0/24')" → "ipnetwork"
        "CidrizeError: bad addr"  → "error:cidrize"
        "ParseException: ..."     → "error:parse"
        "Traceback (most recent)" → "traceback"
        ""                        → "empty"

    The goal: two inputs that trigger the *same program path* should produce
    the same class string even if the output *value* differs.
    """
    if not line:
        return "empty"

    lo = line.lower()

    # Traceback / Python exception header
    if lo.startswith("traceback"):
        return "traceback"

    # Known error class names (grab the class name only, not the message)
    import re as _re
    err_match = _re.match(r"([A-Z][A-Za-z]+(?:Error|Exception|Warning))\s*:", line)
    if err_match:
        return f"error:{err_match.group(1).lower()}"

    # "Reference: ..." lines (these are explicit reference-script labels)
    if lo.startswith("reference:"):
        label = line.split(":", 1)[1].strip().lower()
        # Collapse specific messages into a few classes
        if "invalid" in label:
            return "reference:invalid"
        if "valid" in label:
            return "reference:valid"
        return f"reference:{label[:20]}"

    # "Output: [...]" — the parsed value is in brackets; strip it
    if lo.startswith("output:"):
        rest = line[7:].strip()
        if rest.startswith("[") and rest.endswith("]"):
            return "output:bracketed"
        if rest.startswith("{"):
            return "output:object"
        if rest.startswith("["):
            return "output:array"
        return "output:other"

    # IPNetwork / IPRange / IPAddress repr strings (cidrize output)
    if lo.startswith("ipnetwork(") or lo.startswith("iprange("):
        return "ipnetwork"
    if lo.startswith("ipaddress("):
        return "ipaddress"

    # Generic: take only the first word (the "verb" / label) of the line
    first_word = lo.split()[0].rstrip(":").rstrip("(")[:20]
    return f"generic:{first_word}"


def _compute_output_signature(
    stdout: str, stderr: str, returncode: int, timed_out: bool
) -> str:
    """Compute a canonical BEHAVIORAL CLASS fingerprint from raw target output.="""
    if timed_out:
        return "rc=timeout|out=empty|err=empty"

    # ── 1. Exit-code bucket ────────────────────────────────────────────────
    if returncode == 0:
        rc = "ok"
    elif returncode == 1:
        rc = "e1"
    elif returncode == 2:
        rc = "e2"
    elif returncode < 0:
        rc = "crash"
    else:
        rc = "eN"

    # ── 2. Output class (first non-empty stdout line, value-stripped) ──────
    stdout_line1 = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped:
            stdout_line1 = stripped
            break
    out_class = _extract_output_class(stdout_line1)

    # ── 3. Error class (first non-empty stderr line, value-stripped) ───────
    stderr_line1 = ""
    for line in stderr.splitlines():
        stripped = line.strip()
        if stripped:
            stderr_line1 = stripped
            break
    err_class = _extract_output_class(stderr_line1)

    return f"rc={rc}|out={out_class}|err={err_class}"


def update(
    bug: BugResult, config: dict, input_depth: int = 1, reference_result=None
) -> bool:
    """Translate a BugResult into a FuzzIterationPayload and update the tracker."""
    global _tracker, _iteration
    with _tracker_lock:
        _iteration += 1

        if _tracker is None or _tracker.target != bug.target:
            _tracker = CoverageTracker(config)

        coverage_enabled = bool(config.get("coverage_enabled", False))
        tracking_mode = str(config.get("tracking_mode", "behavioral")).strip().lower()

        if coverage_enabled: # whitebox
            cov_stdout = bug.stdout
            cov_stderr = bug.stderr
        elif tracking_mode == "code_execution" and reference_result is not None: # greybox
            cov_stdout = reference_result.stdout
            cov_stderr = reference_result.stderr
        else: # blackbox
            cov_stdout = ""
            cov_stderr = ""

        coverage_percentages = _extract_coverage_percentages(cov_stdout, cov_stderr)
        execution_metrics = {
            "coverage_percentages": coverage_percentages,
        }

        output_sig = _compute_output_signature(
            bug.stdout, bug.stderr, bug.returncode, bug.timed_out
        )

        payload = FuzzIterationPayload(
            iteration_id=_iteration,
            target_name=bug.target,
            strategy_used=bug.strategy,
            bug_key=bug.bug_key,
            execution_metrics=execution_metrics,
            input_data=bug.input_data,
            exec_time_ms=bug.exec_time_ms,
            input_depth=input_depth,
            output_signature=output_sig,
        )

        new_path = _tracker.update(payload)

        if new_path:
            bug.new_coverage = True

        return new_path


def reset() -> None:
    global _tracker, _iteration
    with _tracker_lock:
        _tracker = None
        _iteration = 0


def get_tracker() -> CoverageTracker | None:
    return _tracker


def _extract_coverage_percentages(stdout: str, stderr: str) -> dict[str, float]:
    """
    Parse percentage values from target output lines like:
    - line coverage     : _%
    - branch coverage   : _%
    - combined coverage : _%
    """
    if "\t<cov_lines>" in stdout:
        text = stdout.split("\t<cov_lines>", 1)[1]
    else:
        text = stdout + "\n" + stderr
    out: dict[str, float] = {}

    patterns = {
        "statement": r"line\s+coverage\s*:\s*([0-9]+(?:\.[0-9]+)?)%",
        "branch": r"branch\s+coverage\s*:\s*([0-9]+(?:\.[0-9]+)?)%",
        "combined": r"combined\s+coverage\s*:\s*([0-9]+(?:\.[0-9]+)?)%",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if not m:
            continue
        try:
            out[key] = max(0.0, min(100.0, float(m.group(1))))
        except (TypeError, ValueError):
            continue

    if "combined" in out and "function" not in out:
        out["function"] = out["combined"]

    return out