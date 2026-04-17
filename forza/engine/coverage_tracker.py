"""
Coverage tracking for both white-box and black-box fuzz targets.

YAML fields read:
    - tracking_mode:
        - "behavioral": black-box binaries, a novel bug_key is treated as a new path
        - "code_execution": white-box targets, execution data can be supplied in execution_metrics

AFL-style features implemented:
    - 8-tier frequency bucketing  [1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+]
    - Bucket novelty detection    (new frequency class = new path)
    - Coverage stability tracking (variable edges excluded from novelty decisions)
    - Favored input selection     (smallest/fastest input per edge)
    - Coverage plateau detection  (stall detection for mutation escalation)
    - Bitmap-hash fast path       (O(1) "no change" detection)
    - Input-to-coverage map       (edge_id → input_hash for corpus analysis)
    - Bitmap snapshot export      (periodic coverage evolution checkpoints)
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

_COVERAGE_LOG_FIELDS = [
    "timestamp",
    "run_id",
    "statement_coverage",
    "branch_coverage",
    "function_coverage",
    "map_density",
    "total_inputs",
    "coverage_source",
    "coverage_data_valid",
    "instrumentation_error",
]


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
    # Behavioral fingerprint for blackbox targets (computed from raw target output)
    output_signature: Optional[str] = None


class CoverageTracker:
    """
    Tracks fuzzing progress using behavioral or code-execution semantics.

    'update()' returns True when new coverage/novelty is discovered.

    AFL-compatible features:
        - Bucket novelty: a new frequency bucket for an existing edge = new path
        - Stability tracking: edges that vary across re-runs are marked variable
        - Favored inputs: smallest/fastest input per edge is tracked
        - Plateau detection: detects when coverage growth stalls
        - Bitmap hash: O(1) fast-path for "no new coverage" detection
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

        # Configurable total edges baseline
        self.total_edges: int = int(config_dict.get("total_edges", 300))

        # State for black-box novelty tracking
        self.seen_bug_keys: set[str] = set()

        # Behavioral output signatures for blackbox coverage.
        # Each unique (exit_code_bucket, stdout_shape, stderr_line1) fingerprint
        # is a distinct "behavioral edge" mapped into the 64KB bitmap.
        self._seen_output_signatures: set[str] = set()

        # State for white-box edge coverage tracking
        self.covered_line_ids: set[str] = set()

        # Dual metrics persisted for Firestore/reporting
        self.behavioral_metric: int = 0
        self.execution_metric: int = 0

        self.current_metric: int = 0
        self.last_iteration_id: int = 0

        # Firestore uploads are throttled to avoid blocking the hot path.
        try:
            upload_every = int(config_dict.get("coverage_upload_interval", 25))
        except (TypeError, ValueError):
            upload_every = 25
        self._coverage_upload_interval: int = max(1, upload_every)
        self._last_uploaded_input_count: int = 0

        # AFL tuple bucketing for count coverage
        # Maps edge_id → set of observed bucket indices
        self.global_edge_buckets: dict[str, set[int]] = collections.defaultdict(set)

        # =====================================================================
        # AFL 64KB bitmap simulation
        # =====================================================================
        # Simulates AFL's shared-memory bitmap. Each edge ID is hashed into
        # one of 65536 slots. The slot stores the highest bucket index seen
        # for any edge mapping to that slot. This gives us directly
        # comparable map density numbers (nonzero_slots / MAP_SIZE * 100).
        self._bitmap: bytearray = bytearray(MAP_SIZE)
        # Track which slots have ever been touched (for count coverage)
        self._bitmap_virgin: bytearray = bytearray(MAP_SIZE)  # 0 = virgin, 0xFF = seen

        # --- Coverage stability tracking ---
        # Maps edge_id → list of bucket indices observed across calibration runs.
        # An edge is "variable" if it shows different buckets on identical inputs.
        self._edge_stability: dict[str, set[int]] = collections.defaultdict(set)
        self._variable_edges: set[str] = set()

        # --- Favored input tracking ---
        # Maps edge_id → (input_hash, input_length, exec_time_ms)
        # Keeps the smallest/fastest input that first triggered each edge.
        self._favored_inputs: dict[str, tuple[str, int, float]] = {}

        # --- Input-to-coverage association ---
        # Maps edge_id → input_hash of the input that first discovered it
        self._edge_discoverer: dict[str, str] = {}

        # --- Plateau detection ---
        self._iterations_since_new_cov: int = 0
        self._is_plateau: bool = False

        # --- Bitmap-hash fast path ---
        # Hash of the previous iteration's full frequency dict for O(1) comparison
        self._last_bitmap_hash: str = ""

        # --- Thread-safe cached metric strings ---
        # Updated atomically at the end of update(); read by the UI thread.
        self._cached_map_density: str = "0.00%"
        self._cached_count_coverage_bits: str = "1.00 bits/tuple"

        # Real coverage percentages from --show-coverage output (json_decoder)
        # None = not yet seen, use proxy metric instead
        self._last_line_cov: float | None = None
        self._last_branch_cov: float | None = None
        self._last_function_cov: float | None = None

        # Current statement coverage (used in map_density calculation)
        self.current_statement_cov: float = 0.0

        # =====================================================================
        # Item geometry tracking (AFL-compatible)
        # =====================================================================
        # levels: maximum mutation depth reached (seeds = level 1)
        self._max_depth: int = 0
        # own_finds: count of inputs that first hit a new bitmap slot
        self._own_finds: int = 0
        # pending: corpus entries not yet used as a mutation parent
        self._pending_total: int = 0
        # pend_fav: pending entries that are also favored
        self._pending_favs: int = 0
        # imported: paths imported from another fuzzer instance (always 0)
        self._imported: int = 0
        # Track which edges are covered by favored inputs for pend_fav
        self._favored_corpus_indices: set[int] = set()

        # --- Bitmap snapshot export ---
        self._snapshot_interval: int = 1000  # every N iterations
        self._snapshot_dir = _RESULTS_DIR / "bitmap_snapshots"

        _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        self.coverage_log_path = _RESULTS_DIR / f"{self.target}_coverage.csv"
        self._coverage_log_fields: list[str] = []
        self.ensure_log_file()

    def update(self, payload: FuzzIterationPayload) -> bool:
        """Update tracker state using one fuzz iteration payload."""
        new_path_found = False
        new_behavior_found = False
        new_execution_found = False
        bucket_novel = False
        self.last_iteration_id = payload.iteration_id
        self.total_inputs += 1

        # --- Update max depth (item geometry: levels) ---
        if payload.input_depth > self._max_depth:
            self._max_depth = payload.input_depth

        if payload.bug_key and payload.bug_key not in self.seen_bug_keys:
            self.seen_bug_keys.add(payload.bug_key)
            new_behavior_found = True

        newly_seen_lines = self.extract_line_identifiers(payload.execution_metrics)
        coverage_percentages = self.extract_percentage_metrics(
            payload.execution_metrics
        )
        payload_coverage_source = ""
        payload_instrumentation_error = ""
        if isinstance(payload.execution_metrics, dict):
            raw_source = payload.execution_metrics.get("coverage_source")
            if raw_source is not None:
                payload_coverage_source = str(raw_source).strip().lower()
            raw_instr_err = payload.execution_metrics.get("instrumentation_error")
            if raw_instr_err:
                payload_instrumentation_error = str(raw_instr_err).strip()
        if newly_seen_lines:
            novel_lines = newly_seen_lines - self.covered_line_ids
            if novel_lines:
                self.covered_line_ids.update(novel_lines)
                new_execution_found = True

                # Record which input first discovered each new edge
                if payload.input_data:
                    input_hash = hashlib.md5(
                        payload.input_data[:200].encode(errors="replace")
                    ).hexdigest()[:12]
                    input_len = len(payload.input_data) if payload.input_data else 0
                    for edge_id in novel_lines:
                        if edge_id not in self._edge_discoverer:
                            self._edge_discoverer[edge_id] = input_hash
                        # Update favored input: prefer smaller/faster inputs
                        self._update_favored(
                            edge_id, input_hash, input_len, payload.exec_time_ms
                        )

        self.behavioral_metric = len(self.seen_bug_keys)
        self.execution_metric = len(self.covered_line_ids)

        if self.mode == "behavioral":
            self.current_metric = self.behavioral_metric

            # --- Bitmap: mark bug_key slot ---
            if payload.bug_key:
                self.global_edge_buckets[payload.bug_key].add(0)  # 1-hit bucket
                idx = _hash_edge_to_bitmap_idx(payload.bug_key)
                self._bitmap[idx] = max(self._bitmap[idx], 1)
                self._bitmap_virgin[idx] = 0xFF

            # --- Bitmap: mark output-signature slot (blackbox behavioral edge) ---
            # Every distinct output fingerprint (exit-code bucket + output shape)
            # is treated as a new "edge" in the 64KB bitmap, exactly like AFL does
            # for compiled targets.  This gives a meaningful, monotonically growing
            # map_density for fully black-box targets.
            new_sig_found = False
            if payload.output_signature:
                sig = payload.output_signature
                if sig not in self._seen_output_signatures:
                    self._seen_output_signatures.add(sig)
                    sig_idx = _hash_edge_to_bitmap_idx(sig)
                    self._bitmap[sig_idx] = max(self._bitmap[sig_idx], 1)
                    self._bitmap_virgin[sig_idx] = 0xFF
                    self.global_edge_buckets[sig].add(0)
                    new_sig_found = True

            new_path_found = new_behavior_found or new_sig_found

            # Behavioral mode has NO source code instrumentation, so
            # statement/branch/function coverage cannot exist — log 0.0.
            # The map_density (computed below) is the meaningful metric.
            statement_coverage = 0.0
            branch_coverage = 0.0
            function_coverage = 0.0
        elif self.mode == "code_execution":
            fallback_sig_novel = False
            if payload_coverage_source == "proxy_none" and payload.output_signature:
                sig = payload.output_signature
                if sig not in self._seen_output_signatures:
                    self._seen_output_signatures.add(sig)
                    fallback_sig_novel = True

            prev_statement_cov = self._last_line_cov if self._last_line_cov is not None else 0.0
            prev_branch_cov = self._last_branch_cov if self._last_branch_cov is not None else prev_statement_cov
            prev_function_cov = self._last_function_cov if self._last_function_cov is not None else prev_statement_cov

            if coverage_percentages:
                # Keep percentage-based coverage cumulative so charts represent
                # "coverage discovered so far" rather than per-input volatility.
                raw_statement_cov = coverage_percentages.get(
                    "statement", round(float(self.current_metric), 2)
                )
                raw_branch_cov = coverage_percentages.get("branch", raw_statement_cov)
                raw_function_cov = coverage_percentages.get(
                    "function", coverage_percentages.get("combined", raw_statement_cov)
                )

                self._last_line_cov = max(prev_statement_cov, raw_statement_cov)
                self._last_branch_cov = max(prev_branch_cov, raw_branch_cov)
                self._last_function_cov = max(prev_function_cov, raw_function_cov)

                statement_coverage = self._last_line_cov
                branch_coverage = self._last_branch_cov
                function_coverage = self._last_function_cov

                coverage_improved = (
                    statement_coverage > prev_statement_cov
                    or branch_coverage > prev_branch_cov
                    or function_coverage > prev_function_cov
                )
                new_path_found = coverage_improved
                self.current_metric = self.execution_metric
            elif newly_seen_lines:
                self.current_metric = self.execution_metric
                new_path_found = new_execution_found

                # No percentage metrics this iteration; retain the best known
                # percentages so missing data does not create visual drops.
                statement_coverage = prev_statement_cov
                branch_coverage = prev_branch_cov
                function_coverage = prev_function_cov
            else:
                # No coverage data from this run (target crashed / produced no
                # --show-coverage output). Keep the execution-scale metric stable,
                # and use output-signature novelty as a separate fallback signal.
                self.current_metric = self.execution_metric
                new_path_found = fallback_sig_novel

                # No --show-coverage data this iteration (e.g. target crashed).
                # Carry the last valid measurement forward so the chart stays
                # flat during bad runs rather than spiking down to a raw count.
                statement_coverage = prev_statement_cov
                branch_coverage = prev_branch_cov
                function_coverage = prev_function_cov

            # --- AFL bucket novelty detection ---
            # Extract per-edge hit frequencies and check for new bucket entries.
            # A new bucket for an EXISTING edge = new path (AFL virgin-bits).
            line_frequencies = self.extract_line_frequencies(payload.execution_metrics)

            # Bitmap-hash fast path: if the entire frequency dict hashes the
            # same as last iteration, skip the per-edge bucket check.
            bitmap_hash = hashlib.md5(
                str(sorted(line_frequencies.items())).encode()
            ).hexdigest()

            if bitmap_hash != self._last_bitmap_hash:
                self._last_bitmap_hash = bitmap_hash

                for edge_id, count in line_frequencies.items():
                    # Skip summary entries (line:N/M, branch:N/M)
                    if edge_id.startswith(("line:", "branch:")):
                        continue
                    b = get_bucket(count)

                    # --- Update the simulated 64KB bitmap ---
                    idx = _hash_edge_to_bitmap_idx(edge_id)
                    self._bitmap[idx] = max(self._bitmap[idx], b + 1)
                    self._bitmap_virgin[idx] = 0xFF

                    # Check if this bucket is NEW for this edge
                    if b not in self.global_edge_buckets[edge_id]:
                        # Skip variable edges for novelty decisions
                        if edge_id not in self._variable_edges:
                            bucket_novel = True
                    self.global_edge_buckets[edge_id].add(b)

                    # Update stability tracking
                    self._edge_stability[edge_id].add(b)

            if bucket_novel:
                new_path_found = True

        self.current_statement_cov = statement_coverage

        # --- Own finds tracking ---
        if new_path_found:
            self._own_finds += 1

        # --- Plateau detection ---
        if new_path_found:
            self._iterations_since_new_cov = 0
            self._is_plateau = False
        else:
            self._iterations_since_new_cov += 1
            if self._iterations_since_new_cov >= self.PLATEAU_THRESHOLD:
                self._is_plateau = True

        # --- Update thread-safe cached metric strings ---
        self._update_cached_metrics()

        # --- Periodic bitmap snapshot export ---
        if self.total_inputs % self._snapshot_interval == 0:
            self._export_bitmap_snapshot()

        # --- Compute map density (universal metric for both modes) ---
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
            coverage_source=(
                payload_coverage_source
                if payload_coverage_source
                else ("instrumented" if coverage_percentages else "proxy")
            ),
            coverage_data_valid=(
                self.mode == "behavioral" or payload_coverage_source != "proxy_none"
            ),
            instrumentation_error=payload_instrumentation_error,
        )
        return new_path_found

    # --- Favored input management ---

    def _update_favored(
        self,
        edge_id: str,
        input_hash: str,
        input_len: int,
        exec_time_ms: float,
    ) -> None:
        """Track the smallest/fastest input for each edge.

        Prefers shorter inputs; breaks ties with faster execution time.
        """
        if edge_id not in self._favored_inputs:
            self._favored_inputs[edge_id] = (input_hash, input_len, exec_time_ms)
            return
        _, old_len, old_time = self._favored_inputs[edge_id]
        # Prefer smaller inputs; break ties with faster execution
        if input_len < old_len or (input_len == old_len and exec_time_ms < old_time):
            self._favored_inputs[edge_id] = (input_hash, input_len, exec_time_ms)

    # --- Stability API ---

    def mark_variable_edges(self, edge_ids: set[str]) -> None:
        """Mark edges as variable (non-deterministic).

        Variable edges are excluded from bucket novelty decisions to avoid
        corpus pollution from non-deterministic coverage changes.

        Typically called after running calibration (same input multiple times).
        """
        self._variable_edges.update(edge_ids)

    def calibrate(
        self, edge_buckets_run1: dict[str, int], edge_buckets_run2: dict[str, int]
    ) -> set[str]:
        """Compare two runs of the same input and detect variable edges.

        Returns the set of edge IDs that showed different bucket values.
        """
        variable = set()
        all_edges = set(edge_buckets_run1) | set(edge_buckets_run2)
        for edge_id in all_edges:
            b1 = edge_buckets_run1.get(edge_id, -1)
            b2 = edge_buckets_run2.get(edge_id, -1)
            if b1 != b2:
                variable.add(edge_id)
        self._variable_edges.update(variable)
        return variable

    @property
    def is_plateau(self) -> bool:
        """True if coverage has stalled for PLATEAU_THRESHOLD iterations."""
        return self._is_plateau

    @property
    def iterations_since_new_coverage(self) -> int:
        """Number of consecutive iterations without new coverage."""
        return self._iterations_since_new_cov

    # --- Thread-safe cached metrics ---

    def _update_cached_metrics(self) -> None:
        """Recompute and cache metric strings atomically.

        Called at the end of update(). The fuzzer UI thread reads cached
        values without locks — CPython's GIL ensures string assignment
        is atomic.

        Map density uses the simulated 64KB bitmap, matching AFL:
          density = nonzero_slots / MAP_SIZE * 100

        Count coverage uses bits/tuple from the bitmap:
          bits_per_tuple = total_distinct_buckets / nonzero_slots
        """
        # --- Map density from simulated 64KB bitmap ---
        nonzero = sum(1 for b in self._bitmap if b > 0)
        density = nonzero / MAP_SIZE * 100
        self._cached_map_density = f"{density:.2f}%"

        # --- Count coverage (bits/tuple) ---
        # AFL counts distinct bucket values per bitmap slot.
        # We use total distinct buckets / total covered edges.
        if not self.global_edge_buckets:
            self._cached_count_coverage_bits = "1.00 bits/tuple"
        else:
            total_bits = sum(len(b) for b in self.global_edge_buckets.values())
            avg = total_bits / len(self.global_edge_buckets)
            self._cached_count_coverage_bits = f"{avg:.2f} bits/tuple"

    @property
    def map_density(self) -> str:
        """Thread-safe cached map density string."""
        return self._cached_map_density

    @property
    def count_coverage_bits(self) -> str:
        """Thread-safe cached count coverage string."""
        return self._cached_count_coverage_bits

    # --- Item geometry properties (AFL-compatible) ---

    @property
    def levels(self) -> int:
        """Maximum mutation depth reached (seeds = level 1)."""
        return max(self._max_depth, 1)

    @property
    def own_finds(self) -> int:
        """Number of inputs that first discovered new coverage."""
        return self._own_finds

    @property
    def imported(self) -> int:
        """Paths imported from another instance (always 0 for single-instance)."""
        return self._imported

    @property
    def stability(self) -> float:
        """Coverage stability as a percentage (0-100).

        Computed as the fraction of tracked edges that are NOT variable
        (i.e. they produce deterministic bucket values across runs).
        An edge is "variable" if it has been observed in more than one
        frequency bucket.

        Matches AFL's stability metric semantics.
        """
        total_tracked = len(self._edge_stability)
        if total_tracked == 0:
            return 100.0
        # An edge is variable if it appears in >1 bucket
        variable_count = sum(
            1 for buckets in self._edge_stability.values() if len(buckets) > 1
        )
        return (total_tracked - variable_count) / total_tracked * 100

    @property
    def stability_str(self) -> str:
        """Thread-safe stability string for UI display."""
        return f"{self.stability:.2f}%"

    @property
    def bitmap_nonzero(self) -> int:
        """Number of non-zero slots in the simulated bitmap."""
        return sum(1 for b in self._bitmap if b > 0)

    def update_geometry(self, pending: int, pend_fav: int) -> None:
        """Update pending/pend_fav from the fuzzer main loop.

        These values require corpus-level knowledge that only fuzzer.py has,
        so the main loop calls this after each iteration.
        """
        self._pending_total = pending
        self._pending_favs = pend_fav

    @property
    def pending(self) -> int:
        """Corpus entries not yet used as a mutation parent."""
        return self._pending_total

    @property
    def pend_fav(self) -> int:
        """Pending entries that are also favored."""
        return self._pending_favs

    # --- Bitmap snapshot export ---

    def _export_bitmap_snapshot(self) -> None:
        """Save a compressed snapshot of current edge→bucket state.

        Written every _snapshot_interval iterations for post-hoc analysis
        of coverage evolution over time.
        """
        try:
            self._snapshot_dir.mkdir(parents=True, exist_ok=True)
            path = self._snapshot_dir / (f"{self.target}_iter{self.total_inputs}.csv")
            with path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["edge_id", "buckets", "discoverer"])
                for edge_id, buckets in sorted(self.global_edge_buckets.items()):
                    if edge_id.startswith(("line:", "branch:")):
                        continue
                    discoverer = self._edge_discoverer.get(edge_id, "")
                    writer.writerow(
                        [
                            edge_id,
                            "|".join(str(b) for b in sorted(buckets)),
                            discoverer,
                        ]
                    )
        except Exception:
            pass  # never crash the fuzzer for snapshot failures

    # --- Coverage log file ---

    def ensure_log_file(self) -> None:
        # Create the log file with headers if it doesn't already exist.
        # If the file already exists, migrate legacy headers to include
        # diagnostics columns while preserving prior rows.
        if self.coverage_log_path.exists():
            try:
                with self.coverage_log_path.open("r", newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    existing_rows = list(reader)
                    existing_fields = list(reader.fieldnames or [])

                if not existing_fields:
                    self._coverage_log_fields = list(_COVERAGE_LOG_FIELDS)
                    return

                missing_fields = [
                    name for name in _COVERAGE_LOG_FIELDS if name not in existing_fields
                ]
                if missing_fields:
                    with self.coverage_log_path.open("w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(_COVERAGE_LOG_FIELDS)
                        for row in existing_rows:
                            writer.writerow([row.get(name, "") for name in _COVERAGE_LOG_FIELDS])
                    self._coverage_log_fields = list(_COVERAGE_LOG_FIELDS)
                else:
                    self._coverage_log_fields = existing_fields
            except Exception:
                self._coverage_log_fields = list(_COVERAGE_LOG_FIELDS)
            return

        with self.coverage_log_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(_COVERAGE_LOG_FIELDS)
        self._coverage_log_fields = list(_COVERAGE_LOG_FIELDS)

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
        coverage_data_valid: bool,
        instrumentation_error: str,
    ) -> None:

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        row = {
            "timestamp": timestamp,
            "run_id": self.run_id,
            "statement_coverage": statement_coverage,
            "branch_coverage": branch_coverage,
            "function_coverage": function_coverage,
            "map_density": round(map_density, 4),
            "total_inputs": self.total_inputs,
            "coverage_source": coverage_source,
            "coverage_data_valid": int(bool(coverage_data_valid)),
            "instrumentation_error": instrumentation_error,
        }
        fields = self._coverage_log_fields or list(_COVERAGE_LOG_FIELDS)

        with self.coverage_log_path.open("a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([row.get(name, "") for name in fields])

        should_upload = (
            self.total_inputs == 1
            or new_path_found
            or (self.total_inputs - self._last_uploaded_input_count)
            >= self._coverage_upload_interval
        )
        if should_upload:
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
            self._last_uploaded_input_count = self.total_inputs

    # --- Metric extraction from target output ---

    def extract_line_identifiers(self, execution_metrics: Optional[Any]) -> set[str]:
        """Normalize possible metric shapes into a set of line/edge identifiers"""
        if execution_metrics is None:
            return set()

        if isinstance(execution_metrics, (set, list, tuple)):
            return {str(item) for item in execution_metrics}

        if isinstance(execution_metrics, dict):
            for key in ("covered_lines", "executed_lines", "lines"):
                if key in execution_metrics:
                    return self.extract_line_identifiers(execution_metrics[key])

            truthy_line_map = {
                str(line_id)
                for line_id, executed in execution_metrics.items()
                if bool(executed)
            }
            if truthy_line_map:
                return truthy_line_map
            return set()

        for attr in ("covered_lines", "executed_lines", "lines"):
            if hasattr(execution_metrics, attr):
                return self.extract_line_identifiers(getattr(execution_metrics, attr))

        return set()

    def extract_line_frequencies(
        self, execution_metrics: Optional[Any]
    ) -> dict[str, int]:
        if execution_metrics is None:
            return {}
        if isinstance(execution_metrics, dict):
            for key in ("covered_lines", "executed_lines", "lines"):
                if key in execution_metrics:
                    val = execution_metrics[key]
                    if isinstance(val, dict):
                        return {str(k): int(v) for k, v in val.items()}
                    elif isinstance(val, (set, list, tuple)):
                        return {str(k): 1 for k in val}
        return {}

    def extract_percentage_metrics(
        self, execution_metrics: Optional[Any]
    ) -> dict[str, float]:
        """Extract normalized coverage percentages from execution metrics payloads."""
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
    """Compute a canonical BEHAVIORAL CLASS fingerprint from raw target output.

    For blackbox targets this fingerprint substitutes for edge-coverage data.

    ### Design: class-level, not value-level

    The key insight is that behavioral coverage should count DISTINCT PROGRAM
    PATHS, not distinct output VALUES.  An IPv4 parser that returns
    "Output: [192.168.0.1]" and one that returns "Output: [10.0.0.2]" both
    exercised the SAME path (the valid-parse path).  Treating them as different
    "edges" would saturate the bitmap with value diversity, not path diversity.

    This function reduces each observation to a small, stable class label so
    that the bitmap's 65,536 slots correspond to distinct behavioral responses
    (parse-success, error-type-A, error-type-B, crash, timeout), NOT to the
    universe of possible output values.

    ### What does map_density mean for blackbox targets?

    The number of possible behavioral class combinations is small and bounded
    by the target's logic — typically a few dozen at most for a parser.
    Therefore 100% map density = "we have seen every distinct behavioral
    response class at least once".  The metric saturates only when no new
    behavior can be triggered, which is what we actually want to measure.

    ### Components
    - exit_code_bucket: ok / e1 / e2 / eN / crash(sig) / timeout
    - output_class:     structural class of first stdout line (see _extract_output_class)
    - error_class:      structural class of first stderr line (same logic)
    """
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


def _has_coverage_signal(stdout: str, stderr: str) -> bool:
    text = (stdout or "") + "\n" + (stderr or "")
    lo = text.lower()
    return (
        "coverage_freq:" in text
        or "line coverage" in lo
        or "branch coverage" in lo
        or "combined coverage" in lo
    )


def update(
    bug: BugResult,
    config: dict,
    input_depth: int = 1,
    reference_result=None,
    instrumentation_coverage_text: str = "",
) -> bool:
    """Translate a BugResult into a FuzzIterationPayload and update the tracker."""
    global _tracker, _iteration
    with _tracker_lock:
        _iteration += 1

        if _tracker is None or _tracker.target != bug.target:
            _tracker = CoverageTracker(config)

        coverage_enabled = bool(config.get("coverage_enabled", False))

        # For whitebox targets (coverage_enabled=True): coverage comes from the
        # buggy target's own --show-coverage output (bug.stdout).
        # For blackbox targets: use the reference's stdout/stderr ONLY if the
        # tracker is in code_execution mode (i.e. it expects line-coverage text).
        # In behavioral mode, we ignore reference output for coverage — only the
        # buggy binary's behavioral fingerprint matters.
        tracking_mode = str(config.get("tracking_mode", "behavioral")).strip().lower()

        if coverage_enabled:
            # Whitebox: always read from the buggy target itself
            cov_stdout = bug.stdout
            cov_stderr = bug.stderr
            coverage_source = "whitebox_target"
        elif tracking_mode == "code_execution":
            if instrumentation_coverage_text:
                # Preferred blackbox path: instrumentation emitted edge frequencies.
                cov_stdout = instrumentation_coverage_text
                cov_stderr = ""
                coverage_source = "instrumentation_edges"
            elif _has_coverage_signal(bug.stdout, bug.stderr):
                # Some targets emit coverage directly from the buggy binary.
                cov_stdout = bug.stdout
                cov_stderr = bug.stderr
                coverage_source = "buggy_output"
            elif reference_result is not None:
                # Fallback path: reference emits summarized coverage percentages.
                cov_stdout = reference_result.stdout
                cov_stderr = reference_result.stderr
                coverage_source = "reference_percentages"
            else:
                cov_stdout = ""
                cov_stderr = ""
                coverage_source = "proxy_none"
        else:
            # Behavioral blackbox: no coverage lines to parse; set empty so the
            # tracker reaches the output-signature path cleanly
            cov_stdout = ""
            cov_stderr = ""
            coverage_source = "behavioral_signature"

        covered_lines = _extract_coverage_lines(cov_stdout, cov_stderr)
        coverage_percentages = _extract_coverage_percentages(cov_stdout, cov_stderr)
        instrumentation_error = str(config.get("_last_instr_error") or "").strip()
        execution_metrics = {
            "covered_lines": covered_lines,
            "coverage_percentages": coverage_percentages,
            "coverage_source": coverage_source,
            "instrumentation_error": instrumentation_error,
        }

        # Compute a behavioral output fingerprint from the BUGGY target's output.
        # This is always derived from bug.stdout/stderr/returncode — independent of
        # whether a reference was run — because we want to characterise the behavior
        # of the system-under-test, not its oracle.
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



def _extract_coverage_lines(stdout: str, stderr: str) -> set[str]:
    """
    Parse coverage data from target output:
    Format 1 — simple line identifiers (generic):
        coverage: engine/json_decoder.py:42
        → assumes 1 hit

    Format 2 — json_decoder's --show-coverage summary:
        line coverage     : 63.16% (204/323)
        branch coverage   : 65.22% (90/138)

    Format 3 — edge frequency tracking (AFL-style):
        coverage_freq: engine/foo.py:40->42=5
        → tracks edge 40→42 with count of 5

    Format 4 — coverage.py table (per-file Stmts/Miss/Missing):
        buggy_json\\decoder_stv.py     224    174     78     13    21%   3-85, 101, ...
        → Infers covered lines by subtracting Missing ranges from 1..Stmts
        → Generates entries like 'decoder_stv.py:L42' for each covered line
        → Also parses 'X->Y' branch entries as 'decoder_stv.py:B42->44'
    """
    frequencies: dict[str, int] = {}
    combined = stdout + "\n" + stderr

    # --- Coverage table regex (coverage.py format) ---
    # Matches lines like:
    #   buggy_json\decoder_stv.py     224    174     78     13    21%   3-85, 101, ...
    _COV_TABLE_RE = re.compile(
        r'^(\S+\.py)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+%\s*(.*)?$'
    )

    for line in combined.splitlines():
        stripped = line.strip()

        if stripped.startswith("coverage_freq:"):
            parts = stripped[len("coverage_freq:"):].split("=")
            if len(parts) == 2:
                loc = parts[0].strip()
                try:
                    frequencies[loc] = int(parts[1].strip())
                except ValueError:
                    pass

        elif stripped.startswith("coverage:"):
            loc = stripped[len("coverage:"):].strip()
            frequencies[loc] = frequencies.get(loc, 0) + 1

        elif "line coverage" in stripped.lower() and "%" in stripped:
            m = re.search(r"(\d+)/(\d+)", stripped)
            if m:
                frequencies[f"line:{m.group(1)}/{m.group(2)}"] = 1

        elif "branch coverage" in stripped.lower() and "%" in stripped:
            m = re.search(r"(\d+)/(\d+)", stripped)
            if m:
                frequencies[f"branch:{m.group(1)}/{m.group(2)}"] = 1

        else:
            # Format 4: coverage.py table row
            m = _COV_TABLE_RE.match(stripped)
            if m:
                fname = m.group(1).replace("\\", "/")
                # Use just the basename for shorter keys
                base = fname.rsplit("/", 1)[-1] if "/" in fname else fname
                total_stmts = int(m.group(2))
                miss_count = int(m.group(3))
                missing_str = (m.group(4) or "").strip()

                # Parse the Missing column into a set of line numbers
                missing_lines: set[int] = set()
                if missing_str:
                    for part in missing_str.split(","):
                        part = part.strip()
                        if not part:
                            continue
                        # Skip branch entries like "105->109" — those are branches, not lines
                        if "->" in part:
                            # Parse as a branch edge: "105->109"
                            br_parts = part.split("->")
                            if len(br_parts) == 2:
                                try:
                                    src = int(br_parts[0].strip())
                                    dst = int(br_parts[1].strip())
                                    # This is a MISSING branch — we don't add it
                                except ValueError:
                                    pass
                            continue
                        # Line range: "3-85" or single line: "101"
                        range_match = re.match(r"(\d+)-(\d+)", part)
                        if range_match:
                            lo = int(range_match.group(1))
                            hi = int(range_match.group(2))
                            missing_lines.update(range(lo, hi + 1))
                        else:
                            try:
                                missing_lines.add(int(part))
                            except ValueError:
                                pass

                # Generate covered line entries: all lines in 1..total_stmts
                # that are NOT in the missing set
                for line_no in range(1, total_stmts + 1):
                    if line_no not in missing_lines:
                        edge_key = f"{base}:L{line_no}"
                        frequencies[edge_key] = frequencies.get(edge_key, 0) + 1

    return frequencies


def _extract_coverage_percentages(stdout: str, stderr: str) -> dict[str, float]:
    """
    Parse percentage values from target output lines like:
    - line coverage     : 37.50%
    - branch coverage   : 22.22%
    - combined coverage : 31.03%
    """
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
