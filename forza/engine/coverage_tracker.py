"""Coverage tracking for both white-box and black-box fuzz targets.

This module intentionally avoids importing any project-specific runtime modules
(for example, bug oracle, runner, or mutator components). The fuzzer
orchestrator provides a small data-transfer payload per iteration, and the
tracker updates its internal state using one of two modes:

1. behavioral:
   Used for black-box binaries where line-level execution coverage is not
	available. A novel bug_key is treated as a new path.
2. code_execution:
   Used for white-box targets where execution data (typically line coverage)
	can be supplied in execution_metrics.

The tracker persists a time-series view of coverage growth in
logs/coverage_evolution.csv.
"""

from __future__ import annotations

import csv
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

_ENGINE_DIR  = Path(__file__).resolve().parent
_PROJECT_DIR = _ENGINE_DIR.parent
_RESULTS_DIR = _PROJECT_DIR / "results"

@dataclass(frozen=True)
class FuzzIterationPayload:
	"""Per-iteration, transport-only data for coverage updates.

	The payload keeps the tracker decoupled from concrete implementations of
	target execution, bug classification, and mutation strategy management.
	"""

	iteration_id: int
	target_name: str
	strategy_used: str
	bug_key: Optional[str] = None
	execution_metrics: Optional[Any] = None


class CoverageTracker:
	"""Tracks fuzzing progress using behavioral or code-execution semantics.

	Configuration
	-------------
	config_dict['tracking_mode'] controls behavior:
	- behavioral: novel bug_key values are counted as new paths.
	- code_execution: novel executed line identifiers are counted.

	The public update method returns True when new coverage/novelty is
	discovered so the orchestrator can reward the current mutation strategy.
	"""

	valid_modes = {"behavioral", "code_execution"}

	def __init__(self, config_dict: dict[str, Any]) -> None:
		mode = str(config_dict.get("tracking_mode", "behavioral")).strip().lower()
		if mode not in self.valid_modes:
			raise ValueError(
				"Invalid tracking_mode. Expected one of "
				f"{sorted(self.valid_modes)}, got: {mode!r}"
			)

		self.mode: str = mode
		self.target     : str   = config_dict.get("name", "unknown")
		self.start_time: float = time.time()
		self.total_inputs: int  = 0

		# State for black-box novelty tracking
		self.seen_bug_keys: set[str] = set()

		# State for white-box line coverage tracking
		self.covered_line_ids: set[str] = set()

		self.current_metric: int = 0
		self.last_iteration_id: int = 0

		_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
		self.coverage_log_path = _RESULTS_DIR / f"{self.target}_coverage.csv"
		self.ensure_log_file()

	def update(self, payload: FuzzIterationPayload) -> bool:
		"""Update tracker state using one fuzz iteration payload.

		Parameters
		----------
		payload:
			The iteration DTO produced by the orchestrator.

		Returns
		-------
		bool
			True if this iteration discovered new coverage/novel behavior,
			otherwise False.
		"""
		# Update tracker state based on mode, then log the new state 
		new_path_found = False
		self.last_iteration_id = payload.iteration_id
		self.total_inputs += 1

		if self.mode == "behavioral":
			if payload.bug_key and payload.bug_key not in self.seen_bug_keys:
				self.seen_bug_keys.add(payload.bug_key)
				self.current_metric = len(self.seen_bug_keys)
				new_path_found = True
			
		elif self.mode == "code_execution":
			newly_seen_lines = self.extract_line_identifiers(payload.execution_metrics)
			if newly_seen_lines:
                # True white-box coverage data available — use it
				novel_lines = newly_seen_lines - self.covered_line_ids
				if novel_lines:
					self.covered_line_ids.update(novel_lines)
					self.current_metric = len(self.covered_line_ids)
					new_path_found = True
			else:
                # No coverage lines in output — fall back to behavioral
                # (happens when --show-coverage flag is not active)
				if payload.bug_key and payload.bug_key not in self.seen_bug_keys:
					self.seen_bug_keys.add(payload.bug_key)
					self.current_metric = len(self.seen_bug_keys)
					new_path_found = True

		# elif self.mode == "code_execution":
		# 	newly_seen_lines = self.extract_line_identifiers(payload.execution_metrics)
		# 	novel_lines = newly_seen_lines - self.covered_line_ids
		# 	if novel_lines:
		# 		self.covered_line_ids.update(novel_lines)
		# 		self.current_metric = len(self.covered_line_ids)
		# 		new_path_found = True

		self.log_state(current_metric=self.current_metric, new_path_found=new_path_found)
		return new_path_found

	def ensure_log_file(self) -> None:
		# Create the log file with headers if it doesn't already exist
		if self.coverage_log_path.exists():
			return

		with self.coverage_log_path.open("w", newline="", encoding="utf-8") as f:
			writer = csv.writer(f)
			writer.writerow(["Timestamp", "Iteration", "Coverage_Metric", "New_Paths_Found"])

	def log_state(self, current_metric: int, new_path_found: bool) -> None:
		# Log the current state to CSV
		# elapsed_seconds = time.time() - self.start_time
		# recorded_iteration = self.last_iteration_id

		# with self.coverage_log_path.open("a", newline="", encoding="utf-8") as f:
		# 	writer = csv.writer(f)
		# 	writer.writerow(
		# 		[
		# 			f"{elapsed_seconds:.6f}",
		# 			recorded_iteration,
		# 			current_metric,
		# 			int(new_path_found),
		# 		]
		# 	)
		
		timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
 
        # Express current_metric as a coverage percentage proxy capped at 100
		if self.mode == "behavioral":
			cov = min(100.0, current_metric * 2.0)
		else:
			cov = round(float(current_metric), 2)
		
		with self.coverage_log_path.open("a", newline="", encoding="utf-8") as f:
			csv.writer(f).writerow([
                timestamp,
                cov,   # statement_coverage
                cov,   # branch_coverage  (same proxy until richer data available)
                cov,   # function_coverage
                self.total_inputs,
            ])

	def extract_line_identifiers(self, execution_metrics: Optional[Any]) -> set[str]:
		# Normalize possible metric shapes into a set of line identifiers 
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
	
from engine.types import BugResult
 
_tracker  : CoverageTracker | None = None
_iteration: int = 0
 
 
def update(bug: BugResult, config: dict) -> bool:
    """
    Translate a BugResult into a FuzzIterationPayload and update the tracker.
 
    Called by fuzzer.py after every classify() call. Returns True if this
    input revealed new coverage so fuzzer.py can grow the corpus and boost
    the mutation strategy.
 
    Also sets bug.new_coverage = True on the passed-in object if new paths
    were found.
    """
    global _tracker, _iteration
    _iteration += 1
 
    if _tracker is None or _tracker.target != bug.target:
        _tracker = CoverageTracker(config)
 
    # Extract execution metrics from stdout for code_execution mode.
    # json_decoder prints "coverage: <file>:<line>" with --show-coverage.
    execution_metrics = _extract_coverage_lines(bug.stdout, bug.stderr)
 
    payload = FuzzIterationPayload(
        iteration_id      = _iteration,
        target_name       = bug.target,
        strategy_used     = bug.strategy,
        bug_key           = bug.bug_key,
        execution_metrics = execution_metrics if execution_metrics else None,
    )
 
    new_path = _tracker.update(payload)
 
    if new_path:
        bug.new_coverage = True
 
    return new_path
 
 
def reset() -> None:
    """
    Drop the current CoverageTracker instance and reset the iteration counter.
    Call this between targets when running --all.
    """
    global _tracker, _iteration
    _tracker   = None
    _iteration = 0
 
 
def _extract_coverage_lines(stdout: str, stderr: str) -> set[str]:
    """
    Parse coverage line identifiers from target output.
 
    json_decoder with --show-coverage prints lines like:
        coverage: engine/json_decoder.py:42
 
    Any line starting with "coverage:" is treated as a line identifier.
    Returns an empty set if no coverage output is found (behavioral mode
    targets won't emit any, which is fine — execution_metrics=None triggers
    the behavioral path in CoverageTracker).
    """
    lines: set[str] = set()
    for line in (stdout + "\n" + stderr).splitlines():
        stripped = line.strip()
        if stripped.startswith("coverage:"):
            lines.add(stripped[len("coverage:"):].strip())
    return lines