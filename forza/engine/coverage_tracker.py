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
import re
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
		self.run_id: str = time.strftime("%Y%m%d_%H%M%S")
		self.start_time: float = time.time()
		self.total_inputs: int  = 0

		# State for black-box novelty tracking
		self.seen_bug_keys: set[str] = set()

		# State for white-box line coverage tracking
		self.covered_line_ids: set[str] = set()

		# Dual metrics persisted for Firestore/reporting
		self.behavioral_metric: int = 0
		self.execution_metric: int = 0

		self.current_metric: int = 0
		self.last_iteration_id: int = 0

		# Real coverage percentages from --show-coverage output (json_decoder)
        # None = not yet seen, use proxy metric instead
		self._last_line_cov  : float | None = None
		self._last_branch_cov: float | None = None

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
		new_behavior_found = False
		new_execution_found = False
		self.last_iteration_id = payload.iteration_id
		self.total_inputs += 1

		if payload.bug_key and payload.bug_key not in self.seen_bug_keys:
			self.seen_bug_keys.add(payload.bug_key)
			new_behavior_found = True

		newly_seen_lines = self.extract_line_identifiers(payload.execution_metrics)
		coverage_percentages = self.extract_percentage_metrics(payload.execution_metrics)
		if newly_seen_lines:
			novel_lines = newly_seen_lines - self.covered_line_ids
			if novel_lines:
				self.covered_line_ids.update(novel_lines)
				new_execution_found = True

		self.behavioral_metric = len(self.seen_bug_keys)
		self.execution_metric = len(self.covered_line_ids)

		if self.mode == "behavioral":
			self.current_metric = self.behavioral_metric
			new_path_found = new_behavior_found
			statement_coverage = min(100.0, float(self.behavioral_metric) * 2.0)
			branch_coverage = statement_coverage
			function_coverage = statement_coverage
		elif self.mode == "code_execution":
			if newly_seen_lines:
				self.current_metric = self.execution_metric
				new_path_found = new_execution_found
			else:
				self.current_metric = self.behavioral_metric
				new_path_found = new_behavior_found

			if coverage_percentages:
				statement_coverage = coverage_percentages.get("statement", round(float(self.current_metric), 2))
				branch_coverage = coverage_percentages.get("branch", statement_coverage)
				function_coverage = coverage_percentages.get("function", coverage_percentages.get("combined", statement_coverage))
			else:
				statement_coverage = round(float(self.current_metric), 2)
				branch_coverage = statement_coverage
				function_coverage = statement_coverage

		# elif self.mode == "code_execution":
		# 	newly_seen_lines = self.extract_line_identifiers(payload.execution_metrics)
		# 	novel_lines = newly_seen_lines - self.covered_line_ids
		# 	if novel_lines:
		# 		self.covered_line_ids.update(novel_lines)
		# 		self.current_metric = len(self.covered_line_ids)
		# 		new_path_found = True

		self.log_state(
			current_metric=self.current_metric,
			new_path_found=new_path_found,
			behavioral_metric=self.behavioral_metric,
			execution_metric=self.execution_metric,
			statement_coverage=statement_coverage,
			branch_coverage=branch_coverage,
			function_coverage=function_coverage,
			coverage_source=("instrumented" if coverage_percentages else "proxy"),
		)
		return new_path_found

	def ensure_log_file(self) -> None:
		# Create the log file with headers if it doesn't already exist
		if self.coverage_log_path.exists():
			return

		# with self.coverage_log_path.open("w", newline="", encoding="utf-8") as f:
		# 	writer = csv.writer(f)
		# 	writer.writerow(["Timestamp", "Iteration", "Coverage_Metric", "New_Paths_Found"])

		with self.coverage_log_path.open("w", newline="", encoding="utf-8") as f:
			writer = csv.writer(f)
			writer.writerow([
				"timestamp",
				"statement_coverage",
				"branch_coverage",
				"function_coverage",
				"total_inputs",
				"coverage_source",
			])

	def log_state(
		self,
		current_metric: int,
		new_path_found: bool,
		behavioral_metric: int,
		execution_metric: int,
		statement_coverage: float,
		branch_coverage: float,
		function_coverage: float,
		coverage_source: str,
	) -> None:
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
		
		with self.coverage_log_path.open("a", newline="", encoding="utf-8") as f:
			csv.writer(f).writerow([
                timestamp,
				statement_coverage,
				branch_coverage,
				function_coverage,
                self.total_inputs,
				coverage_source,
            ])

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

	def extract_percentage_metrics(self, execution_metrics: Optional[Any]) -> dict[str, float]:
		# Extract normalized coverage percentages from execution metrics payloads.
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
	
from engine.types import BugResult
from engine import firestore_client
 
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
    # json_decoder prints detailed coverage percentages with --show-coverage.
    covered_lines = _extract_coverage_lines(bug.stdout, bug.stderr)
    coverage_percentages = _extract_coverage_percentages(bug.stdout, bug.stderr)
    execution_metrics = {
        "covered_lines": covered_lines,
        "coverage_percentages": coverage_percentages,
    } if covered_lines or coverage_percentages else None
 
    payload = FuzzIterationPayload(
        iteration_id      = _iteration,
        target_name       = bug.target,
        strategy_used     = bug.strategy,
				bug_key           = bug.bug_key,
				execution_metrics = execution_metrics,
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
    Parse coverage data from target output.
 
    Supports two formats:
 
    Format 1 — simple line identifiers (generic):
        coverage: engine/json_decoder.py:42
        → returns {"engine/json_decoder.py:42", ...}
 
    Format 2 — json_decoder's --show-coverage report:
        line coverage     : 63.16% (204/323)
        branch coverage   : 65.22% (90/138)
        → returns {"line:63.16", "branch:65.22"} as proxy identifiers
 
    Returns an empty set if no coverage output is found, which triggers
    the behavioral fallback in CoverageTracker.update().
    """
    lines: set[str] = set()
    combined = stdout + "\n" + stderr
 
    for line in combined.splitlines():
        stripped = line.strip()
 
        # Format 1: "coverage: <file>:<lineno>"
        if stripped.startswith("coverage:"):
            lines.add(stripped[len("coverage:"):].strip())
 
        # Format 2: json_decoder coverage report
        # "line coverage     : 63.16% (204/323)"
        # "branch coverage   : 65.22% (90/138)"
        elif "line coverage" in stripped.lower() and "%" in stripped:
            import re
            m = re.search(r"(\d+)/(\d+)", stripped)
            if m:
                lines.add(f"line:{m.group(1)}/{m.group(2)}")
 
        elif "branch coverage" in stripped.lower() and "%" in stripped:
            import re
            m = re.search(r"(\d+)/(\d+)", stripped)
            if m:
                lines.add(f"branch:{m.group(1)}/{m.group(2)}")
 
    return lines


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