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
		self.start_time: float = time.time()

		# State for black-box novelty tracking
		self.seen_bug_keys: set[str] = set()

		# State for white-box line coverage tracking
		self.covered_line_ids: set[str] = set()

		self.current_metric: int = 0
		self.last_iteration_id: int = 0

		project_root = Path(__file__).resolve().parents[1]
		logs_dir = project_root / "logs"
		logs_dir.mkdir(parents=True, exist_ok=True)

		self.coverage_log_path = logs_dir / "coverage_evolution.csv"
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

		if self.mode == "behavioral":
			if payload.bug_key and payload.bug_key not in self.seen_bug_keys:
				self.seen_bug_keys.add(payload.bug_key)
				self.current_metric = len(self.seen_bug_keys)
				new_path_found = True

		elif self.mode == "code_execution":
			newly_seen_lines = self.extract_line_identifiers(payload.execution_metrics)
			novel_lines = newly_seen_lines - self.covered_line_ids
			if novel_lines:
				self.covered_line_ids.update(novel_lines)
				self.current_metric = len(self.covered_line_ids)
				new_path_found = True

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
		elapsed_seconds = time.time() - self.start_time
		recorded_iteration = self.last_iteration_id

		with self.coverage_log_path.open("a", newline="", encoding="utf-8") as f:
			writer = csv.writer(f)
			writer.writerow(
				[
					f"{elapsed_seconds:.6f}",
					recorded_iteration,
					current_metric,
					int(new_path_found),
				]
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