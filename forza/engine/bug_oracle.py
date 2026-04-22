"""
Take a RawResult from target_runner.py and classify it into a structured BugResult
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from engine.types import BugResult, BugType
from engine.target_runner import RawResult


def _last_meaningful_line(stdout: str) -> Optional[str]:
    lines: list[str] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(
            (
                "line coverage",
                "branch coverage",
                "combined coverage",
                "coverage data saved to",
                "saved bug count report",
                "loading existing coverage data from",
                "final bug count:",
            )
        ):
            continue
        if set(line) == {"="}:
            continue
        lines.append(line)
    return lines[-1] if lines else None


def _extract_output(stdout: str, pattern: str) -> Optional[str]:
    if not pattern or "{value}" not in pattern:
        return None
    if pattern == "{value}":
        if "\t<cov_lines>" in stdout:
            return stdout.split("\t<cov_lines>")[0].strip()
        return stdout.strip()
    regex = re.escape(pattern).replace(r"\{value\}", r"(.+?)")
    regex = regex.replace(r"\ ", r"\s*")
    match = re.search(regex, stdout, flags=re.DOTALL)
    if match:
        return match.group(1).strip()
    return _last_meaningful_line(stdout)


class BugOracle:
    """
    Classifies a RawResult into a BugResult.

    Classification priority:
        1.  TIMEOUT
        2.  PERFORMANCE
        3.  INVALIDITY
        4.  VALIDITY
        5.  SYNTACTIC
        6.  FUNCTIONAL
        7.  BOUNDARY
        8.  BONUS
        9.  RELIABILITY
        10. MISMATCH
    """

    # Matches Python exception class names like "JSONDecodeError:", "ValueError:", etc.
    _EXC_CLASS_RE = re.compile(
        r"([A-Z][A-Za-z]*(?:Error|Exception|Warning|Fault))\s*[:\(]"
    )
    _TRACEBACK_LINE_RE = re.compile(r'File ".*?", line (\d+)')

    def classify(
        self,
        raw: RawResult,
        input_data: str,
        config: dict,
        ref: Optional[RawResult] = None,
    ) -> BugResult:
        target = config.get("name")
        stdout = raw.stdout
        stderr = raw.stderr
        combined = stdout + "\n" + stderr
        lower = combined.lower()

        bug_keywords = config.get("bug_keywords", [])

        exc_class = self._extract_exc_class(combined)
        line_num = self._extract_line_number(combined)

        # 1. TIMEOUT
        if raw.timed_out:
            return self._make_result(
                bug_type=BugType.TIMEOUT,
                raw_key=("timeout", "", ""),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 2. PERFORMANCE
        if "performance" in lower or "PerformanceBug" in combined:
            return self._make_result(
                bug_type=BugType.PERFORMANCE,
                raw_key=("performance", "PerformanceBug", line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 3. INVALIDITY
        if "invalidity" in lower or "InvalidityBug" in combined:
            return self._make_result(
                bug_type=BugType.INVALIDITY,
                raw_key=("invalidity", "InvalidityBug", line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 4. VALIDITY
        if "validity" in lower or "ValidityBug" in combined:
            return self._make_result(
                bug_type=BugType.VALIDITY,
                raw_key=("validity", "ValidityBug", line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 5. SYNTACTIC
        if (
            "syntactic" in lower
            or "syntax error" in lower
            or "AddrFormatError" in combined
        ):
            return self._make_result(
                bug_type=BugType.SYNTACTIC,
                raw_key=("syntactic", "AddrFormatError", line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 6. FUNCTIONAL
        if "functional" in lower or "FunctionalBug" in lower:
            return self._make_result(
                bug_type=BugType.FUNCTIONAL,
                raw_key=("functional", "FunctionalBug", line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 7. BOUNDARY
        if "boundary" in lower or "BoundaryBug" in combined:
            return self._make_result(
                bug_type=BugType.BOUNDARY,
                raw_key=("boundary", "BoundaryBug", line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 8. BONUS
        if "bonus" in lower or any(key.lower() in lower for key in bug_keywords):

            return self._make_result(
                bug_type=BugType.BONUS,
                raw_key=("bonus", exc_class, line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 9. RELIABILITY
        if "reliability" in lower or "ReliabilityBug" in combined:
            return self._make_result(
                bug_type=BugType.RELIABILITY,
                raw_key=("reliability_seeded", "ReliabilityBug", line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        if raw.returncode != 0:
            line_num = self._extract_line_number(combined)
            return self._make_result(
                bug_type=BugType.RELIABILITY,
                raw_key=("reliability", str(raw.returncode), exc_class, line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 10. MISMATCH
        if ref is not None:
            norm_out = _extract_output(stdout, config.get("buggy_output_pattern"))
            norm_ref = _extract_output(
                ref.stdout, config.get("reference_output_pattern")
            )
            if norm_out is not None and norm_ref is not None and norm_out != norm_ref:
                return self._make_result(
                    bug_type=BugType.MISMATCH,
                    raw_key=(
                        "mismatch",
                        "OutputMismatch",
                        f"out={norm_out} ref={norm_ref}",
                    ),
                    input_data=input_data,
                    target=target,
                    raw=raw,
                )

        return self._make_result(
            bug_type=BugType.NORMAL,
            raw_key=None,
            input_data=input_data,
            target=target,
            raw=raw,
        )

    # Helper functions
    @classmethod
    def _extract_exc_class(cls, text: str) -> str:
        """Extract the exception class name from combined output: 'ValueError: ...' -> 'ValueError'"""
        match = cls._EXC_CLASS_RE.search(text)
        return match.group(1) if match else "UnknownError"

    @classmethod
    def _extract_line_number(cls, text: str, max_frames: int = 3) -> str:
        matches = cls._TRACEBACK_LINE_RE.findall(text)
        if matches:
            return ":".join(matches[-max_frames:])
        return _last_meaningful_line(text) or ""

    @staticmethod
    def _make_result(
        bug_type: BugType,
        raw_key: Optional[tuple],
        input_data: str,
        target: str,
        raw: RawResult,
    ) -> BugResult:
        if raw_key is not None:
            key_str = ":".join(str(p) for p in raw_key)
        else:
            key_str = f"normal:{input_data[:40]}"
        bug_key = hashlib.md5(key_str.encode()).hexdigest()[:16]

        return BugResult(
            bug_type=bug_type,
            bug_key=bug_key,
            input_data=input_data,
            target=target,
            strategy="",
            stdout=raw.stdout,
            stderr=raw.stderr,
            returncode=raw.returncode,
            timed_out=raw.timed_out,
            crashed=raw.crashed,
        )
