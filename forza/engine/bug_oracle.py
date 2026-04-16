"""
Take a RawResult from target_runner.py and classify it into a structured BugResult

YAML fields read:
    - bug_keywords: list[str]
    - output_pattern: str | None
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from engine.types import BugResult, BugType
from engine.target_runner import RawResult


def _extract_output(stdout: str, pattern: str) -> Optional[str]:
    if not pattern or "{value}" not in pattern:
        return None
    regex = re.escape(pattern).replace(r"\{value\}", r"(.+?)")
    match = re.search(regex, stdout)
    return match.group(1).strip() if match else None

class BugOracle:
    """
    Classifies a RawResult into a BugResult.

    Classification priority:
        1.  TIMEOUT
        2.  Structured (explicitly stated)
        3.  PERFORMANCE
        4.  INVALIDITY
        5.  VALIDITY
        6.  SYNTACTIC
        7.  FUNCTIONAL
        8.  BOUNDARY
        9.  BONUS
        10. RELIABILITY
        11. MISMATCH
    """

    _PARSE_EXC_RE = re.compile(r"ParseException: (.+?)(?:\n|$)", re.MULTILINE)

    # Matches Python exception class names like "JSONDecodeError:", "ValueError:", etc.
    _EXC_CLASS_RE = re.compile(
        r"([A-Z][A-Za-z]*(?:Error|Exception|Warning|Fault))\s*[:\(]"
    )

    # Matches "File "...", line xxx" from Python tracebacks
    _TRACEBACK_LINE_RE = re.compile(r'File ".*?", line (\d+)')

    _BUG_COUNT_RE = re.compile(
        r"Final bug count: defaultdict\(<class 'int'>, \{(.*)\}\)"
    )
    _BUG_ENTRY_RE = re.compile(
        r"\('(\w+)', <class '([^']+)'>, '([^']*)', '[^']*', \d+\)"
    )


    def classify(
        self,
        raw: RawResult,
        input_data: str,
        target: str,
        config: dict = None,
        ref: Optional[RawResult] = None,
    ) -> BugResult:
        config = config or {}
        stdout = raw.stdout
        stderr = raw.stderr
        combined = stdout + "\n" + stderr
        bug_keywords = config.get("bug_keywords", [])

        # 1. TIMEOUT
        if raw.timed_out:
            return self._make_result(
                bug_type=BugType.TIMEOUT,
                raw_key=("timeout", "", ""),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 2. Structured (explicitly stated)
        count_match = self._BUG_COUNT_RE.search(combined)
        if count_match:
            entries_str = count_match.group(1).strip()
            if entries_str:
                entry_match = self._BUG_ENTRY_RE.search(entries_str)
                if entry_match:
                    category = entry_match.group(1)
                    exc_type = entry_match.group(2)
                    # Dedup by (category, exception_class) only.
                    # The err_msg contains position-specific details like
                    # "Expected '.', found '1' (at char 3)" which differ per
                    # input but represent the same bug class.
                    return self._make_result(
                        bug_type=self._category_to_bug_type(category),
                        raw_key=(category, exc_type),
                        input_data=input_data,
                        target=target,
                        raw=raw,
                    )

        exc_match = self._PARSE_EXC_RE.search(combined)
        exc_msg = exc_match.group(
            1)[:120] if exc_match else combined[-120:].strip()
        lower = combined.lower()

        # # 3. BONUS ??
        # # Check BEFORE "invalidity" because "An invalidity bug has been triggered:"
        # # might contain JSONDecodeError class name. If it's unhandled (has Traceback),
        # # it's a bonus bug, not a seeded invalidity bug.
        # if "Traceback (most recent" in combined:

        #     if "JSONDecodeError" in combined or "CidrizeError" in combined:
        #         exc_snippet = (
        #             combined[-200:] if len(combined) > 200 else combined
        #         ).strip()
        #         return self._make_result(
        #             bug_type=BugType.BONUS,
        #             raw_key=(
        #                 "bonus_unhandled",
        #                 "JSONDecodeError|CidrizeError",
        #                 exc_snippet,
        #             ),
        #             input_data=input_data,
        #             target=target,
        #             raw=raw,
        #         )

        # 3. PERFORMANCE
        if "performance bug" in lower or "PerformanceBug" in combined:
            return self._make_result(
                bug_type=BugType.PERFORMANCE,
                raw_key=("performance", "PerformanceBug"),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 4. INVALIDITY
        if "invalidity" in lower or "InvalidityBug" in combined:
            return self._make_result(
                bug_type=BugType.INVALIDITY,
                raw_key=("invalidity", "InvalidityBug"),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 5. VALIDITY
        if "validity" in lower or "ValidityBug" in combined:
            return self._make_result(
                bug_type=BugType.VALIDITY,
                raw_key=("validity", "ValidityBug"),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 6. SYNTACTIC
        if (
            "syntactic" in lower
            or "syntax error" in lower
            or "AddrFormatError" in combined
        ):
            # Dedup by exception class only — "AddrFormatError: '999.0.0.1'" and
            # "AddrFormatError: 'abc'" are the same bug class.
            return self._make_result(
                bug_type=BugType.SYNTACTIC,
                raw_key=("syntactic", "AddrFormatError"),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 7. FUNCTIONAL
        if "functional" in lower and "functional bug" in lower:
            return self._make_result(
                bug_type=BugType.FUNCTIONAL,
                raw_key=("functional", "FunctionalBug"),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 8. BOUNDARY
        if "boundary" in lower or "BoundaryBug" in combined:
            return self._make_result(
                bug_type=BugType.BOUNDARY,
                raw_key=("boundary", "BoundaryBug"),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 9. BONUS
        if "bonus" in lower or any(key.lower() in lower for key in bug_keywords):
            # Extract exception class name for dedup (e.g. "JSONDecodeError")
            exc_class = self._extract_exc_class(combined)
            return self._make_result(
                bug_type=BugType.BONUS,
                raw_key=("bonus", exc_class),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 10. RELIABILITY
        if "reliability" in lower or "ReliabilityBug" in combined:
            return self._make_result(
                bug_type=BugType.RELIABILITY,
                raw_key=("reliability_seeded", "ReliabilityBug"),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        if raw.returncode != 0:
            # Dedup by (exit_code, exception_class, line_number)
            exc_class = self._extract_exc_class(combined)
            line_num = self._extract_line_number(combined)
            return self._make_result(
                bug_type=BugType.RELIABILITY,
                raw_key=("reliability", str(raw.returncode), exc_class, line_num),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 11. MISMATCH
        if ref is not None:
            pattern = config.get("output_pattern")
            bug_out = _extract_output(stdout, pattern)
            ref_out = _extract_output(ref.stdout, pattern) if ref.stdout else None
            # Only mark as mismatch if both extractions succeeded and outputs differ
            if pattern and bug_out is not None and ref_out is not None and bug_out != ref_out:
                return self._make_result(
                    bug_type=BugType.MISMATCH,
                    raw_key=(
                        "mismatch",
                        "OutputMismatch",
                        f"out={bug_out} ref={ref_out}",
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
        """Extract the exception class name from combined output.

        Examples:
            'json.decoder.JSONDecodeError: ...' → 'JSONDecodeError'
            'netaddr.core.AddrFormatError: ...'  → 'AddrFormatError'
            'ValueError: ...'                    → 'ValueError'
            'no exception found'                 → 'UnknownError'

        Used for bug deduplication: two triggers of the same exception class
        are the same bug, regardless of the specific error message.
        """
        match = cls._EXC_CLASS_RE.search(text)
        return match.group(1) if match else "UnknownError"


    @classmethod
    def _extract_line_number(cls, text: str) -> str:
        match = cls._TRACEBACK_LINE_RE.search(text)
        return match.group(1) if match else ""
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

    @staticmethod
    def _category_to_bug_type(category: str) -> BugType:
        return {
            "invalidity": BugType.INVALIDITY,
            "bonus": BugType.BONUS,
            "syntactic": BugType.SYNTACTIC,
            "functional": BugType.FUNCTIONAL,
            "boundary": BugType.BOUNDARY,
            "validity": BugType.VALIDITY,
            "performance": BugType.PERFORMANCE,
            "reliability": BugType.RELIABILITY,
        }.get(category, BugType.RELIABILITY)
