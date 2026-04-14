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

# def _extract_output(text, pattern):
#     if not pattern:
#         return text.strip()

#     # Try to find the pattern
#     match = re.search(pattern, text)
#     if match:
#         # If the pattern has a group, return it, else the whole match
#         return match.group(1).strip() if match.groups() else match.group(0).strip()

#     # FALLBACK: If pattern fails, return the last non-empty line
#     # This usually catches the clean output of a reference script
#     lines = [l for l in text.strip().split('\n') if l.strip()]
#     return lines[-1] if lines else ""


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
                    err_msg = entry_match.group(3)[:120]
                    return self._make_result(
                        bug_type=self._category_to_bug_type(category),
                        raw_key=(category, exc_type, err_msg),
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
            perf_match = re.search(r"PerformanceBug: (.+?)(?:\n|$)", combined)
            perf_msg = perf_match.group(1)[:160] if perf_match else exc_msg
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.PERFORMANCE,
                raw_key=("performance", "PerformanceBug",
                         perf_msg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 4. INVALIDITY
        if "invalidity" in lower or "InvalidityBug" in combined:
            inv_match = re.search(
                r"(?:InvalidityBug): (.+?)(?:\n|$)", combined)
            inv_msg = inv_match.group(1)[:160] if inv_match else exc_msg
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.INVALIDITY,
                raw_key=("invalidity", "InvalidityBug",
                         inv_msg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 5. VALIDITY
        if "validity" in lower or "ValidityBug" in combined:
            val_match = re.search(r"ValidityBug: (.+?)(?:\n|$)", combined)
            val_msg = val_match.group(1)[:160] if val_match else exc_msg
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.VALIDITY,
                raw_key=("validity", "ValidityBug", val_msg, stdout_snippet),
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
            syn_match = re.search(r"AddrFormatError: (.+?)(?:\n|$)", combined)
            syn_msg = syn_match.group(1)[:160] if syn_match else exc_msg
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.SYNTACTIC,
                raw_key=("syntactic", "AddrFormatError",
                         syn_msg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 7. FUNCTIONAL
        if "functional" in lower and "functional bug" in lower:
            func_match = re.search(r"FunctionalBug: (.+?)(?:\n|$)", combined)
            func_msg = func_match.group(1)[:160] if func_match else exc_msg
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.FUNCTIONAL,
                raw_key=("functional", "FunctionalBug",
                         func_msg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 8. BOUNDARY
        if "boundary" in lower or "BoundaryBug" in combined:
            bnd_match = re.search(r"BoundaryBug: (.+?)(?:\n|$)", combined)
            bnd_msg = bnd_match.group(1)[:160] if bnd_match else exc_msg
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.BOUNDARY,
                raw_key=("boundary", "BoundaryBug", bnd_msg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 9. BONUS
        if "bonus" in lower or any(key.lower() in lower for key in bug_keywords):
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.BONUS,
                raw_key=("bonus", "BonusBug", exc_msg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 10. RELIABILITY
        if "reliability" in lower or "ReliabilityBug" in combined:
            rel_match = re.search(r"ReliabilityBug: (.+?)(?:\n|$)", combined)
            rel_msg = rel_match.group(1)[:160] if rel_match else exc_msg
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.RELIABILITY,
                raw_key=(
                    "reliability_seeded",
                    "ReliabilityBug",
                    rel_msg,
                    stdout_snippet,
                ),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        if raw.returncode != 0:
            rel_msg = (stderr[:160] or stdout[:160]).strip()
            return self._make_result(
                bug_type=BugType.RELIABILITY,
                raw_key=("reliability", str(raw.returncode), rel_msg),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 11. MISMATCH
        if ref is not None and ref.stdout.strip() != raw.stdout.strip():
            return self._make_result(
                bug_type=BugType.MISMATCH,
                raw_key=(
                    "mismatch",
                    "OutputMismatch",
                    f"out='{raw.stdout.strip()}' ref='{ref.stdout.strip()}'",
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
