"""
take a RawResult from target_runner.py and classify it into a structured BugResult

YAML fields read:
    - bug_keywords: list[str]
    - output_pattern: str | None
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from engine.types import BugResult, BugType, classify_from_keywords
from engine.target_runner import RawResult


# Generic output extractor
def _extract_output(stdout: str, pattern: str) -> Optional[str]:
    """Extract the output value from stdout using a pattern defined in the YAML."""
    if not pattern or "{value}" not in pattern:
        return None
    regex = re.escape(pattern).replace(r"\{value\}", r"(.+?)")
    match = re.search(regex, stdout)
    return match.group(1).strip() if match else None


# ---------------------------------------------------------------------------
# BugOracle
# ---------------------------------------------------------------------------


class BugOracle:
    """
    Classifies a RawResult into a BugResult.

    Classification priority (first match wins):
        1. TIMEOUT     — raw.timed_out is True
        2. Structured  — "Final bug count" line in output (json_decoder)
        3. INVALIDITY  — "invalidity" keyword in output
        4. SYNTACTIC   — "syntactic" / "syntax error" / "AddrFormatError"
        5. FUNCTIONAL  — "functional bug" keyword
        6. BONUS       — "bonus" keyword
        7. RELIABILITY — non-zero exit with no structured output
        8. MISMATCH    — normalised buggy output differs from reference
        9. NORMAL      — none of the above
    """

    # Regex: pull the ParseException message from stdout or stderr
    _PARSE_EXC_RE = re.compile(r"ParseException: (.+?)(?:\n|$)", re.MULTILINE)

    # Regex: structured "Final bug count" line emitted
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
        ref_stdout: Optional[str] = None,
    ) -> BugResult:
        """Classify one RawResult into a BugResult."""
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

        # 2. Structured "Final bug count" line (json_decoder) ───────────
        count_match = self._BUG_COUNT_RE.search(combined)
        if count_match:
            entries_str = count_match.group(1).strip()
            if entries_str:
                entry_match = self._BUG_ENTRY_RE.search(entries_str)
                if entry_match:
                    category = entry_match.group(1)
                    exc_type = entry_match.group(2)
                    exc_msg = entry_match.group(3)[:120]
                    return self._make_result(
                        bug_type=self._category_to_bug_type(category),
                        raw_key=(category, exc_type, exc_msg),
                        input_data=input_data,
                        target=target,
                        raw=raw,
                    )

        # Shared fallback message used by checks 3–7
        exc_match = self._PARSE_EXC_RE.search(combined)
        exc_msg = exc_match.group(1)[:120] if exc_match else combined[-120:].strip()
        lower = combined.lower()

        # 3. INVALIDITY
        if "invalidity" in lower:
            # Include stdout to differentiate similar invalidity bugs
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.INVALIDITY,
                raw_key=("invalidity", "ParseException", exc_msg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 4. SYNTACTIC (cidrize: AddrFormatError, SyntaxError)
        if (
            "syntactic" in lower
            or "syntax error" in lower
            or "AddrFormatError" in combined
        ):
            addr_match = re.search(r"AddrFormatError: (.+?)(?:\n|$)", combined)
            smsg = addr_match.group(1)[:160] if addr_match else exc_msg
            # Include stdout to differentiate similar syntactic bugs
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.SYNTACTIC,
                raw_key=("syntactic", "AddrFormatError", smsg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 5. FUNCTIONAL
        if "functional" in lower:
            func_match = re.search(r"FunctionalBug: (.+?)(?:\n|$)", combined)
            fmsg = (
                func_match.group(1)[:160] if func_match else exc_msg
            )  # increased from 120
            # Include stdout snippet to differentiate similar functional bugs
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.FUNCTIONAL,
                raw_key=("functional", "FunctionalBug", fmsg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 6. BONUS (untracked)
        if "bonus" in lower:
            # Include stdout to differentiate similar bonus bugs
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type=BugType.BONUS,
                raw_key=("bonus", "ParseException", exc_msg, stdout_snippet),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 7. Generic keyword fallback from YAML bug_keywords
        for kw in bug_keywords:
            if kw.lower() in lower:
                specific = classify_from_keywords(stdout, stderr)
                bug_type = specific if specific is not None else BugType.RELIABILITY
                # Include stdout/stderr to differentiate similar keyword-triggered bugs
                stdout_snippet = stdout[:80].strip() if stdout else ""
                return self._make_result(
                    bug_type=bug_type,
                    raw_key=("keyword", kw, exc_msg, stdout_snippet),
                    input_data=input_data,
                    target=target,
                    raw=raw,
                )

        # 8. RELIABILITY
        if raw.returncode != 0:
            # Include returncode + more stderr/stdout to differentiate bugs
            rel_msg = (stderr[:160] or stdout[:160]).strip()
            return self._make_result(
                bug_type=BugType.RELIABILITY,
                raw_key=("reliability", str(raw.returncode), rel_msg),
                input_data=input_data,
                target=target,
                raw=raw,
            )

        # 9. MISMATCH
        if ref_stdout is not None:
            pattern = config.get("output_pattern")
            norm_out = _extract_output(stdout, pattern)
            norm_ref = _extract_output(ref_stdout, pattern)
            if pattern and norm_out != norm_ref:
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

        # 10. NORMAL
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
        """Build a BugResult from a RawResult"""
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
            strategy="",  # stamped by fuzzer.py after classify()
            stdout=raw.stdout,
            stderr=raw.stderr,
            returncode=raw.returncode,
            timed_out=raw.timed_out,
            crashed=raw.crashed,
        )

    @staticmethod
    def _category_to_bug_type(category: str) -> BugType:
        """Map a structured bug count category string to a BugType."""
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

