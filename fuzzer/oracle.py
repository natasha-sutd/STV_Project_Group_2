# -*- coding: utf-8 -*-
"""
BugOracle: classifies the output of a binary run into a result type.

Since both the IPv4/IPv6 parsers are closed binaries, coverage is approximated
via behavioral novelty — every unique (bug_category, error_message) pair is
treated as "new coverage" for corpus scheduling purposes.
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Tuple


class BugType(Enum):
    NORMAL = "normal"           # Parsed successfully, no bug
    INVALIDITY = "invalidity"  # ParseException classified as invalidity
    BONUS = "bonus"            # ParseException classified as bonus (e.g. StringEnd)
    FUNCTIONAL = "functional"  # FunctionalBug: incorrect computation result
    CRASH = "crash"            # Binary exited with non-zero code unexpectedly
    TIMEOUT = "timeout"        # Binary exceeded time limit


@dataclass
class RunResult:
    """Captures a single execution outcome from a target binary."""
    input_data: bytes
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    bug_type: BugType
    # Unique key for deduplication: (category, exc_type_str, truncated_message)
    bug_key: Optional[Tuple[str, str, str]]
    is_new_behavior: bool = False  # Set by SeedCorpus after lookup


class BugOracle:
    """
    Classifies binary stdout into RunResult.

    The binary always exits 0 (even on parse errors) and prints structured
    output. We parse stdout for:
      - "invalidity" keyword -> INVALIDITY bug
      - "bonus" keyword      -> BONUS bug
      - non-zero exit code   -> potential CRASH
      - timeout flag         -> TIMEOUT
    """

    # Regex to pull the ParseException message from stdout or stderr
    _PARSE_EXC_RE = re.compile(
        r"ParseException: (.+?)(?:\n|$)", re.MULTILINE
    )
    # Final bug count line, e.g.:
    # Final bug count: defaultdict(<class 'int'>, {('invalidity', ..., ..., ..., ...): 1})
    _BUG_COUNT_RE = re.compile(
        r"Final bug count: defaultdict\(<class 'int'>, \{(.*)\}\)"
    )
    _BUG_ENTRY_RE = re.compile(
        r"\('(\w+)', <class '([^']+)'>, '([^']*)', '[^']*', \d+\)"
    )

    def classify(
        self,
        input_data: bytes,
        stdout: str,
        stderr: str,
        exit_code: int,
        timed_out: bool,
    ) -> RunResult:

        if timed_out:
            return RunResult(
                input_data=input_data,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=True,
                bug_type=BugType.TIMEOUT,
                bug_key=("timeout", "", ""),
            )

        combined = stdout + "\n" + stderr

        # --- Try to parse the structured Final bug count line first ---
        count_match = self._BUG_COUNT_RE.search(combined)
        if count_match:
            entries_str = count_match.group(1).strip()
            if entries_str:
                # There is at least one entry — grab the first one
                entry_match = self._BUG_ENTRY_RE.search(entries_str)
                if entry_match:
                    category = entry_match.group(1)   # e.g. "invalidity"
                    exc_type = entry_match.group(2)   # e.g. "pyparsing.exceptions.ParseException"
                    exc_msg = entry_match.group(3)[:120]  # truncate long messages
                    bug_key = (category, exc_type, exc_msg)
                    bug_type = (
                        BugType.INVALIDITY if category == "invalidity"
                        else BugType.BONUS if category == "bonus"
                        else BugType.FUNCTIONAL if category == "functional"
                        else BugType.CRASH
                    )
                    return RunResult(
                        input_data=input_data,
                        stdout=stdout,
                        stderr=stderr,
                        exit_code=exit_code,
                        timed_out=False,
                        bug_type=bug_type,
                        bug_key=bug_key,
                    )

        # --- Fallback: keyword search ---
        lower = combined.lower()
        exc_match = self._PARSE_EXC_RE.search(combined)
        exc_msg = exc_match.group(1)[:120] if exc_match else combined[-120:].strip()

        if "invalidity" in lower:
            return RunResult(
                input_data=input_data,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=False,
                bug_type=BugType.INVALIDITY,
                bug_key=("invalidity", "ParseException", exc_msg),
            )

        if "functional" in lower and "functional bug" in lower:
            func_match = re.search(r"FunctionalBug: (.+?)(?:\n|$)", combined)
            fmsg = func_match.group(1)[:120] if func_match else exc_msg
            return RunResult(
                input_data=input_data,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=False,
                bug_type=BugType.FUNCTIONAL,
                bug_key=("functional", "FunctionalBug", fmsg),
            )

        if "bonus" in lower:
            return RunResult(
                input_data=input_data,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=False,
                bug_type=BugType.BONUS,
                bug_key=("bonus", "ParseException", exc_msg),
            )

        # Unexpected non-zero exit with no structured output -> crash
        if exit_code != 0:
            return RunResult(
                input_data=input_data,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=False,
                bug_type=BugType.CRASH,
                bug_key=("crash", "", stderr[:80].strip()),
            )

        # Clean run
        return RunResult(
            input_data=input_data,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=False,
            bug_type=BugType.NORMAL,
            bug_key=None,
        )
