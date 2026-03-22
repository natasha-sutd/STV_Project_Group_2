"""
take a RawResult from target_runner.py and classify it into a structured BugResult with 
bug_type, bug_key etc. This is the "oracle" that determines whether a given test input 
triggers a bug and what kind of bug it is.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

from target_runner import RawResult

class BugType(Enum):
    NORMAL = "normal"
    INVALIDITY = "invalidity"
    BONUS = "bonus"
    FUNCTIONAL = "functional"
    CRASH = "crash"
    TIMEOUT = "timeout"

@dataclass
class BugResult:
    input_data: bytes
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    bug_type: BugType
    bug_key: Optional[Tuple[str, str, str]]
    is_new_behavior: bool = False
    strategy: Optional[str] = None

class BugOracle:
    # Regex to extract ParseException message from stdout/stderr
    _PARSE_EXC_RE = re.compile(
        r"ParseException: (.+?)(?:\n|$)", re.MULTILINE
    )

    # Regex to match the structured "Final bug count" line all harnesses print:
    # Final bug count: defaultdict(<class 'int'>, {('invalidity', ...): 1})
    _BUG_COUNT_RE = re.compile(
        r"Final bug count: defaultdict\(<class 'int'>, \{(.*)\}\)"
    )

    # Regex to extract one bug entry from the Final bug count line:
    # ('invalidity', <class 'pyparsing.exceptions.ParseException'>, 'msg', 'file', 123)
    _BUG_ENTRY_RE = re.compile(
        r"\('(\w+)', <class '([^']+)'>, '([^']*)', '[^']*', \d+\)"
    )

    def classify(
        self,
        raw: RawResult,
        config: dict,
    ) -> BugResult:
        if raw.timed_out:
            return BugResult(
                input_data      = raw.input_data,
                stdout          = raw.stdout,
                stderr          = raw.stderr,
                exit_code       = raw.returncode,
                timed_out       = True,
                bug_type        = BugType.TIMEOUT,
                bug_key         = ("timeout", "", ""),
                strategy        = raw.strategy,
            )

        combined = raw.stdout + "\n" + raw.stderr

        count_match = self._BUG_COUNT_RE.search(combined)
        if count_match:
            entries_str = count_match.group(1).strip()
            if entries_str:
                entry_match = self._BUG_ENTRY_RE.search(entries_str)
                if entry_match:
                    category = entry_match.group(1) 
                    exc_type = entry_match.group(2) 
                    exc_msg  = entry_match.group(3)[:120] 
                    bug_key  = (category, exc_type, exc_msg)
                    bug_type = (
                        BugType.INVALIDITY if category == "invalidity"
                        else BugType.BONUS      if category == "bonus"
                        else BugType.FUNCTIONAL if category == "functional"
                        else BugType.CRASH
                    )
                    return BugResult(
                        input_data = raw.input_data,
                        stdout     = raw.stdout,
                        stderr     = raw.stderr,
                        exit_code  = raw.returncode,
                        timed_out  = False,
                        bug_type   = bug_type,
                        bug_key    = bug_key,
                        strategy   = raw.strategy,
                    )

        lower = combined.lower()
        exc_match = self._PARSE_EXC_RE.search(combined)
        exc_msg = exc_match.group(1)[:120] if exc_match else combined[-120:].strip()
        bug_keywords = config.get("bug_keywords", [])

        if any(kw.lower() == "invalidity" for kw in bug_keywords) and "invalidity" in lower:
            return BugResult(
                input_data = raw.input_data,
                stdout = raw.stdout,
                stderr = raw.stderr,
                exit_code = raw.returncode,
                timed_out = False,
                bug_type = BugType.INVALIDITY,
                bug_key = ("invalidity", "ParseException", exc_msg),
                strategy = raw.strategy,
            )

        if "functional bug" in lower:
            func_match = re.search(r"FunctionalBug: (.+?)(?:\n|$)", combined)
            fmsg = func_match.group(1)[:120] if func_match else exc_msg
            return BugResult(
                input_data = raw.input_data,
                stdout     = raw.stdout,
                stderr     = raw.stderr,
                exit_code  = raw.returncode,
                timed_out  = False,
                bug_type   = BugType.FUNCTIONAL,
                bug_key    = ("functional", "FunctionalBug", fmsg),
                strategy   = raw.strategy,
            )

        if any(kw.lower() == "bonus" for kw in bug_keywords) and "bonus" in lower:
            return BugResult(
                input_data = raw.input_data,
                stdout     = raw.stdout,
                stderr     = raw.stderr,
                exit_code  = raw.returncode,
                timed_out  = False,
                bug_type   = BugType.BONUS,
                bug_key    = ("bonus", "ParseException", exc_msg),
                strategy   = raw.strategy,
            )

        for kw in bug_keywords:
            if kw.lower() in lower:
                return BugResult(
                    input_data = raw.input_data,
                    stdout = raw.stdout,
                    stderr = raw.stderr,
                    exit_code = raw.returncode,
                    timed_out = False,
                    bug_type = BugType.CRASH,
                    bug_key = ("crash", kw, exc_msg),
                    strategy = raw.strategy,
                )

        if raw.returncode != 0:
            return BugResult(
                input_data = raw.input_data,
                stdout     = raw.stdout,
                stderr     = raw.stderr,
                exit_code  = raw.returncode,
                timed_out  = False,
                bug_type   = BugType.CRASH,
                bug_key    = ("crash", "", raw.stderr[:80].strip()),
                strategy   = raw.strategy,
            )

        return BugResult(
            input_data = raw.input_data,
            stdout     = raw.stdout,
            stderr     = raw.stderr,
            exit_code  = raw.returncode,
            timed_out  = False,
            bug_type   = BugType.NORMAL,
            bug_key    = None,
            strategy   = raw.strategy,
        )

if __name__ == "__main__":
    import yaml
    from pathlib import Path
    from target_runner import load_config, load_seeds, run_both

    yaml_path = "targets/json_decoder.yaml"
    cfg = load_config(yaml_path)
    seeds = load_seeds(cfg["seeds_path"])
    oracle = BugOracle()

    test_inputs = seeds[:3] + ['{"a":', '{"a": ' * 50]

    print(f"{'='*60}")
    print(f"TARGET : {cfg['name']}")
    print(f"{'='*60}")

    for inp in test_inputs:
        buggy_results, _ = run_both(cfg, inp, strategy="manual_test")
        raw = buggy_results[0]
        bug = oracle.classify(raw, cfg)

        print(
            f"  [{bug.bug_type.value:11s}] "
            f"key={str(bug.bug_key)[:60] if bug.bug_key else 'None':<60} "
            f"| {repr(inp[:40])}"
        )