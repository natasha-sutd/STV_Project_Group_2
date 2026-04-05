"""
take a RawResult from target_runner.py and classify it into a structured BugResult with 
bug_type, bug_key etc. This is the "oracle" that determines whether a given test input 
triggers a bug and what kind of bug it is.

Since both the IPv4/IPv6 parsers are closed binaries, coverage is
approximated via behavioural novelty — every unique (bug_category,
error_message) pair is treated as "new coverage" for corpus scheduling.

Usage in output_parser.classify():
    from engine.bug_oracle import BugOracle
    from engine.target_runner import RawResult

    oracle = BugOracle()
    bug = oracle.classify(
        raw         = buggy_raw,        # RawResult from run_both()
        ref_stdout  = ref.stdout,       # reference stdout (or None)
        target      = config["name"],   # e.g. "json_decoder"
        input_data  = mutated_input,    # str — the input sent to the target
        target_name = config["input_format"],  # "json"|"ipv4"|"ipv6"|"cidr"
    )

Classifies the output of a binary execution into a BugResult.

Accepts a RawResult (from target_runner.run_both) and returns a BugResult
(from engine.types) directly — no intermediate RunResult needed.

Since both the IPv4/IPv6 parsers are closed binaries, coverage is
approximated via behavioural novelty — every unique (bug_category,
error_message) pair is treated as "new coverage" for corpus scheduling.

All target-specific knowledge lives in the YAML config — this file
contains no hardcoded target names, output formats, or patterns.

Usage in output_parser.classify():
    from engine.bug_oracle import BugOracle

    oracle = BugOracle()
    bug = oracle.classify(
        raw        = buggy_raw,     # RawResult from run_both()
        input_data = mutated_input, # str — the input sent to the target
        target     = config["name"],
        config     = config,        # full YAML config
        ref_stdout = ref.stdout,    # reference stdout (or None)
    )

YAML fields read by this module
--------------------------------
bug_keywords   : list[str]  — keywords triggering bug detection (already used
                              by target_runner; reused here for fallback)
output_pattern : str | None — pattern for extracting the parsed output value
                              for differential (MISMATCH) comparison.
                              Use {value} as the capture placeholder.
                              Example:  "Output: [{value}]"
                              Example:  "Output decoded data: {value} of type"
                              If absent, MISMATCH detection is skipped.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from engine.types import BugResult, BugType, classify_from_keywords
from engine.target_runner import RawResult

# ---------------------------------------------------------------------------
# Generic output extractor
# ---------------------------------------------------------------------------
def _extract_output(stdout: str, pattern: str) -> Optional[str]:
    """
    Extract the output value from stdout using a pattern defined in the YAML.

    {value} in the pattern marks the capture group. Everything else is
    treated as a literal string (re.escape'd).

    Examples
    --------
    pattern = "Output: [{value}]"
        matches "Output: [3232235777]" → returns "3232235777"

    pattern = "Output decoded data: {value} of type"
        matches "Output decoded data: {'a': 1} of type" → returns "{'a': 1}"

    pattern = "IPNetwork('{value}')"
        matches "IPNetwork('192.168.1.0/24')" → returns "192.168.1.0/24"

    Returns None if the pattern does not match stdout.
    """
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

    # Regex: structured "Final bug count" line emitted by json_decoder
    # e.g. Final bug count: defaultdict(<class 'int'>, {('invalidity',...): 1})
    _BUG_COUNT_RE = re.compile(
        r"Final bug count: defaultdict\(<class 'int'>, \{(.*)\}\)"
    )
    _BUG_ENTRY_RE = re.compile(
        r"\('(\w+)', <class '([^']+)'>, '([^']*)', '[^']*', \d+\)"
    )

    def classify(
        self,
        raw        : RawResult,
        input_data : str,              # already-decoded str input
        target     : str,              # config["name"], e.g. "json_decoder"
        config     : dict  = None,     # full YAML config (bug_keywords, output_pattern)
        ref_stdout : Optional[str] = None,  # reference binary stdout for MISMATCH check
    ) -> BugResult:
        """
        Classify one RawResult into a BugResult.

        Parameters
        ----------
        raw        : RawResult from target_runner.run_both() (buggy binary only)
        input_data : the str input that was sent to the target
        target     : target name from config["name"]
        config     : full YAML config dict. Two fields are used:
                       bug_keywords   — list of strings for generic fallback detection
                       output_pattern — pattern for MISMATCH differential comparison
                                        (e.g. "Output: [{value}]")
                     Pass {} or None to skip both.
        ref_stdout : stdout from the reference binary for differential testing;
                     pass None to skip MISMATCH detection
        """
        config       = config or {}
        stdout       = raw.stdout
        stderr       = raw.stderr
        combined     = stdout + "\n" + stderr
        bug_keywords = config.get("bug_keywords", [])

        # ── 1. TIMEOUT ────────────────────────────────────────────────────
        if raw.timed_out:
            return self._make_result(
                bug_type   = BugType.TIMEOUT,
                raw_key    = ("timeout", "", ""),
                input_data = input_data,
                target     = target,
                raw        = raw,
            )

        # ── 2. Structured "Final bug count" line (json_decoder) ───────────
        count_match = self._BUG_COUNT_RE.search(combined)
        if count_match:
            entries_str = count_match.group(1).strip()
            if entries_str:
                entry_match = self._BUG_ENTRY_RE.search(entries_str)
                if entry_match:
                    category = entry_match.group(1)
                    exc_type = entry_match.group(2)
                    exc_msg  = entry_match.group(3)[:120]
                    return self._make_result(
                        bug_type   = self._category_to_bug_type(category),
                        raw_key    = (category, exc_type, exc_msg),
                        input_data = input_data,
                        target     = target,
                        raw        = raw,
                    )

        # Shared fallback message used by checks 3–7
        exc_match = self._PARSE_EXC_RE.search(combined)
        exc_msg   = exc_match.group(1)[:120] if exc_match else combined[-120:].strip()
        lower     = combined.lower()

        # ── 3. INVALIDITY ─────────────────────────────────────────────────
        if "invalidity" in lower:
            # Include stdout to differentiate similar invalidity bugs
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type   = BugType.INVALIDITY,
                raw_key    = ("invalidity", "ParseException", exc_msg, stdout_snippet),
                input_data = input_data,
                target     = target,
                raw        = raw,
            )

        # ── 4. SYNTACTIC (cidrize: AddrFormatError, SyntaxError) ──────────
        if ("syntactic" in lower
                or "syntax error" in lower
                or "AddrFormatError" in combined):   # class name is case-sensitive
            addr_match = re.search(r"AddrFormatError: (.+?)(?:\n|$)", combined)
            smsg = addr_match.group(1)[:160] if addr_match else exc_msg  # increased from 120
            # Include stdout to differentiate similar syntactic bugs
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type   = BugType.SYNTACTIC,
                raw_key    = ("syntactic", "AddrFormatError", smsg, stdout_snippet),
                input_data = input_data,
                target     = target,
                raw        = raw,
            )

        # ── 5. FUNCTIONAL ─────────────────────────────────────────────────
        if "functional" in lower and "functional bug" in lower:
            func_match = re.search(r"FunctionalBug: (.+?)(?:\n|$)", combined)
            fmsg = func_match.group(1)[:160] if func_match else exc_msg  # increased from 120
            # Include stdout snippet to differentiate similar functional bugs
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type   = BugType.FUNCTIONAL,
                raw_key    = ("functional", "FunctionalBug", fmsg, stdout_snippet),
                input_data = input_data,
                target     = target,
                raw        = raw,
            )

        # ── 6. BONUS (untracked / unseeded exceptions) ────────────────────
        if "bonus" in lower:
            # Include stdout to differentiate similar bonus bugs
            stdout_snippet = stdout[:80].strip() if stdout else ""
            return self._make_result(
                bug_type   = BugType.BONUS,
                raw_key    = ("bonus", "ParseException", exc_msg, stdout_snippet),
                input_data = input_data,
                target     = target,
                raw        = raw,
            )

        # ── 7. Generic keyword fallback (from YAML bug_keywords) ──────────
        # Any target can define custom detection keywords in its YAML without
        # modifying this file — directly supports the generalisability rubric.
        for kw in bug_keywords:
            if kw.lower() in lower:
                specific = classify_from_keywords(stdout, stderr)
                bug_type = specific if specific is not None else BugType.RELIABILITY
                # Include stdout/stderr to differentiate similar keyword-triggered bugs
                stdout_snippet = stdout[:80].strip() if stdout else ""
                return self._make_result(
                    bug_type   = bug_type,
                    raw_key    = ("keyword", kw, exc_msg, stdout_snippet),
                    input_data = input_data,
                    target     = target,
                    raw        = raw,
                )

        # ── 8. RELIABILITY — non-zero exit, no structured output ──────────
        if raw.returncode != 0:
            # Include returncode + more stderr/stdout to differentiate bugs
            rel_msg = (stderr[:160] or stdout[:160]).strip()
            return self._make_result(
                bug_type   = BugType.RELIABILITY,
                raw_key    = ("reliability", str(raw.returncode), rel_msg),
                input_data = input_data,
                target     = target,
                raw        = raw,
            )

        # ── 9. MISMATCH — differential oracle ─────────────────────────────
        # output_pattern is read from config — no hardcoded target logic here.
        # Each YAML defines its own pattern e.g. "Output: [{value}]"
        if ref_stdout is not None:
            pattern  = config.get("output_pattern")
            norm_out = _extract_output(stdout,    pattern)
            norm_ref = _extract_output(ref_stdout, pattern)
            if pattern and norm_out != norm_ref:
                return self._make_result(
                    bug_type   = BugType.MISMATCH,
                    raw_key    = ("mismatch", "OutputMismatch",
                                  f"out={norm_out} ref={norm_ref}"),
                    input_data = input_data,
                    target     = target,
                    raw        = raw,
                )

        # ── 10. NORMAL ────────────────────────────────────────────────────
        return self._make_result(
            bug_type   = BugType.NORMAL,
            raw_key    = None,
            input_data = input_data,
            target     = target,
            raw        = raw,
        )

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _make_result(
        bug_type   : BugType,
        raw_key    : Optional[tuple],
        input_data : str,
        target     : str,
        raw        : RawResult,
    ) -> BugResult:
        """
        Build a BugResult from a RawResult, hashing the tuple raw_key
        into a stable 16-char string for bug_logger deduplication.
        Uses 16 characters (64 bits) instead of 12 to reduce collision risk.
        """
        if raw_key is not None:
            key_str = ":".join(str(p) for p in raw_key)
        else:
            key_str = f"normal:{input_data[:40]}"
        bug_key = hashlib.md5(key_str.encode()).hexdigest()[:16]  # increased from 12 to 16

        return BugResult(
            bug_type   = bug_type,
            bug_key    = bug_key,
            input_data = input_data,
            target     = target,
            strategy   = "",           # stamped by fuzzer.py after classify()
            stdout     = raw.stdout,
            stderr     = raw.stderr,
            returncode = raw.returncode,
            timed_out  = raw.timed_out,
            crashed    = raw.crashed,
        )

    @staticmethod
    def _category_to_bug_type(category: str) -> BugType:
        """Map a structured bug count category string to a BugType."""
        return {
            "invalidity" : BugType.INVALIDITY,
            "bonus"      : BugType.BONUS,
            "syntactic"  : BugType.SYNTACTIC,
            "functional" : BugType.FUNCTIONAL,
            "boundary"   : BugType.BOUNDARY,
            "validity"   : BugType.VALIDITY,
            "performance": BugType.PERFORMANCE,
            "reliability": BugType.RELIABILITY,
        }.get(category, BugType.RELIABILITY)


# ---------------------------------------------------------------------------
# Quick sanity test — run directly to verify oracle against live targets
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from pathlib import Path
    from engine.target_runner import load_config, load_seeds, run_both

    TARGET_YAMLS = [
        "targets/json_decoder.yaml",
        "targets/cidrize.yaml",
        "targets/ipv4_parser.yaml",
        "targets/ipv6_parser.yaml",
    ]

    oracle = BugOracle()

    for yaml_path in TARGET_YAMLS:
        if not Path(yaml_path).exists():
            print(f"[skip] {yaml_path} not found")
            continue

        cfg    = load_config(yaml_path)
        seeds  = load_seeds(cfg["seeds_path"])

        # A few seeds + a couple of obviously malformed inputs for each target
        test_inputs = seeds[:3] + ['{"a":', '{"a": ' * 50]

        print(f"{'='*60}")
        print(f"TARGET : {cfg['name']}")
        print(f"{'='*60}")

        for inp in test_inputs:
            buggy_results, ref = run_both(cfg, inp, strategy="oracle_test")
            raw = buggy_results[0]
            bug = oracle.classify(
                raw        = raw,
                input_data = inp,
                target     = cfg["name"],
                config     = cfg,
                ref_stdout = ref.stdout if ref else None,
            )
            print(
                f"  [{bug.bug_type.name:12s}] "
                f"key={bug.bug_key:<14} "
                f"| {repr(inp[:45])}"
            )