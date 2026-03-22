"""
engine/types.py

Canonical shared types for the fuzzer pipeline.
ALL modules import BugResult and BugType from here — never redefine them.

Import pattern:
    from engine.types import BugResult, BugType
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class BugType(Enum):
    """
    Project-specific bug taxonomy, matching the raised exceptions in each target.

    Seeded bugs (explicitly raised by the buggy targets):
    -------------------------------------------------------
    VALIDITY     — input is syntactically correct but semantically wrong.
                   Raised as: ValidityBug
                   Example:   date "24/22/2025" is well-formed but month 24 is invalid.

    INVALIDITY   — input is syntactically incorrect / malformed.
                   Raised as: InvalidityBug, InvalidCidrFormatError
                   Example:   date "AB/22/2025" — letters where digits are expected.

    PERFORMANCE  — input causes abnormal execution delay (near-hang / slow path).
                   Raised as: PerformanceBug
                   Detected via: execution time significantly exceeding baseline.

    FUNCTIONAL   — program produces semantically incorrect output for valid input.
                   Raised as: FunctionalBug
                   Example:   add("2","3") returns 23 instead of 5.

    BOUNDARY     — bug triggered at the edge of the accepted input range.
                   Raised as: BoundaryBug
                   Example:   off-by-one in a loop causing IndexError.

    RELIABILITY  — program crashes (non-zero/negative exit code) on certain inputs.
                   Raised as: ReliabilityBug
                   Example:   division by zero with no guard.

    Untracked / bonus bugs (not seeded — extra marks if found):
    ------------------------------------------------------------
    BONUS        — unexpected exceptions not seeded into the buggy target.
                   Raised as: JSONDecodeError, CidrizeError, AddrFormatError, etc.
                   These appear in stderr as an unhandled Traceback.

    Infrastructure results (not bugs in the target itself):
    -------------------------------------------------------
    TIMEOUT      — execution exceeded the configured timeout.
                   Distinct from PERFORMANCE: the process was killed, not just slow.

    DIFF         — output differed from reference binary (differential oracle).
                   Used when no named exception is raised but behaviour diverges.

    NORMAL       — clean run, no bug signal detected.

    ERROR        — unexpected Python-level failure in the fuzzer infrastructure.
    """
    # ── seeded bug types (from the PDF taxonomy) ──────────────────────────
    VALIDITY    = auto()
    INVALIDITY  = auto()
    PERFORMANCE = auto()
    FUNCTIONAL  = auto()
    BOUNDARY    = auto()
    RELIABILITY = auto()

    # ── bonus / untracked bugs ────────────────────────────────────────────
    BONUS       = auto()

    # ── infrastructure results ────────────────────────────────────────────
    TIMEOUT     = auto()   # process killed by timeout
    DIFF        = auto()   # differential divergence (no named exception)
    NORMAL      = auto()   # clean run
    ERROR       = auto()   # fuzzer-level failure


# ---------------------------------------------------------------------------
# Keyword → BugType mapping
#
# output_parser.classify() should scan stdout+stderr for these strings
# (in priority order) to determine which seeded bug was triggered.
# Keys are checked as substrings (case-sensitive).
# ---------------------------------------------------------------------------
KEYWORD_TO_BUGTYPE: list[tuple[str, BugType]] = [
    # Seeded exception class names (highest specificity — check first)
    ("ValidityBug",             BugType.VALIDITY),
    ("invalidity bug",          BugType.INVALIDITY),   # json_decoder keyword
    ("InvalidityBug",           BugType.INVALIDITY),
    ("InvalidCidrFormatError",  BugType.INVALIDITY),
    ("PerformanceBug",          BugType.PERFORMANCE),
    ("FunctionalBug",           BugType.FUNCTIONAL),
    ("BoundaryBug",             BugType.BOUNDARY),
    ("ReliabilityBug",          BugType.RELIABILITY),
    ("bug has been triggered",  BugType.RELIABILITY),  # json_decoder keyword

    # Bonus / untracked exceptions (lower priority — check after seeded)
    ("JSONDecodeError",         BugType.BONUS),
    ("CidrizeError",            BugType.BONUS),
    ("AddrFormatError",         BugType.BONUS),
    ("Traceback (most recent",  BugType.BONUS),        # any unhandled exception
]


def classify_from_keywords(stdout: str, stderr: str) -> BugType | None:
    """
    Scan stdout+stderr for known exception strings and return the matching
    BugType. Returns None if no keyword matches (caller should fall through
    to crash/timeout/diff/normal detection).

    Checks KEYWORD_TO_BUGTYPE in order — first match wins.
    """
    combined = stdout + stderr
    for keyword, bug_type in KEYWORD_TO_BUGTYPE:
        if keyword in combined:
            return bug_type
    return None


# ---------------------------------------------------------------------------
# BugResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class BugResult:
    """
    Output of output_parser.classify(raw, ref, config).
    Input to bug_logger.log() and coverage_tracker.update().

    Fields
    ------
    bug_type     : BugType — classification of this execution (see taxonomy above)
    bug_key      : str     — stable 12-char dedup hash used by bug_logger to
                             avoid logging the same bug twice:
                             hashlib.md5(f"{bug_type.name}:{input[:80]}".encode())
                             .hexdigest()[:12]
    input_data   : str     — the input that triggered this result
    target       : str     — target name from config["name"]
    strategy     : str     — mutation strategy that produced input_data;
                             left blank by output_parser, stamped by fuzzer.py
    stdout       : str     — captured stdout from the buggy binary
    stderr       : str     — captured stderr from the buggy binary
    returncode   : int     — process return code (-1 for timeout/infra error)
    timed_out    : bool    — True if process was killed by timeout
    crashed      : bool    — True if returncode < 0 (signal / segfault)
    new_coverage : bool    — set True by coverage_tracker if this input
                             revealed new edges/paths; used by fuzzer.py for
                             corpus growth and energy boosting
    exec_time_ms : float   — wall-clock execution time in milliseconds;
                             used by output_parser to detect PERFORMANCE bugs
                             (execution time significantly above baseline)
    """
    bug_type    : BugType
    bug_key     : str
    input_data  : str
    target      : str
    strategy    : str        = ""
    stdout      : str        = ""
    stderr      : str        = ""
    returncode  : int        = 0
    timed_out   : bool       = False
    crashed     : bool       = False
    new_coverage: bool       = False
    exec_time_ms: float      = 0.0

    def is_bug(self) -> bool:
        """True for any result that should be logged (everything except NORMAL)."""
        return self.bug_type not in (BugType.NORMAL, BugType.ERROR)

    def is_seeded(self) -> bool:
        """True for the 6 explicitly seeded bug types from the project PDF."""
        return self.bug_type in (
            BugType.VALIDITY,
            BugType.INVALIDITY,
            BugType.PERFORMANCE,
            BugType.FUNCTIONAL,
            BugType.BOUNDARY,
            BugType.RELIABILITY,
        )

    def label(self) -> str:
        """Short human-readable label for terminal output."""
        return self.bug_type.name