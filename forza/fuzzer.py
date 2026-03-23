"""
The orchestrator that wires everything together into the main fuzzing loop.

# Pseudocode of the main loop
config = load_config("targets/json_decoder.yaml")
seeds  = load_seeds(config["seeds_path"])
engine = MutationEngine(input_format=config["input_format"])
corpus = list(seeds)   # start with seeds, grow as new paths found

for iteration in range(MAX_ITERATIONS):
    seed      = random.choice(corpus)             # pick a seed
    mutated   = engine.mutate(seed)               # mutate it
    raw, ref  = run_both(config, mutated,         # run target
                         strategy=engine.get_last_strategy())
    bug       = output_parser.classify(raw, ref, config)   # classify
    new_paths = coverage_tracker.update(raw, bug)          # track coverage
    if new_paths:
        engine.boost(engine.get_last_strategy())  # boost winning strategy
        corpus.append(mutated)                    # add to corpus
    if bug.bug_type != BugType.NORMAL:
        bug_logger.log(bug, config)               # save bug
# Connections
fuzzer.py
    │
    ├── load_config()  ← target_runner.py
    ├── MutationEngine ← mutation_engine.py
    ├── run_both()     ← target_runner.py    →  RawResult
    ├── output_parser.classify()             →  BugResult
    ├── coverage_tracker.update()
    └── bug_logger.log()                     →  CSV + crash file
            │
            ▼
    report_generator.generate()              →  report.html

fuzzer.py
=========
Main entry point. Wires the full pipeline together:

    seed / mutated input
        └─► target_runner.run_both()      →  [RawResult], RawResult | None
        └─► BugOracle.classify()          →  BugResult
        └─► CoverageTracker.update()      →  bool  (new paths?)
        └─► bug_logger.log()              →  CSV + crash file
        └─► report_generator  (background, every REPORT_INTERVAL seconds)

Modes
-----
Fuzz mode (default):
    AFL-style energy-based mutation loop. Runs until --duration seconds
    elapses, --iterations is reached, or Ctrl+C (graceful shutdown).

    python3 fuzzer.py --target targets/json_decoder.yaml
    python3 fuzzer.py --target targets/json_decoder.yaml --duration 3600
    python3 fuzzer.py --target targets/json_decoder.yaml --iterations 5000
    python3 fuzzer.py --target targets/json_decoder.yaml --duration 3600 --iterations 50000
    python3 fuzzer.py --all --duration 1800

Seed mode (--seed):
    Runs every seed through the full pipeline once with no mutation.
    Useful for sanity-checking a new target config.

    python3 fuzzer.py --target targets/json_decoder.yaml --seed
    python3 fuzzer.py --all --seed

Interface contracts (for teammates)
------------------------------------
See INTERFACES.md for full details. Quick summary:

    MutationEngine(input_format: str)
        .mutate(seed: str) -> str
        .get_last_strategy() -> str
        .boost(strategy: str) -> None

    output_parser.classify(buggy_results, ref, config) -> BugResult

    coverage_tracker.update(bug, config) -> bool

    bug_logger.log(bug, config) -> None

    report_generator.load_all(targets) -> dict
    report_generator.load_all_coverage(targets) -> dict
    report_generator.generate_report(all_data, all_coverage, targets, out_path) -> Path
    report_generator.RESULTS_DIR  (Path)
"""

from __future__ import annotations

import argparse
import random
import signal
import sys
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Core imports (always available — no teammate dependencies)
# ---------------------------------------------------------------------------
from engine.target_runner import load_config, load_seeds, run_both
from engine.types import BugResult, BugType, classify_from_keywords

# ---------------------------------------------------------------------------
# Pipeline imports — loaded at runtime so seed mode works independently
# ---------------------------------------------------------------------------
def _import_fuzz_pipeline():
    """
    Import all engine modules. Called once at the start of fuzz mode.
    Raises ImportError with a clear message if a module is missing.
    """
    try:
        from engine.mutation_engine import MutationEngine
    except ImportError:
        raise ImportError(
            "engine/mutation_engine.py not found.\n"
            "Expected: class MutationEngine with mutate(), "
            "get_last_strategy(), boost() — see INTERFACES.md"
        )

    try:
        from engine.bug_oracle import BugOracle
    except ImportError as e:
        raise ImportError(f"engine/bug_oracle.py: {e}\nSee INTERFACES.md")

    try:
        from engine import coverage_tracker
        if not hasattr(coverage_tracker, "update"):
            raise ImportError("coverage_tracker.py is missing update()")
    except ImportError as e:
        raise ImportError(f"engine/coverage_tracker.py: {e}\nSee INTERFACES.md")

    try:
        from engine import bug_logger
        if not hasattr(bug_logger, "log"):
            raise ImportError("bug_logger.py is missing log()")
    except ImportError as e:
        raise ImportError(f"engine/bug_logger.py: {e}\nSee INTERFACES.md")

    try:
        from engine import report_generator
    except ImportError as e:
        raise ImportError(f"engine/report_generator.py: {e}")

    return MutationEngine, BugOracle, coverage_tracker, bug_logger, report_generator


def _import_report_generator():
    from engine import report_generator
    return report_generator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DISPLAY_INTERVAL  = 20      # iterations between status redraws
REPORT_INTERVAL   = 300     # seconds between background report refreshes (5 min)
DEFAULT_DURATION  = None    # None = no time limit unless --duration given
DEFAULT_ITERS     = 100_000 # safety cap when no --iterations given

TARGETS_DIR  = Path(__file__).resolve().parent / "targets"
KNOWN_YAMLS  = [
    "json_decoder.yaml",
    "cidrize.yaml",
    "ipv4_parser.yaml",
    "ipv6_parser.yaml",
]

# ---------------------------------------------------------------------------
# ANSI colour helpers (no external deps)
# ---------------------------------------------------------------------------
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

    @staticmethod
    def green(s):   return f"\033[92m{s}\033[0m"
    @staticmethod
    def yellow(s):  return f"\033[93m{s}\033[0m"
    @staticmethod
    def red(s):     return f"\033[91m{s}\033[0m"
    @staticmethod
    def cyan(s):    return f"\033[96m{s}\033[0m"
    @staticmethod
    def dim(s):     return f"\033[2m{s}\033[0m"
    @staticmethod
    def bold(s):    return f"\033[1m{s}\033[0m"
    @staticmethod
    def magenta(s): return f"\033[95m{s}\033[0m"
    @staticmethod
    def white(s):   return f"\033[97m{s}\033[0m"


# ---------------------------------------------------------------------------
# AFL-style terminal UI
# ---------------------------------------------------------------------------
_W = 72  # display width

def _div(label: str = "") -> str:
    if label:
        inner = f" {label} "
        dashes = "─" * (_W - len(inner) - 2)
        return f"{C.CYAN}──{inner}{'─' * (_W - len(inner) - 2)}{C.RESET}"
    return C.cyan("─" * _W)


def _kv(key: str, val: str, w: int = 26) -> str:
    return f"  {C.DIM}{key:<{w}}{C.RESET}: {val}"


def _fmt_elapsed(seconds: float) -> str:
    h, r    = divmod(int(seconds), 3600)
    m, s    = divmod(r, 60)
    return f"{h}h {m:02d}m {s:02d}s"


def _fmt_remaining(elapsed: float, duration: float | None) -> str:
    if duration is None:
        return C.dim("∞")
    rem = max(0.0, duration - elapsed)
    return C.yellow(_fmt_elapsed(rem))


def print_banner(config: dict, mode: str, duration: float | None, max_iters: int) -> None:
    name    = config.get("name", "unknown")
    fmt     = config.get("input_format", "?")
    timeout = config.get("timeout", "?")
    dur_str = f"{duration:.0f}s" if duration else "∞"
    iter_str = f"{max_iters:,}"

    print()
    print(_div())
    print(f"  {C.bold(C.cyan('greybox fuzzer'))}  ·  "
          f"target: {C.green(name)}  ·  mode: {C.yellow(mode)}")
    print(_div())
    print(_kv("target name",   C.green(name)))
    print(_kv("input format",  C.cyan(fmt)))
    print(_kv("exec timeout",  f"{timeout}s per input"))
    print(_kv("stop after",    f"{dur_str}  /  {iter_str} iters (whichever first)"))
    print(_kv("detection",     config.get("detection_mode", "keyword+crash+diff")))
    print(_kv("coverage",      C.green("enabled") if config.get("coverage_enabled") else C.dim("disabled")))
    print(_div())
    print()


# Number of lines in the live status block (must match print_fuzz_status exactly)
_STATUS_LINES = 18

def print_fuzz_status(
    config      : dict,
    iteration   : int,
    total_bugs  : int,
    new_paths   : int,
    corpus_len  : int,
    execs_sec   : float,
    elapsed     : float,
    duration    : float | None,
    max_iters   : int,
    last_bug    : BugResult | None,
    last_report : float | None,
    strategy_counts : dict[str, int],
) -> None:
    """Overwrite the previous status block in-place."""
    name = config.get("name", "unknown")

    # Progress bar toward duration or iteration limit
    if duration:
        progress = min(elapsed / duration, 1.0)
        limit_str = f"{_fmt_elapsed(elapsed)} / {duration:.0f}s"
    else:
        progress = min(iteration / max_iters, 1.0)
        limit_str = f"{iteration:,} / {max_iters:,} iters"

    bar_w   = 36
    filled  = int(bar_w * progress)
    bar     = C.green("█" * filled) + C.dim("░" * (bar_w - filled))

    # Top strategy
    top_strat = (
        max(strategy_counts, key=strategy_counts.get)
        if strategy_counts else "—"
    )
    top_count = strategy_counts.get(top_strat, 0)

    last_bug_str = (
        C.red(f"{last_bug.label():<8}") + C.dim(f" {repr(last_bug.input_data[:32])}")
        if last_bug else C.dim("none yet")
    )

    report_str = (
        C.dim(f"{_fmt_elapsed(elapsed - last_report)} ago")
        if last_report is not None else C.dim("pending...")
    )

    lines = [
        "",
        _div("process timing"),
        _kv("elapsed",       C.white(_fmt_elapsed(elapsed))),
        _kv("remaining",     _fmt_remaining(elapsed, duration)),
        _kv("execs / sec",   C.green(f"{execs_sec:.1f}")),
        _div("overall results"),
        _kv("iterations",    C.white(f"{iteration:,}")),
        _kv("corpus size",   C.cyan(str(corpus_len))),
        _kv("new paths",     C.cyan(str(new_paths))),
        _kv("total bugs",    C.red(str(total_bugs)) if total_bugs else C.green("0")),
        _div("fuzzing strategy"),
        _kv("top strategy",  C.magenta(f"{top_strat}") + C.dim(f"  ({top_count} bugs)")),
        _div("last finding"),
        _kv("last bug",      last_bug_str),
        _div("report"),
        _kv("last refresh",  report_str),
        f"  {bar}  {C.dim(limit_str)}",
        "",
    ]

    assert len(lines) == _STATUS_LINES, \
        f"_STATUS_LINES mismatch: expected {_STATUS_LINES}, got {len(lines)}"

    # Move cursor up to overwrite previous block (skip on first draw)
    if iteration > 1:
        sys.stdout.write(f"\033[{_STATUS_LINES}A\033[J")

    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()


def print_seed_result(
    seed    : str,
    bug     : BugResult,
    idx     : int,
    total   : int,
) -> None:
    tag = {
        BugType.NORMAL      : C.green("  ok         "),
        BugType.RELIABILITY : C.red("  RELIABILITY"),
        BugType.TIMEOUT     : C.yellow("  TIMEOUT    "),
        BugType.VALIDITY    : C.magenta("  VALIDITY   "),
        BugType.INVALIDITY  : C.magenta("  INVALIDITY "),
        BugType.PERFORMANCE : C.yellow("  PERFORMANCE"),
        BugType.FUNCTIONAL  : C.magenta("  FUNCTIONAL "),
        BugType.BOUNDARY    : C.magenta("  BOUNDARY   "),
        BugType.BONUS       : C.cyan("  BONUS      "),
        BugType.SYNTACTIC   : C.yellow("  SYNTACTIC  "),
        BugType.ERROR       : C.red("  ERROR      "),
    }.get(bug.bug_type, C.dim("  ?           "))

    progress = C.dim(f"[{idx:>3}/{total}]")
    seed_str = C.dim(repr(seed[:48]))
    print(f"  {progress} {tag}  {seed_str}")


def print_summary(
    label      : str,
    n_run      : int,
    total_bugs : int,
    new_paths  : int,
    corpus_len : int,
    elapsed    : float,
    report_path: Path | None = None,
) -> None:
    print()
    print(_div(f"{label} — complete"))
    print(_kv("inputs run",  C.white(f"{n_run:,}")))
    print(_kv("total bugs",  C.red(str(total_bugs)) if total_bugs else C.green("0")))
    if new_paths is not None:
        print(_kv("new paths",  C.cyan(str(new_paths))))
        print(_kv("corpus size", C.white(str(corpus_len))))
    print(_kv("elapsed",     _fmt_elapsed(elapsed)))
    if report_path:
        print(_kv("report",  C.green(str(report_path))))
    print(_div())
    print()


# ---------------------------------------------------------------------------
# Background report refresh thread
# ---------------------------------------------------------------------------

class ReportRefresher(threading.Thread):
    """
    Daemon thread that regenerates report.html every REPORT_INTERVAL seconds.
    Keeps the report warm during long fuzz runs so Ctrl+C exit is fast.
    """
    def __init__(self, targets: list[str], out_path: Path) -> None:
        super().__init__(daemon=True)
        self.targets    = targets
        self.out_path   = out_path
        self._stop_evt  = threading.Event()
        self.last_run   : float | None = None
        self._rg        = _import_report_generator()

    def run(self) -> None:
        # First refresh after a short delay so there's some data to show
        self._stop_evt.wait(timeout=30)
        while not self._stop_evt.is_set():
            self._refresh()
            self._stop_evt.wait(timeout=REPORT_INTERVAL)
        # Final refresh on stop
        self._refresh()

    def _refresh(self) -> None:
        try:
            rg           = self._rg
            all_data     = rg.load_all(self.targets)
            all_coverage = rg.load_all_coverage(self.targets)
            rg.generate_report(all_data, all_coverage, self.targets, self.out_path)
            self.last_run = time.monotonic()
        except Exception:
            pass  # never crash the fuzzer because the report failed

    def stop(self) -> None:
        self._stop_evt.set()
        self.join(timeout=10)

    def elapsed_since_last(self, now: float) -> float | None:
        if self.last_run is None:
            return None
        return now - self.last_run


# ---------------------------------------------------------------------------
# Inline minimal classifier (seed mode only — no output_parser dependency)
# ---------------------------------------------------------------------------

def _classify_inline(
    buggy_results : list,
    ref           : object | None,
    config        : dict,
    seed          : str,
) -> BugResult:
    """
    Inline classifier used in seed mode (no output_parser.py dependency).

    Implements the full project bug taxonomy from the PDF, in priority order:

        1. TIMEOUT     — process was killed (timed_out flag)
        2. RELIABILITY — process crashed (returncode < 0), maps to ReliabilityBug
        3. Seeded keyword match — scans stdout+stderr using KEYWORD_TO_BUGTYPE:
               VALIDITY, INVALIDITY, PERFORMANCE, FUNCTIONAL, BOUNDARY,
               RELIABILITY (raised explicitly), BONUS (untracked exceptions)
        4. DIFF        — output diverged from reference (differential oracle)
        5. NORMAL      — no bug signal detected

    Note on PERFORMANCE: the seeded PerformanceBug raises an exception keyword,
    so it is caught in step 3. True hang/timeout (process killed) is step 1.
    """
    import hashlib

    target = config.get("name", "unknown")

    for raw in buggy_results:
        combined = raw.stdout + raw.stderr

        # 1. Timeout — process was killed by the runner
        if raw.timed_out:
            btype = BugType.TIMEOUT

        # 2. Crash — negative return code (segfault, signal, unhandled exception
        #    that caused a non-zero exit WITHOUT a known keyword in output)
        #    We check keywords first before committing to RELIABILITY so that
        #    an explicit "raise ReliabilityBug" (which also exits non-zero) is
        #    classified as RELIABILITY rather than a generic crash.
        elif raw.crashed:
            # Still check for a named exception in stderr — prefer the specific type
            keyword_type = classify_from_keywords(raw.stdout, raw.stderr)
            btype = keyword_type if keyword_type is not None else BugType.RELIABILITY

        # 3. Named exception keyword in output — covers all 6 seeded types + BONUS
        else:
            keyword_type = classify_from_keywords(raw.stdout, raw.stderr)
            if keyword_type is not None:
                btype = keyword_type

            # 4. Differential divergence — ref exists, didn't crash/timeout,
            #    but return code differs (functional divergence without a named bug)
            elif (ref
                  and not ref.timed_out
                  and not ref.crashed
                  and raw.returncode != ref.returncode):
                btype = BugType.DIFF

            # 5. Clean run
            else:
                btype = BugType.NORMAL

        bug_key = hashlib.md5(
            f"{btype.name}:{seed[:80]}".encode()
        ).hexdigest()[:12]

        return BugResult(
            bug_type   = btype,
            bug_key    = bug_key,
            input_data = seed,
            target     = target,
            strategy   = "seed",
            stdout     = raw.stdout,
            stderr     = raw.stderr,
            returncode = raw.returncode,
            timed_out  = raw.timed_out,
            crashed    = raw.crashed,
        )

    # Fallback if buggy_results is somehow empty
    return BugResult(
        bug_type=BugType.ERROR, bug_key="empty", input_data=seed,
        target=target, strategy="seed",
    )


# ---------------------------------------------------------------------------
# Seed mode
# ---------------------------------------------------------------------------

def run_seed_mode(config: dict) -> None:
    """
    Run every seed through the full pipeline once (no mutation).
    Uses inline classifier — does not require output_parser.py.
    Useful for sanity-checking a new target config.
    """
    seeds = load_seeds(config["seeds_path"])
    if not seeds:
        print(C.yellow("  [warn] no seeds found — check seeds_path in YAML"))
        return

    print_banner(config, mode="seed", duration=None, max_iters=len(seeds))
    print(f"  {C.dim('running')} {C.bold(str(len(seeds)))} "
          f"{C.dim('seeds through pipeline...')}")
    print()

    total_bugs = 0
    start      = time.monotonic()

    for idx, seed in enumerate(seeds, 1):
        buggy_results, ref = run_both(config, seed, strategy="seed")
        bug = _classify_inline(buggy_results, ref, config, seed)
        if bug.is_bug():
            total_bugs += 1
        print_seed_result(seed, bug, idx, len(seeds))

    elapsed = time.monotonic() - start
    print_summary(
        label      = "seed mode",
        n_run      = len(seeds),
        total_bugs = total_bugs,
        new_paths  = None,
        corpus_len = None,
        elapsed    = elapsed,
    )
    print(C.dim("  tip: omit --seed to run the full mutation loop"))
    print()


# ---------------------------------------------------------------------------
# Fuzz mode
# ---------------------------------------------------------------------------

def run_fuzz_mode(
    config    : dict,
    duration  : float | None,
    max_iters : int,
) -> None:
    """
    AFL-style energy-based mutation loop.

    Stop conditions (whichever fires first):
        • elapsed time >= --duration  (if provided)
        • iteration count >= --iterations
        • Ctrl+C  (SIGINT → graceful shutdown)

    Energy scheduling:
        MutationEngine.boost(strategy) is called whenever coverage_tracker
        reports new paths. The engine increases selection weight for that
        strategy. fuzzer.py is strategy-agnostic — it only signals outcomes.

    Corpus growth:
        Inputs producing new coverage are added to the corpus so they can
        be used as seeds for further mutation (greybox fuzzing).

    Background reporting:
        ReportRefresher regenerates report.html every REPORT_INTERVAL seconds
        in a daemon thread. Final refresh happens on shutdown.
    """
    MutationEngine, BugOracle, coverage_tracker, bug_logger, report_generator = (
        _import_fuzz_pipeline()
    )

    seeds = load_seeds(config["seeds_path"])
    if not seeds:
        print(C.yellow("  [warn] no seeds found — check seeds_path in YAML"))
        return

    engine     = MutationEngine(input_format=config.get("input_format", "text"))
    oracle     = BugOracle()
    corpus     = list(seeds)
    target     = config.get("name", "unknown")
    out_path   = report_generator.RESULTS_DIR / "report.html"

    # ── seed corpus initialisation ────────────────────────────────────────
    # Augment static seeds.txt with dynamically generated seeds.
    # seed_count in the YAML controls how many to add (0 = static only).
    seed_count   = config.get("seed_count", 0)
    input_format = config.get("input_format", "")
    if seed_count > 0 and input_format:
        try:
            from engine.seed_generator import generate_seed
            generated = [generate_seed(input_format) for _ in range(seed_count)]
            corpus.extend(generated)
            print(C.dim(
                f"  corpus: {len(seeds)} static seeds "
                f"+ {seed_count} generated = {len(corpus)} total"
            ))
        except Exception as e:
            print(C.yellow(f"  [warn] seed_generator failed: {e} — using static seeds only"))

    # Reset per-target state in module-level wrappers
    bug_logger.reset()
    coverage_tracker.reset()

    print_banner(config, mode="fuzz", duration=duration, max_iters=max_iters)

    # ── background report refresher ───────────────────────────────────────
    refresher = ReportRefresher(targets=[target], out_path=out_path)
    refresher.start()

    # ── graceful shutdown ─────────────────────────────────────────────────
    _shutdown = threading.Event()

    def _handle_sigint(sig, frame):
        if not _shutdown.is_set():
            _shutdown.set()
            sys.stdout.write(
                f"\n{C.yellow('  [!] Ctrl+C received — finishing iteration, then shutting down...')}\n\n"
            )
            sys.stdout.flush()

    signal.signal(signal.SIGINT, _handle_sigint)

    # ── loop state ────────────────────────────────────────────────────────
    total_bugs      = 0
    new_paths       = 0
    last_bug        : BugResult | None = None
    strategy_counts : dict[str, int]   = {}
    start           = time.monotonic()
    iteration       = 0

    try:
        for iteration in range(1, max_iters + 1):

            # ── stop conditions ───────────────────────────────────────────
            if _shutdown.is_set():
                break
            elapsed = time.monotonic() - start
            if duration is not None and elapsed >= duration:
                print(C.yellow(f"\n  [!] duration limit reached ({duration:.0f}s) — stopping\n"))
                break

            # ── 1. pick seed and mutate ───────────────────────────────────
            seed     = random.choice(corpus)
            mutated  = engine.mutate(seed)
            strategy = engine.get_last_strategy()

            # ── 2. run target ─────────────────────────────────────────────
            buggy_results, ref = run_both(
                config, mutated, strategy=strategy, use_coverage=True
            )

            # ── 3. classify ───────────────────────────────────────────────
            raw        = buggy_results[0]
            ref_stdout = ref.stdout if ref else None
            bug        = oracle.classify(
                raw        = raw,
                input_data = mutated,
                target     = target,
                config     = config,
                ref_stdout = ref_stdout,
            )
            bug.strategy = strategy  # stamp strategy (classify leaves it blank)

            # ── 4. coverage tracking ──────────────────────────────────────
            found_new = coverage_tracker.update(bug, config)

            # ── 5. corpus growth + energy boost ───────────────────────────
            if found_new:
                corpus.append(mutated)
                engine.boost(strategy)
                new_paths += 1

            # AFL-style energy decay — prevents one strategy dominating
            engine.decay()

            # ── 6. log bugs ───────────────────────────────────────────────
            if bug.is_bug():
                bug_logger.log(bug, config)
                total_bugs += 1
                last_bug    = bug
                strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1

            # ── 7. live status redraw ─────────────────────────────────────
            if iteration % DISPLAY_INTERVAL == 0 or iteration == 1:
                elapsed   = time.monotonic() - start
                execs_sec = iteration / elapsed if elapsed > 0 else 0.0
                print_fuzz_status(
                    config          = config,
                    iteration       = iteration,
                    total_bugs      = total_bugs,
                    new_paths       = new_paths,
                    corpus_len      = len(corpus),
                    execs_sec       = execs_sec,
                    elapsed         = elapsed,
                    duration        = duration,
                    max_iters       = max_iters,
                    last_bug        = last_bug,
                    last_report     = refresher.elapsed_since_last(time.monotonic()),
                    strategy_counts = strategy_counts,
                )

    finally:
        # ── shutdown sequence ─────────────────────────────────────────────
        elapsed = time.monotonic() - start

        # Stop refresher → triggers final report generation
        sys.stdout.write(f"\n{C.dim('  stopping report refresher...')}\n")
        sys.stdout.flush()
        refresher.stop()

        print_summary(
            label       = "fuzz",
            n_run       = iteration,
            total_bugs  = total_bugs,
            new_paths   = new_paths,
            corpus_len  = len(corpus),
            elapsed     = elapsed,
            report_path = out_path if out_path.exists() else None,
        )


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def _collect_yamls(explicit: str | None, run_all: bool) -> list[str]:
    if explicit:
        return [explicit]
    found = []
    for name in KNOWN_YAMLS:
        p = TARGETS_DIR / name
        if p.exists():
            found.append(str(p))
        else:
            print(C.dim(f"  [skip] {p} not found"))
    return found


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fuzzer.py",
        description=(
            "Greybox fuzzer — mutation loop (default) or seed pipeline (--seed).\n\n"
            "examples:\n"
            "  python3 fuzzer.py --target targets/json_decoder.yaml\n"
            "  python3 fuzzer.py --target targets/json_decoder.yaml --duration 3600\n"
            "  python3 fuzzer.py --target targets/json_decoder.yaml --iterations 5000\n"
            "  python3 fuzzer.py --all --duration 1800\n"
            "  python3 fuzzer.py --target targets/json_decoder.yaml --seed\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Target selection (mutually exclusive)
    tgt = parser.add_mutually_exclusive_group()
    tgt.add_argument(
        "--target", "-t",
        metavar="YAML",
        help="Path to a single target YAML (e.g. targets/json_decoder.yaml)",
    )
    tgt.add_argument(
        "--all", "-a",
        action="store_true",
        help="Run all known targets in sequence",
    )

    # Mode
    parser.add_argument(
        "--seed",
        action="store_true",
        help="Seed mode: run each seed once with no mutation (sanity check)",
    )

    # Stop conditions (both optional; whichever fires first wins)
    parser.add_argument(
        "--duration", "-d",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Stop after this many seconds (e.g. 3600 for 1 hour)",
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=DEFAULT_ITERS,
        metavar="N",
        help=f"Safety cap on iterations (default: {DEFAULT_ITERS:,})",
    )

    args = parser.parse_args()

    if not args.target and not args.all:
        parser.print_help()
        sys.exit(0)

    yaml_paths = _collect_yamls(args.target, args.all)
    if not yaml_paths:
        print(C.red("  [error] no target YAMLs found"))
        sys.exit(1)

    for yaml_path in yaml_paths:
        try:
            config = load_config(yaml_path)
        except Exception as e:
            print(C.red(f"  [error] failed to load {yaml_path}: {e}"))
            continue

        if args.seed:
            run_seed_mode(config)
        else:
            try:
                run_fuzz_mode(
                    config    = config,
                    duration  = args.duration,
                    max_iters = args.iterations,
                )
            except ImportError as e:
                print(C.red(f"\n  [error] missing module:\n  {e}\n"))
                print(C.dim("  run with --seed to test without all modules present"))
                sys.exit(1)


if __name__ == "__main__":
    main()