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
"""
from __future__ import annotations

import argparse
import random
import signal
import sys
import threading
import time
from pathlib import Path

from engine.types import BugResult, BugType, classify_from_keywords
from engine.mutation_engine import MutationEngine
from engine.bug_oracle import BugOracle
from engine.target_runner import RawResult, load_config, load_seeds, run_both
from engine import coverage_tracker, bug_logger, report_generator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DISPLAY_INTERVAL = 5    # iterations between status redraws
DISPLAY_TIME_INT = 0.5  # seconds between status redraws
REPORT_INTERVAL = 300   # seconds between background report refreshes (5 min)
DEFAULT_DURATION = None # None = no time limit unless --duration given
DEFAULT_ITERS = 100_000 # safety cap when no --iterations given

TARGETS_DIR  = Path(__file__).resolve().parent / "targets"
KNOWN_YAMLS  = [
    "json_decoder.yaml",
    "cidrize.yaml",
    "ipv4_parser.yaml",
    "ipv6_parser.yaml",
]

MAX_CORPUS = 10000

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------
def get_input_type(config: dict) -> str:
    """Resolve the input format string from a config dict."""
    input_block = config.get("input", {})
    input_type = input_block.get("type", "") if isinstance(input_block, dict) else None
    return input_type

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
    def green(s): return f"\033[92m{s}\033[0m"
    @staticmethod
    def yellow(s): return f"\033[93m{s}\033[0m"
    @staticmethod
    def red(s): return f"\033[91m{s}\033[0m"
    @staticmethod
    def cyan(s): return f"\033[96m{s}\033[0m"
    @staticmethod
    def dim(s): return f"\033[2m{s}\033[0m"
    @staticmethod
    def bold(s): return f"\033[1m{s}\033[0m"
    @staticmethod
    def magenta(s): return f"\033[95m{s}\033[0m"
    @staticmethod
    def white(s): return f"\033[97m{s}\033[0m"


# ---------------------------------------------------------------------------
# AFL-style terminal UI
# ---------------------------------------------------------------------------
_W = 72  # display width

def _div(label: str = "") -> str:
    if label:
        inner = f" {label} "
        return f"{C.CYAN}──{inner}{'─' * (_W - len(inner) - 2)}{C.RESET}"
    return C.cyan("─" * _W)

def _kv(key: str, val: str, w: int = 26) -> str:
    return f"  {C.DIM}{key:<{w}}{C.RESET}: {val}"

def _fmt_elapsed(seconds: float) -> str:
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    return f"{h}h {m:02d}m {s:02d}s"

def _fmt_remaining(elapsed: float, duration: float | None) -> str:
    if duration is None:
        return C.dim("∞")
    rem = max(0.0, duration - elapsed)
    return C.yellow(_fmt_elapsed(rem))

def print_banner(config: dict, mode: str, duration: float | None, max_iters: int) -> None:
    target = config.get("name", "unknown")
    input_type = get_input_type(config)
    timeout = config.get("timeout", "?")
    dur_str = f"{duration:.0f}s" if duration else "∞"
    iter_str = f"{max_iters:,}"

    print()
    print(_div())
    print(f"  {C.bold(C.cyan('greybox fuzzer'))}  ·  "
          f"target: {C.green(target)}  ·  mode: {C.yellow(mode)}")
    print(_div())
    if (input_type != None): print(_kv("input format",  C.cyan(input_type)))
    print(_kv("exec timeout", f"{timeout}s per input"))
    print(_kv("stop after", f"{dur_str}  /  {iter_str} iters (whichever first)"))
    print(_kv("detection", config.get("detection_mode", "keyword+crash+diff")))
    print(_kv("coverage", C.green("enabled") if config.get("coverage_enabled") else C.dim("disabled")))
    print(_div())
    print()

# number of lines in the live status block (must match print_fuzz_status exactly)
_STATUS_LINES = 23
_status_drawn = False 

def _afl_time(seconds: float) -> str:
    if seconds is None:
        return "none seen yet"
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{d} days, {h} hrs, {m} min, {s} sec"

def _pad(s: str, w: int) -> str:
    v = str(s)[:w]
    return v + " " * (w - len(v))

def _cp(s: str, w: int, c_fn=None) -> str:
    padded = _pad(s, w)
    return c_fn(padded) if c_fn else padded

def print_fuzz_status(
    config: dict,
    iteration: int,
    total_bugs: int,
    new_paths: int,
    corpus_len: int,
    execs_sec: float,
    elapsed: float,
    duration: float | None,
    max_iters: int,
    last_bug: BugResult | None,
    last_report: float | None,
    strategy_counts: dict[str, int],
) -> None:
    """Overwrite the previous status block in-place."""
    import shutil
    _, rows = shutil.get_terminal_size()
    if rows < _STATUS_LINES + 2:
        pass
    
    # Process timing
    t_run_time    = _afl_time(elapsed)
    t_last_find   = _afl_time(elapsed - last_report) if last_report is not None else "none seen yet"
    t_last_crash  = "recently" if last_bug else "none seen yet"
    t_last_hang   = "none seen yet"
    
    # Overall results
    t_cycles      = "n/a"
    t_corpus      = str(corpus_len)
    t_crashes     = str(total_bugs)
    t_hangs       = "n/a"
    
    # Cycle progress
    t_now_proc    = "n/a"
    t_runs_to     = "n/a"
    t_map_dens    = "n/a"
    t_count_cov   = "n/a"
    
    # Stage progress
    strats = list(strategy_counts.items())
    strats.sort(key=lambda x: x[1], reverse=True)
    t_now_trying  = strats[0][0] if strats else "explore"
    t_stage_execs = "n/a"
    
    if iteration >= 1000:
        t_total_execs = f"{iteration/1000:.1f}k"
    else:
        t_total_execs = str(iteration)
        
    t_exec_speed = f"{execs_sec:.1f}/sec"
    
    # Findings 
    t_fav_items = str(corpus_len)  # the whole corpus is favored basically
    t_new_edges = str(new_paths)
    
    def st_name(i):
        if i < len(strats):
            return f"{strats[i][0]}: {strats[i][1]}"
        return "n/a"
        
    s1, s2, s3, s4, s5, s6, s7 = [st_name(i) for i in range(7)]

    lines = [
        f"┌─ process timing ─────────────────────────────────────┬─ overall results ─────┐",
        f"│        run time : {_cp(t_run_time, 35, C.white)}│  cycles done : {_cp(t_cycles, 7, C.magenta)}│",
        f"│   last new find : {_cp(t_last_find, 35, C.white)}│ corpus count : {_cp(t_corpus, 7, C.cyan)}│",
        f"│last saved crash : {_cp(t_last_crash, 35, C.white)}│saved crashes : {_cp(t_crashes, 7, C.red)}│",
        f"│ last saved hang : {_cp(t_last_hang, 35, C.white)}│  saved hangs : {_cp(t_hangs, 7, C.green)}│",
        f"├─ cycle progress ──────────────────┬─ map coverage ───┴───────────────────────┤",
        f"│  now processing : {_cp(t_now_proc, 16, C.white)}│ map density : {_cp(t_map_dens, 27, C.white)}│",
        f"│  runs timed out : {_cp(t_runs_to, 16, C.white)}│ count coverage : {_cp(t_count_cov, 24, C.white)}│",
        f"├─ stage progress ──────────────────┼─ findings in depth ──────────────────────┤",
        f"│  now trying : {_cp(t_now_trying, 20, C.white)}│ favored items : {_cp(t_fav_items, 25, C.white)}│",
        f"│ stage execs : {_cp(t_stage_execs, 20, C.white)}│  new edges on : {_cp(t_new_edges, 25, C.cyan)}│",
        f"│ total execs : {_cp(t_total_execs, 20, C.white)}│ total crashes : {_cp(t_crashes, 25, C.red)}│",
        f"│  exec speed : {_cp(t_exec_speed, 20, C.green)}│  total tmouts : {_cp('n/a', 25, C.white)}│",
        f"├─ fuzzing strategy yields ─────────┴─────────────┬─ item geometry ────────────┤",
        f"│   strategy 1 : {_cp(s1, 33, C.white)}│       levels : {_cp('n/a', 12, C.white)}│",
        f"│   strategy 2 : {_cp(s2, 33, C.white)}│      pending : {_cp('n/a', 12, C.white)}│",
        f"│   strategy 3 : {_cp(s3, 33, C.white)}│     pend fav : {_cp('n/a', 12, C.white)}│",
        f"│   strategy 4 : {_cp(s4, 33, C.white)}│    own finds : {_cp(t_corpus, 12, C.cyan)}│",
        f"│   strategy 5 : {_cp(s5, 33, C.white)}│     imported : {_cp('n/a', 12, C.white)}│",
        f"│   strategy 6 : {_cp(s6, 33, C.white)}│    stability : {_cp('100.00%', 12, C.white)}│",
        f"│   strategy 7 : {_cp(s7, 33, C.white)}├────────────────────────────┘",
        f"│          --  : {_cp('n/a', 33, C.white)}│          [cpu000: --%]     ",
        f"└─ strategy: {_cp('explore', 14, C.white)}── state: {_cp('in progress', 13, C.green)}┘                             ",
    ]

    assert len(lines) == _STATUS_LINES, \
        f"_STATUS_LINES mismatch: expected {_STATUS_LINES}, got {len(lines)}"

    global _status_drawn
    output = ""
    if _status_drawn:
        output += f"\033[{_STATUS_LINES}A"
    
    output += "\n".join(lines) + "\n"

    sys.stdout.write(output)
    sys.stdout.flush()
    _status_drawn = True

def print_seed_result(
    seed: str,
    bug: BugResult,
    idx: int,
    total: int,
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
    label: str,
    n_run: int,
    total_bugs: int,
    new_paths: int,
    corpus_len: int,
    elapsed: float,
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
        self.targets = targets
        self.out_path = out_path
        self._stop_evt = threading.Event()
        self.last_run : float | None = None
        self._rg = report_generator

    def run(self) -> None:
        # First refresh after a short delay so there's some data to show
        self._stop_evt.wait(timeout=30)
        while not self._stop_evt.is_set():
            self._refresh()
            self._stop_evt.wait(timeout=REPORT_INTERVAL)

    def _refresh(self, final: bool = False) -> None:
        try:
            rg = self._rg
            all_data = rg.load_all(self.targets, use_firestore=final)
            all_coverage = rg.load_all_coverage(self.targets)
            rg.generate_report(all_data, all_coverage, self.targets, self.out_path)
            self.last_run = time.monotonic()
        except Exception as e:
            print(f"\n[report_generator] Report generation failed: {e}")

    def stop(self) -> None:
        self._stop_evt.set()
        self.join(timeout=10)
        self._refresh(final=True)

    def elapsed_since_last(self, now: float) -> float | None:
        if self.last_run is None:
            return None
        return now - self.last_run

# ---------------------------------------------------------------------------
# Inline minimal classifier (seed mode only — no output_parser dependency)
# ---------------------------------------------------------------------------
def _classify_inline(
    buggy_result: RawResult,
    ref: RawResult | None,
    config: dict,
    seed: str,
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
    if buggy_result is None:
        return BugResult(
            bug_type=BugType.ERROR, bug_key="no_result", input_data=seed,
            target=config.get("name", "unknown"), strategy="seed",
        )
    
    import hashlib

    target = config.get("name", "unknown")

    # 1. Timeout — process was killed by the runner
    if buggy_result.timed_out:
        btype = BugType.TIMEOUT

    # 2. Crash — negative return code (segfault, signal, unhandled exception
    #    that caused a non-zero exit WITHOUT a known keyword in output)
    #    We check keywords first before committing to RELIABILITY so that
    #    an explicit "raise ReliabilityBug" (which also exits non-zero) is
    #    classified as RELIABILITY rather than a generic crash.
    elif buggy_result.crashed:
        # Still check for a named exception in stderr — prefer the specific type
        keyword_type = classify_from_keywords(buggy_result.stdout, buggy_result.stderr)
        btype = keyword_type if keyword_type is not None else BugType.RELIABILITY

    # 3. Named exception keyword in output — covers all 6 seeded types + BONUS
    else:
        keyword_type = classify_from_keywords(buggy_result.stdout, buggy_result.stderr)
        if keyword_type is not None:
            btype = keyword_type

        # 4. Differential divergence — ref exists, didn't crash/timeout,
        #    but return code differs (functional divergence without a named bug)
        elif (ref
                and not ref.timed_out
                and not ref.crashed
                and buggy_result.returncode != ref.returncode):
            btype = BugType.DIFF

        # 5. Clean run
        else:
            btype = BugType.NORMAL

    bug_key = hashlib.md5(f"{btype.name}:{seed[:80]}".encode()).hexdigest()[:12]

    return BugResult(
        bug_type = btype,
        bug_key = bug_key,
        input_data = seed,
        target = target,
        strategy = "seed",
        stdout = buggy_result.stdout,
        stderr = buggy_result.stderr,
        returncode = buggy_result.returncode,
        timed_out = buggy_result.timed_out,
        crashed = buggy_result.crashed,
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
        label = "seed mode",
        n_run = len(seeds),
        total_bugs = total_bugs,
        new_paths = None,
        corpus_len = None,
        elapsed = elapsed,
    )
    print(C.dim("  tip: omit --seed to run the full mutation loop"))
    print()


# ---------------------------------------------------------------------------
# Fuzz mode
# ---------------------------------------------------------------------------
def run_fuzz_mode(
    config: dict,
    duration: float | None,
    max_iters: int,
    all_targets: list[str] | None = None,
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

    # Reset draw flag so the first status block of this run prints fresh
    global _status_drawn
    _status_drawn = False

    seeds = load_seeds(config["seeds_path"])
    if not seeds:
        print(C.yellow("  [warn] no seeds found — check seeds_path in YAML"))
        return
    
    # Get the input spec from the config (the 'input:' section of your YAML)
    grammar_spec = config.get("input", {})

    engine = MutationEngine(input_format=get_input_type(config), grammar_spec=grammar_spec)
    oracle = BugOracle()
    corpus = list(seeds)
    target = config.get("name", "unknown")
    out_path = report_generator.RESULTS_DIR / "report.html"

    # ── energy scheduling state ───────────────────────────────
    energy = {s: 1.0 for s in corpus}

    def pick_seed(corpus, energy):
        weights = [energy.get(s, 1.0) for s in corpus]
        return random.choices(corpus, weights=weights, k=1)[0] # weighted random choice based on energy

    # ── seed corpus initialisation ────────────────────────────────────────
    # Augment static seeds.txt with dynamically generated seeds using the
    # grammar defined in config["input"]. seed_count in the YAML controls
    # how many to add (0 = static seeds only).
    # Falls back gracefully if seed_generator is unavailable or input: is absent.
    seed_count = config.get("seed_count", 0)
    if seed_count > 0 and config.get("input"):
        try:
            from engine.seed_generator import generate_from_spec
            input_spec = config["input"]
            generated = []
            for _ in range(seed_count):
                seed = generate_from_spec(input_spec)
                # generate_from_spec may return non-str (e.g. dict, list) — coerce
                if not isinstance(seed, str):
                    seed = str(seed)
                generated.append(seed)
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

   # ── timing state (adaptive timeout) ──────────────────────────────
    CALIBRATION_WINDOW = 50
    RECALIBRATE_EVERY = 200
    TIMEOUT_MULTIPLIER = 3.0
    TIMEOUT_FLOOR = 1.0
    timeout = config.get("timeout", 60)
    exec_time_window = []     # rolling window of recent exec times
    MAX_WINDOW = 100    # keep last 100 timings for rolling average

    # ── reset accumulated coverage file ───────────────────────────────────
    # Ensures the coverage curve always starts from 0% for a clean,
    # meaningful upward trend in the report. Only applies to white-box
    # targets where coverage_enabled: true and a buggy_cwd is set.
    if config.get("coverage_enabled") and config.get("buggy_cwd"):
        cov_file = Path(config["buggy_cwd"]) / ".coverage_buggy_json"
        if cov_file.exists():
            try:
                cov_file.unlink()
                print(C.dim("  reset accumulated coverage data for clean baseline"))
            except Exception as e:
                print(C.yellow(f"  [warn] could not reset coverage file: {e}"))

    print_banner(config, mode="fuzz", duration=duration, max_iters=max_iters)

    # ── background report refresher ───────────────────────────────────────
    # Report on all known targets so the HTML always shows the full picture,
    # not just the target currently being fuzzed.
    report_targets = all_targets if all_targets else [target]
    refresher = ReportRefresher(targets=report_targets, out_path=out_path)
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
                break

            # ── 1. pick seed and mutate ───────────────────────────────────
            seed     = pick_seed(corpus, energy)
            mutated  = engine.mutate(seed)
            strategy = engine.get_last_strategy()

            # ── 2. run target ─────────────────────────────────────────────
            t0 = time.monotonic()
            buggy_result, reference_result = run_both(config, mutated, strategy=strategy, use_coverage=True, timeout=timeout)
            exec_time = time.monotonic() - t0
            exec_time_window.append(exec_time)
            if len(exec_time_window) > MAX_WINDOW:
                exec_time_window.pop(0)

            if (iteration == CALIBRATION_WINDOW or (iteration > CALIBRATION_WINDOW and iteration % RECALIBRATE_EVERY == 0)):
                avg = sum(exec_time_window) / len(exec_time_window)
                new_timeout = max(TIMEOUT_FLOOR, TIMEOUT_MULTIPLIER * avg)
                if abs(new_timeout - config["timeout"]) > 0.5:
                    timeout = round(new_timeout, 1)

            # ── 3. classify ───────────────────────────────────────────────
            ref_stdout = reference_result.stdout if reference_result else None
            bug = oracle.classify(
                raw        = buggy_result,
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
                parent_energy = energy.get(seed, 1.0)
                energy[mutated] = min(10.0, parent_energy * 1.2 + 2.0) # assign high energy to new seed
                energy[seed] = min(10.0, energy.get(seed, 1.0) * 1.5) # reward parent seed
                engine.boost(strategy)
                new_paths += 1
                # limit corpus size
                if len(corpus) > MAX_CORPUS:
                    worst = min(corpus, key=lambda s: energy.get(s, 1.0))
                    corpus.remove(worst)
                    energy.pop(worst, None)
            else:
                energy[seed] = max(0.1, energy.get(seed, 1.0) * 0.95) # decay seed if it didn't find anything

            # AFL-style energy decay — prevents one strategy dominating
            engine.decay()
            
            # global energy decay to prevent domination
            for s in energy:
                energy[s] = max(0.1, energy[s] * 0.999)

            # ── 6. log bugs ───────────────────────────────────────────────
            if bug.is_bug():
                bug_logger.log(bug, config)
                total_bugs += 1
                last_bug    = bug
                strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1

            # ── 7. live status redraw ─────────────────────────────────────
            elapsed = time.monotonic() - start

            if (time.monotonic() - getattr(print_fuzz_status, "last_draw", 0)) > DISPLAY_TIME_INT or iteration == 1:
                execs_sec = iteration / elapsed if elapsed > 0 else 0.0
                print_fuzz_status.last_draw = time.monotonic()
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
        
        # Issue final redraw to ensure 100% accurate final stats
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

    # Resolve all target names upfront so every run's report covers all targets
    all_targets = []
    for yp in yaml_paths:
        try:
            all_targets.append(load_config(yp).get("name", "unknown"))
        except Exception:
            pass

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
                    config      = config,
                    duration    = args.duration,
                    max_iters   = args.iterations,
                    all_targets = all_targets,
                )
            except ImportError as e:
                print(C.red(f"\n  [error] missing module:\n  {e}\n"))
                print(C.dim("  run with --seed to test without all modules present"))
                sys.exit(1)


if __name__ == "__main__":
    main()