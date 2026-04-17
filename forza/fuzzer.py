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
    report_generator.generate()              →  report_<target_name>.html

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
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import random
import signal
import sys
import threading
import time
from pathlib import Path

from engine.types import BugResult
from engine.mutation_engine import MutationEngine
from engine.bug_oracle import BugOracle
from engine.target_runner import load_config, load_seeds, run_both
from engine import coverage_tracker, bug_logger, report_generator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DISPLAY_INTERVAL = 5  # iterations between status redraws
DISPLAY_TIME_INT = 0.5  # seconds between status redraws
REPORT_INTERVAL = 300  # seconds between background report refreshes (5 min)
DEFAULT_DURATION = None  # None = no time limit unless --duration given
DEFAULT_ITERS = 100_000  # safety cap when no --iterations given

TARGETS_DIR = Path(__file__).resolve().parent / "targets"
KNOWN_YAMLS = [f.name for f in TARGETS_DIR.glob("*.yaml")]

MAX_CORPUS = 10000
ENERGY_MIN = 0.1
ENERGY_DECAY_PER_ITER = 0.999
ENERGY_DECAY_INTERVAL = 50
DEFAULT_GENERATED_SEEDS = 30
DEFAULT_PARALLEL_WORKERS = 2
MAX_PARALLEL_WORKERS = 16

# ─────────────────────────────────────────────────────────────────────
# Threading for parallel fuzzing
# ─────────────────────────────────────────────────────────────────────
_corpus_energy_lock = threading.Lock()  # Protects corpus and energy dict updates
_engine_lock = threading.Lock()         # Protects MutationEngine state
_stats_lock = threading.Lock()          # Protects exec_time_window and completed iteration count
_energy_decay_counter = 0

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def get_input_type(config: dict) -> str:
    """Resolve the input format string from a config dict."""
    input_block = config.get("input", {})
    input_type = input_block.get("type", "") if isinstance(input_block, dict) else None
    return input_type


def get_parallel_workers(config: dict) -> int:
    """Resolve outer fuzz-loop worker count from target config."""
    raw_workers = config.get("parallel_workers", DEFAULT_PARALLEL_WORKERS)
    try:
        workers = int(raw_workers)
    except (TypeError, ValueError):
        workers = DEFAULT_PARALLEL_WORKERS
    return max(1, min(MAX_PARALLEL_WORKERS, workers))


def _config_bool(config: dict, key: str, default: bool = False) -> bool:
    raw = config.get(key, default)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _load_static_seeds(config: dict) -> list[str]:
    seeds_path = config.get("seeds_path")
    if not seeds_path:
        return []
    return load_seeds(str(seeds_path))


def _generate_grammar_seeds(config: dict, count: int) -> list[str]:
    if count <= 0:
        return []

    input_spec = config.get("input")
    if not input_spec:
        return []

    try:
        from engine.seed_generator import generate_from_spec
    except Exception as e:
        print(f"[warn] seed_generator unavailable: {e}")
        return []

    generated: list[str] = []
    for _ in range(count):
        try:
            seed = generate_from_spec(input_spec)
        except Exception as e:
            print(f"[warn] seed_generator failed: {e}")
            break

        if not isinstance(seed, str):
            seed = str(seed)
        if seed:
            generated.append(seed)

    return generated


def _maybe_apply_plateau_escalation(config: dict, engine: MutationEngine) -> None:
    """Increase aggressive strategy weights when coverage has plateaued."""
    if not _config_bool(config, "plateau_escalation_enabled", default=False):
        return

    tracker = coverage_tracker.get_tracker()
    if tracker is None or not tracker.is_plateau:
        return

    try:
        cooldown = int(config.get("plateau_escalation_cooldown", 100))
    except (TypeError, ValueError):
        cooldown = 100
    cooldown = max(1, cooldown)

    try:
        current_inputs = int(getattr(tracker, "total_inputs", 0))
    except (TypeError, ValueError):
        current_inputs = 0

    try:
        last_boost_at = int(config.get("_last_plateau_boost_input", -10**9))
    except (TypeError, ValueError):
        last_boost_at = -10**9

    if current_inputs - last_boost_at < cooldown:
        return

    try:
        constraint_factor = float(config.get("plateau_constraint_boost", 1.35))
    except (TypeError, ValueError):
        constraint_factor = 1.35
    try:
        grammar_factor = float(config.get("plateau_grammar_boost", 1.2))
    except (TypeError, ValueError):
        grammar_factor = 1.2
    try:
        dictionary_factor = float(config.get("plateau_dictionary_boost", 1.15))
    except (TypeError, ValueError):
        dictionary_factor = 1.15

    engine.boost("constraint_violation", factor=max(1.0, constraint_factor))
    engine.boost("grammar_mutate", factor=max(1.0, grammar_factor))
    engine.boost("insert_dictionary_token", factor=max(1.0, dictionary_factor))
    config["_last_plateau_boost_input"] = current_inputs


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"

    @staticmethod
    def green(s):
        return f"\033[92m{s}\033[0m"

    @staticmethod
    def yellow(s):
        return f"\033[93m{s}\033[0m"

    @staticmethod
    def red(s):
        return f"\033[91m{s}\033[0m"

    @staticmethod
    def cyan(s):
        return f"\033[96m{s}\033[0m"

    @staticmethod
    def dim(s):
        return f"\033[2m{s}\033[0m"

    @staticmethod
    def bold(s):
        return f"\033[1m{s}\033[0m"

    @staticmethod
    def magenta(s):
        return f"\033[95m{s}\033[0m"

    @staticmethod
    def white(s):
        return f"\033[97m{s}\033[0m"


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


def print_banner(
    config: dict, mode: str, duration: float | None, max_iters: int
) -> None:
    target = config.get("name", "unknown")
    input_type = get_input_type(config)
    dur_str = f"{duration:.0f}s" if duration else "∞"
    iter_str = f"{max_iters:,}"

    # Label: whitebox targets with coverage_enabled → "greybox fuzzer",
    # blackbox behavioral targets → "blackbox fuzzer"
    tracking_mode = str(config.get("tracking_mode", "behavioral")).strip().lower()
    if config.get("coverage_enabled") or tracking_mode == "code_execution":
        fuzzer_label = "greybox fuzzer"
    else:
        fuzzer_label = "blackbox fuzzer"

    print()
    print(_div())
    print(
        f"  {C.bold(C.cyan(fuzzer_label))}  ·  "
        f"target: {C.green(target)}  ·  mode: {C.yellow(mode)}"
    )
    print(_div())
    if input_type != None:
        print(_kv("input format", C.cyan(input_type)))
    print(_kv("stop after", f"{dur_str}  /  {iter_str} iters (whichever first)"))
    print(
        _kv(
            "coverage",
            C.green("enabled") if config.get("coverage_enabled") else C.dim("disabled"),
        )
    )
    print(_div())
    print()

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

_STATUS_LINES = 23
_status_drawn = False
stdout_lock = threading.Lock()

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
    t_run_time = _afl_time(elapsed)
    t_last_find = (
        _afl_time(elapsed - last_report) if last_report is not None else "none seen yet"
    )
    t_last_crash = "recently" if last_bug else "none seen yet"
    t_last_hang = "none seen yet"

    # Overall results
    t_cycles = "n/a"
    t_corpus = str(corpus_len)
    t_crashes = str(total_bugs)
    _lg = bug_logger._logger
    t_unique = str(_lg.unique_bugs) if _lg else "0"

    # Cycle progress
    t_now_proc = "n/a"
    t_runs_to = "n/a"

    from engine.coverage_tracker import get_tracker

    _trk = get_tracker()
    tracking_mode = str(config.get("tracking_mode", "behavioral")).strip().lower()
    if _trk:
        t_map_dens = _trk.map_density
        # Count coverage only makes sense for code_execution mode (edge-frequency
        # data from instrumented targets).  In behavioral mode there are no
        # per-edge hit counts, so show n/a instead of a misleading "1.00 bits/tuple".
        if tracking_mode == "behavioral" and not config.get("coverage_enabled"):
            t_count_cov = "n/a"
        else:
            t_count_cov = _trk.count_coverage_bits
        # Item geometry — real values from tracker
        t_levels = str(_trk.levels)
        t_pending = str(_trk.pending)
        t_pend_fav = str(_trk.pend_fav)
        t_own_finds = str(_trk.own_finds)
        t_imported = str(_trk.imported)
        t_stability = _trk.stability_str
    else:
        t_map_dens = "n/a"
        t_count_cov = "n/a"
        t_levels = "n/a"
        t_pending = "n/a"
        t_pend_fav = "n/a"
        t_own_finds = "n/a"
        t_imported = "n/a"
        t_stability = "n/a"

    # Stage progress
    strats = list(strategy_counts.items())
    strats.sort(key=lambda x: x[1], reverse=True)
    t_now_trying = strats[0][0] if strats else "explore"
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
        f"│last saved crash : {_cp(t_last_crash, 35, C.white)}│saved crashes : {_cp(t_unique, 7, C.red)}│",
        f"│  last saved hang : {_cp(t_last_hang, 34, C.white)}│ unique bugs  : {_cp(t_unique, 7, C.yellow)}│",
        f"├─ cycle progress ──────────────────┬─ map coverage ───┴───────────────────────┤",
        f"│  now processing : {_cp(t_now_proc, 16, C.white)}│ map density : {_cp(t_map_dens, 27, C.white)}│", 
        f"│  runs timed out : {_cp(t_runs_to, 16, C.white)}│ count coverage : {_cp(t_count_cov, 24, C.white)}│", 
        f"├─ stage progress ──────────────────┼─ findings in depth ──────────────────────┤",
        f"│  now trying : {_cp(t_now_trying, 20, C.white)}│ favored items : {_cp(t_fav_items, 25, C.white)}│",
        f"│ stage execs : {_cp(t_stage_execs, 20, C.white)}│  new edges on : {_cp(t_new_edges, 25, C.cyan)}│",
        f"│ total execs : {_cp(t_total_execs, 20, C.white)}│ total crashes : {_cp(t_crashes, 25, C.red)}│",
        f"│  exec speed : {_cp(t_exec_speed, 20, C.green)}│  total tmouts : {_cp('n/a', 25, C.white)}│",
        f"├─ fuzzing strategy yields ─────────┴─────────────┬─ item geometry ────────────┤",
        f"│   strategy 1 : {_cp(s1, 33, C.white)}│       levels : {_cp(t_levels, 12, C.white)}│",
        f"│   strategy 2 : {_cp(s2, 33, C.white)}│      pending : {_cp(t_pending, 12, C.white)}│",
        f"│   strategy 3 : {_cp(s3, 33, C.white)}│     pend fav : {_cp(t_pend_fav, 12, C.white)}│",
        f"│   strategy 4 : {_cp(s4, 33, C.white)}│    own finds : {_cp(t_own_finds, 12, C.cyan)}│",
        f"│   strategy 5 : {_cp(s5, 33, C.white)}│     imported : {_cp(t_imported, 12, C.white)}│",
        f"│   strategy 6 : {_cp(s6, 33, C.white)}│    stability : {_cp(t_stability, 12, C.white)}│",
        f"│   strategy 7 : {_cp(s7, 33, C.white)}├────────────────────────────┘",
        f"│          --  : {_cp('n/a', 33, C.white)}│          [cpu000: --%]     ",
        f"└─ strategy: {_cp('explore', 14, C.white)}── state: {_cp('in progress', 13, C.green)}┘                             ",
    ]

    assert (
        len(lines) == _STATUS_LINES
    ), f"_STATUS_LINES mismatch: expected {_STATUS_LINES}, got {len(lines)}"

    global _status_drawn
    prefix = f"\033[{_STATUS_LINES}A\r" if _status_drawn else ""

    final_output = f"\033[?25l{prefix}" + "\n".join(lines) + "\n\033[?25h"

    with stdout_lock:
        sys.stdout.write(final_output)
        sys.stdout.flush()

    _status_drawn = True


def print_seed_result(
    seed: str,
    bug: BugResult,
    idx: int,
    total: int,
) -> None:
    tag = bug.bug_type.name if bug.is_bug() else C.dim("no bug")

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
    print(_kv("inputs run", C.white(f"{n_run:,}")))
    print(_kv("total bugs", C.red(str(total_bugs)) if total_bugs else C.green("0")))
    if new_paths is not None:
        print(_kv("new paths", C.cyan(str(new_paths))))
        print(_kv("corpus size", C.white(str(corpus_len))))
    print(_kv("elapsed", _fmt_elapsed(elapsed)))
    if report_path:
        print(_kv("report", C.green(str(report_path))))
    print(_div())
    print()


# ---------------------------------------------------------------------------
# Background report refresh thread
# ---------------------------------------------------------------------------


class ReportRefresher(threading.Thread):
    """
    Daemon thread that regenerates the configured report path every REPORT_INTERVAL seconds.
    Keeps the report warm during long fuzz runs so Ctrl+C exit is fast.
    """

    def __init__(self, targets: list[str], out_path: Path) -> None:
        super().__init__(daemon=True)
        self.targets = targets
        self.out_path = out_path
        self._stop_evt = threading.Event()
        self.last_run: float | None = None
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
            run_ids = rg.resolve_latest_run_ids(self.targets)
            all_data = rg.load_all(self.targets, use_firestore=final, run_ids=run_ids)
            all_coverage = rg.load_all_coverage(self.targets, run_ids=run_ids)
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
# Seed mode
# ---------------------------------------------------------------------------


def run_seed_mode(config: dict) -> None:
    """
    Run every seed through the full pipeline once (no mutation).
    Uses inline classifier — does not require output_parser.py.
    Useful for sanity-checking a new target config.
    """
    seeds = _load_static_seeds(config)
    if not seeds:
        seeds = _generate_grammar_seeds(config, DEFAULT_GENERATED_SEEDS)
    seeds = _dedupe_preserve_order(seeds)

    if not seeds:
        print(
            C.yellow(
                "  [warn] no seeds available — set seeds_path or provide input grammar"
            )
        )
        return

    print_banner(config, mode="seed", duration=None, max_iters=len(seeds))
    print(
        f"  {C.dim('running')} {C.bold(str(len(seeds)))} "
        f"{C.dim('seeds through pipeline...')}"
    )
    print()

    total_bugs = 0
    start = time.monotonic()

    oracle = BugOracle()
    target = config.get("name", "unknown")

    for idx, seed in enumerate(seeds, 1):
        buggy_result, ref, _ = run_both(config, seed, strategy="seed")
        bug = oracle.classify(buggy_result, seed, target, config, ref)
        if bug.is_bug():
            total_bugs += 1
        print_seed_result(seed, bug, idx, len(seeds))

    elapsed = time.monotonic() - start
    print_summary(
        label="seed mode",
        n_run=len(seeds),
        total_bugs=total_bugs,
        new_paths=None,
        corpus_len=None,
        elapsed=elapsed,
    )
    print(C.dim("  tip: omit --seed to run the full mutation loop"))
    print()


# ---------------------------------------------------------------------------
# Fuzz mode
# ---------------------------------------------------------------------------
def _fuzz_one_iteration(
    config: dict,
    oracle: BugOracle,
    corpus: list[tuple[str, int]],
    energy: dict,
    engine: MutationEngine,
    timeout: int,
) -> tuple[BugResult, bool, int, float, float]:
    """
    Execute one fuzzing iteration: pick seed, mutate, run, classify, update coverage.
    
    Returns: (bug_result, found_new, child_depth, run_time_s, generation_time_s)
    
    Thread-safe: only acquires lock for corpus/energy reads and updates + engine operations.
    """
    global _corpus_energy_lock, _engine_lock, _energy_decay_counter
    
    # ── 1. pick seed and mutate (needs lock for corpus/energy and engine)
    with _corpus_energy_lock:
        weights = [energy.get(s[0], 1.0) for s in corpus]
        corpus_idx = random.choices(range(len(corpus)), weights=weights, k=1)[0]
        seed, seed_depth = corpus[corpus_idx]
    
    with _engine_lock:
        gen_t0 = time.monotonic()
        mutated = engine.mutate(seed)
        generation_time = time.monotonic() - gen_t0
        strategy = engine.get_last_strategy()
    
    child_depth = seed_depth + 1

    # ── 2. run target (I/O bound, no lock needed)
    t0 = time.monotonic()
    buggy_result, reference_result, instrumentation_coverage_text = run_both(
        config, mutated, strategy=strategy, use_coverage=True, timeout=timeout
    )
    run_time = time.monotonic() - t0

    # ── 3. classify (no lock needed)
    bug = oracle.classify(
        raw=buggy_result,
        input_data=mutated,
        target=config.get("name", "unknown"),
        config=config,
        ref=reference_result,
    )
    bug.strategy = strategy
    bug.exec_time_ms = run_time * 1000.0

    # ── 4. coverage tracking (has internal lock)
    found_new = coverage_tracker.update(
        bug,
        config,
        input_depth=child_depth,
        reference_result=reference_result,
        instrumentation_coverage_text=instrumentation_coverage_text,
    )
    
    # ── 5. corpus growth + energy boost (needs lock)
    if found_new:
        with _corpus_energy_lock:
            corpus.append((mutated, child_depth))
            parent_energy = energy.get(seed, 1.0)
            energy[mutated] = min(10.0, parent_energy * 1.2 + 2.0)
            energy[seed] = min(10.0, energy.get(seed, 1.0) * 1.5)
            # limit corpus size
            if len(corpus) > MAX_CORPUS:
                worst_idx = min(
                    range(len(corpus)), key=lambda i: energy.get(corpus[i][0], 1.0)
                )
                removed_str, _ = corpus.pop(worst_idx)
                energy.pop(removed_str, None)
        
        with _engine_lock:
            engine.boost(strategy)
    else:
        with _corpus_energy_lock:
            energy[seed] = max(ENERGY_MIN, energy.get(seed, 1.0) * 0.95)

    # AFL-style energy decay
    with _engine_lock:
        _maybe_apply_plateau_escalation(config, engine)
        engine.decay()
    
    with _corpus_energy_lock:
        _energy_decay_counter += 1
        if _energy_decay_counter % ENERGY_DECAY_INTERVAL == 0:
            decay_factor = ENERGY_DECAY_PER_ITER ** ENERGY_DECAY_INTERVAL
            for s in list(energy.keys()):
                energy[s] = max(ENERGY_MIN, energy[s] * decay_factor)

    # ── 6. log run (has internal lock)
    with _corpus_energy_lock:
        corpus_size = len(corpus)
    bug_logger.log(
        bug,
        config,
        corpus_size=corpus_size,
        generation_time_ms=generation_time * 1000.0,
        execution_time_ms=run_time * 1000.0,
        is_new_coverage=found_new,
    )

    return (bug, found_new, child_depth, run_time, generation_time)

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
        ReportRefresher regenerates report_<target_name>.html every REPORT_INTERVAL seconds
        in a daemon thread. Final refresh happens on shutdown.
    """

    # Reset draw flag so the first status block of this run prints fresh
    global _status_drawn
    _status_drawn = False

    seeds = _load_static_seeds(config)
    if not seeds and config.get("seeds_path"):
        print(C.yellow("  [warn] seeds_path provided but no seeds found — using grammar generation"))

    # Get the input spec from the config (the 'input:' section of YAML)
    grammar_spec = config.get("input", {})

    engine = MutationEngine(
        input_format=get_input_type(config),
        grammar_spec=grammar_spec,
        mutation_dictionary=config.get("mutation_dictionary"),
        enabled_strategies=config.get("enabled_strategies"),
        disabled_strategies=config.get("disabled_strategies"),
    )
    oracle = BugOracle()
    # Corpus stores (input_str, depth) tuples; seeds start at depth 1
    corpus: list[tuple[str, int]] = [(s, 1) for s in seeds]
    target = config.get("name", "unknown")
    out_path = report_generator.RESULTS_DIR / f"report_{target}.html"

    # Track which corpus indices have been used as mutation parents
    used_as_parent: set[int] = set()

    # ── energy scheduling state ───────────────────────────────
    energy = {s[0]: 1.0 for s in corpus}

    global _energy_decay_counter
    _energy_decay_counter = 0

    def pick_seed(corpus, energy):
        # We extract the string (s[0]) from the (str, depth) tuple for the energy lookup
        weights = [energy.get(s[0], 1.0) for s in corpus]
        return random.choices(range(len(corpus)), weights=weights, k=1)[0]

    # ── seed corpus initialisation ────────────────────────────────────────
    # Augment static seeds with grammar-generated seeds up to DEFAULT_GENERATED_SEEDS.
    generated = _generate_grammar_seeds(config, max(0, DEFAULT_GENERATED_SEEDS - len(seeds)))
    if generated:
        for g in generated:
            corpus.append((g, 1))
            energy[g] = 1.0

    deduped_corpus: list[tuple[str, int]] = []
    seen_seed_values: set[str] = set()
    for seed_value, depth in corpus:
        if seed_value in seen_seed_values:
            continue
        seen_seed_values.add(seed_value)
        deduped_corpus.append((seed_value, depth))
    corpus = deduped_corpus
    energy = {seed_value: energy.get(seed_value, 1.0) for seed_value, _ in corpus}

    if not corpus:
        print(
            C.yellow(
                "  [warn] no seeds available — set seeds_path or provide input grammar"
            )
        )
        return

    # Reset per-target state in module-level wrappers
    bug_logger.reset()
    coverage_tracker.reset()

    # ── timing state (adaptive timeout) ──────────────────────────────
    CALIBRATION_WINDOW = 50
    RECALIBRATE_EVERY = 200
    TIMEOUT_MULTIPLIER = 3.0
    TIMEOUT_FLOOR = 1.0
    timeout = 60
    exec_time_window = []  # rolling window of recent exec times
    MAX_WINDOW = 100  # keep last 100 timings for rolling average

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
    total_bugs = 0
    new_paths = 0
    last_bug: BugResult | None = None
    strategy_counts: dict[str, int] = {}
    start = time.monotonic()
    iteration = 0

    try:
        # ── parallel fuzzing with configurable worker threads ────────────
        exec_time_window = []
        completed_iterations = 0  # Tracks actual completed work for calibration
        MAX_WINDOW = 100
        parallel_workers = get_parallel_workers(config)
        
        with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
            futures = {}
            next_iter = 1
            pending_futures = set()
            
            def submit_next():
                """Submit the next iteration to the thread pool."""
                nonlocal next_iter
                if next_iter <= max_iters and not _shutdown.is_set():
                    future = executor.submit(
                        _fuzz_one_iteration,
                        config, oracle, corpus, energy, engine, timeout
                    )
                    futures[future] = next_iter
                    pending_futures.add(future)
                    next_iter += 1
            
            # ── prime the pump: submit first 2 iterations ───────────────
            submit_next()
            submit_next()
            
            # ── main collection loop ────────────────────────────────────
            while pending_futures and not _shutdown.is_set():
                # Check stop conditions
                elapsed = time.monotonic() - start
                if duration is not None and elapsed >= duration:
                    break
                
                # Collect results as they complete
                done_set, pending_futures = wait(
                    pending_futures, timeout=DISPLAY_TIME_INT, return_when=FIRST_COMPLETED
                )
                
                for future in done_set:
                    iteration = futures[future]
                    try:
                        bug, found_new, child_depth, run_time, _generation_time = future.result()
                        
                        # ── Update stats with lock ────────────────────────────────────
                        with _stats_lock:
                            completed_iterations += 1
                            exec_time_window.append(run_time)
                            if len(exec_time_window) > MAX_WINDOW:
                                exec_time_window.pop(0)
                        
                        # ── Log aggregated results ────────────────────────────────────
                        if found_new:
                            new_paths += 1
                        if bug.is_bug():
                            total_bugs += 1
                            last_bug = bug
                            strategy_counts[bug.strategy] = strategy_counts.get(bug.strategy, 0) + 1

                        # Use the logger's deduplicated count for the UI
                        # instead of raw total_bugs to avoid inflated numbers.
                        _lg = bug_logger._logger
                        if _lg:
                            unique_bug_count = _lg.unique_bugs
                        else:
                            unique_bug_count = 0
                        
                        # ── Calibrate timeout based on completed iterations ───────────
                        with _stats_lock:
                            if completed_iterations == CALIBRATION_WINDOW or (
                                completed_iterations > CALIBRATION_WINDOW 
                                and completed_iterations % RECALIBRATE_EVERY == 0
                            ):
                                if exec_time_window:
                                    avg = sum(exec_time_window) / len(exec_time_window)
                                    new_timeout = max(TIMEOUT_FLOOR, TIMEOUT_MULTIPLIER * avg)
                                    if abs(new_timeout - timeout) > 0.5:
                                        timeout = round(new_timeout, 1)
                        
                    except Exception as e:
                        print(C.red(f"  [error] iteration {iteration} failed: {e}"))
                    finally:
                        del futures[future]
                    
                    # Submit next iteration
                    submit_next()
                
                # ── live status redraw ─────────────────────────────────────
                elapsed = time.monotonic() - start
                if (
                    time.monotonic() - getattr(print_fuzz_status, "last_draw", 0)
                ) > DISPLAY_TIME_INT or next_iter == 2:
                    with _stats_lock:
                        current_completed = completed_iterations
                    execs_sec = current_completed / elapsed if elapsed > 0 else 0.0
                    print_fuzz_status.last_draw = time.monotonic()
                    print_fuzz_status(
                        config=config,
                        iteration=current_completed,
                        total_bugs=total_bugs,
                        new_paths=new_paths,
                        corpus_len=len(corpus),
                        execs_sec=execs_sec,
                        elapsed=elapsed,
                        duration=duration,
                        max_iters=max_iters,
                        last_bug=last_bug,
                        last_report=refresher.elapsed_since_last(time.monotonic()),
                        strategy_counts=strategy_counts,
                    )

    finally:
        # ── shutdown sequence ─────────────────────────────────────────────
        elapsed = time.monotonic() - start

        # Issue final redraw to ensure 100% accurate final stats
        with _stats_lock:
            current_completed = completed_iterations
        execs_sec = current_completed / elapsed if elapsed > 0 else 0.0
        print_fuzz_status(
            config=config,
            iteration=current_completed,
            total_bugs=total_bugs,
            new_paths=new_paths,
            corpus_len=len(corpus),
            execs_sec=execs_sec,
            elapsed=elapsed,
            duration=duration,
            max_iters=max_iters,
            last_bug=last_bug,
            last_report=refresher.elapsed_since_last(time.monotonic()),
            strategy_counts=strategy_counts,
        )

        # Stop refresher → triggers final report generation
        sys.stdout.write(f"\n{C.dim('  stopping report refresher...')}\n")
        sys.stdout.flush()
        refresher.stop()

        print_summary(
            label="fuzz",
            n_run=current_completed,
            total_bugs=total_bugs,
            new_paths=new_paths,
            corpus_len=len(corpus),
            elapsed=elapsed,
            report_path=out_path if out_path.exists() else None,
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
        "--target",
        "-t",
        metavar="YAML",
        help="Path to a single target YAML (e.g. targets/json_decoder.yaml)",
    )
    tgt.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Run all known targets in sequence",
    )

    # Mode
    parser.add_argument(
        "--seed",
        action="store_true",
        help="Seed mode: run each seed once with no mutation (sanity check)",
    )

    # Stop conditions
    parser.add_argument(
        "--duration",
        "-d",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Stop after this many seconds (e.g. 3600 for 1 hour)",
    )
    parser.add_argument(
        "--iterations",
        "-n",
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
                    config=config,
                    duration=args.duration,
                    max_iters=args.iterations,
                    all_targets=all_targets,
                )
            except ImportError as e:
                print(C.red(f"\n  [error] missing module:\n  {e}\n"))
                print(C.dim("  run with --seed to test without all modules present"))
                sys.exit(1)


if __name__ == "__main__":
    main()