"""
The orchestrator that wires everything together into the main fuzzing loop.

Fuzz mode (default):
    python3 fuzzer.py --target targets/json_decoder.yaml
    python3 fuzzer.py --target targets/json_decoder.yaml --duration 3600
    python3 fuzzer.py --target targets/json_decoder.yaml --iterations 5000
    python3 fuzzer.py --target targets/json_decoder.yaml --duration 3600 --iterations 50000
    python3 fuzzer.py --all --duration 1800

Seed mode (--seed):
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
import engine.seed_generator as seed_generator

from engine.types import BugResult
from engine.mutation_engine import MutationEngine
from engine.bug_oracle import BugOracle
from engine.target_runner import load_config, load_seeds, run_both, cleanup_coverage_files
from engine import coverage_tracker, bug_logger, report_generator

DISPLAY_INTERVAL = 5  # iterations between status redraws
DISPLAY_TIME_INT = 0.5  # seconds between status redraws
REPORT_INTERVAL = 300
DEFAULT_DURATION = None
DEFAULT_ITERS = 100_000

TARGETS_DIR = Path(__file__).resolve().parent / "targets"
KNOWN_YAMLS = [f.name for f in sorted(TARGETS_DIR.glob("*.yaml"))]

MAX_CORPUS = 10000

_corpus_energy_lock = threading.Lock()
_engine_lock = threading.Lock()
_stats_lock = threading.Lock()


def get_input_type(config: dict) -> str:
    """Resolve the input format string from a config dict."""
    input_block = config.get("input", {})
    input_type = input_block.get("type", "") if isinstance(input_block, dict) else None
    return input_type


# colours
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


# terminal ui
DISPLAY_WIDTH = 72


def _div(label: str = "") -> str:
    if label:
        inner = f" {label} "
        return f"{C.CYAN}──{inner}{'─' * (DISPLAY_WIDTH - len(inner) - 2)}{C.RESET}"
    return C.cyan("─" * DISPLAY_WIDTH)


def _kv(key: str, val: str, w: int = 26) -> str:
    return f"  {C.DIM}{key:<{w}}{C.RESET}: {val}"


def _fmt_elapsed(seconds: float) -> str:
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    return f"{h}h {m:02d}m {s:02d}s"


def print_banner(
    config: dict, mode: str, duration: float | None, max_iters: int
) -> None:
    target = config.get("name", "unknown")
    input_type = get_input_type(config)
    dur_str = f"{duration:.0f}s" if duration else "∞"
    iter_str = f"{max_iters:,}"

    tracking_mode = str(config.get("tracking_mode", "behavioral")).strip().lower()
    if config.get("coverage_enabled") and tracking_mode == "code_execution":
        fuzzer_label = "whitebox fuzzer"
    elif tracking_mode == "code_execution":
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
_status_reserved = False
stdout_lock = threading.Lock()


def _reserve_status_block() -> None:
    global _status_reserved
    sys.stdout.write("\n" * _STATUS_LINES)
    sys.stdout.flush()
    _status_reserved = True


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
    import shutil

    _, rows = shutil.get_terminal_size()
    if rows < _STATUS_LINES + 2:
        pass

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

    strats = list(strategy_counts.items())
    strats.sort(key=lambda x: x[1], reverse=True)
    t_now_trying = strats[0][0] if strats else "explore"
    t_stage_execs = "n/a"

    if iteration >= 1000:
        t_total_execs = f"{iteration/1000:.1f}k"
    else:
        t_total_execs = str(iteration)

    t_exec_speed = f"{execs_sec:.1f}/sec"

    t_fav_items = str(corpus_len)
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

    final_output = (
        f"\033[?25l\033[{_STATUS_LINES}A\r" + "\n".join(lines) + "\n\033[?25h"
    )

    with stdout_lock:
        sys.stdout.write(final_output)
        sys.stdout.flush()


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


# html report
class ReportRefresher(threading.Thread):
    """
    Daemon thread that regenerates report.html every REPORT_INTERVAL seconds.
    """

    def __init__(self, targets: list[str], out_path: Path) -> None:
        super().__init__(daemon=True)
        self.targets = targets
        self.out_path = out_path
        self._stop_evt = threading.Event()
        self.last_run: float | None = None
        self._rg = report_generator

    def run(self) -> None:
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


# modes
def run_seed_mode(config: dict) -> None:
    seeds = load_seeds(config["seeds_path"])
    if not seeds:
        print(C.yellow("  [warn] no seeds found — check seeds_path in YAML"))
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

    for idx, seed in enumerate(seeds, 1):
        buggy_result, ref = run_both(
            config=config, 
            seed=seed, 
            use_coverage=False,
            strategy="seed")
        bug = oracle.classify(buggy_result, seed, config, ref)
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


def _fuzz_one_iteration(
    config: dict,
    oracle: BugOracle,
    corpus: list[tuple[str, int]],
    energy: dict,
    engine: MutationEngine,
    timeout: int,
) -> tuple[BugResult, bool, int, float]:
    global _corpus_energy_lock, _engine_lock

    # 1. pick seed
    with _corpus_energy_lock:
        weights = [energy.get(s[0], 1.0) for s in corpus]
        corpus_idx = random.choices(range(len(corpus)), weights=weights, k=1)[0]
        seed, seed_depth = corpus[corpus_idx]

    # 2. mutation_engine
    with _engine_lock:
        mutated = engine.mutate(seed)
        strategy = engine.get_last_strategy()

    child_depth = seed_depth + 1

    # 3. target_runner
    t0 = time.monotonic()
    buggy_result, reference_result = run_both(
        config=config,
        input_str=mutated,
        use_coverage=True,
        strategy=strategy,
        timeout=timeout,
    )
    exec_time = time.monotonic() - t0

    # 4. bug_oracle
    bug = oracle.classify(
        raw=buggy_result,
        input_data=mutated,
        config=config,
        ref=reference_result,
    )
    bug.strategy = strategy

    # 5. coverage_tracker
    found_new = coverage_tracker.update(
        bug, config, input_depth=child_depth, reference_result=reference_result
    )

    # 6. corpus and energy scheduling updates
    if found_new:
        with _corpus_energy_lock:
            corpus.append((mutated, child_depth))
            parent_energy = energy.get(seed, 1.0)
            energy[mutated] = min(10.0, parent_energy * 1.2 + 2.0)
            energy[seed] = min(10.0, energy.get(seed, 1.0) * 1.5)
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
            energy[seed] = max(0.1, energy.get(seed, 1.0) * 0.95)

    with _engine_lock:
        engine.decay()

    with _corpus_energy_lock:
        for s in energy:
            energy[s] = max(0.1, energy[s] * 0.999)

    # 7. bug_logger
    if bug.is_bug():
        bug_logger.log(bug, config)

    return (bug, found_new, child_depth, exec_time)


def run_fuzz_mode(
    config: dict,
    duration: float | None,
    max_iters: int,
    all_targets: list[str] | None = None,
) -> None:
    seeds = load_seeds(config["seeds_path"])
    if not seeds:
        print(C.yellow("  [warn] no seeds found — check seeds_path in YAML"))
        return

    if not config.get("input"):
        print(
            C.yellow("  [warn] no input spec found in config — using static seeds only")
        )
    engine = MutationEngine(
        input_format=get_input_type(config), grammar_spec=config.get("input", {})
    )
    oracle = BugOracle()
    corpus: list[tuple[str, int]] = [(s, 1) for s in seeds]  # (seed, depth) pairs
    target = config.get("name")
    out_path = report_generator.RESULTS_DIR / f"{target}_report.html"

    energy = {s: 1.0 for s in corpus}

    if config.get("input"):
        try:
            any_spec = config.get("any", {})
            if any_spec:
                seed_generator.ANY_OPTIONS = any_spec.get("options", [])
                seed_generator.ANY_MAX_DEPTH = any_spec.get("max_depth", 3)

            input_spec = config.get("input")
            generated = []
            for _ in range(30 - len(seeds)):
                seed = seed_generator.generate_from_spec(input_spec)
                if not isinstance(seed, str):
                    seed = str(seed)
                generated.append(seed)
            for g in generated:
                corpus.append((g, 1))
                energy[g] = 1.0
        except Exception as e:
            print(
                C.yellow(
                    f"  [warn] seed_generator failed: {e} — using static seeds only"
                )
            )

    # Reset per-target state in module-level wrappers
    bug_logger.reset()
    coverage_tracker.reset()

    # adaptive timeout
    CALIBRATION_WINDOW = 50
    RECALIBRATE_EVERY = 200
    TIMEOUT_MULTIPLIER = 3.0
    TIMEOUT_FLOOR = 1.0
    timeout = 60
    exec_time_window = []
    MAX_WINDOW = 100

    # reset json target coverage file
    if config.get("coverage_enabled") and config.get("buggy_cwd"):
        cov_file = Path(config["buggy_cwd"]) / ".coverage_buggy_json"
        if cov_file.exists():
            try:
                cov_file.unlink()
            except Exception as e:
                print(C.yellow(f"  [warn] could not reset coverage file: {e}"))

    print_banner(config, mode="fuzz", duration=duration, max_iters=max_iters)
    _reserve_status_block()

    report_targets = all_targets if all_targets else [target]
    refresher = ReportRefresher(targets=report_targets, out_path=out_path)
    refresher.start()

    # force shut down
    _shutdown = threading.Event()

    def _handle_sigint(sig, frame):
        if not _shutdown.is_set():
            _shutdown.set()
            sys.stdout.write(
                f"\n{C.yellow('  [!] Ctrl+C received — finishing iteration, then shutting down...')}\n\n"
            )
            sys.stdout.flush()

    signal.signal(signal.SIGINT, _handle_sigint)

    # loop state
    total_bugs = 0
    new_paths = 0
    last_bug: BugResult | None = None
    strategy_counts: dict[str, int] = {}
    start = time.monotonic()
    iteration = 0

    try:
        exec_time_window = []
        completed_iterations = 0
        MAX_WINDOW = 100

        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = {}
            next_iter = 1
            pending_futures = set()

            def submit_next():
                """Submit the next iteration to the thread pool."""
                nonlocal next_iter
                if next_iter <= max_iters and not _shutdown.is_set():
                    future = executor.submit(
                        _fuzz_one_iteration,
                        config,
                        oracle,
                        corpus,
                        energy,
                        engine,
                        timeout,
                    )
                    futures[future] = next_iter
                    pending_futures.add(future)
                    next_iter += 1

            submit_next()

            while pending_futures and not _shutdown.is_set():
                elapsed = time.monotonic() - start
                if duration is not None and elapsed >= duration:
                    break

                done_set, pending_futures = wait(
                    pending_futures,
                    timeout=DISPLAY_TIME_INT,
                    return_when=FIRST_COMPLETED,
                )

                for future in done_set:
                    iteration = futures[future]
                    try:
                        bug, found_new, child_depth, exec_time = future.result()

                        with _stats_lock:
                            completed_iterations += 1
                            exec_time_window.append(exec_time)
                            if len(exec_time_window) > MAX_WINDOW:
                                exec_time_window.pop(0)

                        if found_new:
                            new_paths += 1
                        if bug.is_bug():
                            total_bugs += 1
                            last_bug = bug
                            strategy_counts[bug.strategy] = (
                                strategy_counts.get(bug.strategy, 0) + 1
                            )

                        _lg = bug_logger._logger
                        if _lg:
                            unique_bug_count = _lg.unique_bugs
                        else:
                            unique_bug_count = 0

                        # timeout recalibration
                        with _stats_lock:
                            if completed_iterations == CALIBRATION_WINDOW or (
                                completed_iterations > CALIBRATION_WINDOW
                                and completed_iterations % RECALIBRATE_EVERY == 0
                            ):
                                if exec_time_window:
                                    avg = sum(exec_time_window) / len(exec_time_window)
                                    new_timeout = max(
                                        TIMEOUT_FLOOR, TIMEOUT_MULTIPLIER * avg
                                    )
                                    if abs(new_timeout - timeout) > 0.5:
                                        timeout = round(new_timeout, 1)

                    except Exception as e:
                        print(C.red(f"  [error] iteration {iteration} failed: {e}"))
                    finally:
                        del futures[future]

                    submit_next()

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

    finally:  # shutdown
        elapsed = time.monotonic() - start

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


# Entry point
def _preflight(all_targets: list[str]) -> None:
    print()
    print(_div("startup"))
    print(_kv("targets", C.cyan(", ".join(all_targets))))

    # archive
    sys.stdout.write(_kv("firestore archive", C.dim("connecting...")) + "\r")
    sys.stdout.flush()
    try:
        from engine.firestore_client import get_archive_db

        db = get_archive_db()
        if db is not None:
            list(db.collection("bugs").limit(1).stream())  # ping
            print(_kv("firestore archive", C.green("connected")) + "              ")
        else:
            print(
                _kv("firestore archive", C.dim("unavailable — local CSVs only")) + "  "
            )
    except Exception as e:
        print(
            _kv("firestore archive", C.yellow(f"failed ({e.__class__.__name__})"))
            + "  "
        )

    # current
    sys.stdout.write(_kv("firestore current", C.dim("connecting...")) + "\r")
    sys.stdout.flush()
    try:
        from engine.firestore_client import get_current_db

        db = get_current_db()
        if db is not None:
            list(db.collection("bugs").limit(1).stream())  # ping
            print(_kv("firestore current", C.green("connected")) + "              ")
        else:
            print(
                _kv("firestore current", C.dim("unavailable — local CSVs only")) + "  "
            )
    except Exception as e:
        print(
            _kv("firestore current", C.yellow(f"failed ({e.__class__.__name__})"))
            + "  "
        )

    sys.stdout.write(_kv("report cache", C.dim("warming...")) + "\r")
    sys.stdout.flush()
    try:
        report_generator.load_all(all_targets, use_firestore=True)
        print(_kv("report cache", C.green("ready")) + "              ")
    except Exception as e:
        print(_kv("report cache", C.yellow(f"warn: {e}")) + "  ")

    print(_div())
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fuzzer.py",
        description=(
            "Fuzzer — mutation loop (default) or seed pipeline (--seed).\n\n"
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

    # Seed Mode
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

    all_targets = []
    for yp in yaml_paths:
        try:
            all_targets.append(load_config(yp).get("name", "unknown"))
        except Exception:
            pass

    # Connect to Firestore + warm cache before any banner or fuzzing starts
    if not args.seed:
        _preflight(all_targets)

    for yaml_path in yaml_paths:
        try:
            config = load_config(yaml_path)
            cleanup_coverage_files(config)
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
