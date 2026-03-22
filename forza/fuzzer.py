"""
The orchestrator that wires everything together into the main fuzzing loop.
"""
"""
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
```

---

## How they all connect
```
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
"""

"""
fuzzer.py

Main entry point for the fuzzer.

For Project Meeting 1 (PM1) this runs the full pipeline on seed inputs —
no mutation yet, just demonstrating the end-to-end flow:

    seed → target_runner → output_parser (Bug Oracle) → console output

For Project Meeting 2 onward, the mutation loop will be activated via
--fuzz flag, wiring in mutation_engine, coverage_tracker, and bug_logger.

Usage
-----
# Run seeds through the full pipeline (PM1 demo mode):
    python3 fuzzer.py --target targets/json_decoder.yaml
    python3 fuzzer.py --target targets/cidrize.yaml
    python3 fuzzer.py --target targets/ip_parser_v4.yaml
    python3 fuzzer.py --target targets/ip_parser_v6.yaml

# Run all targets at once:
    python3 fuzzer.py --all

# (PM2+) Run full mutation fuzzing loop:
    python3 fuzzer.py --target targets/json_decoder.yaml --fuzz
    python3 fuzzer.py --target targets/json_decoder.yaml --fuzz --iterations 1000
"""

import argparse
import sys
import time
import random
import re
from pathlib import Path
from collections import Counter
from typing import Any

from engine.seed_generator import generate_seed
from engine.mutation_engine import MutationEngine
from engine.target_runner import load_config, load_seeds, run_both
from engine.bug_oracle import BugOracle, BugType
from engine.coverage_tracker import CoverageTracker, FuzzIterationPayload
# from engine.bug_logger import BugLogger


# ── Colour helpers (makes terminal output easier to read during demo) ─────────

RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

def colourise(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}"

BUG_TYPE_COLOURS = {
    BugType.NORMAL:     GREEN,
    BugType.INVALIDITY: RED,
    BugType.BONUS:      YELLOW,
    BugType.FUNCTIONAL: RED,
    BugType.CRASH:      RED,
    BugType.TIMEOUT:    YELLOW,
}


def resolve_tracking_mode(config: dict[str, Any]) -> str:
    # Set tracking mode by config, otherwise use fallback
    explicit_mode = str(config.get("tracking_mode", "")).strip().lower()
    if explicit_mode in {"behavioral", "code_execution"}:
        return explicit_mode

    if config.get("coverage_enabled") and config.get("coverage_flag"):
        return "code_execution"
    return "behavioral"


def extract_execution_metrics(raw_stdout: str, raw_stderr: str) -> dict[str, list[int]] | None:
    # Extract integers from lines mentioning coverage/execution/lines as a heuristic
    combined = f"{raw_stdout}\n{raw_stderr}"
    candidate_lines = []

    for line in combined.splitlines():
        lower = line.lower()
        if "coverage" in lower or "covered" in lower or "executed" in lower or "line" in lower:
            candidate_lines.append(line)

    if not candidate_lines:
        return None

    numbers: set[int] = set()
    for line in candidate_lines:
        for match in re.findall(r"\b\d+\b", line):
            numbers.add(int(match))

    if not numbers:
        return None
    return {"covered_lines": sorted(numbers)}


# ── Seed runner (Don't need for PM2) ───────────────────────────────────────────────

# def run_seeds(config: dict, num_seeds=20, verbose: bool = False) -> dict:
#     """
#     Run all seeds for a target through the full pipeline:
#         seed → target_runner → output_parser → print result

#     Returns a summary dict with counts per BugType.
#     """
#     input_format = config.get("input_format", "generic")
#     seeds = [generate_seed(input_format) for _ in range(num_seeds)]
#     oracle = BugOracle()

#     if not seeds:
#         print(f"  {YELLOW}[WARN] No seeds found at {config['seeds_path']}{RESET}")
#         return {}

#     summary = {bt: 0 for bt in BugType}
#     bugs_found = []

#     print(f"\n  {'INPUT':<45} {'BUG TYPE':<14} {'KEY'}")
#     print(f"  {'-'*45} {'-'*14} {'-'*40}")

#     for seed in seeds:
#         buggy_results, ref_result = run_both(config, seed, strategy="seed")

#         for i, raw in enumerate(buggy_results):
#             bug    = oracle.classify(raw, config)
#             colour = BUG_TYPE_COLOURS.get(bug.bug_type, RESET)
#             label  = f"buggy[{i}]" if len(buggy_results) > 1 else "buggy"

#             key_str = str(bug.bug_key)[:40] if bug.bug_key else "-"
#             print(
#                 f"  {repr(seed[:43]):<45} "
#                 + colourise(f"{bug.bug_type.value:<14}", colour)
#                 + f" {key_str}"
#             )

#             summary[bug.bug_type] += 1
#             if bug.bug_type != BugType.NORMAL:
#                 bugs_found.append((seed, bug, label))

#         if verbose and ref_result:
#             ref_bug = oracle.classify(ref_result, config)
#             print(f"    {'(ref)':<43} {ref_bug.bug_type.value:<14}")

#     # Print per-target summary
#     print(f"\n  {'─'*70}")
#     print(f"  SUMMARY  |  Seeds: {len(seeds)}  |  ", end="")
#     for bt, count in summary.items():
#         if count > 0:
#             colour = BUG_TYPE_COLOURS.get(bt, RESET)
#             print(colourise(f"{bt.value}: {count}  ", colour), end="")
#     print()

#     # Print bug details if any found
#     if bugs_found:
#         print(f"\n  {BOLD}Bugs found:{RESET}")
#         for seed, bug, label in bugs_found:
#             colour = BUG_TYPE_COLOURS.get(bug.bug_type, RESET)
#             print(
#                 f"    [{label}] "
#                 + colourise(bug.bug_type.value, colour)
#                 + f" | input: {repr(seed[:60])}"
#             )
#             if bug.bug_key:
#                 print(f"           key: {bug.bug_key}")

#     return summary

# ── Mutation Fuzzing ────────────────────────────────────────────────
def run_mutation_fuzzing(config: dict, iterations: int = 1000, verbose: bool = False):
    """
    Run the full mutation fuzzing loop on a single target.

    Parameters
    ----------
    config : dict
        Target configuration (from YAML)
    iterations : int
        Number of mutation iterations
    verbose : bool
        Whether to print extra info
    """
    input_format = config.get("input_format", "*")
    engine = MutationEngine(input_format=input_format)
    oracle = BugOracle()
    tracking_mode = resolve_tracking_mode(config)
    coverage_tracker = CoverageTracker({"tracking_mode": tracking_mode})
    # bug_logger = BugLogger(target_name=config.get("name", "unknown"))

    # Start with 10 auto-generated seeds
    # corpus = [generate_seed(input_format) for _ in range(10)]

    # Start with 10 auto-generated seeds + 1 guaranteed valid seed
    corpus = [generate_seed(input_format) for _ in range(9)]
    # Add a valid seed based on format for demonstration
    if input_format == "cidr":
        corpus.append("192.168.1.0/24")
    elif input_format == "ipv4":
        corpus.append("127.0.0.1")
    elif input_format == "ipv6":
        corpus.append("::1")
    elif input_format == "json":
        corpus.append('{"key":123}')
    else:
        corpus.append("test")

    strategy_usage = Counter()
    total_bugs = 0
    
    summary = {bt: 0 for bt in BugType}

    # print(f"\n  Starting mutation fuzzing loop with {iterations} iterations...")
    print(f"\n  {'ITER':<6} {'STRATEGY':<20} {'SEED/TRUNC':<45} {'BUG TYPE':<12} {'NEW_PATH':<8}")

    for i in range(1, iterations + 1):
        seed = random.choice(corpus)
        # mutated = engine.mutate(seed)
        # Soft mutation: 30% chance to keep seed unchanged → NORMAL possible
        if random.random() < 0.3:
            mutated = seed
            engine._last_strategy = "seed_preserve"
        else:
            mutated = engine.mutate(seed)
        strategy = engine.get_last_strategy()
        strategy_usage[strategy] += 1

        # Run target binary (both buggy and reference)
        use_coverage = tracking_mode == "code_execution"
        buggy_results, ref_result = run_both(
            config,
            mutated,
            strategy=strategy,
            use_coverage=use_coverage,
        )
        if not buggy_results:
            continue

        # Classify results
        raw = buggy_results[0]

        bug = oracle.classify(raw, config)
        summary[bug.bug_type] += 1

        execution_metrics = None
        if tracking_mode == "code_execution":
            execution_metrics = extract_execution_metrics(raw.stdout, raw.stderr)

        payload = FuzzIterationPayload(
            iteration_id=i,
            target_name=config.get("name", "unknown"),
            strategy_used=strategy,
            bug_key=str(bug.bug_key) if bug.bug_key else None,
            execution_metrics=execution_metrics,
        )
        new_path_found = coverage_tracker.update(payload)

        if new_path_found:
            engine.boost(strategy)
            corpus.append(mutated)

        if bug.bug_type != BugType.NORMAL:
            total_bugs += 1

        # Print iteration details
        colour = BUG_TYPE_COLOURS.get(bug.bug_type, RESET)
        truncated_seed = repr(mutated[:40])
        print(
            f"  {i:<6} {strategy:<20} {truncated_seed:<45} "
            f"{colourise(bug.bug_type.value, colour):<12} {str(new_path_found):<8}"
        )

        if verbose and ref_result:
            ref_bug = oracle.classify(ref_result, config)
            print(f"    {'(ref)':<43} {ref_bug.bug_type.value:<12}")
    total_bugs = sum(count for bt, count in summary.items() if bt != BugType.NORMAL)

    # Summary
    print(f"\n{BOLD}=== SUMMARY ==={RESET}")
    print(f"Total iterations : {iterations}")
    print(f"Corpus size      : {len(corpus)}")
    print(f"Total bugs found : {total_bugs}")
    print(f"Tracking mode    : {tracking_mode}")
    print(f"Coverage metric  : {coverage_tracker.current_metric}")
    print("Strategy usage   :", dict(strategy_usage))
    print("BugType summary  :", {bt.value: count for bt, count in summary.items()})

    return summary

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Forza Fuzzer — generic mutation-based fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # PM1 demo — run seeds through full pipeline for one target:
  python3 fuzzer.py --target targets/json_decoder.yaml

  # Run all targets:
  python3 fuzzer.py --all

  # Verbose output (show reference binary results too):
  python3 fuzzer.py --target targets/json_decoder.yaml --verbose
        """
    )

    parser.add_argument(
        "--target", "-t",
        metavar="YAML",
        help="Path to target YAML config (e.g. targets/json_decoder.yaml)"
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Run all targets found in the targets/ directory"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show reference binary results alongside buggy binary results"
    )
    parser.add_argument(
        "--fuzz",
        action="store_true",
        help="(PM2+) Run full mutation fuzzing loop instead of seed-only mode"
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=1000,
        help="(PM2+) Number of fuzzing iterations per target (default: 1000)"
    )

    args = parser.parse_args()

    if not args.target and not args.all:
        parser.print_help()
        sys.exit(1)

    # ── Collect target configs ────────────────────────────────────────────────
    if args.all:
        yaml_files = sorted(Path("targets").glob("*.yaml"))
        if not yaml_files:
            print(f"{RED}No YAML configs found in targets/{RESET}")
            sys.exit(1)
    else:
        yaml_files = [Path(args.target)]

    # ── Run each target ───────────────────────────────────────────────────────
    total_bugs = 0
    start_time = time.time()

    for yaml_file in yaml_files:
        if not yaml_file.exists():
            print(f"{RED}[ERROR] Config not found: {yaml_file}{RESET}")
            continue

        config = load_config(str(yaml_file))

        print(f"\n{BOLD}{'='*70}{RESET}")
        print(f"{BOLD}TARGET  : {config['name']}{RESET}")
        print(f"CONFIG  : {yaml_file}")
        print(f"FORMAT  : {config.get('input_format', 'generic')}")
        print(f"MODE    : {'mutation fuzzing' if args.fuzz else 'seed demo (PM1)'}")
        print(f"{'='*70}{RESET}")

        if args.fuzz:
            # ── PM2+ mutation loop (placeholder) ─────────────────────────────
            summary = run_mutation_fuzzing(config, iterations=args.iterations, verbose=args.verbose)
            bugs = sum(v for k, v in summary.items() if k != BugType.NORMAL)
            total_bugs += bugs
            # print(f"\n  {YELLOW}[INFO] Mutation fuzzing not yet implemented.{RESET}")
            # print(f"  {YELLOW}       Run without --fuzz for PM1 seed demo mode.{RESET}")
        else:
            # ── PM1 seed demo mode ────────────────────────────────────────────
            summary = run_seeds(config, verbose=args.verbose)
            bugs = sum(v for k, v in summary.items() if k != BugType.NORMAL)
            total_bugs += bugs

    # ── Final summary across all targets ─────────────────────────────────────
    elapsed = time.time() - start_time
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}DONE{RESET}  |  "
          + colourise(f"{total_bugs} bugs found", RED if total_bugs else GREEN)
          + f"  |  {elapsed:.1f}s elapsed")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()