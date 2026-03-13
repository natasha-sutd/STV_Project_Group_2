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
from pathlib import Path

from engine.target_runner import load_config, load_seeds, run_both
from engine.bug_oracle import BugOracle, BugType


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


# ── Seed runner (PM1 demo mode) ───────────────────────────────────────────────

def run_seeds(config: dict, verbose: bool = False) -> dict:
    """
    Run all seeds for a target through the full pipeline:
        seed → target_runner → output_parser → print result

    Returns a summary dict with counts per BugType.
    """
    seeds  = load_seeds(config["seeds_path"])
    oracle = BugOracle()

    if not seeds:
        print(f"  {YELLOW}[WARN] No seeds found at {config['seeds_path']}{RESET}")
        return {}

    summary = {bt: 0 for bt in BugType}
    bugs_found = []

    print(f"\n  {'INPUT':<45} {'BUG TYPE':<14} {'KEY'}")
    print(f"  {'-'*45} {'-'*14} {'-'*40}")

    for seed in seeds:
        buggy_results, ref_result = run_both(config, seed, strategy="seed")

        for i, raw in enumerate(buggy_results):
            bug    = oracle.classify(raw, config)
            colour = BUG_TYPE_COLOURS.get(bug.bug_type, RESET)
            label  = f"buggy[{i}]" if len(buggy_results) > 1 else "buggy"

            key_str = str(bug.bug_key)[:40] if bug.bug_key else "-"
            print(
                f"  {repr(seed[:43]):<45} "
                + colourise(f"{bug.bug_type.value:<14}", colour)
                + f" {key_str}"
            )

            summary[bug.bug_type] += 1
            if bug.bug_type != BugType.NORMAL:
                bugs_found.append((seed, bug, label))

        if verbose and ref_result:
            ref_bug = oracle.classify(ref_result, config)
            print(f"    {'(ref)':<43} {ref_bug.bug_type.value:<14}")

    # Print per-target summary
    print(f"\n  {'─'*70}")
    print(f"  SUMMARY  |  Seeds: {len(seeds)}  |  ", end="")
    for bt, count in summary.items():
        if count > 0:
            colour = BUG_TYPE_COLOURS.get(bt, RESET)
            print(colourise(f"{bt.value}: {count}  ", colour), end="")
    print()

    # Print bug details if any found
    if bugs_found:
        print(f"\n  {BOLD}Bugs found:{RESET}")
        for seed, bug, label in bugs_found:
            colour = BUG_TYPE_COLOURS.get(bug.bug_type, RESET)
            print(
                f"    [{label}] "
                + colourise(bug.bug_type.value, colour)
                + f" | input: {repr(seed[:60])}"
            )
            if bug.bug_key:
                print(f"           key: {bug.bug_key}")

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
            print(f"\n  {YELLOW}[INFO] Mutation fuzzing not yet implemented.{RESET}")
            print(f"  {YELLOW}       Run without --fuzz for PM1 seed demo mode.{RESET}")
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