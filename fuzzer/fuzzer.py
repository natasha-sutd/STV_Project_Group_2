# -*- coding: utf-8 -*-
"""
fuzzer.py — Main entry point for the IPv4/IPv6 black-box fuzzer.

Usage
-----
  python fuzzer.py --target ipv4 --budget 300
  python fuzzer.py --target ipv6 --budget 600 --results-dir ../results
  python fuzzer.py --target ipv4 --no-grammar    # ablation: disable grammar mutations
  python fuzzer.py --target ipv4 --no-schedule   # ablation: uniform random seed selection

Architecture
------------
  select seed (power schedule)
       |
       v
  mutate seed (grammar-aware + generic strategies)
       |
       v
  run binary via WSL  (TargetDriver)
       |
       v
  classify output     (BugOracle)
       |
       v
  update corpus energy + behavior table  (SeedCorpus)
       |
       v
  log result          (FuzzLogger)
       |
       v
  [repeat]

Coverage approximation
----------------------
Because the binaries are closed (no instrumentation), "coverage" is
approximated via *behavioral novelty*: every unique (bug_category,
exception_type, exception_message) triple is counted as a new behavior.
Seeds that discover new behaviors receive energy boosts; seeds that do not
are gradually deprioritised.
"""

import argparse
import random
import signal
import sys
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Ensure the fuzzer/ directory is on sys.path so sibling modules resolve.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus import Seed, SeedCorpus
from driver import make_driver
from logger import FuzzLogger
from mutator import MutationEngine
from oracle import BugType
from seed_gen import get_seeds


# ---------------------------------------------------------------------------
# Signal handler for clean exit (Ctrl-C)
# ---------------------------------------------------------------------------

_STOP = False

def _handle_sigint(sig, frame):
    global _STOP
    print("\n\n[!] Interrupt received — finishing current run then stopping …")
    _STOP = True

signal.signal(signal.SIGINT, _handle_sigint)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Black-box grammar+coverage fuzzer for IPv4/IPv6 parsers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--target", required=True, choices=["ipv4", "ipv6"],
        help="Which binary parser to fuzz.",
    )
    p.add_argument(
        "--budget", type=int, default=300,
        help="Maximum number of fuzzing iterations (default: 300).",
    )
    p.add_argument(
        "--timeout", type=float, default=30.0,
        help="Per-run timeout in seconds (default: 30; PyInstaller bundles need ~5s cold start).",
    )
    p.add_argument(
        "--bin-dir", type=str, default=None,
        help="Directory containing the linux-ipv*-parser binaries. "
             "Defaults to ../IPv4-IPv6-parser-main/bin/ relative to this file.",
    )
    p.add_argument(
        "--results-dir", type=str, default=None,
        help="Base directory for result logs. "
             "Defaults to ../results/ relative to this file.",
    )
    p.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for reproducibility.",
    )
    # ---- Ablation flags ----
    p.add_argument(
        "--no-grammar", action="store_true",
        help="[Ablation] Disable grammar-aware mutations; use only generic bitflip/byte strategies.",
    )
    p.add_argument(
        "--no-schedule", action="store_true",
        help="[Ablation] Disable power scheduling; select seeds uniformly at random.",
    )
    p.add_argument(
        "--status-interval", type=int, default=10,
        help="Print status line every N iterations (default: 10).",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Core fuzzing loop
# ---------------------------------------------------------------------------

def run_fuzzer(args: argparse.Namespace) -> None:
    if args.seed is not None:
        random.seed(args.seed)

    # -- Resolve paths -------------------------------------------------------
    project_root = Path(__file__).resolve().parent.parent
    results_dir = args.results_dir or str(project_root / "results")
    bin_dir = args.bin_dir  # None → driver auto-detects

    # -- Initialise components -----------------------------------------------
    mutation_target = "generic" if args.no_grammar else args.target
    engine = MutationEngine(target=mutation_target)
    corpus = SeedCorpus()
    driver = make_driver(args.target, bin_dir=bin_dir, timeout=args.timeout)
    logger = FuzzLogger(output_dir=results_dir, target=args.target)

    print(f"[fuzzer] Target        : {args.target}")
    print(f"[fuzzer] Binary        : {driver.binary_path}")
    print(f"[fuzzer] Budget        : {args.budget} iterations")
    print(f"[fuzzer] Grammar mut.  : {'OFF (ablation)' if args.no_grammar else 'ON'}")
    print(f"[fuzzer] Power sched.  : {'OFF (ablation)' if args.no_schedule else 'ON'}")
    print()

    # -- Load initial seeds --------------------------------------------------
    initial_seeds = get_seeds(args.target)
    added = corpus.add_many(initial_seeds)
    print(f"[fuzzer] Loaded {added} initial seeds into corpus.")

    # Feed all valid initial seeds to the splice pool
    for s in initial_seeds:
        engine.feed_splice_pool(s.data)

    # -- Warm-up: run each seed once to populate the behavior table ----------
    print(f"[fuzzer] Warm-up: running {corpus.size()} initial seeds …")
    all_seeds_list = corpus.all_seeds()
    for i, seed in enumerate(all_seeds_list):
        if _STOP:
            break
        result = driver.run(seed.data)
        is_new = corpus.update(seed, result)
        logger.record(result, corpus_size=corpus.size())
        if is_new:
            # A new interesting seed to add (the seed itself, not a mutant)
            pass  # The seed is already in corpus; just note the behavior
        if (i + 1) % 20 == 0:
            print(f"  … {i+1}/{len(all_seeds_list)} warm-up runs done, "
                  f"{corpus.seen_behavior_count()} behaviors seen")

    print(f"[fuzzer] Warm-up complete. {corpus.seen_behavior_count()} behaviors seen.\n")
    print(f"[fuzzer] Starting main fuzzing loop for {args.budget} iterations …\n")

    # -- Main loop -----------------------------------------------------------
    iteration = 0
    start_time = time.monotonic()

    while iteration < args.budget and not _STOP:
        iteration += 1

        # 1. Select a seed
        if args.no_schedule:
            seed = random.choice(corpus.all_seeds())
            seed.times_selected += 1
        else:
            seed = corpus.select()

        # 2. Mutate
        mutant_bytes = engine.mutate(seed.data)
        engine.feed_splice_pool(mutant_bytes)

        # 3. Run
        result = driver.run(mutant_bytes)

        # 4. Classify novelty & update corpus
        is_new = corpus.update(seed, result)

        # 5. If the mutant found new behavior AND is not a duplicate, add it
        if is_new and mutant_bytes != seed.data:
            new_seed = Seed(
                data=mutant_bytes,
                energy=4.0,  # High initial energy: it already found something
                origin=f"mutant_of_{seed.origin}",
            )
            corpus.add(new_seed)

        # 6. Log
        logger.record(result, corpus_size=corpus.size())

        # 7. Progress output
        if iteration % args.status_interval == 0:
            logger.print_status(corpus_size=corpus.size())

    # -- Final report --------------------------------------------------------
    elapsed = time.monotonic() - start_time
    logger.snapshot(corpus_size=corpus.size())
    print(f"\n\n{'='*60}")
    print(f"Fuzzing complete.")
    print(f"  Target          : {args.target}")
    print(f"  Total runs      : {logger.iteration}")
    print(f"  Elapsed         : {elapsed:.1f}s  ({logger.iteration / max(elapsed,1):.1f} runs/s)")
    print(f"  Unique bugs     : {logger.unique_bugs}")
    print(f"  Corpus size     : {corpus.size()}")
    print(f"  New behaviors   : {corpus.seen_behavior_count()}")
    print(f"  Results dir     : {logger.out_dir}")
    print(f"{'='*60}\n")
    print("[Mutation strategy breakdown]")
    print(engine.stats())
    print()
    print("[Corpus summary]")
    print(corpus.summarize())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_fuzzer(parse_args())
