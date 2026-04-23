# 50.053 SOFTWARE TESTING & VERIFICATION PROJECT GROUP 2
# Forza

Forza is built from scratch to detect seeded bugs in four Python targets: `json_decoder`, `cidrize`, `ipv4_parser`, and `ipv6_parser`. It implements AFL-style energy-based mutation, grammar-aware seed generation via a Context-Free Grammar (CFG) Tree, differential oracle testing, and HTML reporting backed by Firebase Firestore. It is designed to be sufficiently general, and can be used to fuzz any target provided their target specific YAML configuration (not tested).

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Design Overview](#design-overview)
3. [Design Details](#design-details)
4. [Key Design Choices](#key-design-choices)
5. [Implementation Challenges](#implementation-challenges)
6. [Experiments & Results](#experiments--results)
7. [Lessons Learned](#lessons-learned)
8. [Future Improvements](#future-improvements)
9. [Setup & Usage](#setup--usage)

---

## Project Structure

```
forza/
├── targets/                   # Target configs: commands, seeds, coverage flags
│   ├── json_decoder.yaml
│   ├── cidrize.yaml
│   ├── ipv4_parser.yaml
|   └── ipv6_parser.yaml
├── engine/
│   ├── types.py               # Shared types: BugType enum, BugResult dataclass
│   ├── seed_generator.py      # Grammar-based seed generation and CFG tree mutations
│   ├── mutation_engine.py     # AFL-style weighted mutation with grammar support
│   ├── target_runner.py       # Subprocess runner — executes targets, captures output
│   ├── bug_oracle.py          # Classifies raw output into structured BugResult types
│   ├── coverage_tracker.py    # AFL-compatible bitmap tracker (behavioral + code_execution)
│   ├── bug_logger.py          # Writes bugs to CSV and uploads to Firestore
│   ├── firestore_client.py    # Firebase Firestore client (archive + current DBs)
│   └── report_generator.py    # Generates per-target report.html from CSV/Firestore data
├── results/
│   ├── *_bugs.csv             # Deduplicated bug log per target
│   ├── *_coverage.csv         # Coverage snapshots per target
|   ├── */<run_id>/            # Per-run directory: all_runs.csv, stats.csv, tracebacks.log, bug_inputs/
│   └── *_report.html          # Generated HTML report per target
├── sample.yaml                # Sample yaml structure for new targets
└── fuzzer.py                  # Main entry point — orchestrates the full pipeline
```

---

## Design Overview

Forza's overall design is as follows:

```
Repeat:
1. Orchestrator picks a seed
2. Mutation engine modifies it
3. Target Runner feeds it to the target
4. Bug Oracle monitors for crashes/memory leaks
5. Coverage Tracker checks if new code paths were hit
6. Bug Logger deduplicates and saves the bug to CSV + Firestore
```

### External Libraries/Tools Used

| Libraries/Tools       | Description                                                                           |
| --------------------- | ------------------------------------------------------------------------------------- |
| `Radamsa`             | A high-performance test case generator used to create "extreme" mutated inputs from our seeds without requiring knowledge of the program's internal logic.
| `PyPYAML`             | Defines how each target is executed in separate YAML files. Promotes extensibility by allowing new targets to be added without modifying the core fuzzer logic.
| `Coverage`            | Analyzes the source code of our Python targets to identify which lines and branches are executed, helping the fuzzer decide which inputs are "interesting" enough to keep in the corpus.
| `firebase-admin`      | The bridge between our fuzzer and Google Cloud, enabling firestore_client.py to upload bugs and coverage snapshots to our "Archive" and "Current" databases.

---

### What We Built Ourselves

Besides the external libraries/tools/test targets used, the fuzzing framework which is a custom-built orchestration engine was built from scratch with the following components:
1. Core fuzzer controller and fuzzing logic loop
2. Seed generation and mutation engine for generating test inputs
3. Bug detection and classification system
4. Coverage tracking and analysis
5. Automated report generation
6. Firebase integration for distributed testing

---

## Design Details

### 1. Seed Generator (`seed_generator.py`)

Seed Generator is responsible for generating the initial corpus from a grammar specification defined in each YAML config's `input` block. Supports: `int`, `float`, `hex`, `string`, `boolean`, `null`, `any`, `literal`, `array`, `object`, `sequence`, `one_of`, `concat`.

Seeds are produced by `generate_from_spec()`, which recursively walks the grammar tree and samples from each node type's range or character set. Beyond initial generation, `seed_generator.py` exposes two functions used by the mutation engine at runtime:

- **`mutate_from_spec(seed, spec)`** — parses the seed string back into a CFG derivation tree (`CFGNode`) and applies one of three operations chosen at random: `fresh` (regenerate from spec), `mutate` (probabilistic subtree replacement via `mutate_tree()`), or `violate` (intentional constraint breaking via `violate_tree()`).
- **`violate_tree(node)`** — traverses the CFG tree and intentionally breaks constraints at each node type: out-of-range integers, wrong-length sequences, malformed hex, invalid characters for string fields, and field count overflow/underflow for objects. This directly targets logic bugs that only appear at boundary inputs.

### 2. Mutation Engine (`mutation_engine.py`)

There are two tiers of mutation: generic and grammar-aware mutation.

**Generic (format-agnostic):**

- `bit_flip` — flips a random bit in a random character
- `truncate` — cuts input at a random position
- `insert_special_char` — injects null bytes, overflow bait, path traversal strings, shell injection characters
- `repeat_chunk` — duplicates a slice to stress length handling
- `byte_insert` — inserts random printable ASCII
- `swap_chars` — swaps two random characters
- `radamsa` — delegates to Radamsa (skipped if not installed)

**Grammar-aware (when YAML `input:` spec is present):**

- `grammar_mutate` — calls `seed_generator.mutate_from_spec()` for structurally valid variants
- `constraint_violation` — calls `seed_generator.violate_tree()` to intentionally break grammar rules (wrong IP octet range, bad field count, non-numeric where int expected)

Each strategy carries a **weight**. Strategies that find new coverage get their weight boosted (×1.5). All weights decay each iteration (×0.95) to prevent any one strategy dominating. This is the AFL energy scheduling model. The `enabled_strategies` and `disabled_strategies` YAML keys allow per-target fine-tuning.

### 3. Target Runner (`target_runner.py`)

Target Runner is responsible for executing the targets with the commands specified in the target’s accompanying YAML configuration. Different input formats are supported including `arg`, `stdin`, and `file` input modes, though for this project, only `arg` is used across the four main targets. Different platforms are also supported, specifically windows, linux, and mac, as long as they are stated in the YAML configuration. Target Runner is also equipped with differential testing capabilities. Given that the YAML configuration specifies reference commands and the reference target folders are included in the root folder, Target Runner can execute reference targets when necessary. 

After each execution, a `RawResult` class is produced, storing crucial information such as `input_data`, `stdout`, `stderr`, etc. Typically, the `run_both()` function is called, executing both the buggy target and the reference target, producing a buggy `RawResult` and a reference `RawResult` for the Bug Oracle to classify.

### 4. Bug Oracle (`bug_oracle.py`)

Bug Oracle is responsible for interpreting the RawResult from the target runner and returns a BugResult, which has a standardized data structure that every detected bug gets stored as. As such, bugs are fully reproducible from just the BugResult. The strategy field records which mutation strategy produced the bug, which feeds back into the fuzzer to boost that strategy's energy.

A ten-stage classification pipeline applied to every execution result. Stages are evaluated in priority order; the first match wins:

1. **TIMEOUT** — process was killed by the runner
2. **PERFORMANCE** — `"performance bug"` or `PerformanceBug` keyword in output
3. **INVALIDITY** — `"invalidity"` or `"ValidityBug"` keyword
4. **VALIDITY** — `"validity"` or `ValidityBug` keyword
5. **SYNTACTIC** — `"syntax error"`, `AddrFormatError`, or `"syntactic"` keyword
6. **FUNCTIONAL** — `"functional"` or `FunctionalBug` keyword
7. **BOUNDARY** — `"boundary"` or `BoundaryBug` keyword
8. **BONUS** — `"bonus"` keyword, or any YAML-defined `bug_keywords` match
9. **RELIABILITY** — non-zero exit code with no structured output; also triggered by `ReliabilityBug` keyword
10. **MISMATCH** — differential oracle: normalised buggy output diverges from reference output. is detected by comparing buggy output and reference output

Bug deduplication uses a 16-char MD5 hash of a`(bug_type, exception_class, line_number)` tuple. Excluding the exception message text ensures that the same underlying bug triggered by many different inputs is counted as a single unique bug.

Bug Oracle's rule-based bug detection uses keyword and pattern matching to identify bugs in the target's output. It detects three things, exception types like ValueError, crash signals, and custom bug markers like FunctionalBug that are defined in the YAML config. To do this, it extracts two key pieces of information. First, the exception class using the EXC CLASS RE regex, which matches anything that looks like a Python exception name. Second, the line number from the traceback using TRACEBACK LINE RE, which takes the last 3 stack frames to give a more precise location of where the bug occurred. These two pieces together form the bug key, which is used to deduplicate bugs so we don't count the same crash twice.

### 5. Coverage Tracker (`coverage_tracker.py`)

The coverage tracker determines whether a generated input is interesting enough to be added to the corpus for future mutation. This is a core part of the feedback loop in the fuzzer, because it allows the system to retain inputs that reveal previously unseen behaviour and to discard those that do not contribute anything new. In this project, the tracker acts as the single decision point for novelty detection after execution and bug classification.

Controlled by the `tracking_mode` flag in the YAML config, the tracker operates in one of two fundamental modes:

The tracker supports three operational modes. 
- For whitebox targets, where Python source-level instrumentation is possible, the tracker uses real execution coverage derived from the Python coverage framework. 
- For greybox targets, where the buggy binary itself does not expose coverage but a reference implementation does, the tracker uses the reference program’s coverage output as an approximation of structural novelty. 
- For blackbox targets, where neither the buggy program nor the reference implementation yields usable execution coverage, the tracker falls back to a behavioural model in which novelty is inferred from distinct output signatures or bug classifications. 

For instrumented runs, the tracker uses an AFL-style 64 KB bitmap and hashes coverage identifiers into bitmap slots so that familiar metrics such as map density and count coverage can be displayed. In whitebox mode, coverage information is appended to program output using the `\t<cov_lines>` sentinel, allowing the tracker to separate actual coverage data from normal program output before parsing it. This makes the coverage pipeline more reliable and prevents accidental misinterpretation of ordinary output text as coverage information.

Novelty is determined mainly in two ways. First, the tracker checks whether the current execution produces a higher statement coverage percentage than any previous run. Second, it checks whether a coverage key has entered a new bucket that has not been observed before. In behavioural mode, novelty instead depends on whether a new output signature or bug key has appeared. The result of this decision is returned as `new_path_found`, which then drives corpus growth, seed energy updates, and mutation strategy boosting.

### 6. Bug Logger (`bug_logger.py`)

Bug Logger records every fuzzing execution result. It tracks all runs in a CSV for the full history.
Each fuzzing session creates a `FuzzLogger` with a timestamped `run_id`. It writes to three files:
- `results/<target>_bugs.csv` — flat deduplicated bug log appended across all runs
- `results/<target>/<run_id>/all_runs.csv` — one row per iteration (for throughput analysis)
- `results/<target>/<run_id>/stats.csv` — periodic snapshots of runs/bugs/corpus/rps
- `results/<target>/<run_id>/tracebacks.log` — raw stdout/stderr for all non-NORMAL results
- `results/<target>/<run_id>/bug_inputs/` — the triggering input saved as a `.txt` file for each unique bug

The logger also tracks `_first_by_type`: one representative `BugResult` per `BugType`, used by the report generator to surface one clean example per bug category.

Uploads to Firestore are fired on every unique bug and on every stats snapshot.

### 7. Firestore Integration (`firestore_client.py`)

Firestore Client upload bugs and coverage snapshots to 2 separate databases. The two separate Firebase apps are initialized from credentials files in the project root:

- **Archive DB** — permanent record of all bugs across all runs, never cleared
- **Current DB** — cleared at the start of each new run via `clear_current_db()`; holds only the latest session

The archive DB is used by `report_generator.py` with a **local cache** (`results/firestore_cache.json`) to minimise Firestore reads — on subsequent runs only newly added documents are fetched.

### 8. Report Generator (`report_generator.py`)

Report Generator is responsible for generating a self-contained, human-readable `<target>_report.html` per target. Data is split into two scopes:

- **All-time** (deduped across all runs from the bug CSV): displayed in the overview card and ablation study
- **Current run** (most recent `run_id` only): displayed in the coverage graph, recent bugs table, and bug report cards

Report sections:

- Overview card: total bugs across all runs, total unique bugs, timeouts, crashes
- Ablation study: unique bugs broken down by mutation strategy
- Coverage over time: statement, branch, and combined coverage vs iteration count
- Recent bugs table: scoped to current run
- Bug report cards: one per representative bug type, showing triggering input, stdout/stderr excerpt, and returncode

The Firestore cache (`results/firestore_cache.json`) stores the last fetched timestamp so subsequent refreshes only pull newly added documents, avoiding repeated full collection scans.

---

## Key Design Choices

### YAML-Driven Target Configuration

All target-specific logic (binary paths, input mode, seeds path, coverage flag, bug keywords, output pattern, grammar spec) lives in YAML files. The engine has zero hardcoded target knowledge — adding a new target requires only a new YAML file.

### AFL-Style Energy Scheduling

Rather than selecting mutations uniformly at random, strategies that find new coverage are boosted in weight. All weights decay each iteration to prevent premature convergence. This mirrors AFL's core insight: spend more time on strategies that are actually finding new paths.

### Corpus Growth

Inputs that trigger new coverage are added to the corpus and can be selected as seeds for future mutations. This ensures the fuzzer explores paths discovered by previous iterations.

### Adaptive Timeout

The fuzzer begins with a default timeout of 60 seconds, which is recalibrated every 200 iterations based on real execution data. The new timeout is set to 3 times the rolling average execution time, but only updated if the change exceeds 0.5 seconds. This prevents unnecessary fluctuations while still adapting to the target's actual performance. This approach avoids false timeouts on legitimately slow inputs while ensuring genuine hangs are still detected.

### Dual Thread Setup

To increase the efficiency of our fuzzer, we implemented 2 concurrent worker threads running in parallel. This gave us faster speed, higher throughput, and more iterations completed per run. To protect shared state across the two threads, we implemented 3 locks, one for the corpus and energy dictionary, one for the mutation engine weights, and one for the timing statistics. This ensures that when both threads are running simultaneously, they do not overwrite each other's data or produce inconsistent results.

---

## Implementation Challenges

### 1. Coverage Measurement

A major limitation of the coverage system is that its accuracy depends heavily on the type of target being fuzzed. For whitebox Python targets, coverage measurement is meaningful because the tracker can obtain real statement and branch coverage through instrumentation. However, even in this case, the coverage is accumulated across runs, which means the tracker can detect that coverage has increased but cannot precisely identify which exact lines were newly contributed by a particular input. This makes the system good at measuring overall progress, but weaker at per-input attribution.
The biggest limitations appear in blackbox mode. Since native binaries do not expose direct execution coverage, the system uses behavioural coverage based on output signatures and bug classifications. While this allows the fuzzer to remain feedback-guided, the signal saturates quickly because the number of distinct observable behaviours is small. Once saturation is reached, the tracker stops identifying new behaviour even if additional internal paths still exist.
Another limitation is the use of reference implementation coverage as a proxy in greybox mode. This can help guide mutation, but it does not measure the buggy binary directly, since the buggy and reference programs may follow different internal paths on the same input. Therefore, greybox coverage should be interpreted as an approximation rather than exact code coverage of the target under test.
Attempts to obtain stronger instrumentation coverage through python-afl or AFL QEMU-style mechanisms ran into major practical barriers, including interpreter compatibility problems, extra subprocess overhead, and throughput collapse caused by repeated target startup costs. In particular, designs that required multiple binary executions per iteration made fuzzing too slow to remain useful. Attempts to parallelise around this problem introduced secondary issues in the mutation decay and energy scheduling logic, showing that coverage instrumentation could not be changed in isolation without affecting the rest of the architecture. This demonstrates that the problem of coverage is not confined to one module; it is tightly coupled to the execution model and scheduler of the entire fuzzer.
Finally, the coverage pipeline is vulnerable to silent failures. Because coverage information is passed through multiple components, a small change in formatting or configuration can silently break the signal without causing an obvious runtime error. This makes coverage bugs difficult to diagnose, since the fuzzer may continue running normally while the quality of the feedback signal has already degraded. Overall, the system works best for whitebox targets and becomes increasingly approximate for greybox and blackbox targets.


### 2. Firestore Read Costs

Initially, `report_generator.py` streamed all documents from Firestore on every background refresh. With 1000+ bugs accumulated, this was ~1000 reads per refresh, hitting Firestore's no-cost limits quickly. The fix was a local JSON cache (`results/firestore_cache.json`) that records the last fetched timestamp and only queries documents newer than that timestamp on subsequent refreshes.

### 3. Bug Over-counting

Early versions counted every unique input triggering a bug as a separate bug, producing hundreds of "unique" entries for `json_decoder`. The fix was to exclude the exception message from the deduplication hash — since the same underlying bug (e.g. `ParseException`) produces different messages for different inputs, only the exception class and line number are used as the deduplication key.

---

## Experiments & Results

Each target was run for 6 hours each per person, equating to 30 hours per target. Additionally, crashes are read the last 3 frames of the Traceback.
Please refer to our report for detailed RQ1-RQ4 experiments.

---

## Lessons Learned

- Our team had several issues with bug deduplication across project meetings 2 and 3 as we did not understand how we should define ‘deduplication’ correctly according to what our professor is looking for. Our first approach was to hash the input data to identify unique bugs, but that turned out to be wrong. A single ParseException would get triggered by hundreds of different inputs, each producing a slightly different error message, and we ended up with hundreds of “unique” bugs. What we learned after project meeting 3 was that what makes two bugs the same is not the input that triggers them, but the code path they exercise. Hence we switched to hashing (`bug_type`, `exception_class`, `line_number`) instead. That collapsed everything down to a much more honest count. In hindsight, we should have thought and clarified what “uniqueness” actually means at the start as this should be one of the first design decisions we nail down, not something we fix halfway through.

- One key lesson we learnt from evolving our seed generator is the importance of moving from ad-hoc input generation to structured, grammar-driven design. Initially, our generators were simple and target-specific (e.g. manually crafting JSON or IPv4 strings with random values), which was easy to implement but not scalable or reusable. As we transitioned to a generalized grammar-based approach, we realized how powerful it is to separate input specification from generation logic using YAML and type-based generators. This made the system far more flexible, allowing us to support many input formats without rewriting code. We also learnt that effective fuzzing is not just about generating random inputs, but about maintaining structure while introducing controlled mutations, which we achieved through Context-Free Grammar (CFG) trees and grammar-aware mutations. This helped balance valid and invalid inputs, improving coverage and bug discovery. Overall, this process deepened our understanding of how abstraction, modular design, and structured randomness can significantly enhance both scalability and effectiveness in fuzzing systems.

- Our 6 hours runs were done with each member running each target for 6 hours. This resulted in 5 different engines running each target, producing 5 very different results. Only after the long run did we realise that this would be problematic for empirical evaluation. Regardless, Forza managed to prove stable, as seen in RQ4, despite the very different engines, 6 hour runs allowed the fuzzing sessions to converge to a similar result. Having said that, it would have been a better comparison for each member to only run a single target, allowing for fairer comparisons across runs per target.

---

## Future Improvements

- For our Bug Oracle and Target Runner, we would like them to be able to more accurately classify bugs such as Timeout and Mismatch. For our Coverage Tracker, we would like it to be able to accurately instrument black box binary targets for coverage tracking.

- For Frida for Blackbox Coverage, a future improvement is to replace the current behavioural proxy with true blackbox coverage measurement using Frida-based dynamic instrumentation. In the current implementation, blackbox targets rely on output signatures and bug classifications as a substitute for real execution coverage, which causes the feedback signal to saturate quickly and limits the fuzzer’s ability to distinguish between structurally different internal paths. The report identifies Frida’s `Stalker.follow()` API as the correct long-term solution, since it can observe executed basic blocks in a running native binary without requiring source code access. These block transitions could then be hashed into AFL-style edge identifiers and written into the fuzzer’s bitmap, allowing the system to compute genuine blackbox coverage metrics such as edge discovery, map density, and count coverage rather than relying on behavioural approximations. 
Using Frida would also avoid the throughput problems encountered in earlier blackbox instrumentation attempts, where separate subprocess executions were needed to extract coverage data. Instead, instrumentation could be attached directly to the target process during execution, making it possible to collect coverage information and program output in the same run. This would produce a more accurate and non-saturating guidance signal for native binaries, while also making blackbox coverage results more directly comparable to AFL-style metrics. Although this approach introduces engineering challenges such as callback overhead and instrumentation tuning, it would provide a much stronger foundation for future versions of the fuzzer.

---

## Setup & Usage

### Prerequisites

```bash
python3 -m venv .venv
pip install -r requirements.txt
cd forza
```
Do ensure that your Python version is 3.10 and above before running the fuzzer.

### Running the Fuzzer

Note: Run the following command before every fuzzing .
```bash
rm ../json-decoder/logs/bug_counts.csv
rm ../IPv4-IPv6-parser-main/logs/bug_counts.csv
rm ../cidrize-runner-main/logs/bug_counts.csv
```

```bash
# Single target
python3 fuzzer.py --target targets/json_decoder.yaml --duration 3600

# All targets, 30 minutes each
python3 fuzzer.py --all --duration 1800

# With iteration cap
python3 fuzzer.py --target targets/json_decoder.yaml --iterations 5000

# Seed mode (sanity check, no mutation)
python3 fuzzer.py --target targets/json_decoder.yaml --seed
```

### Viewing Results

```bash
# Open report directly
start results/<target>_report.html          # Windows
open results/<target>_report.html           # macOS
xdg-open results/<target>_report.html       # Linux

# Or use VS Code Live Server extension
```
* Additionally, the results of the 5 * 6 hour runs per target are archived under the empirical_evaluation/, containing 
*\_bugs\_{name}.csv, *\_coverage\_{name}.csv, and *\_report\_{name}.html for each target. evaluation.ipynb contains 
the graphs plotted for empirical evaluation. 

### Output Files

| Path                                       | Contents                                           |
| ------------------------------------------ | -------------------------------------------------- |
| `results/<target>_bugs.csv`                | All unique bugs found, one row per unique `bug_key`, appended across runs  |
| `results/<target>_coverage.csv`            | Per-iteration coverage snapshots: statement, branch, function, map density |
| `results/<target>/<run_id>/stats.csv`      | Periodic throughput and bug count snapshots                 |
| `results/<target>/<run_id>/tracebacks.log` | Raw stdout/stderr for all non-NORMAL results       |
| `results/<target>_report.html`             | Full HTML report with charts and bug details       |
| `results/firestore_cache.json`             | Local cache of Firestore data to minimise reads    |
