# 50.053 SOFTWARE TESTING AND VERIFICATION PROJECT GROUP 2

A fuzzer built from scratch to detect seeded bugs in four Python targets: `json_decoder`, `cidrize`, `ipv4_parser`, and `ipv6_parser`. The fuzzer implements AFL-style energy-based mutation, grammar-aware seed generation via a Context-Free Grammar (CFG)Tree, differential oracle testing, and HTML reporting backed by Firebase Firestore.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Design Overview](#design-overview)
3. [Design Details](#design-details)
4. [Key Design Choices](#key-design-choices)
5. [Implementation Challenges](#implementation-challenges)
6. [Experiments & Results](#experiments--results)
7. [Lessons Learned](#lessons-learned)
8. [Setup & Usage](#setup--usage)

---

## Project Structure

```
forza/
├── fuzzer.py                  # Main entry point — orchestrates the full pipeline
├── targets/
│   ├── json_decoder.yaml      # Target config: commands, seeds, coverage flags
│   ├── cidrize.yaml
│   ├── ipv4_parser.yaml
|   ├── ipv6_parser.yaml
│   └── sample.yaml            # Sample yaml structure for new targets
├── engine/
│   ├── types.py               # Shared types: BugType enum, BugResult dataclass
│   ├── target_runner.py       # Subprocess runner — executes targets, captures output
│   ├── mutation_engine.py     # AFL-style weighted mutation with grammar support
│   ├── seed_generator.py      # Grammar-based seed generation and CFG tree mutations
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

```

---

## Design Overview

Our fuzzer's overall design is as follows:

```
1. Orchestrator picks a seed from the corpus
        ↓
2. Mutation engine modifies it (weighted strategy selection)
        ↓
3. Target Runner feeds it to the target 
        ↓
4. Bug Oracle monitors for crashes/memory leaks
        ↓
5. Coverage Tracker checks if new code paths were hit
        ↓
6. Bug Logger deduplicates and saves the bug to CSV + Firestore
        ↓
     Repeat
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

Every component in `engine/` was written from scratch:

| Component             | Description |
|-----------------------|-------------|
| `mutation_engine.py`  | AFL-style weighted strategy selection, energy boosting/decay, grammar-aware mutations |
| `seed_generator.py`   | CFG derivation tree for grammar-driven seed generation, tree mutation, and constraint violation |
| `bug_oracle.py`       | Ten-stage classifier: timeout → keyword detection → crash → differential → normal |
| `coverage_tracker.py` | Dual-mode tracker: AFL 64 KB bitmap with bucket novelty detection; behavioral proxy for blackbox targets |
| `bug_logger.py`       | Per-run deduplication using MD5 hash keys, structured CSV logging, Firestore upload |
| `firestore_client.py` | Dual Firestore setup (archive + current), singleton pattern, graceful fallback when credentials absent |
| `report_generator.py` | Self-contained HTML report with ablation study, coverage graphs, and per-target bug cards |
| `fuzzer.py`           | Main loop with AFL-style terminal UI, corpus growth, graceful shutdown, background report refresh |

---

## Design Details

### 1. Seed Generator (`seed_generator.py`)

Generates the initial corpus from a grammar specification defined in each YAML config's `input:` block. Supports: `int`, `float`, `hex`, `string`, `boolean`, `null`, `any`, `literal`, `array`, `object`, `sequence`, `one_of`, `concat`.

Seeds are produced by `generate_from_spec()`, which recursively walks the grammar tree and samples from each node type's range or character set.

Beyond initial generation, `seed_generator.py` exposes two functions used by the mutation engine at runtime:

- **`mutate_from_spec(seed, spec)`** — parses the seed string back into a CFG derivation tree (`CFGNode`) and applies one of three operations chosen at random: `fresh` (regenerate from spec), `mutate` (probabilistic subtree replacement via `mutate_tree()`), or `violate` (intentional constraint breaking via `violate_tree()`).
- **`violate_tree(node)`** — traverses the CFG tree and intentionally breaks constraints at each node type: out-of-range integers, wrong-length sequences, malformed hex, invalid characters for string fields, and field count overflow/underflow for objects. This directly targets logic bugs that only appear at boundary inputs.

### 2. Mutation Engine (`mutation_engine.py`)

Two tiers of mutation:

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

Executes any target as a subprocess driven entirely by YAML config. All target-specific logic lives in the YAML file.

- Supports `arg`, `stdin`, and `file` input modes
- Cross-platform binary resolution: reads OS-keyed paths (`linux`, `mac`, `windows`) from YAML
- Optionally appends `--show-coverage` flag for instrumented targets when `coverage_enabled: true`
- Runs both the **buggy** binary and an optional **reference** binary side-by-side for differential testing

### 4. Bug Oracle (`bug_oracle.py`)

Ten-stage classification pipeline applied to every execution result. Stages are evaluated in priority order; the first match wins:

1. **TIMEOUT** — process was killed by the runner
2. **PERFORMANCE** — `"performance bug"` or `PerformanceBug` keyword in output
3. **INVALIDITY** — `"invalidity"` or `"ValidityBug"` keyword
4. **VALIDITY** — `"validity"` or `ValidityBug` keyword
5. **SYNTACTIC** — `"syntax error"`, `AddrFormatError`, or `"syntactic"` keyword
6. **FUNCTIONAL** — `"functional"` or `FunctionalBug` keyword
7. **BOUNDARY** — `"boundary"` or `BoundaryBug` keyword
8. **BONUS** — `"bonus"` keyword, or any YAML-defined `bug_keywords` match (catches untracked exceptions)
9. **RELIABILITY** — non-zero exit code with no structured output; also triggered by `ReliabilityBug` keyword
10. **MISMATCH** — differential oracle: normalised buggy output diverges from reference output

Bug deduplication uses a 16-char MD5 hash of a`(bug_type, exception_class, line_number)` tuple. Excluding the exception message text ensures that the same underlying bug triggered by many different inputs is counted as a single unique bug.

### 5. Coverage Tracker (`coverage_tracker.py`)

Two modes controlled by `tracking_mode` in the YAML:

**`code_execution` (json_decoder):**
Real coverage via Python's `coverage` library. `json_decoder` is instrumented with `--show-coverage`, which prints cumulative line/branch/combined percentages after each execution. These are parsed by `_extract_coverage_percentages()` and fed into the tracker. New coverage is detected when statement coverage percentage increases.

**`behavioral` (ipv4, ipv6, cidrize):**
Blackbox proxy coverage using two signals: unique bug keys seen so far, and a behavioral output signature computed by `_compute_output_signature()`.

Additional tracking features:
- Plateau detection: if no new coverage is found for 500 consecutive iterations, `is_plateau` is set, which the main loop can use to trigger corpus diversification
- Item geometry tracking: `levels` (max input depth), `own_finds`, `pending`, `pend_fav` — compatible with AFL's terminal display format

### 6. Bug Logger (`bug_logger.py`)

Each fuzzing session creates a `FuzzLogger` with a timestamped `run_id`. It writes to three files:
- `results/<target>_bugs.csv` — flat deduplicated bug log appended across all runs
- `results/<target>/<run_id>/all_runs.csv` — one row per iteration (for throughput analysis)
- `results/<target>/<run_id>/stats.csv` — periodic snapshots of runs/bugs/corpus/rps
- `results/<target>/<run_id>/tracebacks.log` — raw stdout/stderr for all non-NORMAL results
- `results/<target>/<run_id>/bug_inputs/` — the triggering input saved as a `.txt` file for each unique bug

The logger also tracks `_first_by_type`: one representative `BugResult` per `BugType`, used by the report generator to surface one clean example per bug category.

Uploads to Firestore are fired on every unique bug and on every stats snapshot.

### 7. Firestore Integration (`firestore_client.py`)

Two separate Firebase apps are initialised from credentials files in the project root:

- **Archive DB** (`firebase-credentials.json`) — permanent record of all bugs across all runs, never cleared
- **Current DB** (`firebase-credentials-current.json`) — cleared at the start of each new run via `clear_current_db()`; holds only the latest session

The archive DB is used by `report_generator.py` with a **local cache** (`results/firestore_cache.json`) to minimise Firestore reads — on subsequent runs only newly added documents are fetched.

### 8. Report Generator (`report_generator.py`)

Generates a self-contained `<target>_report.html` per target. Data is split into two scopes:

- **All-time** (deduped across all runs from the bug CSV): displayed in the overview card and ablation study
- **Current run** (most recent `run_id` only): displayed in the coverage graph, recent bugs table, and bug report cards

Report sections:

- Overview card: total unique bugs (all-time), current-run stats, run ID
- Ablation study: unique bugs broken down by mutation strategy
- Coverage over time: statement, branch, and function coverage plotted against iteration count
- Recent bugs table: sortable, scoped to current run
- Bug report cards: one per representative bug type, showing triggering input, stdout/stderr excerpt, and returncode

The Firestore cache (`results/firestore_cache.json`) stores the last fetched timestamp so subsequent refreshes only pull newly added documents, avoiding repeated full collection scans.

---

## Key Design Choices

### YAML-Driven Target Configuration

All target-specific logic (binary paths, input mode, seeds path, coverage flag, bug keywords, output pattern, grammar spec) lives in YAML files. The engine has zero hardcoded target knowledge — adding a new target requires only a new YAML file.

### AFL-Style Energy Scheduling

Rather than selecting mutations uniformly at random, strategies that find new coverage are boosted in weight. All weights decay each iteration to prevent premature convergence. This mirrors AFL's core insight: spend more time on strategies that are actually finding new paths.

### CFG Tree Mutations

Grammar-aware mutation operates directly on a derivation tree rather than the string representation. This allows structurally meaningful mutations (subtree replacement, count violation, type corruption) that would be extremely unlikely to arise from random byte-level mutations on format-sensitive inputs like IP addresses.

### Dual Oracle Strategy

For targets with a reference binary, we use differential testing: if the buggy binary's normalised output diverges from the reference for the same input, it's flagged as a `MISMATCH` bug. This catches semantic bugs that do not produce any exception or non-zero exit code.

### Behavioral Output Signatures (Blackbox Coverage)
For blackbox targets where source instrumentation is not possible, we treat unique (exit-code-class, stdout-class, stderr-class) triples as distinct program paths. The class extraction in `_extract_output_class()` strips specific values (IP addresses, error messages) and retains structural labels, so two inputs that exercise the same code path produce the same signature even if their output values differ.

### Corpus Growth

Inputs that trigger new coverage are added to the corpus and can be selected as seeds for future mutations. This ensures the fuzzer progressively explores paths discovered by earlier iterations rather than repeatedly mutating from the same starting points.

### Bug Deduplication by Signature

Rather than hashing on input data (which would count every unique triggering input as a new bug), we hash the `(bug_type, exception_class, line_number)` tuple. This collapses many inputs triggering the same underlying bug into a single unique entry.

---

## Implementation Challenges

### 1. Coverage Measurement for Blackbox Targets

`ipv4_parser`, `ipv6_parser`, and `cidrize` are opaque binaries — we cannot instrument them directly. We implemented the behavioral output signature as a proxy, clearly labelled `proxy` in the coverage CSV and report. True statement/branch/function coverage is only available for `json_decoder`.

### 2. Firestore Read Costs

Initially, `report_generator.py` streamed all documents from Firestore on every background refresh. With 1000+ bugs accumulated, this was ~1000 reads per refresh, hitting Firestore's no-cost limits quickly. The fix was a local JSON cache (`results/firestore_cache.json`) that records the last fetched timestamp and only queries documents newer than that timestamp on subsequent refreshes.

### 3. Bug Over-counting

Early versions counted every unique input triggering a bug as a separate bug, producing hundreds of "unique" entries for `json_decoder`. The fix was to exclude the exception message from the deduplication hash — since the same underlying bug (e.g. `ParseException`) produces different messages for different inputs, only the exception class and line number are used as the dedup key.

---

## Experiments & Results

### RQ1 — Effectiveness

**Unique bugs found (after deduplication):**

| Target       | Total Logged | Unique Bugs | Bug Types Found                                         |
| ------------ | ------------ | ----------- | ------------------------------------------------------- |
| json_decoder | 946          | ~8–12       | INVALIDITY, RELIABILITY, BONUS, PERFORMANCE             |
| cidrize      | 32           | 12          | RELIABILITY, FUNCTIONAL, INVALIDITY, PERFORMANCE, BONUS |
| ipv4_parser  | 124          | ~10–15      | INVALIDITY, RELIABILITY, FUNCTIONAL, BONUS              |
| ipv6_parser  | 57           | ~8–10       | BONUS, INVALIDITY, RELIABILITY                          |

**Coverage achieved (json_decoder, instrumented):**



### RQ2 — Efficiency



### RQ3 — Ablation Study



### RQ4 — Stability



---

## Lessons Learned

- Our team had several issues with bug deduplication across project meetings 2 and 3 as we did not understand how we should define ‘deduplication’ correctly according to what our professor is looking for. Our first approach was to hash the input data to identify unique bugs, but that turned out to be wrong. A single ParseException would get triggered by hundreds of different inputs, each producing a slightly different error message, and we ended up with hundreds of “unique” bugs. What we learned after project meeting 3 was that what makes two bugs the same is not the input that triggers them, but the code path they exercise. Hence we switched to hashing (bug_type, exception_class, line_number) instead. That collapsed everything down to a much more honest count. In hindsight, we should have thought and clarified what “uniqueness” actually means at the start as this should be one of the first design decisions we nail down, not something we fix halfway through.


---

## Setup & Usage

### Prerequisites

Ensure requirements.txt is in the project root folder.
```bash
pip install -r requirements.txt
```

Place `firebase-credentials.json` and `firebase-credentials-current.json` in the parent directory of `forza/`.

### Running the Fuzzer

Note: Run the following command before every fuzzing session
```bash
rm ../json-decoder/logs/bug_counts.csv
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

### Output Files

| Path                                       | Contents                                           |
| ------------------------------------------ | -------------------------------------------------- |
| `results/<target>_bugs.csv`                | All unique bugs found, one row per unique `bug_key`, appended across runs  |
| `results/<target>_coverage.csv`            | Per-iteration coverage snapshots: statement, branch, function, map density |
| `results/<target>/<run_id>/stats.csv`      | Periodic throughput and bug count snapshots                 |
| `results/<target>/<run_id>/tracebacks.log` | Raw stdout/stderr for all non-NORMAL results       |
| `results/<target>_report.html`             | Full HTML report with charts and bug details       |
| `results/firestore_cache.json`             | Local cache of Firestore data to minimise reads    |