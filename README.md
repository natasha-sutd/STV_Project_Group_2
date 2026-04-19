# 50.053 SOFTWARE TESTING AND VERIFICATION PROJECT GROUP 2

A fuzzer built from scratch to detect seeded bugs in four Python targets: `json_decoder`, `cidrize`, `ipv4_parser`, and `ipv6_parser`. The fuzzer implements AFL-style energy-based mutation, grammar-aware seed generation, differential oracle testing, and HTML reporting backed by Firebase Firestore.

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
│   └── sample.yaml            # Sample yaml structure for new target
├── engine/
│   ├── types.py               # Shared types: BugType enum, BugResult dataclass
│   ├── target_runner.py       # Subprocess runner — executes targets, captures output
│   ├── mutation_engine.py     # AFL-style weighted mutation with grammar support
│   ├── seed_generator.py      # Grammar-based seed generation from YAML spec
│   ├── bug_oracle.py          # Classifies output into bug types
│   ├── coverage_tracker.py    # Tracks coverage (instrumented or behavioral proxy)
│   ├── bug_logger.py          # Writes bugs to CSV and uploads to Firestore
│   ├── firestore_client.py    # Firebase Firestore client (archive + current DBs)
│   └── report_generator.py    # Generates report.html from CSV/Firestore data
├── results/
│   ├── *_bugs.csv             # Deduplicated bug log per target
│   ├── *_coverage.csv         # Coverage snapshots per target
│   └── *_report.html          # Generated HTML report per target

```

---

## Design Overview

Our fuzzer's overall design is as follows:

```
1. Orchestrator picks a seed
        ↓
2. Mutation engine modifies it
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

### External Libraries Used

| Libraries             | Description                                                                           |
| --------------------- | ------------------------------------------------------------------------------------- |
| `Radamsa`             | Specializes in generating extreme cases without needing to know code structure        |
| `PyPYAML`             | Defines how each target is executed in separate YAML files. Promotes extensibility by allowing new targets to be added without modifying the core fuzzer logic  |

---

### What We Built Ourselves

Every component in `engine/` was written from scratch:

| Component             | Description                                                                           |
| --------------------- | ------------------------------------------------------------------------------------- |
| `mutation_engine.py`  | AFL-style weighted strategy selection, energy boosting/decay, grammar-aware mutations |
| `seed_generator.py`   | Grammar-driven seed generation and constraint violation from YAML spec                |
| `bug_oracle.py`       | Multi-stage classifier: timeout → crash → keyword → differential → normal             |
| `coverage_tracker.py` | Dual-mode tracker (instrumented for json_decoder, behavioral proxy for blackbox)      |
| `bug_logger.py`       | Per-run deduplication using MD5 hash keys, CSV logging, Firestore upload              |
| `firestore_client.py` | Dual Firestore setup (archive + current), singleton pattern                           |
| `report_generator.py` | Full HTML report with RQ1 charts, coverage graphs, ablation study, bug reports        |
| `fuzzer.py`           | Main loop with AFL-style terminal UI, graceful shutdown, background report refresh    |

---

## Design Details

### 1. Seed Generator (`seed_generator.py`)

Generates initial corpus entries from a grammar specification defined in the YAML `input:` block. Supports: `int`, `hex`, `string`, `boolean`, `null`, `any`, `literal`, `array`, `object`, `sequence`, `one_of`, `weighted_one_of`.

Also exposes `mutate_from_spec()` and `violate_constraints()` used by the mutation engine for grammar-aware fuzzing.

### 2. Mutation Engine (`mutation_engine.py`)

Two tiers of mutation:

**Generic (format-agnostic):**

- `bit_flip` — flips a random bit in a random character
- `truncate` — cuts the input at a random position
- `insert_special_char` — injects null bytes, overflow bait, shell characters
- `repeat_chunk` — duplicates a slice to stress length handling
- `byte_insert` — inserts random printable ASCII
- `swap_chars` — swaps two random characters
- `radamsa` — external fuzzer (optional, skipped if not installed)

**Grammar-aware (when YAML `input:` spec is present):**

- `grammar_mutate` — calls `seed_generator.mutate_from_spec()` for structurally valid variants
- `constraint_violation` — calls `seed_generator.violate_constraints()` to intentionally break grammar rules (wrong IP octet range, bad field count, etc.)

Each strategy has a **weight**. Strategies that find new coverage get their weight boosted (×1.5). All weights decay each iteration (×0.95) to prevent one strategy dominating — this is the AFL energy scheduling model.

### 3. Target Runner (`target_runner.py`)

Executes any target as a subprocess using a YAML config. All target-specific logic lives in the YAML.

- Supports `arg`, `stdin`, and `file` input modes
- Cross-platform: resolves Windows/Mac/Linux binary paths from YAML
- Appends `--show-coverage` flag for instrumented targets when `coverage_enabled: true`
- Runs both the **buggy** binary and an optional **reference** binary (for differential testing)

### 4. Bug Oracle (`bug_oracle.py`)

Ten-stage classification pipeline applied to every execution result:

1. **TIMEOUT** — process was killed by the runner
2. **Structured bug count** — parses `json_decoder`'s "Final bug count" line for exact category/type/message
3. **INVALIDITY** — `ParseException` keyword in output
4. **SYNTACTIC** — `AddrFormatError` / `SyntaxError` (cidrize)
5. **FUNCTIONAL** — `FunctionalBug` keyword
6. **BONUS** — unexpected untracked exceptions
7. **Generic keyword fallback** — YAML-defined `bug_keywords`
8. **RELIABILITY** — non-zero exit code with no structured output
9. **MISMATCH** — differential oracle: output diverges from reference binary
10. **NORMAL** — no bug signal

Bug deduplication uses a stable 12-char MD5 hash of `(bug_type, exception_type)` — excluding the message text to avoid counting the same bug triggered by different inputs as multiple unique bugs.

### 5. Coverage Tracker (`coverage_tracker.py`)

Two modes controlled by `tracking_mode` in the YAML:

**`code_execution` (json_decoder):**
Real coverage via Python's `coverage` library. `json_decoder` is run with `--show-coverage` which prints accumulated line/branch/combined percentages after each execution. These are parsed by `_extract_coverage_percentages()` using regex and logged as `instrumented` data. Coverage is cumulative — each input adds to a shared `.coverage_buggy_json` file.

**`behavioral` (ipv4, ipv6, cidrize):**
Blackbox proxy — counts unique bug keys seen so far as a diversity metric. Not true code coverage. The formula `min(100, unique_bugs × 2.0)` is a rough estimate only and is clearly labelled `proxy` in the CSV.

### 6. Bug Logger (`bug_logger.py`)

Each fuzzing session creates a `FuzzLogger` with a timestamped `run_id`. Unique bugs are written to a flat `<target>_bugs.csv` (appended across runs, with `run_id` column for filtering). Periodic stats snapshots are written to `results/<target>/<run_id>/stats.csv`.

### 7. Firestore Integration (`firestore_client.py`)

Two separate Firebase apps:

- **Archive DB** — permanent record of all bugs across all runs, never cleared
- **Current DB** — cleared on each new run, holds only the latest session

The archive DB is used by `report_generator.py` with a **local cache** (`results/firestore_cache.json`) to minimise Firestore reads — on subsequent runs only newly added documents are fetched.

### 8. Report Generator (`report_generator.py`)

Generates a self-contained `report.html` covering:

- Global overview stats
- Per-target summary cards with bug type breakdown
- **RQ1 charts**: unique bugs vs wall clock time, unique bugs vs number of tests
- Ablation study: bugs per mutation strategy
- Coverage over time (statement, branch, function) — with dynamic y-axis scaling
- Recent bugs table and detailed bug report cards

---

## Key Design Choices

### YAML-Driven Target Configuration

All target-specific logic (binary paths, input mode, seeds path, coverage flag, bug keywords, output pattern) lives in YAML files. The fuzzer engine has zero hardcoded target knowledge — adding a new target requires only a new YAML file.

### AFL-Style Energy Scheduling

Rather than selecting mutations uniformly at random, strategies that find new coverage are rewarded with higher selection probability. This is the core insight from AFL — spending more time on productive strategies. The decay mechanism prevents premature convergence on a single strategy.

### Dual Oracle Strategy

For targets with a reference binary, we use **differential testing** — if the buggy binary's output diverges from the reference for the same input, it's flagged as a `MISMATCH` bug. This catches bugs that don't raise explicit exceptions.

### Corpus Growth

Inputs that trigger new coverage are added to the corpus and can be selected as seeds for future mutations. This ensures the fuzzer explores paths discovered by previous iterations.

### Deduplication by Bug Signature

Rather than hashing on input data (which would make every unique input a new bug), we hash on `(bug_type, exception_class)`. This collapses many inputs triggering the same underlying bug into a single unique entry.

---

## Implementation Challenges

### 1. Coverage Measurement for Blackbox Targets

`ipv4_parser`, `ipv6_parser`, and `cidrize` are compiled/opaque binaries — we have no access to their source code and cannot instrument them. We implemented a behavioral proxy metric (unique bug keys) as a substitute, clearly labelled as `proxy` in the CSV and report. True statement/branch/function coverage is only available for `json_decoder`.

### 2. Firestore Read Costs

Initially, `report_generator.py` streamed all documents from Firestore on every background refresh (every 5 minutes). With 1000+ bugs accumulated, this was ~1000 reads per refresh, hitting Firestore's no-cost limits quickly. Fixed by implementing a local JSON cache that only fetches documents newer than the last cached timestamp.

### 3. Bug Over-counting

Early versions counted every unique input that triggered a bug as a separate bug, resulting in 900+ "unique" bugs for `json_decoder`. The fix was to exclude `exc_msg` from the deduplication hash — since the same underlying bug (e.g. `ParseException`) produces different messages for different inputs, only the exception class is used as the dedup key.

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



---

## Setup & Usage

### Prerequisites

```bash
pip install firebase-admin pyyaml coverage pandas
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

# Or use VS Code Live Server extension
```

### Output Files

| Path                                       | Contents                                           |
| ------------------------------------------ | -------------------------------------------------- |
| `results/<target>_bugs.csv`                | All unique bugs found, one row per unique bug_key  |
| `results/<target>_coverage.csv`            | Coverage snapshots per iteration, tagged by run_id |
| `results/<target>/<run_id>/stats.csv`      | Throughput and bug count over time                 |
| `results/<target>/<run_id>/tracebacks.log` | Raw stdout/stderr for all non-NORMAL results       |
| `results/<target>_report.html`             | Full HTML report with charts and bug details       |
| `results/firestore_cache.json`             | Local cache of Firestore data to minimise reads    |
