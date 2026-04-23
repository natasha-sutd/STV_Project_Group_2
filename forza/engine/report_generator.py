"""
Reads the CSVs produced by bug_logger.py and generates a human-readable summary report.
"""

from __future__ import annotations
from datetime import timezone
import json as _json_mod

import argparse
import csv
import webbrowser
from collections import Counter
from datetime import datetime
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = ENGINE_DIR.parent
RESULTS_DIR = PROJECT_DIR / "results"
_CACHE_PATH = RESULTS_DIR / "firestore_cache.json"


# Data loading
def load_csv(target: str) -> list[dict]:
    csv_path = RESULTS_DIR / f"{target}_bugs.csv"
    if not csv_path.exists():
        return []
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def load_coverage_csv(target: str) -> list[dict]:
    csv_path = RESULTS_DIR / f"{target}_coverage.csv"
    if not csv_path.exists():
        return []
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return []
    latest_run = max(r.get("run_id", "") for r in rows)
    return [r for r in rows if r.get("run_id") == latest_run]


def _normalise_row(row: dict) -> dict:
    ts = row.get("timestamp")
    if ts and hasattr(ts, "strftime"):
        row["_ts_iso"] = ts.isoformat()
        row["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
    row["timed_out"] = str(row.get("timed_out", False)).lower()
    row["crashed"] = str(row.get("crashed",   False)).lower()
    return row


def _load_from_firestore(targets: list[str]) -> tuple[dict[str, list[dict]], int] | None:
    """
    Fetch bugs from Firestore using a local cache to minimise reads.

    First run: fetches all documents, saves to results/firestore_cache.json.
    Later runs: only fetches documents newer than the cached last_timestamp, merges with cache, and updates the cache file.

    Returns (bug_data, total_ever) where total_ever is the cumulative count
    persisted across cache resets so the report always shows the true total.

    Use local CSV if Firestore is unavailable.
    """
    try:
        from engine.firestore_client import get_archive_db
    except ImportError:
        return None

    db = get_archive_db()
    if db is None:
        return None

    try:
        cached_bugs: dict[str, list[dict]] = {t: [] for t in targets}
        last_timestamp: str | None = None
        seen_keys: set[str] = set()

        if _CACHE_PATH.exists():
            try:
                with open(_CACHE_PATH, encoding="utf-8") as f:
                    cache_data = _json_mod.load(f)
                for t in targets:
                    cached_bugs[t] = cache_data.get("bugs", {}).get(t, [])
                last_timestamp = cache_data.get("last_timestamp")
                seen_keys = set(cache_data.get("seen_keys", []))
                # backfill seen_keys from cached bugs if cache predates this field
                if not seen_keys:
                    for rows in cached_bugs.values():
                        for r in rows:
                            k = r.get("bug_key", "")
                            if k:
                                seen_keys.add(k)
            except Exception:
                pass  # corrupted cache — refetch everything

        # query only new docs
        query = db.collection("bugs")
        if last_timestamp:
            from datetime import datetime
            dt = datetime.fromisoformat(
                last_timestamp).replace(tzinfo=timezone.utc)
            try:
                from google.cloud.firestore_v1.base_query import FieldFilter
                query = query.where(filter=FieldFilter("timestamp", ">", dt))
            except ImportError:
                query = query.where("timestamp", ">", dt)

        new_docs = list(query.stream())

        result: dict[str, list[dict]] = {
            t: list(cached_bugs[t]) for t in targets}
        newest_ts = last_timestamp

        for doc in new_docs:
            row = _normalise_row(doc.to_dict())
            ts_iso = row.pop("_ts_iso", None)
            if ts_iso and (newest_ts is None or ts_iso > newest_ts):
                newest_ts = ts_iso
            k = row.get("bug_key", "")
            if k:
                seen_keys.add(k)
            target = row.get("target", "")
            if target in result:
                result[target].append(row)

        total_ever = len(seen_keys)

        # save updated cache
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        with open(_CACHE_PATH, "w", encoding="utf-8") as f:
            _json_mod.dump({
                "bugs": {t: result[t] for t in targets},
                "last_timestamp": newest_ts,
                "seen_keys": list(seen_keys),
                "total_ever": total_ever,
            }, f)

        return result, total_ever

    except Exception as e:
        print(f"[report_generator] Firestore fetch failed: {e}")
        return None


# Module-level total_ever so generate_report can access it
_total_ever: int | None = None


def load_all(targets: list[str], use_firestore: bool = True) -> dict[str, list[dict]]:
    """Try Firestore first, fall back to local CSVs if unavailable."""
    global _total_ever
    if use_firestore:
        firestore_result = _load_from_firestore(targets)
        if firestore_result is not None:
            data, total_ever = firestore_result
            _total_ever = total_ever
            return data
    return {t: load_csv(t) for t in targets}


def load_all_coverage(targets: list[str]) -> dict[str, list[dict]]:
    return {t: load_coverage_csv(t) for t in targets}


def summarise(rows: list[dict]) -> dict:
    total = len(rows)
    by_type = Counter(r.get("bug_type", "unknown") for r in rows)
    by_strategy = Counter(r.get("strategy",  "unknown") for r in rows)
    timeouts = sum(1 for r in rows if str(
        r.get("timed_out", "")).lower() == "true")
    crashes = sum(1 for r in rows if str(
        r.get("crashed",   "")).lower() == "true")
    unique_keys = len({r.get("bug_key", "") for r in rows})
    return dict(
        total=total,
        by_type=dict(by_type),
        by_strategy=dict(by_strategy),
        timeouts=timeouts,
        crashes=crashes,
        unique_keys=unique_keys,
    )

# HTML helper functions
def _esc(s) -> str:
    s = str(s) if not isinstance(s, str) else s
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _pill(row: dict) -> str:
    bt = row.get("bug_type", "").lower()
    label = _esc(row.get("bug_type", "unknown"))
    if "crash" in bt:
        return f'<span class="pill pill-crash">{label}</span>'
    if "timeout" in bt:
        return f'<span class="pill pill-timeout">{label}</span>'
    if "keyword" in bt:
        return f'<span class="pill pill-keyword">{label}</span>'
    if "diff" in bt:
        return f'<span class="pill pill-diff">{label}</span>'
    return f'<span class="pill pill-error">{label}</span>'


def _badge(total: int, has_data: bool) -> str:
    if not has_data:
        return '<span class="badge muted">no data</span>'
    if total == 0:
        return '<span class="badge ok">clean</span>'
    if total >= 10:
        return f'<span class="badge danger">{total} bugs</span>'
    return f'<span class="badge warn">{total} bugs</span>'


def _target_label(t: str) -> str:
    return t.replace("_", " ").title()


def _bar_row(key: str, count: int, maximum: int) -> str:
    pct = round(count / maximum * 100) if maximum else 0
    return (
        f'<div class="breakdown-row">'
        f'  <span class="breakdown-key">{_esc(key)}</span>'
        f'  <div class="breakdown-bar-wrap">'
        f'    <div class="breakdown-bar" style="width:{pct}%"></div>'
        f'  </div>'
        f'  <span class="breakdown-count">{count}</span>'
        f'</div>'
    )


# Section renderers
def render_overview_card(target: str, rows: list[dict]) -> str:
    summary = summarise(rows)
    has_data = len(rows) > 0
    total = summary["total"]
    card_cls = "card has-bugs" if total > 0 else (
        "card no-data" if not has_data else "card")
    badge = _badge(total, has_data)
    n_timeouts = summary["timeouts"]
    n_unique = summary["unique_keys"]

    cs_total = f'<div class="cs"><div class="v {"d" if total > 0 else ""}" data-count="{total}">{total}</div><div class="l">bugs</div></div>'
    cs_timeouts = f'<div class="cs"><div class="v {"w" if n_timeouts > 0 else ""}" data-count="{n_timeouts}">{n_timeouts}</div><div class="l">timeouts</div></div>'
    cs_unique = f'<div class="cs"><div class="v" data-count="{n_unique}">{n_unique}</div><div class="l">unique</div></div>'

    by_type = summary["by_type"]
    max_count = max(by_type.values(), default=1)
    type_rows = "".join(
        _bar_row(bt, cnt, max_count)
        for bt, cnt in sorted(by_type.items(), key=lambda x: -x[1])
    )

    breakdown = (
        f'<div class="breakdown">{type_rows}</div>'
        if type_rows
        else (
            '<div class="no-data-msg">no CSV data found for this target</div>'
            if not has_data
            else '<div class="no-data-msg">no bugs detected</div>'
        )
    )

    return f"""
<div class="{card_cls}">
  <div class="card-accent-bar"></div>
  <div class="card-header">
    <div>
      <div class="card-title">{_target_label(target)}</div>
      <div class="card-target-id">{target}</div>
    </div>
    {badge}
  </div>
  <div class="card-stats">
    {cs_total}{cs_timeouts}{cs_unique}
  </div>
  {breakdown}
</div>"""


def render_ablation_section(all_data: dict[str, list[dict]], targets: list[str]) -> str:
    """
    Ablation study: which mutation strategies found the most bugs?
    Stacked bar chart (Chart.js) + per-target breakdown table.
    """
    import json as _json

    global_strategy: Counter = Counter()
    per_target_strategy: dict[str, Counter] = {}
    for t in targets:
        c = Counter(r.get("strategy", "unknown") for r in all_data[t])
        per_target_strategy[t] = c
        global_strategy.update(c)

    if not global_strategy:
        return ""

    strategies = [s for s, _ in global_strategy.most_common()]
    labels_js = _json.dumps(strategies)
    palette = ["#00ff88", "#45aaf2", "#ffd32a", "#ff4757"]
    datasets = []
    for i, t in enumerate(targets):
        c = per_target_strategy[t]
        col = palette[i % len(palette)]
        datasets.append({
            "label": _target_label(t),
            "data":  [c.get(s, 0) for s in strategies],
            "backgroundColor": col + "cc",
            "borderColor":     col,
            "borderWidth": 1,
        })
    datasets_js = _json.dumps(datasets)

    table_rows = ""
    for t in targets:
        c = per_target_strategy[t]
        if not c:
            continue
        for strat, cnt in c.most_common():
            pct = round(cnt / sum(c.values()) * 100) if c else 0
            table_rows += (
                f"<tr>"
                f"<td>{_target_label(t)}</td>"
                f"<td class='mono'>{_esc(strat)}</td>"
                f"<td class='mono num'>{cnt}</td>"
                f"<td class='mono num'>{pct}%</td>"
                f"</tr>"
            )

    return f"""
<div class="section-title">ablation study — strategy effectiveness</div>
<div class="ablation-wrap">
  <div class="chart-box" style="border:none;padding:0;margin-bottom:1.5rem;">
    <div class="chart-label">bugs found per mutation strategy (stacked by target)</div>
    <div style="position:relative;height:260px;">
      <canvas id="ablationChart"></canvas>
    </div>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>target</th><th>strategy</th><th>bugs found</th><th>% of target bugs</th></tr></thead>
      <tbody>{table_rows if table_rows else '<tr><td colspan="4" class="no-data-msg-td">no strategy data yet</td></tr>'}</tbody>
    </table>
  </div>
</div>
<script>
(function(){{
  var ctx = document.getElementById('ablationChart');
  if (!ctx) return;
  new Chart(ctx, {{
    type: 'bar',
    data: {{ labels: {labels_js}, datasets: {datasets_js} }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      plugins: {{
        legend: {{ labels: {{ color: '#c8d6e5', font: {{ family: "'Share Tech Mono'" }}, boxWidth: 12 }} }}
      }},
      scales: {{
        x: {{ stacked: true, ticks: {{ color: '#718096', font: {{ family: "'Share Tech Mono'", size: 11 }} }}, grid: {{ color: '#1e2330' }} }},
        y: {{ stacked: true, beginAtZero: true, ticks: {{ color: '#718096', font: {{ family: "'Share Tech Mono'", size: 11 }}, stepSize: 1 }}, grid: {{ color: '#1e2330' }} }}
      }}
    }}
  }});
}})();
</script>"""


def render_coverage_section(all_coverage: dict[str, list[dict]], targets: list[str]) -> str:
    """
    Coverage over time: line charts per metric showing how coverage grows
    as the fuzzer tests more inputs (in-vivo, from coverage_tracker.py).
    """
    import json as _json

    has_any = any(all_coverage[t] for t in targets)
    if not has_any:
        return f"""
<div class="section-title">coverage over time</div>
<div class="no-coverage-msg">
  <span class="nc-icon">◇</span>
  <div>
    <div class="nc-title">no coverage data yet</div>
    <div class="nc-sub">
      <code>coverage_tracker.py</code> needs to write
      <code>results/&lt;target&gt;_coverage.csv</code> during the fuzzing run (in-vivo).<br/>
      Expected columns: <code>timestamp, statement_coverage, branch_coverage, function_coverage, total_inputs</code>
    </div>
  </div>
</div>"""

    palette = ["#00ff88", "#45aaf2", "#ffd32a", "#ff4757"]
    metrics = [
        ("statement_coverage", "statement coverage (%)"),
        ("branch_coverage",    "branch coverage (%)"),
        ("function_coverage",  "function coverage (%)"),
    ]
    rows_html = ""

    for i, t in enumerate(targets):
        t_rows = all_coverage[t]
        if not t_rows:
            continue
        col = palette[i % len(palette)]

        metric_cards = ""
        for metric, metric_label in metrics:
            data_pts = []
            for r in t_rows:
                try:
                    data_pts.append({"x": float(r.get("total_inputs", 0)),
                                     "y": round(float(r.get(metric, 0)), 2)})
                except (ValueError, TypeError):
                    continue
            if not data_pts:
                continue

            chart_id = f"cov_{t}_{metric}"
            dataset = {
                "label": metric_label,
                "data":  data_pts,
                "borderColor": col,
                "backgroundColor": col + "22",
                "fill": True, "tension": 0,
                "pointRadius": 0, "borderWidth": 1.5,
            }
            dataset_js = _json.dumps([dataset])

            all_y = [pt["y"] for pt in data_pts]
            if all_y:
                y_min = max(0.0, round(min(all_y) - 5, 1))
                y_max = min(100.0, round(max(all_y) + 5, 1))
            else:
                y_min, y_max = 0, 100

            metric_cards += f"""
<div class="chart-box">
  <div class="chart-label">{metric_label}</div>
  <div style="position:relative;height:200px;">
    <canvas id="{chart_id}"></canvas>
  </div>
</div>
<script>
(function(){{
  var ctx = document.getElementById('{chart_id}');
  if (!ctx) return;
  new Chart(ctx, {{
    type: 'line',
    data: {{ datasets: {dataset_js} }},
    options: {{
      responsive: true, maintainAspectRatio: false, parsing: false,
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{
          type: 'linear',
          title: {{ display: true, text: 'inputs tested', color: '#4a5568', font: {{ family: "'Share Tech Mono'", size: 10 }} }},
          ticks: {{ color: '#718096', font: {{ family: "'Share Tech Mono'", size: 10 }} }},
          grid:  {{ color: '#1e2330' }}
        }},
        y: {{
          min: {y_min}, max: {y_max},
          ticks: {{ color: '#718096', font: {{ family: "'Share Tech Mono'", size: 10 }}, callback: function(v){{ return v+'%'; }} }},
          grid:  {{ color: '#1e2330' }}
        }}
      }}
    }}
  }});
}})();
</script>"""

        if not metric_cards:
            continue

        rows_html += f"""
<div>
  <div class="coverage-row-title">{_target_label(t)}</div>
  <div class="coverage-row">{metric_cards}</div>
</div>"""

    return f"""
<div class="section-title">coverage over time</div>
<div class="coverage-grid">{rows_html}</div>"""


def render_bug_table(rows: list[dict], target: str) -> str:
    """Recent bugs table — newest first, max 50 rows."""
    if not rows:
        return ""
    label = _target_label(target)
    display = list(reversed(rows[-50:]))
    trows = "".join(
        f"<tr>"
        f"<td>{_pill(r)}</td>"
        f'<td class="input-cell mono" title="{_esc(r.get("input_data", "")[:80])}">{_esc(r.get("input_data", "")[:80])}</td>'
        f"<td class='mono'>{_esc(r.get('strategy', '') or '—')}</td>"
        f"<td class='mono num'>{_esc(r.get('returncode', ''))}</td>"
        f'<td class="ts-cell mono">{_esc(r.get("timestamp", "")[:19])}</td>'
        f"</tr>"
        for r in display
    )
    return f"""
<div class="section-title">{label} — recent bugs (last {min(50, len(rows))} of {len(rows)})</div>
<div class="table-wrap">
  <table>
    <thead><tr><th>type</th><th>input</th><th>strategy</th><th>rc</th><th>timestamp</th></tr></thead>
    <tbody>{trows}</tbody>
  </table>
</div>"""


def _render_target_bug_reports(t: str, rows: list[dict], bug_num_start: int) -> tuple[str, int]:
    """Render up to 11 bug report cards for a single target, one per bug type."""
    cards = ""
    bug_num = bug_num_start
    seen_types: set[str] = set()

    for r in rows:
        bug_type_key = r.get("bug_type", "unknown")
        if bug_type_key in seen_types:
            continue
        seen_types.add(bug_type_key)
        bug_num += 1

        bug_type = bug_type_key
        ts = r.get("timestamp", "unknown")[:19]
        inp = r.get("input_data", "")
        stdout = r.get("stdout", "")[:400]
        stderr = r.get("stderr", "")[:400]
        rc = r.get("returncode", "?")
        strat = r.get("strategy", "unknown")
        crashed = str(r.get("crashed", "")).lower() == "true"
        timed = str(r.get("timed_out", "")).lower() == "true"

        impact = (
            "Process crashed (non-zero/negative return code)." if crashed
            else "Execution timed out — possible infinite loop or hang." if timed
            else "Output keyword matched a known bug signature."
        )
        repro_cmd = f'python3 fuzzer.py --target {t} --input "{_esc(inp[:60])}"'
        out_block = (f'<div class="code-block">{_esc(stdout[:300])}</div>'
                     if stdout.strip() else '<span class="dim">— empty —</span>')
        err_block = (f'<div class="code-block">{_esc(stderr[:300])}</div>'
                     if stderr.strip() else '<span class="dim">— empty —</span>')

        cards += f"""
<div class="bug-report-card">
  <div class="br-header">
    <div>
      <span class="br-num">BUG-{bug_num:03d}</span>
      <span class="br-target">{_target_label(t)}</span>
    </div>
    {_pill(r)}
  </div>
  <div class="br-field">
    <span class="br-label">1. bug title</span>
    <span class="br-value">{_target_label(t)} — {_esc(bug_type)} via <em>{_esc(strat)}</em></span>
  </div>
  <div class="br-field col">
    <span class="br-label">2. bug description</span>
    <div class="br-desc">
      <div>Type: {_pill(r)} &nbsp;|&nbsp; Return code: <code>{_esc(str(rc))}</code> &nbsp;|&nbsp; Detected: <code>{_esc(ts)}</code></div>
      <div class="impact">{impact}</div>
    </div>
  </div>
  <div class="br-field col">
    <span class="br-label">3. reproduction steps</span>
    <div class="br-desc">
      <div>Strategy used: <code>{_esc(strat)}</code></div>
      <div class="code-block">{_esc(repro_cmd)}</div>
    </div>
  </div>
  <div class="br-field col">
    <span class="br-label">4. proof of concept (PoC)</span>
    <div class="br-desc">
      <div class="poc-grid">
        <div><div class="poc-label">input</div><div class="code-block">{_esc(inp[:200])}</div></div>
        <div><div class="poc-label">stdout</div>{out_block}</div>
        <div><div class="poc-label">stderr</div>{err_block}</div>
      </div>
    </div>
  </div>
  <div class="br-field">
    <span class="br-label">5. attachments</span>
  </div>
</div>"""

    return cards, bug_num


def render_bug_reports(all_data: dict[str, list[dict]], targets: list[str]) -> str:
    """
    Appendix: structured bug reports matching the rubric format.
    One representative card per bug type per target (max 11 per target).
    Targets are grouped under their own section header.
    """
    all_sections = ""
    bug_num = 0

    for t in targets:
        rows = all_data[t]
        if not rows:
            continue
        target_cards, bug_num = _render_target_bug_reports(t, rows, bug_num)
        if not target_cards:
            continue
        all_sections += f"""
<div class="section-title" style="margin-top:2rem">{_target_label(t)} — bug reports</div>
<div class="bug-reports-list">{target_cards}</div>"""

    if not all_sections:
        return ""

    return f"""
<div class="section-title">appendix — structured bug reports (one per bug type per target)</div>
{all_sections}"""


# ---------------------------------------------------------------------------
# CSS + JS
# ---------------------------------------------------------------------------
_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0c0f;--surface:#111318;--border:#1e2330;
  --accent:#00ff88;--accent2:#ff4757;--accent3:#ffd32a;--accent4:#45aaf2;
  --muted:#4a5568;--text:#c8d6e5;--text-dim:#718096;
  --mono:'Share Tech Mono',monospace;--sans:'Syne',sans-serif;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;line-height:1.6;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.03) 2px,rgba(0,0,0,.03) 4px);pointer-events:none;z-index:9999}
.header{border-bottom:1px solid var(--border);padding:3rem 4rem;display:flex;align-items:flex-end;justify-content:space-between;gap:1rem;flex-wrap:wrap;position:relative;overflow:hidden}
.header::after{content:'FUZZER';position:absolute;right:-1rem;top:-1.5rem;font-family:var(--sans);font-weight:800;font-size:9rem;color:rgba(255,255,255,.018);user-select:none;letter-spacing:-4px;white-space:nowrap}
.label{font-family:var(--mono);font-size:.7rem;color:var(--accent);letter-spacing:.2em;text-transform:uppercase;margin-bottom:.4rem}
h1{font-family:var(--sans);font-weight:800;font-size:3rem;color:#fff;line-height:1.1}
.header-right{font-family:var(--mono);font-size:.85rem;color:var(--text-dim);text-align:right;line-height:1.8}
.header-right span{color:var(--text)}
.container{max-width:100%;margin:0 auto;padding:2.5rem 4rem 5rem}
.section-title{font-family:var(--mono);font-size:.75rem;letter-spacing:.3em;text-transform:uppercase;color:#fff;margin:3rem 0 1.25rem;display:flex;align-items:center;gap:.75rem}
.section-title::after{content:'';flex:1;height:1px;background:var(--border)}
.global-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);margin-bottom:2rem}
.stat-cell{background:var(--surface);padding:2rem 2rem;display:flex;flex-direction:column;gap:.35rem}
.stat-cell .val{font-family:var(--mono);font-size:3rem;color:#fff;line-height:1}
.stat-cell .val.danger{color:var(--accent2)}.stat-cell .val.warn{color:var(--accent3)}.stat-cell .val.info{color:var(--accent4)}.stat-cell .val.ok{color:var(--accent)}
.stat-cell .lbl{font-family:var(--mono);font-size:.65rem;color:var(--muted);letter-spacing:.12em;text-transform:uppercase}
.cards{display:grid;grid-template-columns:1fr;gap:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);display:flex;flex-direction:column}
.card-accent-bar{height:3px;background:var(--accent)}
.card.has-bugs .card-accent-bar{background:var(--accent2)}
.card.no-data .card-accent-bar{background:var(--muted)}
.card-header{padding:1.2rem 1.5rem .8rem;display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;border-bottom:1px solid var(--border)}
.card-title{font-weight:700;font-size:1.3rem;color:#fff}
.card-target-id{font-family:var(--mono);font-size:.65rem;color:var(--muted);margin-top:.2rem}
.badge{font-family:var(--mono);font-size:.6rem;letter-spacing:.1em;text-transform:uppercase;padding:.25rem .6rem;border:1px solid currentColor;white-space:nowrap;align-self:flex-start}
.badge.danger{color:var(--accent2)}.badge.warn{color:var(--accent3)}.badge.ok{color:var(--accent)}.badge.muted{color:var(--muted)}
.card-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border)}
.cs{background:var(--surface);padding:.8rem 1rem;display:flex;flex-direction:column;gap:.15rem}
.cs .v{font-family:var(--mono);font-size:1.8rem;color:#fff}
.cs .v.d{color:var(--accent2)}.cs .v.w{color:var(--accent3)}
.cs .l{font-family:var(--mono);font-size:.55rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}
.breakdown{padding:1rem 1.5rem;flex:1}
.breakdown-row{display:flex;align-items:center;gap:.75rem;margin-bottom:.65rem;font-family:var(--mono);font-size:.85rem}
.breakdown-key{color:var(--text-dim);min-width:160px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.breakdown-bar-wrap{flex:1;height:4px;background:var(--border)}
.breakdown-bar{height:100%;background:var(--accent)}
.card.has-bugs .breakdown-bar{background:var(--accent2)}
.breakdown-count{color:var(--text-dim);min-width:24px;text-align:right}
.no-data-msg{padding:2rem 1.5rem;font-family:var(--mono);font-size:.75rem;color:var(--muted);display:flex;align-items:center;gap:.6rem}
.no-data-msg::before{content:'//';color:var(--border)}
.ablation-wrap{background:var(--surface);border:1px solid var(--border);padding:1.5rem}
.coverage-grid{display:flex;flex-direction:column;gap:2.5rem}
.coverage-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}
.coverage-row-title{font-family:var(--mono);font-size:.6rem;letter-spacing:.2em;text-transform:uppercase;color:var(--accent4);margin-bottom:.75rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}
.chart-box{background:var(--surface);border:1px solid var(--border);padding:1.2rem 1.5rem}
.chart-label{font-family:var(--mono);font-size:.65rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase;margin-bottom:1rem}
.no-coverage-msg{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--muted);padding:1.5rem 2rem;display:flex;align-items:flex-start;gap:1.5rem;font-family:var(--mono);font-size:.75rem}
.nc-icon{font-size:1.5rem;color:var(--muted);flex-shrink:0;margin-top:.1rem}
.nc-title{color:var(--text);margin-bottom:.4rem;font-size:.8rem}
.nc-sub{color:var(--muted);line-height:1.7}
.nc-sub code{color:var(--text-dim)}
.table-wrap{overflow-x:auto;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:.85rem}
thead tr{background:#0d1017;border-bottom:1px solid var(--border)}
thead th{padding:.8rem 1.25rem;text-align:left;color:var(--muted);letter-spacing:.12em;text-transform:uppercase;font-weight:400;white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border)}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:rgba(255,255,255,.02)}
tbody td{padding:.7rem 1.25rem;color:var(--text);vertical-align:top}
.num{text-align:right}.mono{font-family:var(--mono)}
.no-data-msg-td{color:var(--muted);padding:1.2rem 1rem;font-family:var(--mono);font-size:.72rem}
.pill{display:inline-block;padding:.1rem .45rem;font-size:.6rem;border-radius:2px;letter-spacing:.05em;font-family:var(--mono)}
.pill-crash{background:rgba(255,71,87,.15);color:var(--accent2)}
.pill-timeout{background:rgba(255,211,42,.12);color:var(--accent3)}
.pill-keyword{background:rgba(0,255,136,.1);color:var(--accent)}
.pill-diff{background:rgba(69,170,242,.12);color:var(--accent4)}
.pill-error{background:rgba(100,100,100,.15);color:var(--muted)}
.input-cell{max-width:400px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--text-dim)}
.ts-cell{color:var(--muted);white-space:nowrap}
.bug-reports-list{display:flex;flex-direction:column;gap:1.5rem}
.bug-report-card{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent2)}
.bug-report-card .br-header{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;border-bottom:1px solid var(--border);gap:1rem}
.br-num{font-family:var(--mono);font-size:.7rem;color:var(--accent2);letter-spacing:.1em;margin-right:.75rem}
.br-target{font-family:var(--mono);font-size:.7rem;color:var(--text-dim)}
.br-field{display:flex;align-items:baseline;gap:1rem;padding:.7rem 1.5rem;border-bottom:1px solid var(--border)}
.br-field:last-child{border-bottom:none}
.br-field.col{flex-direction:column;gap:.5rem}
.br-label{font-family:var(--mono);font-size:.6rem;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);white-space:nowrap;min-width:180px;flex-shrink:0}
.br-value{font-family:var(--mono);font-size:.75rem;color:var(--text)}
.br-desc{font-family:var(--mono);font-size:.75rem;color:var(--text);display:flex;flex-direction:column;gap:.5rem;width:100%}
.impact{color:var(--text-dim);font-size:.7rem}
.code-block{background:#0d1017;border:1px solid var(--border);padding:.6rem 1rem;font-family:var(--mono);font-size:.7rem;color:var(--text-dim);word-break:break-all;white-space:pre-wrap;max-height:120px;overflow-y:auto}
.poc-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;width:100%}
.poc-label{font-size:.6rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:.35rem}
code{font-family:var(--mono);font-size:.75rem;color:var(--text-dim);background:#0d1017;padding:.05rem .35rem;border:1px solid var(--border)}
.dim{color:var(--muted)}
em{color:var(--accent4);font-style:normal}
.footer{border-top:1px solid var(--border);padding:1.5rem 4rem;font-family:var(--mono);font-size:.65rem;color:var(--muted);display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem}
"""

_JS_ANIMATE = """
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-count]').forEach(el => {
    const target = parseInt(el.dataset.count, 10);
    if (isNaN(target) || target === 0) return;
    let start = 0;
    const step = Math.ceil(target / 24);
    const id = setInterval(() => {
      start = Math.min(start + step, target);
      el.textContent = start;
      if (start >= target) clearInterval(id);
    }, 30);
  });
});
"""

# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------


def generate_report(
    all_data: dict[str, list[dict]],
    all_coverage: dict[str, list[dict]],
    targets: list[str],
    out_path: Path,
) -> Path:
    """Legacy: generate a combined report for all targets. Delegates to generate_target_report."""
    # out_path is ignored here; each target writes its own file.
    # Returns the path of the last file written (backward-compat).
    last_path = out_path
    for t in targets:
        last_path = generate_target_report(
            target=t,
            rows=all_data[t],
            coverage_rows=all_coverage[t],
            out_path=out_path.parent / f"{t}_report.html",
        )
    return last_path


def generate_target_report(
    target: str,
    rows: list[dict],
    coverage_rows: list[dict],
    out_path: Path,
) -> Path:
    """Generate a single-target HTML report and write it to out_path."""
    now = datetime.now()
    ts = now.strftime("%Y-%m-%d %H:%M:%S")

    summary = summarise(rows)
    total_bugs = summary["total"]

    single_data = {target: rows}
    single_coverage = {target: coverage_rows}

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Fuzzer Report — {_target_label(target)} — {ts}</title>
<style>{_CSS}</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
</head>
<body>
<header class="header">
  <div>
    <div class="label">// fuzzer output</div>
    <h1>{_target_label(target)}</h1>
  </div>
  <div class="header-right">
    generated &nbsp;<span>{ts}</span><br/>
    target &nbsp;&nbsp;&nbsp;&nbsp;<span>{target}</span><br/>
    total bugs&nbsp;<span>{total_bugs}</span>
  </div>
</header>
<main class="container">
  <div class="section-title">target summary</div>
  <div class="cards">{render_overview_card(target, rows)}</div>
  {render_ablation_section(single_data, [target])}
  {render_coverage_section(single_coverage, [target])}
  <div class="section-title">recent bugs</div>
  {render_bug_table(rows, target)}
  {render_bug_reports(single_data, [target])}
</main>
<footer class="footer">
  <span>fuzzer report — {_target_label(target)} — generated {ts}</span>
  <span>results/ → {out_path.name}</span>
</footer>
<script>{_JS_ANIMATE}</script>
</body>
</html>"""

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically: build in memory → write to .tmp → rename into place.
    # This gives Live Server (and any other file watcher) a single filesystem
    # event instead of firing on every incremental write() call.
    tmp_path = out_path.with_suffix(".tmp")
    tmp_path.write_text(html, encoding="utf-8")
    tmp_path.replace(out_path)
    return out_path

# Entry point
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate per-target HTML fuzzing reports from bug + coverage CSVs."
    )
    parser.add_argument("--target", "-t", nargs="+", metavar="TARGET",
                        help=f"Targets to include. Default: all ({', '.join(KNOWN_TARGETS)})")
    parser.add_argument("--out-dir", "-o", default=str(RESULTS_DIR),
                        metavar="DIR", help="Output directory for report files (default: results/)")
    parser.add_argument("--no-open", action="store_true",
                        help="Don't auto-open the reports in a browser")
    args = parser.parse_args()

    targets = args.target if args.target else KNOWN_TARGETS
    out_dir = Path(args.out_dir).resolve()

    print(f"[report_generator] Loading data for: {', '.join(targets)}")
    all_data = load_all(targets)
    all_coverage = load_all_coverage(targets)

    for t in targets:
        print(f"  {'v' if all_data[t] else '.'} {t:<20} "
              f"{len(all_data[t])} bugs  |  {len(all_coverage[t])} coverage snapshots")

    print()
    written: list[Path] = []
    for t in targets:
        out_path = out_dir / f"{t}_report.html"
        print(f"[report_generator] Writing {t} -> {out_path}")
        generate_target_report(
            target=t,
            rows=all_data[t],
            coverage_rows=all_coverage[t],
            out_path=out_path,
        )
        written.append(out_path)

    print("[report_generator] Done.")

    if not args.no_open:
        for p in written:
            webbrowser.open(p.as_uri())


if __name__ == "__main__":
    main()