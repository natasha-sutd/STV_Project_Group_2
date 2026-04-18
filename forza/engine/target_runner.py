"""
Generic subprocess runner for fuzzing targets.
"""

import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import json
import time
import atexit
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

import yaml


_FRIDA_SCRIPT_CACHE: dict[tuple[str, tuple[str, ...], bool, int], str] = {}
_parallel_pool: ThreadPoolExecutor | None = None
_parallel_pool_lock = threading.Lock()
_instr_stats_lock = threading.Lock()
_DEFAULT_PARALLEL_POOL_WORKERS = 4


def _shutdown_parallel_pool() -> None:
    global _parallel_pool
    with _parallel_pool_lock:
        pool = _parallel_pool
        _parallel_pool = None
    if pool is not None:
        pool.shutdown(wait=False, cancel_futures=True)


def get_parallel_pool() -> ThreadPoolExecutor:
    global _parallel_pool
    with _parallel_pool_lock:
        if _parallel_pool is None:
            _parallel_pool = ThreadPoolExecutor(
                max_workers=_DEFAULT_PARALLEL_POOL_WORKERS
            )
        return _parallel_pool


atexit.register(_shutdown_parallel_pool)


def get_platform() -> str:
    system = platform.system()
    if system == "Linux":
        return "linux"
    elif system == "Darwin":
        return "mac"
    else:
        return "windows"


def windows_to_wsl(win_path: str) -> str:
    p = PureWindowsPath(win_path)
    drive = p.drive.rstrip(":").lower()
    parts = p.parts[1:]  # skip root
    posix_parts = "/".join(part.replace("\\", "/") for part in parts)
    return f"/mnt/{drive}/{posix_parts}"


def resolve_binary_path(binary_path: str, use_wsl: bool = False) -> list[str]:
    use_wsl = use_wsl or bool(os.environ.get("FUZZER_USE_WSL"))
    current_platform = get_platform()

    if binary_path.lower() in {"wsl", "bash", "cmd", "powershell", "pwsh"}:
        return [binary_path]

    if current_platform == "windows" and use_wsl:
        return ["wsl", windows_to_wsl(binary_path)]

    return [binary_path]


def resolve_binary_for_platform(binary_config) -> str:
    if isinstance(binary_config, dict):
        current = get_platform()
        if current not in binary_config:
            raise ValueError(
                f"No binary configured for platform '{current}'. "
                f"Available: {list(binary_config.keys())}"
            )
        return binary_config[current]
    return binary_config


@dataclass
class RawResult:
    """output of target_runner.py, input to oracle.py"""

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    crashed: bool
    error: str | None
    strategy: str | None = None
    input_data: bytes = field(default_factory=bytes)


# helper functions


def _inject_input(cmd_template: list[str], replacement: str) -> list[str]:
    return [part.replace("{input}", replacement) for part in cmd_template]


def _make_error_result(e: Exception, input_bytes: bytes) -> RawResult:
    return RawResult(
        stdout="",
        stderr="",
        returncode=-1,
        timed_out=False,
        crashed=True,
        error=str(e),
        input_data=input_bytes,
    )


def resolve_cmd(cmd: list[str]) -> list[str]:
    if cmd[0] in ("python", "python3"):
        return [sys.executable] + cmd[1:]
    resolved = shutil.which(cmd[0])
    if resolved:
        return [resolved] + cmd[1:]
    return cmd


def _resolve_executable_against_cwd(cmd: list[str], cwd: str | None) -> list[str]:
    if not cmd:
        return cmd
    if not cwd:
        return cmd

    exe = cmd[0]
    if os.path.isabs(exe):
        return cmd

    # Only rewrite explicit path-like executables (./bin/foo, bin\\foo.exe, etc.)
    if not (exe.startswith(".") or "/" in exe or "\\" in exe):
        return cmd

    candidate = (Path(cwd) / exe).resolve()
    if candidate.exists():
        return [str(candidate)] + cmd[1:]
    return cmd


def _prepare_run_command(
    cmd_template: list[str],
    input_str: str,
    input_mode: str,
    use_wsl: bool,
    extra_flags: list[str] | None = None,
) -> tuple[list[str], bytes | None, str | None]:
    input_bytes = input_str.encode(errors="replace")
    tmp_file: str | None = None
    stdin_data: bytes | None = None

    if input_mode == "file":
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write(input_str)
        tmp.close()
        tmp_file = tmp.name
        cmd = _inject_input(cmd_template, tmp_file)
    elif input_mode == "stdin":
        cmd = list(cmd_template)
        stdin_data = input_bytes
    else:
        cmd = _inject_input(cmd_template, input_str)

    binary_prefix = resolve_binary_path(cmd[0], use_wsl=use_wsl)
    cmd = binary_prefix + cmd[1:]

    if extra_flags:
        cmd += extra_flags

    cmd = resolve_cmd(cmd)
    return cmd, stdin_data, tmp_file


def run_target(
    cmd_template: list[str],
    input_str: str,
    input_mode: str = "arg",
    cwd: str | None = None,
    timeout: int = 5,
    use_wsl: bool = False,
    extra_flags: list[str] | None = None,
) -> RawResult:
    input_bytes = input_str.encode(errors="replace")
    tmp_file: str | None = None
    cmd: list[str] = []

    try:
        cmd, stdin_data, tmp_file = _prepare_run_command(
            cmd_template=cmd_template,
            input_str=input_str,
            input_mode=input_mode,
            use_wsl=use_wsl,
            extra_flags=extra_flags,
        )

        effective_cwd = cwd or None
        cmd = _resolve_executable_against_cwd(cmd, effective_cwd)

        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            cwd=effective_cwd,
        )

        return RawResult(
            stdout=proc.stdout.decode(errors="replace"),
            stderr=proc.stderr.decode(errors="replace"),
            returncode=proc.returncode,
            timed_out=False,
            crashed=proc.returncode < 0,
            error=None,
            input_data=input_bytes,
        )

    except subprocess.TimeoutExpired:
        return RawResult(
            stdout="",
            stderr="",
            returncode=-1,
            timed_out=True,
            crashed=False,
            error="timeout",
            input_data=input_bytes,
        )

    except FileNotFoundError as e:
        missing_binary = (
            cmd[0] if cmd else (cmd_template[0] if cmd_template else "<unknown>")
        )
        raise RuntimeError(
            f"Binary not found: {missing_binary}\n"
            f"Check the binary path in your YAML config.\n"
            f"Original error: {e}"
        )

    except Exception as e:
        return _make_error_result(e, input_bytes)

    finally:
        if tmp_file and os.path.exists(tmp_file):
            os.remove(tmp_file)


def _parse_coverage_json_to_summary(report_json_text: str) -> str:
    """Parse coverage.py JSON totals and emit normalized summary lines."""
    try:
        payload = json.loads(report_json_text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""

    if not isinstance(payload, dict):
        return ""
    totals = payload.get("totals")
    if not isinstance(totals, dict):
        return ""

    stmts = _as_int(totals.get("num_statements"), 0, minimum=0)
    covered_stmts = _as_int(
        totals.get("covered_lines"),
        default=max(0, stmts - _as_int(totals.get("missing_lines"), 0, minimum=0)),
        minimum=0,
        maximum=stmts,
    )

    branches = _as_int(totals.get("num_branches"), 0, minimum=0)
    covered_branches = _as_int(
        totals.get("covered_branches"),
        default=max(
            0, branches - _as_int(totals.get("missing_branches"), 0, minimum=0)
        ),
        minimum=0,
        maximum=branches,
    )

    line_pct = (covered_stmts / stmts * 100) if stmts else 0.0
    branch_pct = (covered_branches / branches * 100) if branches else line_pct
    combined_pct = (
        ((covered_stmts + covered_branches) / (stmts + branches) * 100)
        if (stmts + branches)
        else line_pct
    )

    return (
        f"line coverage     : {line_pct:.2f}%\n"
        f"branch coverage   : {branch_pct:.2f}%\n"
        f"combined coverage : {combined_pct:.2f}%\n"
    )


def _parse_coverage_report_to_summary(report_text: str) -> str:
    """
    Parse the TOTAL line from a 'coverage report' table and emit the summary
    lines that _extract_coverage_percentages regex-matches against:

        line coverage     : 63.16%
        branch coverage   : 37.68%
        combined coverage : 50.00%

    Coverage report TOTAL line format (--branch mode):
        TOTAL   323   204   138   86   37%
    columns: Name Stmts Miss Branch BrPart Cover
    """
    json_summary = _parse_coverage_json_to_summary(report_text)
    if json_summary:
        return json_summary

    for line in report_text.splitlines():
        parts = line.split()
        if not parts or parts[0].upper() != "TOTAL":
            continue
        try:
            if len(parts) >= 6:
                # branch mode: TOTAL stmts miss branch brpart cover%
                stmts = int(parts[1])
                miss_stmts = int(parts[2])
                branches = int(parts[3])
                cover_pct = float(parts[5].rstrip("%"))
                covered_stmts = stmts - miss_stmts

                line_pct = (covered_stmts / stmts * 100) if stmts else 0.0
                combined_pct = max(0.0, min(100.0, cover_pct))

                # BrPart does not represent covered-branch count. When only
                # TOTAL text is available, estimate branch coverage by solving
                # combined coverage for covered branches.
                if branches:
                    estimated_covered_branches = (
                        (combined_pct / 100.0) * (stmts + branches)
                    ) - covered_stmts
                    estimated_covered_branches = max(
                        0.0, min(float(branches), estimated_covered_branches)
                    )
                    branch_pct = estimated_covered_branches / branches * 100.0
                else:
                    branch_pct = line_pct

                return (
                    f"line coverage     : {line_pct:.2f}%\n"
                    f"branch coverage   : {branch_pct:.2f}%\n"
                    f"combined coverage : {combined_pct:.2f}%\n"
                )
            elif len(parts) >= 4:
                # no-branch mode: TOTAL stmts miss cover%
                stmts = int(parts[1])
                miss_stmts = int(parts[2])
                covered_stmts = stmts - miss_stmts
                line_pct = (covered_stmts / stmts * 100) if stmts else 0.0
                return (
                    f"line coverage     : {line_pct:.2f}%\n"
                    f"branch coverage   : {line_pct:.2f}%\n"
                    f"combined coverage : {line_pct:.2f}%\n"
                )
        except (ValueError, ZeroDivisionError):
            continue
    return ""


def run_reference_with_coverage(
    cmd_template: list[str],
    input_str: str,
    input_mode: str,
    cwd: str | None,
    timeout: int,
    use_wsl: bool,
) -> RawResult:
    """
    'coverage run' a plain Python reference script under, then immediately
    call 'coverage report' and append its output to stdout so that
    _extract_coverage_percentages in coverage_tracker.py can parse the real
    statement/branch/combined percentages.
    """
    import uuid

    python_interpreters = {"python", "python3", "py"}
    rest = (
        cmd_template[1:]
        if cmd_template[0].lower().split(os.sep)[-1].split(".")[0]
        in python_interpreters
        else cmd_template
    )

    data_file = f".coverage_{uuid.uuid4().hex[:8]}"
    cov_run_cmd = [
        sys.executable,
        "-m",
        "coverage",
        "run",
        "--branch",
        f"--data-file={data_file}",
    ] + rest

    run_result = run_target(
        cmd_template=cov_run_cmd,
        input_str=input_str,
        input_mode=input_mode,
        cwd=cwd,
        timeout=timeout,
        use_wsl=use_wsl,
    )

    report_json_file: str | None = None
    try:
        fd, report_json_file = tempfile.mkstemp(
            prefix="forza_cov_report_", suffix=".json", dir=cwd or None
        )
        os.close(fd)

        report_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "json",
                f"--data-file={data_file}",
                "-o",
                report_json_file,
            ],
            capture_output=True,
            timeout=15,
            cwd=cwd or None,
        )

        report_out = ""
        if report_proc.returncode == 0 and os.path.exists(report_json_file):
            with open(report_json_file, "r", encoding="utf-8", errors="replace") as f:
                report_out = f.read()

        cov_lines = _parse_coverage_report_to_summary(report_out)
        merged_stdout = run_result.stdout
        if cov_lines:
            merged_stdout = run_result.stdout + "\n" + cov_lines

        run_result = RawResult(
            stdout=merged_stdout,
            stderr=run_result.stderr,
            returncode=run_result.returncode,
            timed_out=run_result.timed_out,
            crashed=run_result.crashed,
            error=run_result.error,
            strategy=run_result.strategy,
            input_data=run_result.input_data,
        )
    except Exception:
        pass
    finally:
        try:
            cleanup_path = Path(cwd or ".") / data_file
            if cleanup_path.exists():
                cleanup_path.unlink()
        except OSError:
            pass

        if report_json_file and os.path.exists(report_json_file):
            try:
                os.remove(report_json_file)
            except OSError:
                pass

    return run_result


_AFL_MAP_LINE_RE = re.compile(r"^([0-9a-fA-FxX]+)\s*[:=]\s*(\d+)$")
_COVERAGE_FREQ_LINE_RE = re.compile(r"^coverage_freq:\s*([^=\s]+)\s*=\s*(\d+)$")


def _resolve_platform_cmd(cmd_config: Any) -> list[str] | None:
    if not cmd_config:
        return None
    if isinstance(cmd_config, dict):
        current_os = get_platform()
        cmd = cmd_config.get(current_os)
        return list(cmd) if isinstance(cmd, list) else None
    if isinstance(cmd_config, list):
        return list(cmd_config)
    return None


def _replace_instrumentation_placeholders(
    cmd_template: list[str],
    config: dict,
    map_file_host_path: str,
) -> list[str]:
    map_file_for_cmd = map_file_host_path
    if (
        get_platform() == "windows"
        and cmd_template
        and cmd_template[0].lower() == "wsl"
    ):
        map_file_for_cmd = windows_to_wsl(map_file_host_path)

    buggy_cwd = str(config.get("buggy_cwd", "") or "")
    reference_cwd = str(config.get("reference_cwd", "") or "")

    if get_platform() == "windows":
        buggy_cwd_wsl = windows_to_wsl(buggy_cwd) if buggy_cwd else ""
        reference_cwd_wsl = windows_to_wsl(reference_cwd) if reference_cwd else ""
    else:
        buggy_cwd_wsl = buggy_cwd
        reference_cwd_wsl = reference_cwd

    replacements = {
        "{map_file}": map_file_for_cmd,
        "{buggy_cwd}": buggy_cwd,
        "{reference_cwd}": reference_cwd,
        "{buggy_cwd_wsl}": buggy_cwd_wsl,
        "{reference_cwd_wsl}": reference_cwd_wsl,
    }

    out: list[str] = []
    for part in cmd_template:
        new_part = part
        for token, value in replacements.items():
            new_part = new_part.replace(token, value)
        out.append(new_part)
    return out


def _parse_afl_showmap_text(text: str) -> dict[str, int]:
    edge_counts: dict[str, int] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _AFL_MAP_LINE_RE.match(line)
        if not m:
            continue
        edge_id, count_text = m.group(1), m.group(2)
        try:
            count = int(count_text)
        except ValueError:
            continue
        edge_counts[f"afl:{edge_id.lower()}"] = count
    return edge_counts


def _parse_coverage_freq_text(text: str) -> dict[str, int]:
    edge_counts: dict[str, int] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _COVERAGE_FREQ_LINE_RE.match(line)
        if not m:
            continue
        edge_id, count_text = m.group(1), m.group(2)
        try:
            count = int(count_text)
        except ValueError:
            continue
        edge_counts[str(edge_id).strip().lower()] = count
    return edge_counts


def _apply_edge_prefix(edge_counts: dict[str, int], edge_prefix: str) -> dict[str, int]:
    normalized_prefix = str(edge_prefix or "edge").strip().lower().strip(":")
    if not normalized_prefix:
        normalized_prefix = "edge"

    out: dict[str, int] = {}
    for edge_id, count in edge_counts.items():
        raw_id = str(edge_id).strip().lower()
        if not raw_id:
            continue
        suffix = raw_id.split(":", 1)[1] if ":" in raw_id else raw_id
        merged_id = f"{normalized_prefix}:{suffix}"
        out[merged_id] = out.get(merged_id, 0) + int(count)
    return out


def _format_coverage_freq_lines(edge_counts: dict[str, int]) -> str:
    if not edge_counts:
        return ""
    lines = [
        f"coverage_freq: {edge_id}={count}"
        for edge_id, count in sorted(edge_counts.items())
    ]
    return "\n".join(lines)


def _resolve_instrumentation_kind(instr_cfg: dict) -> str:
    current_os = get_platform()
    override_key = f"kind_{current_os}"
    if instr_cfg.get(override_key):
        return str(instr_cfg.get(override_key)).strip().lower()
    return str(instr_cfg.get("kind", "afl_showmap")).strip().lower()


def _resolve_instrumentation_kinds(instr_cfg: dict) -> list[str]:
    primary = _resolve_instrumentation_kind(instr_cfg)

    current_os = get_platform()
    fallback_key = f"fallback_kinds_{current_os}"
    fallback_raw = instr_cfg.get(fallback_key, instr_cfg.get("fallback_kinds", []))

    fallback_values: list[Any]
    if isinstance(fallback_raw, list):
        fallback_values = fallback_raw
    elif fallback_raw is None:
        fallback_values = []
    else:
        fallback_values = [fallback_raw]

    ordered: list[str] = []
    for raw_kind in [primary] + fallback_values:
        kind = str(raw_kind).strip().lower()
        if not kind or kind in ordered:
            continue
        ordered.append(kind)

    return ordered or [primary]


def _run_afl_showmap_instrumentation(
    instr_cfg: dict,
    config: dict,
    input_str: str,
    timeout: int,
    default_input_mode: str,
    default_use_wsl: bool,
) -> tuple[str, str | None]:
    cmd_template = _resolve_platform_cmd(instr_cfg.get("cmd"))
    if not cmd_template:
        return "", "blackbox_instrumentation.cmd is missing for current platform"

    input_mode = str(instr_cfg.get("input_mode", default_input_mode)).strip().lower()
    instr_cwd = instr_cfg.get("cwd") or config.get("buggy_cwd")

    try:
        instr_timeout = int(instr_cfg.get("timeout", timeout))
    except (TypeError, ValueError):
        instr_timeout = timeout

    use_wsl = bool(instr_cfg.get("use_wsl", default_use_wsl))
    if cmd_template and cmd_template[0].lower() == "wsl":
        use_wsl = False

    fd, map_file_host_path = tempfile.mkstemp(prefix="forza_map_", suffix=".txt")
    os.close(fd)

    try:
        cmd_with_map = _replace_instrumentation_placeholders(
            cmd_template, config, map_file_host_path
        )
        instr_result = run_target(
            cmd_template=cmd_with_map,
            input_str=input_str,
            input_mode=input_mode,
            cwd=instr_cwd,
            timeout=max(1, instr_timeout),
            use_wsl=use_wsl,
        )

        parsed = _parse_afl_showmap_text(instr_result.stdout)
        if not parsed:
            parsed = _parse_afl_showmap_text(instr_result.stderr)

        if not parsed and os.path.exists(map_file_host_path):
            try:
                with open(
                    map_file_host_path, "r", encoding="utf-8", errors="replace"
                ) as f:
                    parsed = _parse_afl_showmap_text(f.read())
            except OSError:
                parsed = {}

        coverage_text = _format_coverage_freq_lines(parsed)
        if coverage_text:
            return coverage_text, None

        if instr_result.error:
            return "", f"instrumentation command failed: {instr_result.error}"
        return "", "instrumentation produced no edge map data"
    finally:
        try:
            if os.path.exists(map_file_host_path):
                os.remove(map_file_host_path)
        except OSError:
            pass


def _resolve_frida_cmd_template(instr_cfg: dict, config: dict) -> list[str] | None:
    frida_cmd = _resolve_platform_cmd(instr_cfg.get("frida_cmd"))
    if frida_cmd:
        return frida_cmd

    raw_buggy_cmd = config.get("buggy_cmd")
    if isinstance(raw_buggy_cmd, dict):
        cmd = raw_buggy_cmd.get(get_platform())
        if isinstance(cmd, list):
            return list(cmd)

    return None


def _resolve_tinyinst_cmd_template(instr_cfg: dict) -> list[str] | None:
    tinyinst_cmd = _resolve_platform_cmd(instr_cfg.get("tinyinst_cmd"))
    if tinyinst_cmd:
        return tinyinst_cmd

    tinyinst_cfg = instr_cfg.get("tinyinst")
    if isinstance(tinyinst_cfg, dict):
        nested_cmd = _resolve_platform_cmd(tinyinst_cfg.get("cmd"))
        if nested_cmd:
            return nested_cmd

    return None


def _classify_frida_error(raw_error: str) -> str:
    text = str(raw_error or "").strip()
    lowered = text.lower()
    if "access is denied" in lowered or "permission denied" in lowered:
        return "frida setup failed: access denied (run terminal as administrator)"
    if "architecture mismatch" in lowered or "wrong architecture" in lowered:
        return (
            "frida setup failed: architecture mismatch between Python/Frida and target"
        )
    if "process not found" in lowered:
        return "frida setup failed: target exited before instrumentation could attach"
    if "unable to access process" in lowered:
        return "frida setup failed: unable to access target process"
    if text:
        return f"frida instrumentation failed: {text}"
    return "frida instrumentation failed"


def _is_transient_frida_attach_error(error_text: str) -> bool:
    lowered = str(error_text or "").strip().lower()
    return (
        "process not found" in lowered
        or "unable to access process" in lowered
        or "target exited before instrumentation could attach" in lowered
    )


def _wait_for_frida_process_exit(device: Any, pid: int, timeout_seconds: int) -> bool:
    deadline = time.monotonic() + max(1, timeout_seconds)
    while time.monotonic() < deadline:
        try:
            device.get_process(pid)
        except Exception as exc:
            lowered = str(exc).strip().lower()
            if "process not found" in lowered or "unable to find process" in lowered:
                return True
            if "not found" in lowered:
                return True
            return True
        time.sleep(0.01)
    return False


def _prepare_arg_mode_instrumentation_input(
    input_str: str,
    cfg: dict,
) -> tuple[str, str | None]:
    if "\x00" not in input_str:
        return input_str, None

    policy = str(cfg.get("arg_null_policy", "escape")).strip().lower()
    if policy in {"skip", "strict", "error"}:
        return (
            "",
            "frida arg mode cannot pass NUL bytes; configure arg_null_policy=escape or use non-arg input mode",
        )

    replacement = str(cfg.get("arg_null_replacement", "\\x00"))
    if not replacement:
        replacement = "\\x00"
    if "\x00" in replacement:
        replacement = replacement.replace("\x00", "\\x00")

    return input_str.replace("\x00", replacement), None


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def _as_int(
    value: Any,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    try:
        out = int(value)
    except (TypeError, ValueError):
        out = default

    if minimum is not None and out < minimum:
        out = minimum
    if maximum is not None and out > maximum:
        out = maximum
    return out


def _get_cached_frida_stalker_script(
    target_module: str,
    exclude_modules: list[str],
    use_call_summary: bool,
    flush_event_count: int,
) -> str:
    normalized_target = str(target_module).strip().lower()
    normalized_excludes = tuple(
        sorted(str(mod).strip().lower() for mod in exclude_modules)
    )
    normalized_flush_count = _as_int(flush_event_count, 2048, minimum=64, maximum=50000)
    cache_key = (
        normalized_target,
        normalized_excludes,
        bool(use_call_summary),
        normalized_flush_count,
    )
    cached = _FRIDA_SCRIPT_CACHE.get(cache_key)
    if cached is not None:
        return cached

    script = _build_frida_stalker_script(
        target_module=normalized_target,
        exclude_modules=list(normalized_excludes),
        use_call_summary=bool(use_call_summary),
        flush_event_count=normalized_flush_count,
    )
    _FRIDA_SCRIPT_CACHE[cache_key] = script
    return script


def _build_frida_stalker_script(
    target_module: str,
    exclude_modules: list[str],
    use_call_summary: bool,
    flush_event_count: int,
) -> str:
    target_module_json = json.dumps(target_module.lower())
    exclude_modules_json = json.dumps([m.lower() for m in exclude_modules])
    use_call_summary_json = "true" if use_call_summary else "false"
    flush_event_count = _as_int(flush_event_count, 2048, minimum=64, maximum=50000)
    return f"""
const TARGET_MODULE = {target_module_json};
const EXCLUDE_MODULES = {exclude_modules_json};
const USE_CALL_SUMMARY = {use_call_summary_json};
const FLUSH_EVENT_COUNT = {flush_event_count};
const followed = new Set();
const pendingCounts = {{}};
let pendingEvents = 0;
let targetModule = null;
let targetModuleBase = null;
let targetModuleEnd = null;

if (TARGET_MODULE) {{
    try {{
        const modules = Process.enumerateModules();
        for (let i = 0; i < modules.length; i++) {{
            const mod = modules[i];
            const name = (mod.name || '').toLowerCase();
            if (name === TARGET_MODULE) {{
                targetModule = mod;
                targetModuleBase = mod.base;
                targetModuleEnd = mod.base.add(mod.size);
                break;
            }}
        }}
    }} catch (_) {{}}
}}

function shouldTrackModule(moduleName) {{
  if (!moduleName) return false;
  const name = moduleName.toLowerCase();
  if (TARGET_MODULE && name !== TARGET_MODULE) return false;
  for (let i = 0; i < EXCLUDE_MODULES.length; i++) {{
    const token = EXCLUDE_MODULES[i];
    if (token && name.indexOf(token) !== -1) return false;
  }}
  return true;
}}

function eventAddress(event) {{
  if (Array.isArray(event)) {{
    if (event.length === 0) return null;
    if (typeof event[0] === 'string') {{
      return event.length > 1 ? event[1] : null;
    }}
    return event[0];
  }}
  if (event && typeof event === 'object') {{
    if (event.address !== undefined) return event.address;
    if (event.start !== undefined) return event.start;
    if (event.from !== undefined) return event.from;
  }}
  return null;
}}

function toEdgeKey(rawAddr) {{
  if (rawAddr === null || rawAddr === undefined) return null;
  const addr = ptr(rawAddr);

    if (targetModule !== null && targetModuleBase !== null && targetModuleEnd !== null) {{
        if (addr.compare(targetModuleBase) < 0 || addr.compare(targetModuleEnd) >= 0) return null;
        const offset = addr.sub(targetModuleBase);
        return targetModule.name.toLowerCase() + ':' + offset.toString();
    }}

  const mod = Process.findModuleByAddress(addr);
  if (mod === null) return null;
  if (!shouldTrackModule(mod.name)) return null;
  const offset = addr.sub(mod.base);
  return mod.name.toLowerCase() + ':' + offset.toString();
}}

function addEdgeCount(key, count) {{
    if (!key) return;
    pendingCounts[key] = (pendingCounts[key] || 0) + count;
}}

function flushBatch() {{
    const keys = Object.keys(pendingCounts);
    if (keys.length === 0) return;
    send({{ type: 'bb_batch', counts: pendingCounts }});
    for (let i = 0; i < keys.length; i++) {{
        delete pendingCounts[keys[i]];
    }}
    pendingEvents = 0;
}}

function emitBatch(parsedEvents) {{
  for (let i = 0; i < parsedEvents.length; i++) {{
    const key = toEdgeKey(eventAddress(parsedEvents[i]));
    if (!key) continue;
        addEdgeCount(key, 1);
        pendingEvents += 1;
    }}
    if (pendingEvents >= FLUSH_EVENT_COUNT) {{
        flushBatch();
    }}
}}

function emitCallSummary(summary) {{
    if (!summary || typeof summary !== 'object') return;
    const addrs = Object.keys(summary);
    for (let i = 0; i < addrs.length; i++) {{
        const rawAddr = addrs[i];
        const key = toEdgeKey(rawAddr);
        if (!key) continue;
        const rawCount = Number(summary[rawAddr]);
        if (!isFinite(rawCount) || rawCount <= 0) continue;
        addEdgeCount(key, Math.floor(rawCount));
        pendingEvents += 1;
  }}
    if (pendingEvents >= FLUSH_EVENT_COUNT) {{
        flushBatch();
  }}
}}

function followThread(threadId) {{
  if (followed.has(threadId)) return;
  followed.add(threadId);
  try {{
        const stalkerOptions = USE_CALL_SUMMARY
            ? {{
                    events: {{ call: true }},
                    onCallSummary(summary) {{
                        try {{
                            emitCallSummary(summary);
                            flushBatch();
                        }} catch (err) {{
                            send({{ type: 'stalker_error', error: String(err) }});
                        }}
                    }}
                }}
            : {{
                    events: {{ block: true }},
                    onReceive(events) {{
                        try {{
                            const parsed = Stalker.parse(events, {{ annotate: false }});
                            emitBatch(parsed);
                        }} catch (err) {{
                            send({{ type: 'stalker_error', error: String(err) }});
                        }}
                    }}
                }};
        Stalker.follow(threadId, stalkerOptions);
  }} catch (err) {{
    send({{ type: 'follow_error', threadId: threadId, error: String(err) }});
  }}
}}

function unfollowAll() {{
  followed.forEach(function(threadId) {{
    try {{ Stalker.unfollow(threadId); }} catch (_) {{}}
  }});
  followed.clear();
}}

rpc.exports = {{
  start() {{
    const threads = Process.enumerateThreads();
    for (let i = 0; i < threads.length; i++) {{
      followThread(threads[i].id);
    }}
    try {{
      Process.attachThreadObserver({{
        onAdded(thread) {{
          followThread(thread.id);
        }},
        onRemoved(thread) {{
          try {{ Stalker.unfollow(thread.id); }} catch (_) {{}}
          followed.delete(thread.id);
        }}
      }});
    }} catch (_) {{}}
    return true;
  }},
    flush() {{
        try {{ Stalker.flush(); }} catch (err) {{
            send({{ type: 'stalker_error', error: String(err) }});
        }}
        flushBatch();
        return true;
    }},
  stop() {{
        try {{ Stalker.flush(); }} catch (err) {{
            send({{ type: 'stalker_error', error: String(err) }});
        }}
        
        // Unfollow first so short-lived thread buffers are drained on the next flush.
        unfollowAll();

        try {{ Stalker.flush(); }} catch (err) {{
            send({{ type: 'stalker_error', error: String(err) }});
        }}
        flushBatch();
        try {{ Stalker.garbageCollect(); }} catch (_) {{}}
    return true;
  }}
}};
"""


def _run_frida_stalker_instrumentation(
    instr_cfg: dict,
    config: dict,
    input_str: str,
    timeout: int,
    default_input_mode: str,
) -> tuple[str, str | None]:
    import frida
    current_os = get_platform()

    cmd_template = _resolve_frida_cmd_template(instr_cfg, config)

    input_mode = str(instr_cfg.get("input_mode", default_input_mode)).strip().lower()
    instr_cwd = instr_cfg.get("cwd") or config.get("buggy_cwd")

    timeout_override_key = f"timeout_{current_os}"
    timeout_raw = instr_cfg.get(timeout_override_key, instr_cfg.get("timeout", timeout))
    try:
        instr_timeout = int(timeout_raw)
    except (TypeError, ValueError):
        instr_timeout = timeout
    run_timeout = max(1, instr_timeout)

    frida_cfg = instr_cfg.get("frida_config")
    if not isinstance(frida_cfg, dict):
        frida_cfg = {}

    target_module = (
        str(frida_cfg.get("target_module").get(current_os) or Path(cmd_template[0]).name)
        .strip()
        .lower()
    )
    exclude_modules = frida_cfg.get(
        "exclude_modules",
        ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll"],
    )
    if not isinstance(exclude_modules, list):
        exclude_modules = []
    use_call_summary = _as_bool(frida_cfg.get("use_call_summary"), default=False)
    flush_event_count = _as_int(
        frida_cfg.get("flush_event_count"),
        default=2048,
        minimum=64,
        maximum=50000,
    )
    capture_target_output = _as_bool(
        frida_cfg.get("capture_target_output"),
        default=False,
    )
    inherit_target_output = _as_bool(
        frida_cfg.get("inherit_target_output"),
        default=False,
    )
    attach_retries = _as_int(
        frida_cfg.get("attach_retries"),
        1,
        minimum=1,
        maximum=5,
    )
    attach_retry_delay_ms = _as_int(
        frida_cfg.get("attach_retry_delay_ms"),
        20,
        minimum=0,
        maximum=1000,
    )
    fail_fast_on_setup_error = _as_bool(
        frida_cfg.get("fail_fast_on_setup_error"),
        default=True,
    )

    effective_input = input_str
    if input_mode == "arg":
        effective_input, prep_err = _prepare_arg_mode_instrumentation_input(
            input_str=input_str,
            cfg=frida_cfg,
        )
        if prep_err:
            return "", prep_err

    cmd: list[str] = []
    tmp_file: str | None = None
    session = None
    script = None
    frida_device = None
    active_spawn_pid: int | None = None
    output_handler_registered = False
    frida_errors: list[str] = []
    edge_counts: dict[str, int] = {}

    def _on_frida_message(message, data) -> None:
        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if not isinstance(payload, dict):
                return
            if payload.get("type") in {"stalker_error", "follow_error"}:
                err = payload.get("error")
                if err:
                    frida_errors.append(str(err))
                return
            if payload.get("type") != "bb_batch":
                return
            counts = payload.get("counts")
            if not isinstance(counts, dict):
                return
            for key, raw_count in counts.items():
                try:
                    count = int(raw_count)
                except (TypeError, ValueError):
                    continue
                edge_id = f"frida_bb:{str(key).lower()}"
                edge_counts[edge_id] = edge_counts.get(edge_id, 0) + count
        elif msg_type == "error":
            desc = message.get("description") or message.get("stack") or "script error"
            frida_errors.append(str(desc))

    def _on_device_output(*args) -> None:
        if not capture_target_output or active_spawn_pid is None:
            return
        if len(args) < 3:
            return
        try:
            output_pid = int(args[0])
            output_fd = int(args[1])
            output_data = args[2]
        except (TypeError, ValueError):
            return
        if output_pid != active_spawn_pid:
            return
        if not isinstance(output_data, (bytes, bytearray)):
            return

        text = bytes(output_data).decode(errors="replace")
        parsed = _parse_coverage_freq_text(text)
        for edge_id, count in parsed.items():
            edge_counts[edge_id] = edge_counts.get(edge_id, 0) + count

        if output_fd == 2:
            first_line = text.strip().splitlines()
            if first_line:
                frida_errors.append(f"target stderr: {first_line[0]}")

    try:
        cmd, stdin_data, tmp_file = _prepare_run_command(
            cmd_template=cmd_template,
            input_str=effective_input,
            input_mode=input_mode,
            use_wsl=False,
            extra_flags=None,
        )
        cmd = _resolve_executable_against_cwd(cmd, instr_cwd)
        frida_device = frida.get_local_device()

        if capture_target_output:
            try:
                frida_device.on("output", _on_device_output)
                output_handler_registered = True
            except Exception as exc:
                frida_errors.append(f"frida output capture disabled: {exc}")

        setup_error: str | None = None
        for attempt_idx in range(attach_retries):
            try:
                # Keep target stdout/stderr out of the live table unless explicitly requested.
                spawn_stdio = (
                    "inherit"
                    if (
                        inherit_target_output
                        and stdin_data is None
                        and not capture_target_output
                    )
                    else "pipe"
                )
                active_spawn_pid = frida_device.spawn(
                    cmd,
                    cwd=instr_cwd or None,
                    stdio=spawn_stdio,
                )

                session = frida.attach(active_spawn_pid)
                script = session.create_script(
                    _get_cached_frida_stalker_script(
                        target_module=target_module,
                        exclude_modules=[str(x) for x in exclude_modules],
                        use_call_summary=use_call_summary,
                        flush_event_count=flush_event_count,
                    )
                )
                script.on("message", _on_frida_message)
                script.load()
                script.exports_sync.start()

                frida_device.resume(active_spawn_pid)

                if stdin_data is not None:
                    frida_device.input(active_spawn_pid, stdin_data)
                    frida_device.input(active_spawn_pid, b"")

                if not _wait_for_frida_process_exit(
                    frida_device,
                    active_spawn_pid,
                    run_timeout,
                ):
                    try:
                        frida_device.kill(active_spawn_pid)
                    except Exception:
                        pass
                    return "", f"instrumentation command timeout after {run_timeout}s"

                try:
                    script.exports_sync.flush()
                except Exception:
                    pass

                setup_error = None
                break
            except Exception as exc:
                setup_error = _classify_frida_error(str(exc))
                frida_errors.append(setup_error)

                if active_spawn_pid is not None:
                    try:
                        frida_device.kill(active_spawn_pid)
                    except Exception:
                        pass

                last_attempt = attempt_idx + 1 >= attach_retries
                if last_attempt or not _is_transient_frida_attach_error(setup_error):
                    break
                if attach_retry_delay_ms > 0:
                    time.sleep(attach_retry_delay_ms / 1000.0)
            finally:
                if script is not None:
                    try:
                        script.exports_sync.stop()
                    except Exception:
                        pass
                if session is not None:
                    try:
                        session.detach()
                    except Exception:
                        pass
                script = None
                session = None
                active_spawn_pid = None

        if setup_error:
            if fail_fast_on_setup_error:
                return "", setup_error
    except FileNotFoundError as exc:
        missing_binary = (
            cmd[0] if cmd else (cmd_template[0] if cmd_template else "<unknown>")
        )
        return "", f"Binary not found: {missing_binary} ({exc})"
    except Exception as exc:
        return "", f"frida instrumentation command failed: {exc}"
    finally:
        if active_spawn_pid is not None and frida_device is not None:
            try:
                frida_device.kill(active_spawn_pid)
            except Exception:
                pass
        if output_handler_registered and frida_device is not None:
            try:
                frida_device.off("output", _on_device_output)
            except Exception:
                pass
        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass

    coverage_text = _format_coverage_freq_lines(edge_counts)
    if coverage_text:
        return coverage_text, None

    if frida_errors:
        return "", frida_errors[0]
    return "", "instrumentation produced no edge map data"


def _run_tinyinst_instrumentation(
    instr_cfg: dict,
    config: dict,
    input_str: str,
    timeout: int,
    default_input_mode: str,
    default_use_wsl: bool,
) -> tuple[str, str | None]:
    cmd_template = _resolve_tinyinst_cmd_template(instr_cfg)
    if not cmd_template:
        return "", "tinyinst instrumentation command is missing for current platform"

    tinyinst_cfg = instr_cfg.get("tinyinst")
    if not isinstance(tinyinst_cfg, dict):
        tinyinst_cfg = {}

    input_mode = (
        str(
            tinyinst_cfg.get(
                "input_mode",
                instr_cfg.get("input_mode", default_input_mode),
            )
        )
        .strip()
        .lower()
    )
    instr_cwd = (
        tinyinst_cfg.get("cwd") or instr_cfg.get("cwd") or config.get("buggy_cwd")
    )

    timeout_raw = tinyinst_cfg.get("timeout", instr_cfg.get("timeout", timeout))
    try:
        instr_timeout = int(timeout_raw)
    except (TypeError, ValueError):
        instr_timeout = timeout

    use_wsl = bool(
        tinyinst_cfg.get("use_wsl", instr_cfg.get("use_wsl", default_use_wsl))
    )
    if cmd_template and cmd_template[0].lower() == "wsl":
        use_wsl = False

    edge_prefix = (
        str(
            tinyinst_cfg.get(
                "edge_prefix",
                instr_cfg.get("tinyinst_edge_prefix", "tinyinst"),
            )
        )
        .strip()
        .lower()
    )
    if not edge_prefix:
        edge_prefix = "tinyinst"

    map_file_host_path: str | None = None
    cmd_for_run = list(cmd_template)
    if any("{map_file}" in part for part in cmd_template):
        fd, map_file_host_path = tempfile.mkstemp(
            prefix="forza_tinyinst_", suffix=".txt"
        )
        os.close(fd)
        cmd_for_run = _replace_instrumentation_placeholders(
            cmd_template=cmd_template,
            config=config,
            map_file_host_path=map_file_host_path,
        )

    try:
        instr_result = run_target(
            cmd_template=cmd_for_run,
            input_str=input_str,
            input_mode=input_mode,
            cwd=instr_cwd,
            timeout=max(1, instr_timeout),
            use_wsl=use_wsl,
        )

        parsed = _parse_coverage_freq_text(instr_result.stdout)
        if not parsed:
            parsed = _parse_coverage_freq_text(instr_result.stderr)

        if not parsed:
            parsed = _parse_afl_showmap_text(instr_result.stdout)
        if not parsed:
            parsed = _parse_afl_showmap_text(instr_result.stderr)

        if not parsed and map_file_host_path and os.path.exists(map_file_host_path):
            try:
                with open(
                    map_file_host_path, "r", encoding="utf-8", errors="replace"
                ) as f:
                    map_text = f.read()
                parsed = _parse_coverage_freq_text(map_text)
                if not parsed:
                    parsed = _parse_afl_showmap_text(map_text)
            except OSError:
                parsed = {}

        parsed = _apply_edge_prefix(parsed, edge_prefix=edge_prefix)
        coverage_text = _format_coverage_freq_lines(parsed)
        if coverage_text:
            return coverage_text, None

        if instr_result.error:
            return "", f"tinyinst command failed: {instr_result.error}"
        return "", "tinyinst produced no edge map data"
    finally:
        if map_file_host_path and os.path.exists(map_file_host_path):
            try:
                os.remove(map_file_host_path)
            except OSError:
                pass


def run_blackbox_instrumentation(
    config: dict,
    input_str: str,
    timeout: int,
    default_input_mode: str,
    default_use_wsl: bool,
) -> tuple[str, str | None]:
    """Run optional black-box instrumentation and return coverage_freq text.

    Supported mode:
    blackbox_instrumentation:
      enabled: true
                kind: afl_showmap | frida_stalker | tinyinst
      kind_windows: frida_stalker      # optional platform override
      kind_linux: afl_showmap          # optional platform override
      kind_mac: afl_showmap            # optional platform override
                fallback_kinds: [tinyinst, afl_showmap]              # optional
                fallback_kinds_windows: [tinyinst, afl_showmap]      # optional
      cmd:                             # used by afl_showmap
        windows: ["wsl", "afl-showmap", "-Q", "-o", "{map_file}", "--", ...]
      frida_cmd:                       # optional custom command for frida_stalker
        windows: ["./bin/target.exe", "--arg", "{input}"]
                tinyinst_cmd:                    # optional tinyinst runner command
                    windows: ["python", "tinyinst_runner.py", "--target", "./bin/target.exe", "--input", "{input}"]
      frida_config:
        target_module: "target.exe"
        exclude_modules: ["ntdll.dll"]
                    use_call_summary: true         # optional (faster, less granular)
                    flush_event_count: 4096        # optional (message batch size)
                    capture_target_output: false   # optional (faster)
                    inherit_target_output: false   # optional (default false keeps table output clean)
                    parallel_with_reference: true  # optional run_both optimization gate
      tinyinst:                        # optional tinyinst backend options
        cmd:
          windows: ["python", "tinyinst_runner.py", "--target", "./bin/target.exe", "--input", "{input}"]
        edge_prefix: "tinyinst"
        input_mode: "arg|stdin|file"
        timeout: 15
        use_wsl: false
      cwd: "..."                # optional
      input_mode: "arg|stdin|file"  # optional
      timeout: 10                # optional, seconds
      use_wsl: false             # optional
    """
    instr_cfg = config.get("blackbox_instrumentation")
    if not isinstance(instr_cfg, dict) or not instr_cfg.get("enabled", False):
        return "", None

    kinds = _resolve_instrumentation_kinds(instr_cfg)
    attempt_errors: list[tuple[str, str]] = []

    for kind in kinds:
        if kind == "afl_showmap":
            coverage_text, instr_err = _run_afl_showmap_instrumentation(
                instr_cfg=instr_cfg,
                config=config,
                input_str=input_str,
                timeout=timeout,
                default_input_mode=default_input_mode,
                default_use_wsl=default_use_wsl,
            )
        elif kind == "frida_stalker":
            coverage_text, instr_err = _run_frida_stalker_instrumentation(
                instr_cfg=instr_cfg,
                config=config,
                input_str=input_str,
                timeout=timeout,
                default_input_mode=default_input_mode,
            )
        elif kind == "tinyinst":
            coverage_text, instr_err = _run_tinyinst_instrumentation(
                instr_cfg=instr_cfg,
                config=config,
                input_str=input_str,
                timeout=timeout,
                default_input_mode=default_input_mode,
                default_use_wsl=default_use_wsl,
            )
        else:
            coverage_text, instr_err = "", f"unsupported instrumentation kind: {kind!r}"

        if coverage_text:
            return coverage_text, None

        if instr_err:
            attempt_errors.append((kind, str(instr_err).strip()))

    if not attempt_errors:
        return "", "instrumentation produced no edge map data"
    if len(attempt_errors) == 1:
        return "", attempt_errors[0][1]
    return "", " ; ".join(f"{kind}: {err}" for kind, err in attempt_errors)


def _record_instrumentation_status(
    config: dict,
    instrumentation_coverage_text: str,
    instr_err: str | None,
) -> None:
    with _instr_stats_lock:
        stats = config.get("_instr_stats")
        if not isinstance(stats, dict):
            stats = {}
            config["_instr_stats"] = stats

        runs = _as_int(stats.get("runs"), 0, minimum=0)
        data_hits = _as_int(stats.get("data_hits"), 0, minimum=0)
        no_data_streak = _as_int(stats.get("no_data_streak"), 0, minimum=0)

        runs += 1
        stats["runs"] = runs
        if instrumentation_coverage_text:
            stats["data_hits"] = data_hits + 1
            stats["no_data_streak"] = 0
        else:
            stats["data_hits"] = data_hits
            stats["no_data_streak"] = no_data_streak + 1

        # Periodically relax long no-data streaks so reference parallelization
        # can retry after transient instrumentation outages.
        if runs % 100 == 0:
            refreshed_streak = _as_int(stats.get("no_data_streak"), 0, minimum=0)
            stats["no_data_streak"] = min(refreshed_streak, 2)

        if instr_err:
            stats["last_error"] = str(instr_err).strip()


def _should_parallelize_instrumentation_with_reference(config: dict) -> bool:
    instr_cfg = config.get("blackbox_instrumentation")
    if not isinstance(instr_cfg, dict) or not instr_cfg.get("enabled", False):
        return False
    if _resolve_instrumentation_kind(instr_cfg) != "frida_stalker":
        return False

    frida_cfg = instr_cfg.get("frida_config")
    if isinstance(frida_cfg, dict):
        if not _as_bool(frida_cfg.get("parallel_with_reference"), default=True):
            return False

    with _instr_stats_lock:
        stats = config.get("_instr_stats")
        if not isinstance(stats, dict):
            return False

        data_hits = _as_int(stats.get("data_hits"), 0, minimum=0)
        no_data_streak = _as_int(stats.get("no_data_streak"), 0, minimum=0)
    return data_hits >= 3 and no_data_streak <= 3


def _should_parallelize_buggy_with_instrumentation(config: dict) -> bool:
    instr_cfg = config.get("blackbox_instrumentation")
    if not isinstance(instr_cfg, dict) or not instr_cfg.get("enabled", False):
        return False

    kind = _resolve_instrumentation_kind(instr_cfg)
    if kind == "afl_showmap":
        return _as_bool(instr_cfg.get("parallel_with_buggy"), default=True)

    if kind != "frida_stalker":
        return False

    frida_cfg = instr_cfg.get("frida_config")
    if not isinstance(frida_cfg, dict):
        return False
    return _as_bool(frida_cfg.get("parallel_with_buggy"), default=False)


def _store_instrumentation_error(config: dict, instr_err: str | None) -> None:
    error_text = str(instr_err or "").strip()
    config["_last_instr_error"] = error_text
    emit_warning = _as_bool(config.get("emit_instrumentation_warning"), default=False)
    if error_text and not config.get("_instr_warning_emitted"):
        if emit_warning:
            print(f"[instrumentation] {config.get('name', 'target')}: {error_text}")
        config["_instr_warning_emitted"] = True


def run_both(
    config: dict,
    input_str: str,
    strategy: str | None = None,
    use_coverage: bool = False,
    timeout: int = 60,
) -> tuple[RawResult, RawResult | None, str]:
    """Run buggy and reference targets and optionally collect instrumentation edges."""
    input_mode = config.get("input_mode", "arg")
    use_wsl = config.get("use_wsl", False)
    extra_flags: list[str] | None = None
    coverage_file_cleanup_path: str | None = None
    if use_coverage and config.get("coverage_enabled") and config.get("coverage_flag"):
        extra_flags = [config["coverage_flag"]]

        coverage_file_template = config.get("coverage_file_template")
        if coverage_file_template:
            coverage_file_rendered = str(coverage_file_template)
            coverage_file_rendered = (
                coverage_file_rendered.replace("{pid}", str(os.getpid()))
                .replace("{thread}", str(threading.get_ident()))
                .replace("{time_ns}", str(time.time_ns()))
            )

            coverage_file_path = Path(coverage_file_rendered)
            if not coverage_file_path.is_absolute():
                base_dir = Path(config.get("buggy_cwd") or ".")
                coverage_file_path = (base_dir / coverage_file_path).resolve()

            coverage_file_flag = (
                str(config.get("coverage_file_flag", "--coverage-file")).strip()
                or "--coverage-file"
            )
            extra_flags.extend([coverage_file_flag, str(coverage_file_path)])

            if _as_bool(config.get("coverage_file_cleanup"), default=True):
                coverage_file_cleanup_path = str(coverage_file_path)

    raw_buggy_cmd = config["buggy_cmd"]
    if not raw_buggy_cmd:
        raise ValueError("buggy_cmd is required in the config")
    current_os = get_platform()
    if current_os not in raw_buggy_cmd:
        raise RuntimeError(f"No command configured for {current_os} in YAML!")
    buggy_cmd = raw_buggy_cmd[current_os]

    instrumentation_coverage_text = ""
    config["_last_instr_error"] = ""
    tracking_mode = str(config.get("tracking_mode", "behavioral")).strip().lower()
    should_collect_instr = (
        use_coverage
        and not config.get("coverage_enabled")
        and tracking_mode == "code_execution"
    )

    parallel_with_buggy = (
        should_collect_instr and _should_parallelize_buggy_with_instrumentation(config)
    )

    if parallel_with_buggy:
        pool = get_parallel_pool()
        buggy_future = pool.submit(
            run_target,
            buggy_cmd,
            input_str,
            input_mode,
            config.get("buggy_cwd"),
            timeout,
            use_wsl,
            extra_flags,
        )
        instr_future = pool.submit(
            run_blackbox_instrumentation,
            config,
            input_str,
            timeout,
            input_mode,
            use_wsl,
        )

        buggy_result = buggy_future.result()
        instrumentation_coverage_text, instr_err = instr_future.result()

        _record_instrumentation_status(
            config=config,
            instrumentation_coverage_text=instrumentation_coverage_text,
            instr_err=instr_err,
        )
        _store_instrumentation_error(config, instr_err)
    else:
        buggy_result = run_target(
            cmd_template=buggy_cmd,
            input_str=input_str,
            input_mode=input_mode,
            cwd=config.get("buggy_cwd"),
            timeout=timeout,
            use_wsl=use_wsl,
            extra_flags=extra_flags,
        )

    buggy_result.strategy = strategy
    if coverage_file_cleanup_path and os.path.exists(coverage_file_cleanup_path):
        try:
            os.remove(coverage_file_cleanup_path)
        except OSError:
            pass

    reference_result = None
    buggy_ok = (
        buggy_result.returncode == 0
        and not buggy_result.timed_out
        and not buggy_result.crashed
    )
    ref_cmd = config.get("reference_cmd") if buggy_ok else None

    can_parallelize = (
        should_collect_instr
        and not parallel_with_buggy
        and bool(ref_cmd)
        and _should_parallelize_instrumentation_with_reference(config)
    )

    if should_collect_instr and not parallel_with_buggy and not can_parallelize:
        instrumentation_coverage_text, instr_err = run_blackbox_instrumentation(
            config=config,
            input_str=input_str,
            timeout=timeout,
            default_input_mode=input_mode,
            default_use_wsl=use_wsl,
        )
        _record_instrumentation_status(
            config=config,
            instrumentation_coverage_text=instrumentation_coverage_text,
            instr_err=instr_err,
        )
        _store_instrumentation_error(config, instr_err)

    if ref_cmd:
        needs_reference_coverage = (
            use_coverage
            and not config.get("coverage_enabled")
            and not instrumentation_coverage_text
        )

        if can_parallelize:
            pool = get_parallel_pool()
            instr_future = pool.submit(
                run_blackbox_instrumentation,
                config,
                input_str,
                timeout,
                input_mode,
                use_wsl,
            )
            ref_future = pool.submit(
                run_target,
                ref_cmd[current_os],
                input_str,
                input_mode,
                config.get("reference_cwd"),
                timeout,
                use_wsl,
            )

            instrumentation_coverage_text, instr_err = instr_future.result()
            reference_result = ref_future.result()

            _record_instrumentation_status(
                config=config,
                instrumentation_coverage_text=instrumentation_coverage_text,
                instr_err=instr_err,
            )
            _store_instrumentation_error(config, instr_err)
            needs_reference_coverage = (
                use_coverage
                and not config.get("coverage_enabled")
                and not instrumentation_coverage_text
            )

            # Avoid re-running the reference target in this path. The reference
            # process already executed in parallel above, so fallback coverage
            # is skipped here to preserve throughput.
            if needs_reference_coverage:
                needs_reference_coverage = False
        elif needs_reference_coverage:
            reference_result = run_reference_with_coverage(
                cmd_template=ref_cmd[current_os],
                input_str=input_str,
                input_mode=input_mode,
                cwd=config.get("reference_cwd"),
                timeout=timeout,
                use_wsl=use_wsl,
            )
        else:
            reference_result = run_target(
                cmd_template=ref_cmd[current_os],
                input_str=input_str,
                input_mode=input_mode,
                cwd=config.get("reference_cwd"),
                timeout=timeout,
                use_wsl=use_wsl,
            )

        if reference_result is not None:
            reference_result.strategy = strategy

    return buggy_result, reference_result, instrumentation_coverage_text


def load_config(yaml_path: str) -> dict:
    p = Path(yaml_path).resolve()
    with open(p) as f:
        config = yaml.safe_load(f)

    # Resolve relative paths to absolute paths
    for key in ("buggy_cwd", "reference_cwd"):
        if config.get(key):
            config[key] = str((p.parent / config[key]).resolve())

    instr = config.get("blackbox_instrumentation")
    if isinstance(instr, dict) and instr.get("cwd"):
        instr["cwd"] = str((p.parent / instr["cwd"]).resolve())

    if config.get("seeds_path"):
        config["seeds_path"] = str((p.parent / config["seeds_path"]).resolve())

    return config


def load_seeds(seeds_path: str) -> list[str]:
    path = Path(seeds_path)
    if not path.exists():
        print(f"[WARN] Seeds file not found: {seeds_path}")
        return []
    seeds = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                seeds.append(line)
    return seeds
