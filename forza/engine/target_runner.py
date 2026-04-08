"""
Generic subprocess runner for fuzzing targets.
Reads ALL target-specific behaviour from a YAML config — no hardcoded target logic.
"""

import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

import yaml


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
    tmp_file = None
    stdin_data = None

    try:
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

        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            cwd=cwd or None,
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
        raise RuntimeError(
            f"Binary not found: {cmd[0]}\n"
            f"Check the binary path in your YAML config.\n"
            f"Original error: {e}"
        )

    except Exception as e:
        return _make_error_result(e, input_bytes)

    finally:
        if tmp_file and os.path.exists(tmp_file):
            os.remove(tmp_file)


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
                br_part = int(parts[4])
                covered_stmts = stmts - miss_stmts
                covered_branches = br_part  # BrPart = partially/fully covered

                line_pct = (covered_stmts / stmts * 100) if stmts else 0.0
                branch_pct = (covered_branches / branches * 100) if branches else 0.0
                combined_pct = (
                    ((covered_stmts + covered_branches) / (stmts + branches) * 100)
                    if (stmts + branches)
                    else 0.0
                )

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

    try:
        report_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "report",
                f"--data-file={data_file}",
                "--precision=2",
                "-m",
            ],
            capture_output=True,
            timeout=15,
            cwd=cwd or None,
        )
        report_out = report_proc.stdout.decode(errors="replace")

        cov_lines = _parse_coverage_report_to_summary(report_out)

        try:
            cleanup_path = Path(cwd or ".") / data_file
            if cleanup_path.exists():
                cleanup_path.unlink()
        except OSError:
            pass

        run_result = RawResult(
            stdout=run_result.stdout + "\n" + cov_lines,
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
    return run_result


def _parse_coverage_report_to_summary(report_text: str) -> str:
    """Parse the TOTAL line from a 'coverage report' table and emit the summary lines"""
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
                br_part = int(parts[4])
                covered_stmts = stmts - miss_stmts
                covered_branches = br_part  # BrPart = partially/fully covered

                line_pct = (covered_stmts / stmts * 100) if stmts else 0.0
                branch_pct = (covered_branches / branches * 100) if branches else 0.0
                combined_pct = (
                    ((covered_stmts + covered_branches) / (stmts + branches) * 100)
                    if (stmts + branches)
                    else 0.0
                )

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


def run_both(
    config: dict,
    input_str: str,
    strategy: str | None = None,
    use_coverage: bool = False,
    timeout: int = 60,
) -> tuple[RawResult, RawResult | None]:
    """run buggy binaries and the reference target if necessary, returns buggy result, reference result*"""
    input_mode = config.get("input_mode", "arg")
    use_wsl = config.get("use_wsl", False)
    extra_flags = (
        [config["coverage_flag"]]
        if use_coverage
        and config.get("coverage_enabled")
        and config.get("coverage_flag")
        else None
    )

    raw_buggy_cmd = config["buggy_cmd"]
    if not raw_buggy_cmd:
        raise ValueError("buggy_cmd is required in the config")
    current_os = get_platform()
    if current_os not in raw_buggy_cmd:
        raise RuntimeError(f"No command configured for {current_os} in YAML!")
    buggy_cmd = raw_buggy_cmd[current_os]

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

    reference_result = None
    if (
        buggy_result.returncode == 0
        and not buggy_result.timed_out
        and not buggy_result.crashed
    ):
        ref_cmd = config.get("reference_cmd")
        if ref_cmd:
            if use_coverage and not config.get("coverage_enabled"):
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
            reference_result.strategy = strategy

    return buggy_result, reference_result


def load_config(yaml_path: str) -> dict:
    p = Path(yaml_path).resolve()
    with open(p) as f:
        config = yaml.safe_load(f)

    # Resolve relative paths to absolute paths
    for key in ("buggy_cwd", "reference_cwd"):
        if config.get(key):
            config[key] = str((p.parent / config[key]).resolve())

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
