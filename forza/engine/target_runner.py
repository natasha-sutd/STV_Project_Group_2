"""
Generic subprocess runner for fuzzing targets.
Reads ALL target-specific behaviour from a YAML config — no hardcoded target logic.
"""

import os
import platform
import shutil
import subprocess
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
    """
    This is the OUTPUT of target_runner.py and the INPUT to oracle.py.
    oracle.py then classifies this into a BugResult with bug_type, bug_key etc.
    """
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
    """Replace all {input} placeholders in a command template."""
    return [part.replace("{input}", replacement) for part in cmd_template]


def _make_error_result(e: Exception, input_bytes: bytes) -> RawResult:
    """Return a RawResult representing an unexpected Python-level failure."""
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
    """Replace the command name (cmd[0]) with its full path using shutil.which()."""
    resolved = shutil.which(cmd[0])
    if resolved:
        return [resolved] + cmd[1:]
    return cmd


# runner
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
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            )
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


# wrapper
def run_both(
    config: dict,
    input_str: str,
    strategy: str | None = None,
    use_coverage: bool = False,
) -> tuple[list[RawResult], RawResult | None]:
    """
    Run ALL buggy binaries AND the reference target for a given config dict.
    Returns (buggy_results, reference_result).

    buggy_results is always a LIST of RawResult — one per buggy_cmd entry.
    This supports targets like ip_parser that have multiple binaries
    (mac-ipv4-parser + mac-ipv6-parser) in a single YAML config.

    reference_result is None if no reference_cmd is defined in the config.
    """
    input_mode = config.get("input_mode", "arg")
    timeout = config.get("timeout", 60)
    use_wsl = config.get("use_wsl", False)

    extra_flags = None
    if use_coverage and config.get("coverage_enabled") and config.get("coverage_flag"):
        extra_flags = [config["coverage_flag"]]

    raw_buggy_cmd = config["buggy_cmd"]
    # if isinstance(raw_buggy_cmd[0], list):
    #     buggy_cmds = raw_buggy_cmd
    # else:
    #     buggy_cmds = [raw_buggy_cmd]
    if isinstance(raw_buggy_cmd, dict):
        current_os = get_platform()  # This returns "windows", "mac", or "linux"
        if current_os not in raw_buggy_cmd:
            raise RuntimeError(
                f"No command configured for {current_os} in YAML!")
        buggy_cmds = [raw_buggy_cmd[current_os]]
    elif isinstance(raw_buggy_cmd[0], list):
        buggy_cmds = raw_buggy_cmd
    else:
        buggy_cmds = [raw_buggy_cmd]

    buggy_results = []
    for cmd in buggy_cmds:
        result = run_target(
            cmd_template=cmd,
            input_str=input_str,
            input_mode=input_mode,
            cwd=config.get("buggy_cwd"),
            timeout=timeout,
            use_wsl=use_wsl,
            extra_flags=extra_flags,
        )
        result.strategy = strategy
        buggy_results.append(result)

    ref_cmd = config.get("reference_cmd")
    if ref_cmd:
        reference_result = run_target(
            cmd_template=ref_cmd,
            input_str=input_str,
            input_mode=input_mode,
            cwd=config.get("reference_cwd"),
            timeout=timeout,
            use_wsl=use_wsl,
        )
        reference_result.strategy = strategy
    else:
        reference_result = None

    return buggy_results, reference_result


def load_config(yaml_path: str) -> dict:
    p = Path(yaml_path).resolve()
    with open(p) as f:
        config = yaml.safe_load(f)

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


# test runner
# python3 engine/target_runner.py
if __name__ == "__main__":
    import yaml

    TARGET_YAMLS = [
        "targets/ipv4_parser.yaml",
        "targets/ipv6_parser.yaml",
        "targets/json_decoder.yaml",
        "targets/cidrize.yaml",
    ]

    print(f"Platform : {get_platform()}\n")

    for yaml_file in TARGET_YAMLS:
        if not Path(yaml_file).exists():
            print(f"[SKIP] {yaml_file} not found\n")
            continue

        cfg = load_config(yaml_file)
        seeds = load_seeds(cfg["seeds_path"])

        print(f"{'='*60}")
        print(f"TARGET : {cfg['name']}")
        print(f"CWD    : {cfg.get('buggy_cwd', 'n/a')}")
        print(f"SEEDS  : {len(seeds)} loaded from {cfg['seeds_path']}")
        print(f"{'='*60}")

        if not seeds:
            print("[WARN] No seeds found — skipping\n")
            continue

        for seed in seeds:
            buggy_results, ref = run_both(cfg, seed, strategy="sanity_test")
            bug_keywords = cfg.get("bug_keywords", [])

            for i, buggy in enumerate(buggy_results):
                label = "buggy" if len(buggy_results) == 1 else f"buggy[{i}]"

                if buggy.timed_out:
                    bug_signal = "TIMEOUT"
                elif buggy.crashed:
                    bug_signal = "CRASH"
                elif any(kw in buggy.stdout + buggy.stderr for kw in bug_keywords):
                    bug_signal = "BUG?"
                else:
                    bug_signal = "ok"

                ref_signal = ""
                if ref and i == 0:
                    if ref.timed_out:
                        ref_signal = f"| [TIMEOUT] ref "
                    elif ref.crashed:
                        ref_signal = f"| [CRASH  ] ref "
                    else:
                        ref_signal = f"| [ok     ] ref "

                print(
                    f"  [{bug_signal:7s}] {label:10s} "
                    + ref_signal
                    + f"| {repr(seed[:50])}"
                )

        print()
