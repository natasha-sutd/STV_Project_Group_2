# -*- coding: utf-8 -*-
"""
TargetDriver: executes a binary parser and returns a classified RunResult.

On Windows the driver uses the win-ipv*-parser.exe binaries directly.
On Linux/macOS it uses the corresponding linux-* / mac-* binaries.
WSL is available as an opt-in fallback via use_wsl=True.

Both parsers accept:
    <binary> --ipstr <string>

and always exit 0, printing structured output to stdout.
"""

import os
import platform
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path, PureWindowsPath
from typing import Optional

from oracle import BugOracle, RunResult


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def windows_to_wsl(win_path: str) -> str:
    """
    Convert a Windows absolute path to its WSL /mnt/ equivalent.

    e.g. C:\\Users\\foo\\bar.exe  ->  /mnt/c/Users/foo/bar.exe
    """
    p = PureWindowsPath(win_path)
    # Drive letter, lower-cased and without the trailing colon
    drive = p.drive.rstrip(":").lower()
    # Parts after the drive (PureWindowsPath.parts includes 'C:\\' as first)
    parts = p.parts[1:]  # skip 'C:\\'
    posix_parts = "/".join(part.replace("\\", "/") for part in parts)
    return f"/mnt/{drive}/{posix_parts}"


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class TargetDriver(ABC):
    """
    Runs a parser binary with --ipstr <input> and returns a RunResult.
    """

    def __init__(self, binary_path: str, timeout_secs: float = 10.0, use_wsl: bool = False) -> None:
        self._binary_path = binary_path
        self._timeout = timeout_secs
        self._use_wsl = use_wsl
        self._oracle = BugOracle()
        # Expose wsl path for logging (only meaningful when use_wsl=True)
        self.binary_wsl_path = windows_to_wsl(binary_path) if use_wsl else binary_path

    @abstractmethod
    def name(self) -> str: ...

    def run(self, input_data: bytes) -> RunResult:
        """Execute the binary and return a classified RunResult."""
        # Strip null bytes: Windows rejects them in command-line arguments,
        # and neither parser handles them as valid input anyway.
        cleaned = input_data.replace(b"\x00", b"")
        ip_str = cleaned.decode("utf-8", errors="replace")
        return self._invoke(input_data, ip_str)

    def _build_cmd(self, ip_str: str) -> list:
        if self._use_wsl:
            return ["wsl", windows_to_wsl(self._binary_path), "--ipstr", ip_str]
        return [self._binary_path, "--ipstr", ip_str]

    def _invoke(self, raw: bytes, ip_str: str) -> RunResult:
        cmd = self._build_cmd(ip_str)
        timed_out = False
        stdout = stderr = ""
        exit_code = -1
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            # When text=True the timeout payload is already a str (or None)
            raw_out = exc.stdout or ""
            raw_err = exc.stderr or ""
            stdout = raw_out if isinstance(raw_out, str) else raw_out.decode("utf-8", errors="replace")
            stderr = raw_err if isinstance(raw_err, str) else raw_err.decode("utf-8", errors="replace")
        except FileNotFoundError as e:
            raise RuntimeError(
                f"Binary not found: {cmd[0]}\nOriginal error: {e}\n"
                "Check --bin-dir or ensure the binary path is correct."
            )

        return self._oracle.classify(
            input_data=raw,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=timed_out,
        )

    @property
    def binary_path(self) -> str:
        return self._binary_path


# ---------------------------------------------------------------------------
# Concrete drivers
# ---------------------------------------------------------------------------

class IPv4Driver(TargetDriver):
    def name(self) -> str:
        return "ipv4"


class IPv6Driver(TargetDriver):
    def name(self) -> str:
        return "ipv6"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def make_driver(
    target: str,
    bin_dir: Optional[str] = None,
    use_wsl: bool = False,
    timeout: float = 10.0,
) -> TargetDriver:
    """
    Create a TargetDriver for `target` ('ipv4' or 'ipv6').

    Binary selection priority:
      1. If use_wsl=True or FUZZER_USE_WSL env var is set: linux-* binary via WSL
      2. On Windows : win-*-parser.exe  (fastest, no WSL overhead)
      3. On Linux   : linux-*-parser
      4. On macOS   : mac-*-parser

    `bin_dir` defaults to <project_root>/IPv4-IPv6-parser-main/bin/
    """
    if target not in ("ipv4", "ipv6"):
        raise ValueError(f"Unknown target '{target}'. Choose 'ipv4' or 'ipv6'.")

    if bin_dir is None:
        # fuzzer/ is one level below project root;
        # binaries live at <project_root>/IPv4-IPv6-parser-main/bin/
        project_root = Path(__file__).resolve().parent.parent
        bin_dir = str(project_root / "IPv4-IPv6-parser-main" / "bin")

    use_wsl = use_wsl or bool(os.environ.get("FUZZER_USE_WSL"))
    system = platform.system()

    if use_wsl or system == "Linux":
        binary_name = f"linux-{target}-parser"
    elif system == "Darwin":
        binary_name = f"mac-{target}-parser"
    else:
        # Windows — use the native .exe (no WSL overhead)
        binary_name = f"win-{target}-parser.exe"
        use_wsl = False

    binary_path = str(Path(bin_dir) / binary_name)
    driver_cls = IPv4Driver if target == "ipv4" else IPv6Driver
    return driver_cls(binary_path=binary_path, timeout_secs=timeout, use_wsl=use_wsl)
