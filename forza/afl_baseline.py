import argparse
import subprocess
import os
import shutil
import time
import sys
import csv
from pathlib import Path

# Helper script to orchestrate py-afl-fuzz and standard afl-fuzz
def start_afl(target_name, time_limit):
    base_dir = Path(__file__).parent
    
    # Define our targets based on the yaml configurations
    targets = {
        "ipv4": {
            # Assuming native binary for ipv4
            "cmd": ["../../IPv4-IPv6-parser-main/bin/linux-ipv4-parser", "--ipstr"],
            "seed_dir": "inputs/ipv4_parser/seeds"
        },
        "ipv6": {
            # Assuming native binary for ipv6
            "cmd": ["../../IPv4-IPv6-parser-main/bin/linux-ipv6-parser", "--ipstr"],
            "seed_dir": "inputs/ipv6_parser/seeds"
        },
        "json": {
            # Python target uses py-afl-fuzz via the harness
            "cmd": ["python", "tools/json_afl_harness.py", "--str-json"],
            "seed_dir": "inputs/json_decoder/seeds"
        },
        "cidrize": {
            # Assuming native binary for cidrize
            "cmd": ["../../cidrize-runner-main/bin/linux-cidrize-runner", "--func", "cidrize", "--ipstr"],
            "seed_dir": "inputs/cidrize/seeds"
        }
    }

    t = targets[target_name]
    output_dir = base_dir / "results" / f"afl_baseline_{target_name}"
    
    # Ensure seed directories exist (AFL needs an actual directory, not a .txt file)
    seed_path = base_dir / t["seed_dir"]
    if not seed_path.exists() or len(list(seed_path.glob("*"))) == 0:
        print(f"[-] Seed directory does not exist or is empty: {seed_path}")
        print("[*] Creating seed folder from your seeds.txt if needed...")
        seed_path.mkdir(parents=True, exist_ok=True)
        # Assuming there is a seeds.txt next to it that you need to split
        seed_txt = seed_path.parent / "seeds.txt"
        if seed_txt.exists():
            with open(seed_txt, "r") as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                if line.strip():
                    with open(seed_path / f"seed_{i}.txt", "w") as out_f:
                        out_f.write(line.strip())
        else:
            # write a dummy seed if no seeds.txt is found
            with open(seed_path / "dummy_seed.txt", "w") as out_f:
                out_f.write("test")

    if target_name == "json":
        fuzzer_cmd = "py-afl-fuzz"
        # Since AFL outputs a file path via @@, we switch the python execution argument to stream that file directly.
        # Alternatively, if json_decoder_stv.py needs only strings, you must alter the python harness to read it.
        afl_command = [
            fuzzer_cmd,
            "-i", str(seed_path),
            "-o", str(output_dir),
            "-V", str(time_limit),  # Run for N seconds
            "--",
            sys.executable, str(base_dir / "tools" / "json_persistent_harness.py"), "@@"
        ]
    else:
        # Assuming your binary parsers use afl-fuzz
        fuzzer_cmd = "afl-fuzz"
        afl_command = [
            fuzzer_cmd,
            "-i", str(seed_path),
            "-o", str(output_dir),
            "-V", str(time_limit),  # Run for N seconds
            "-t", "2000",
            "--",
            str(base_dir / "tools" / "afl_arg_harness.sh")
        ] + t["cmd"] + ["@@"]

    print(f"[*] Starting {fuzzer_cmd} for {target_name}")
    print(f"[*] Command: {' '.join(afl_command)}")
    print(f"[*] Results will be logged to: {output_dir}")
    print("[*] Logs and bug counts will be collected after the run...")
    
    try:
        # Run the fuzzer process
        subprocess.run(afl_command)
    except KeyboardInterrupt:
        print("\n[*] Fuzzing interrupted by user.")
        
    # Logging the results phase
    log_results(target_name, output_dir)

def log_results(target_name, output_dir):
    """Parses afl fuzzer_stats and logs to a baseline comparison CSV."""
    stats_file = output_dir / "default" / "fuzzer_stats"
    if not stats_file.exists():
        print("[-] fuzzer_stats not found. Did AFL run successfully?")
        return
        
    stats = {}
    with open(stats_file, "r") as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                stats[k.strip()] = v.strip()
                
    bugs_found = stats.get("saved_crashes", "0")
    exec_count = stats.get("execs_done", "0")
    exec_speed = stats.get("execs_per_sec", "0")
    
    print(f"\n=== AFL Baseline Results for {target_name} ===")
    print(f"  Crashes Found: {bugs_found}")
    print(f"  Total Execs  : {exec_count}")
    print(f"  Exec Speed   : {exec_speed} execs/sec")
    
    # Save to your logs
    log_file = Path(__file__).parent / "results" / "afl_baseline_comparison_latest.csv"
    file_exists = log_file.exists()
    
    with open(log_file, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["Date", "Target", "Fuzzer", "Crashes", "Total_Execs", "Exec_Speed_sec"])
            
        date_str = time.strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([date_str, target_name, "python-afl/afl", bugs_found, exec_count, exec_speed])
        
    print(f"[*] Results logged to {log_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Baseline AFL/python-afl wrapper for targets")
    parser.add_argument("--target", required=True, choices=["ipv4", "ipv6", "json", "cidrize"])
    parser.add_argument("--time", type=int, default=3600, help="Fuzz time limit in seconds")
    
    args = parser.parse_args()
    start_afl(args.target, args.time)
