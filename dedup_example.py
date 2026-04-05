import hashlib

def old_hash(raw_key):
    """Old method - 12 char hash"""
    key_str = ":".join(str(p) for p in raw_key)
    return hashlib.md5(key_str.encode()).hexdigest()[:12]

def new_hash(raw_key):
    """New method - 16 char hash"""
    key_str = ":".join(str(p) for p in raw_key)
    return hashlib.md5(key_str.encode()).hexdigest()[:16]

print("="*80)
print("CIDRIZE - RELIABILITY BUG EXAMPLES (were all hashing to c920ae616677)")
print("="*80)

# Real examples from cidrize_bugs.csv with bug_key c920ae616677
reliability_bugs = [
    {
        "input": "1k92.0.2.18",
        "stderr": "",
        "stdout": "Running cidrize function with the arguments: ipstr: 1k92.0.2.18 strict: False raise-errors: False\nOutput: ['invalid IPNetwork 1k92.0.2.18']\nNo bugs found. Skipping CSV creation\nFinal bug count: defaultdict(<class 'int'>, {})"
    },
    {
        "input": "59.29.153.151/20",
        "stderr": "",
        "stdout": "Running cidrize function with the arguments: ipstr: 59.29.153.151/20 strict: False raise-errors: False\nOutput: [IPNetwork('59.29.144.0/20')]\nNo bugs found. Skipping CSV creation\nFinal bug count: defaultdict(<class 'int'>, {})"
    },
    {
        "input": "192.",
        "stderr": "",
        "stdout": "Running cidrize function with the arguments: ipstr: 192. strict: False raise-errors: False\nOutput: ['invalid IPNetwork 192.']\nNo bugs found. Skipping CSV creation\nFinal bug count: defaultdict(<class 'int'>, {})"
    }
]

print("\nBEFORE (all get same key):")
for i, bug in enumerate(reliability_bugs, 1):
    returncode = 0
    stderr = bug["stderr"][:80].strip()
    old_key = ("reliability", "", stderr)
    old_hash_val = old_hash(old_key)
    print(f"\nBug {i}: {bug['input']}")
    print(f"  raw_key: ('reliability', '', '{stderr}')")
    print(f"  hash: {old_hash_val}")

print("\nAFTER (each gets unique key based on stdout):")
for i, bug in enumerate(reliability_bugs, 1):
    returncode = 0
    stdout = bug["stdout"]
    rel_msg = (stdout[:160] or "").strip()
    new_key = ("reliability", "0", rel_msg)
    new_hash_val = new_hash(new_key)
    print(f"\nBug {i}: {bug['input']}")
    print(f"  raw_key: ('reliability', '0', '{rel_msg[:80]}...')")
    print(f"  hash: {new_hash_val}")

print("\n" + "="*80)
print("IPV6 - FUNCTIONAL BUG EXAMPLES (were colliding with key 28a79a260f33)")
print("="*80)

# Real examples from ipv6_parser_bugs.csv with bug_key 28a79a260f33
functional_bugs = [
    {
        "input": ":>::::",
        "stdout": "Parsing ipv6 input: :>::::\nFunctionalBug: Incorrect parsing of special characters.",
        "stderr": ""
    },
    {
        "input": "grggg::1",
        "stdout": "Parsing ipv6 input: grggg::1\nFunctionalBug: Incorrect parsing of special characters.",
        "stderr": ""
    },
    {
        "input": ">fe80::1",
        "stdout": "Parsing ipv6 input: >fe80::1\nFunctionalBug: Incorrect parsing of special characters.",
        "stderr": ""
    }
]

print("\nBEFORE (all get same key - same error message):")
for i, bug in enumerate(functional_bugs, 1):
    exc_msg = "Incorrect parsing of special characters."[:120]
    old_key = ("bonus", "ParseException", exc_msg)
    old_hash_val = old_hash(old_key)
    print(f"\nBug {i}: {bug['input']}")
    print(f"  raw_key: ('bonus', 'ParseException', '{exc_msg}')")
    print(f"  hash: {old_hash_val}")

print("\nAFTER (each gets unique key with stdout snippet):")
for i, bug in enumerate(functional_bugs, 1):
    stdout = bug["stdout"]
    stdout_snippet = stdout[:80].strip() if stdout else ""
    exc_msg = "Incorrect parsing of special characters."[:120]
    new_key = ("bonus", "ParseException", exc_msg, stdout_snippet)
    new_hash_val = new_hash(new_key)
    print(f"\nBug {i}: {bug['input']}")
    print(f"  raw_key: ('bonus', 'ParseException', '{exc_msg}', '{stdout_snippet}')")
    print(f"  hash: {new_hash_val}")
