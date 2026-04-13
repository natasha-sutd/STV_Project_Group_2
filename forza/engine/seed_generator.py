"""
engine/seed_generator.py

Generalised grammar-based seed generator and grammar-aware mutator.

Generates seeds for the initial corpus based on the input grammar
defined in the target's YAML config under the `input:` key.

Also exposes mutate_from_spec() for grammar-aware mutation in
MutationEngine.

Supported grammar types
-----------------------
  int            — random integer in [min, max]
  hex            — random hex string in [min, max]
  string         — random string of length [min, max]
  boolean        — "True" or "False"
  null           — literal "null"
  any            — random choice of int, string, or boolean
  literal        — fixed string value
  array          — list of elements
  object         — JSON/dict with random keys and values
  sequence       — repeat element N times with separator (count + separator + element)
                   OR concatenate fixed parts (parts list)
  concat         — alias for sequence with parts
  one_of         — choose one option uniformly at random
  weighted_one_of— choose one option by weight

CLI usage
---------
  python3 engine/seed_generator.py targets/json_decoder.yaml
  python3 engine/seed_generator.py targets/ipv4_parser.yaml --count 50
"""

from __future__ import annotations

import json
import os
import random
import string
import yaml
from pathlib import Path
from typing import Any
import copy
import ast


# ---------------------------------------------------------------------------
# Type generator registry
# ---------------------------------------------------------------------------

TYPE_GENERATORS: dict[str, callable] = {}


def register_type(name: str):
    """Decorator to register a generator function for a grammar type."""
    def decorator(func):
        TYPE_GENERATORS[name] = func
        return func
    return decorator


# ---------------------------------------------------------------------------
# Built-in type generators
# ---------------------------------------------------------------------------

@register_type("int")
def gen_int(spec: dict) -> str:
    return str(random.randint(spec.get("min", 0), spec.get("max", 100)))


@register_type("hex")
def gen_hex(spec: dict) -> str:
    return format(random.randint(spec.get("min", 0), spec.get("max", 65535)), "x")


@register_type("string")
def gen_string(spec: dict) -> str:
    length = random.randint(spec.get("min", 1), spec.get("max", 10))
    chars = spec.get("chars", string.ascii_letters)
    return "".join(random.choice(chars) for _ in range(length))


@register_type("boolean")
def gen_boolean(spec: dict) -> str:
    return str(random.choice([True, False]))


@register_type("null")
def gen_null(spec: dict) -> str:
    return "null"


@register_type("any")
def gen_any(spec: dict) -> str:
    """Generate a random value of any basic type."""
    choice = random.choice(["int", "string", "boolean", "null", "hex"])
    return generate_from_spec({"type": choice, "min": 0, "max": 100})


@register_type("literal")
def gen_literal(spec: dict) -> str:
    return str(spec.get("value", ""))


@register_type("array")
def gen_array(spec: dict) -> str:
    length = random.randint(spec.get("min_length", 1),
                            spec.get("max_length", 3))
    element_spec = spec.get("element", {"type": "int", "min": 0, "max": 100})
    items = [generate_from_spec(element_spec) for _ in range(length)]
    return repr(items)


@register_type("object")
def gen_object(spec: dict) -> str:
    """
    Generate a random object/dict.

    Supports two key/value field naming conventions:
      New style: key_schema / value_schema  (explicit)
      Old style: key / value                (shorthand — also accepted)

    encoding field controls output format:
      json     (default) — {"a": 1}   proper JSON
      dict_str           — {'a': 1}   Python dict string
    """
    # Accept both naming conventions
    key_spec = spec.get("key_schema") or spec.get(
        "key",   {"type": "string", "min": 1, "max": 8})
    value_spec = spec.get("value_schema") or spec.get(
        "value", {"type": "int",    "min": 0, "max": 100})

    n_fields = random.randint(1, spec.get("max_fields", 3))
    obj = {}
    for _ in range(n_fields):
        k = generate_from_spec(key_spec)
        v_raw = generate_from_spec(value_spec)
        # Try to parse the value back to a Python type for proper JSON encoding
        try:
            v = json.loads(v_raw)
        except (json.JSONDecodeError, TypeError):
            v = v_raw
        obj[str(k)] = v

    encoding = spec.get("encoding", "json")
    if encoding == "dict_str":
        return repr(obj)
    # Default: proper JSON encoding
    return json.dumps(obj)


@register_type("sequence")
def gen_sequence(spec: dict) -> str:
    """
    Two modes:
      Repeat mode  (count + separator + element) — repeat element N times
      Parts mode   (parts list)                  — concatenate fixed parts
    """
    if "count" in spec and "element" in spec:
        count = spec["count"]
        sep = str(spec.get("separator", ""))
        elements = [str(generate_from_spec(spec["element"]))
                    for _ in range(count)]
        return sep.join(elements)
    # Parts mode
    return "".join(str(generate_from_spec(p)) for p in spec.get("parts", []))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_from_spec(spec: Any) -> str:
    """
    Recursively generate a value from a grammar spec dict.
    Returns a string in all cases.
    """
    if not isinstance(spec, dict):
        return str(spec)

    t = spec.get("type", "")

    # Registered types (int, hex, string, boolean, null, any, literal,
    #                   array, object, sequence)
    if t in TYPE_GENERATORS:
        result = TYPE_GENERATORS[t](spec)

    # Aliases
    elif t == "concat":
        result = "".join(str(generate_from_spec(p))
                         for p in spec.get("parts", []))

    elif t == "one_of":
        options = spec.get("options", [])
        result = str(generate_from_spec(
            random.choice(options))) if options else ""

    elif t == "weighted_one_of":
        options = spec.get("options", [])
        if not options:
            result = ""
        else:
            weights = [float(o.get("weight", 1.0)) for o in options]
            chosen = random.choices(options, weights=weights, k=1)[0]
            result = str(generate_from_spec(chosen))

    else:
        result = ""

    return str(result)


# ---------------------------------------------------------------------------
# CFG Tree
# ---------------------------------------------------------------------------

class CFGNode:
    def __init__(self, spec, children=None, value=None):
        self.spec = spec
        self.children = children or []
        self.value = value

def build_tree_from_spec(spec: dict, depth=0, max_depth=5) -> CFGNode:
    """
    Build a derivation tree from spec.
    Non-terminals → children
    Terminals → value
    """
    if not isinstance(spec, dict):
        return CFGNode(spec, value=str(spec))
    
    if depth > max_depth:
        return CFGNode(spec, value=generate_from_spec(spec))

    t = spec.get("type", "")

    # terminals
    if t in ("int", "hex", "string", "boolean", "null", "any", "literal"):
        return CFGNode(spec, value=generate_from_spec(spec))

    # one_of 
    if t == "one_of":
        options = spec.get("options", [])
        if not options:
            return CFGNode(spec, value="")
        return CFGNode(spec, [
            build_tree_from_spec(random.choice(options), depth + 1, max_depth)
        ])

    # weighted_one_of
    if t == "weighted_one_of":
        options = spec.get("options", [])
        if not options:
            return CFGNode(spec, value="")
        weights = [o.get("weight", 1.0) for o in options]
        chosen = random.choices(options, weights=weights, k=1)[0]
        return CFGNode(spec, [
            build_tree_from_spec(chosen, depth + 1, max_depth)
        ])

    # sequence
    if t == "sequence" and "count" in spec:
        return CFGNode(spec, [
            build_tree_from_spec(spec["element"], depth + 1, max_depth)
            for _ in range(spec.get("count", 1))
        ])
    
    # concat
    if t in ("sequence", "concat"):
        return CFGNode(spec, [
            build_tree_from_spec(p, depth + 1, max_depth)
            for p in spec.get("parts", [])
        ])

    # array
    if t == "array":
        length = random.randint(spec.get("min_length", 1), spec.get("max_length", 3))
        element_spec = spec.get("element", {"type": "any"})
        if not isinstance(element_spec, dict):
            element_spec = {"type": "any"}
        return CFGNode(spec, [
            build_tree_from_spec(element_spec, depth + 1, max_depth)
            for _ in range(length)
        ])

    # object
    if t == "object":
        key_spec = spec.get("key_schema") or spec.get("key", {"type": "string"})
        value_spec = spec.get("value_schema") or spec.get("value", {"type": "any"})
        children = []
        for _ in range(random.randint(1, spec.get("max_fields", 3))):
            k = build_tree_from_spec(key_spec, depth + 1, max_depth)
            v = build_tree_from_spec(value_spec, depth + 1, max_depth)
            children.append((k, v))
        return CFGNode(spec, children)
    return CFGNode(spec, value=str(generate_from_spec(spec)))

def tree_to_string(node: CFGNode) -> str:
    """
    Convert a CFGNode tree back to a string by concatenating terminal values
    """    
    spec = node.spec

    if node.value is not None:
        return str(node.value)

    t = spec.get("type", "")

    if t == "sequence" and "count" in spec:
        sep = str(spec.get("separator", ""))
        return sep.join(tree_to_string(c) for c in node.children)
    
    if t in ("sequence", "concat"):
        return "".join(tree_to_string(c) for c in node.children)

    if t == "array":
        result = []
        for c in node.children:
            result.append(tree_to_string(c))
        return str(result)
    
    if t == "object":
        obj = {}
        for k, v in node.children:
            key = tree_to_string(k)
            val = tree_to_string(v)
            obj[str(key)] = val
        return str(obj)

    if t in ("one_of", "weighted_one_of"):
        return tree_to_string(node.children[0]) if node.children else ""

    return "".join(tree_to_string(c) for c in node.children)

def parse_string_to_tree(seed: str, spec: dict) -> CFGNode:
    """
    Hybrid parser:
    - Tries to parse seed into CFG tree
    - Falls back to generation if parsing fails
    """
    try:
        t = spec.get("type", "")

        # terminals
        if t in ("int", "hex", "string", "boolean", "null", "float"):
            return CFGNode(spec, value=seed)

        # sequence
        if t == "sequence":
            sep = spec.get("separator", "")
            parts = seed.split(sep) if sep else list(seed)
            element_spec = spec.get("element", {})
            children = [
                parse_string_to_tree(p, element_spec)
                for p in parts
            ]
            return CFGNode(spec, children)

        # array
        if t == "array":
            arr = ast.literal_eval(seed)
            element_spec = spec.get("element", {"type": "any"})
            if not isinstance(element_spec, dict):
                element_spec = {"type": "any"}
            children = [
                parse_string_to_tree(str(x), element_spec)
                for x in arr
            ]
            return CFGNode(spec, children)

        # object
        if t == "object":
            obj = ast.literal_eval(seed)
            key_spec = spec.get("key_schema") or spec.get("key", {"type": "string"})
            value_spec = spec.get("value_schema") or spec.get("value", {"type": "any"})
            children = []
            for k, v in obj.items():
                k_node = parse_string_to_tree(str(k), key_spec)
                v_node = parse_string_to_tree(str(v), value_spec)
                children.append((k_node, v_node))
            return CFGNode(spec, children)

        # one_of / weighted_one_of
        if t in ("one_of", "weighted_one_of"):
            for opt in spec.get("options", []):
                try:
                    child = parse_string_to_tree(seed, opt)
                    return CFGNode(spec, [child])
                except:
                    continue
        
        # concat
        if t == "concat":
            children = []
            remaining = seed
            for part_spec in spec.get("parts", []):
                part_type = part_spec.get("type", "")
                # int
                if part_type == "int":
                    i = 0
                    while i < len(remaining) and (remaining[i].isdigit() or (i == 0 and remaining[i] == "-")):
                        i += 1
                    part = remaining[:i]
                    remaining = remaining[i:]
                # string
                elif part_type == "string":
                    part = remaining
                    remaining = ""
                else:
                    # fallback to generation for unsupported types
                    part = remaining
                    remaining = ""
                children.append(parse_string_to_tree(part, part_spec))
            return CFGNode(spec, children)
        
        # literal
        if t == "literal":
            expected = str(spec.get("value", ""))
            if seed == expected:
                return CFGNode(spec, value=seed)
            else:
                raise ValueError(f"Literal mismatch: expected {expected}, got {seed}")

        # fallback, generate a new tree from spec
        return build_tree_from_spec(spec)

    except Exception:
        return build_tree_from_spec(spec)

# ---------------------------------------------------------------------------
# Grammar-aware mutation
# ---------------------------------------------------------------------------

def generate_invalid_value(spec: dict) -> str:
    import string
    import random

    t = spec.get("type", "")

    if t == "int":
        min_v = spec.get("min", 0)
        max_v = spec.get("max", 100)

        return random.choice([
            str(min_v - random.randint(1, 100)), # below min
            str(max_v + random.randint(1, 100)), # above max
            "".join(random.choices(string.ascii_letters, k=5)), # wrong type
            "",  # empty
        ])

    if t == "hex":
        valid_chars = set("0123456789abcdefABCDEF")
        invalid_chars = list(set(string.printable) - valid_chars)
        return "".join(random.choice(invalid_chars) for _ in range(random.randint(1, 6)))

    if t == "string":
        valid_chars = set(spec.get("chars", string.ascii_letters))
        invalid_chars = list(set(string.printable) - valid_chars)
        max_len = spec.get("max", 10)
        return random.choice([
            "", # too short
            "".join(random.choice(list(valid_chars)) for _ in range(max_len + random.randint(1, 20))), # too long
            "".join(random.choice(invalid_chars) for _ in range(5)), # invalid chars
        ])

    if t == "boolean":
        return "".join(random.choices(string.ascii_letters, k=5))

    if t == "null":
        return random.choice(["None", "", "0"])

    if t == "float":
        return random.choice([
            "NaN",
            "inf",
            "-inf",
            "".join(random.choices(string.ascii_letters, k=5)),
            ""
        ])

    return ""

def mutate_tree(node: CFGNode, prob=0.2) -> CFGNode:
    """
    Mutate tree via subtree replacement.
    """
    node = copy.deepcopy(node)

    if random.random() < prob:
        return build_tree_from_spec(node.spec)

    if node.spec.get("type") == "object":
        max_fields = node.spec.get("max_fields", 3)
        new_children = []
        for pair in node.children:
            if isinstance(pair, tuple):
                k, v = pair
            else:
                k, v = pair.children if pair.children else (pair, pair)
            k = mutate_tree(k, prob)
            v = mutate_tree(v, prob)
            new_children.append((k, v))
            if len(new_children) >= max_fields:
                break
        node.children = new_children
        return node

    node.children = [mutate_tree(c, prob) if isinstance(c, CFGNode) else c
                     for c in node.children]
    return node

def violate_tree(node: CFGNode) -> CFGNode:
    """
    Break grammar intentionally at tree level.
    """
    node = copy.deepcopy(node)

    t = node.spec.get("type", "")

    if node.value is not None:
        node.value = generate_invalid_value(node.spec)
        return node

    if t in ("one_of", "weighted_one_of"):
        if node.children:
            node.children[0] = violate_tree(node.children[0])
        return node

    if t == "sequence" and "count" in node.spec:
        expected = node.spec["count"]
        wrong_count = expected + random.choice([
            -expected, # collapse to 0
            -random.randint(1, expected), # partial collapse
            random.randint(2, 5) # controlled expansion
        ])
        wrong_count = max(1, wrong_count)
        element_spec = node.spec["element"]
        node.children = [
            build_tree_from_spec(element_spec)
            for _ in range(wrong_count)
        ]
        return node
    
    if t == "array":
        min_len = node.spec.get("min_length", 0)
        max_len = node.spec.get("max_length", 10)
        current = len(node.children)
        if random.random() < 0.5:
            # underflow, array too small
            target_len = max(0, min_len - random.randint(1, 3))
        else:
            # overflow, array too large
            target_len = max_len + random.randint(1, 3)
        if target_len < current:
            # truncation
            node.children = node.children[:target_len]
        else:
            # expansion
            element_spec = node.spec.get("element", {"type": "int"})
            for _ in range(target_len - current):
                node.children.append(build_tree_from_spec(element_spec))
        return node

    if t == "object":
        current = len(node.children)
        mode = random.choices(
            ["overflow", "underflow", "key_break", "value_break"],
            weights=[0.3, 0.3, 0.2, 0.2]
        )[0]
        key_spec = node.spec.get("key_schema") or node.spec.get("key", {"type": "string"})
        value_spec = node.spec.get("value_schema") or node.spec.get("value", {"type": "int"})
        if mode == "overflow":
            extra = random.randint(1, 3)
            for _ in range(extra):
                k = build_tree_from_spec(key_spec)
                v = build_tree_from_spec(value_spec)
                node.children.append((k, v))
        elif mode == "underflow":
            node.children = node.children[:max(0, len(node.children) - random.randint(1, len(node.children) or 1))]
        elif mode == "key_break":
            if node.children:
                i = random.randint(0, len(node.children) - 1)
                k, v = node.children[i]
                # corrupt key only
                node.children[i] = (
                    CFGNode(key_spec, value=generate_invalid_value(key_spec)),
                    v
                )
        elif mode == "value_break":
            if node.children:
                i = random.randint(0, len(node.children) - 1)
                k, v = node.children[i]
                # corrupt value only
                node.children[i] = (
                    k,
                    CFGNode(value_spec, value=generate_invalid_value(value_spec))
                )
        return node

    if node.children:
        # Recursive Fallback
        i = random.randint(0, len(node.children) - 1)
        node.children[i] = violate_tree(node.children[i])

    return node

def mutate_from_spec(seed: str, spec: dict) -> str:
    """
    CFG-based mutation using tree operations.
    """
    if not spec:
        return seed
    try:
        tree = parse_string_to_tree(seed, spec)
        choice = random.choice(["fresh", "mutate", "violate"])
        if choice == "fresh":
            return generate_from_spec(spec)
        elif choice == "mutate":
            return tree_to_string(mutate_tree(tree))
        elif choice == "violate":
            return tree_to_string(violate_tree(tree))
    except Exception:
        return generate_from_spec(spec)


# ---------------------------------------------------------------------------
# File-based seed generation
# ---------------------------------------------------------------------------

def generate_seeds_from_yaml(yaml_path: str, count: int | None = None) -> list[str]:
    """Generate seeds from a YAML grammar config and write to seeds_path."""
    with open(yaml_path) as f:
        config = yaml.safe_load(f)

    seed_count = count or config.get("seed_count", 10)
    input_spec = config.get("input")
    if not input_spec:
        print(f"[warn] No 'input:' grammar block found in {yaml_path}")
        return []

    seeds = [generate_from_spec(input_spec) for _ in range(seed_count)]

    seeds_path = config.get("seeds_path", "seeds.txt")
    os.makedirs(os.path.dirname(os.path.abspath(seeds_path)), exist_ok=True)
    with open(seeds_path, "w") as f:
        for s in seeds:
            f.write(str(s) + "\n")

    print(f"[+] Generated {len(seeds)} seeds → {seeds_path}")
    return seeds


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Generalised grammar-based seed generator")
    parser.add_argument("yaml_file", help="Path to YAML grammar config")
    parser.add_argument("--count", type=int,
                        help="Number of seeds to generate")
    args = parser.parse_args()
    generate_seeds_from_yaml(args.yaml_file, args.count)
