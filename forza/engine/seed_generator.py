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
    choice = random.choice(["int", "string", "boolean", "null"])
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
    return str(items)


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
        return str(obj)
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

    # one_of / weighted_one_of
    if t in ("one_of", "weighted_one_of"):
        options = spec.get("options", [])
        if not options:
            return CFGNode(spec, value="")
        weights = [float(o.get("weight", 1.0)) for o in options]
        chosen = random.choices(options, weights=weights, k=1)[0]
        return CFGNode(spec, [build_tree_from_spec(chosen, depth + 1, max_depth)])

    # sequence
    if t == "sequence" and "count" in spec:
        return CFGNode(spec, [
            build_tree_from_spec(spec["element"], depth + 1, max_depth)
            for _ in range(spec["count"])
        ])
    
    if t in ("sequence", "concat"):
        return CFGNode(spec, [
            build_tree_from_spec(p, depth + 1, max_depth)
            for p in spec.get("parts", [])
        ])

    # array
    if t == "array":
        length = random.randint(spec.get("min_length", 1), spec.get("max_length", 3))
        return CFGNode(spec, [
            build_tree_from_spec(spec.get("element", {"type": "int"}), depth + 1, max_depth)
            for _ in range(length)
        ])

    # object
    if t == "object":
        key_spec = spec.get("key_schema") or spec.get("key", {"type": "string"})
        value_spec = spec.get("value_schema") or spec.get("value", {"type": "int"})
        children = []
        for _ in range(random.randint(1, spec.get("max_fields", 3))):
            k = build_tree_from_spec(key_spec, depth + 1, max_depth)
            v = build_tree_from_spec(value_spec, depth + 1, max_depth)
            children.append((k, v))
        return CFGNode(spec, children)
    return CFGNode(spec, value=generate_from_spec(spec))

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
            s = tree_to_string(c)
            try:
                val = json.loads(s)
            except:
                val = s
            result.append(val)
        return json.dumps(result)

    if t == "object":
        obj = {}
        for k, v in node.children:
            key = tree_to_string(k)
            val_str = tree_to_string(v)
            try:
                val = json.loads(val_str)
            except:
                val = val_str
            obj[str(key)] = val
        return json.dumps(obj)

    if t in ("one_of", "weighted_one_of"):
        return tree_to_string(node.children[0]) if node.children else ""

    return "".join(tree_to_string(c) for c in node.children)

# ---------------------------------------------------------------------------
# Grammar-aware mutation
# ---------------------------------------------------------------------------

def mutate_tree(node: CFGNode, prob=0.2) -> CFGNode:
    """
    Mutate tree via subtree replacement.
    """
    node = copy.deepcopy(node)

    if random.random() < prob:
        return build_tree_from_spec(node.spec)

    if node.spec.get("type") == "object":
        new_children = []
        for k, v in node.children:
            k = mutate_tree(k, prob)
            v = mutate_tree(v, prob)
            new_children.append((k, v))
        node.children = new_children
        return node

    node.children = [mutate_tree(c, prob) if isinstance(c, CFGNode) else c
                     for c in node.children]
    return node

def violate_tree(node: CFGNode) -> CFGNode:
    """
    Break grammar intentionally at tree level.
    """
    t = node.spec.get("type", "")

    if t == "int":
        node.value = random.choice(["999999", "-999999", "NaN", ""])
        return node

    if t == "hex":
        node.value = random.choice(["GGGG", "-1", ""])
        return node

    if t == "sequence" and "count" in node.spec:
        node.children = [
            build_tree_from_spec(node.spec["element"])
            for _ in range(max(0, node.spec["count"] + random.choice([-2, 2])))
        ]
        return node

    if node.children:
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
        tree = build_tree_from_spec(spec)
        choice = random.choice(["fresh", "mutate", "violate"])
        if choice == "fresh":
            return tree_to_string(tree)
        elif choice == "mutate":
            return tree_to_string(mutate_tree(tree))
        elif choice == "violate":
            return tree_to_string(violate_tree(tree))
    except Exception:
        return generate_from_spec(spec)

def violate_constraints(seed: str, spec: dict) -> str:
    from engine.mutation_engine import insert_special_char
    t = spec.get("type") if spec else ""
    if t == "int":
        return random.choice(["999", "-1", "NaN", ""])
    if t == "sequence" and spec and "count" in spec:
        return seed + ".extra"
    return insert_special_char(seed)


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
