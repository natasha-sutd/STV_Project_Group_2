"""
Generalised grammar-based seed generator and grammar-aware mutator.

Supported grammar types:
  int — random integer in [min, max]
  float — random float in [min, max]
  hex — random hex string in [min, max]
  string — random string of length [min_length, max_length]
  literal — fixed string value
  boolean — "True" or "False"
  null — literal "null"
  array — list of elements
  object — dict with specified keys and values
  sequence — repeat element N times with separator
  concat — concatenate fixed parts
  one_of — randomly choose one of the options
  any - random value of any specified type
"""

from __future__ import annotations

import os
import random
import json
import string
import yaml
from typing import Any
import copy
import ast


TYPE_GENERATORS: dict[str, callable] = {}
TERMINAL_TYPES = {"int", "float", "hex", "string", "literal", "boolean", "null"}

ANY_OPTIONS = []
ANY_MAX_DEPTH = 3


def register_type(name: str):
    """Decorator to register a generator function for a grammar type."""

    def decorator(func):
        TYPE_GENERATORS[name] = func
        return func

    return decorator


@register_type("int")
def gen_int(spec: dict, current_depth: int = 0) -> str:
    return str(random.randint(spec.get("min", 0), spec.get("max", 100)))


@register_type("float")
def gen_float(spec: dict, current_depth: int = 0) -> str:
    return str(random.uniform(spec.get("min", 0.0), spec.get("max", 100.0)))


@register_type("hex")
def gen_hex(spec: dict, current_depth: int = 0) -> str:
    return format(random.randint(spec.get("min", 0), spec.get("max", 65535)), "x")


@register_type("string")
def gen_string(spec: dict, current_depth: int = 0) -> str:
    length = random.randint(spec.get("min_length", 1), spec.get("max_length", 10))
    chars = spec.get("chars", string.ascii_letters)
    return "".join(random.choice(chars) for _ in range(length))


@register_type("boolean")
def gen_boolean(spec: dict, current_depth: int = 0) -> str:
    return str(random.choice([True, False]))


@register_type("null")
def gen_null(spec: dict, current_depth: int = 0) -> str:
    return "null"


@register_type("literal")
def gen_literal(spec: dict, current_depth: int = 0) -> str:
    return str(spec.get("value", ""))


@register_type("array")
def gen_array(spec: dict, current_depth: int = 0) -> str:
    length = random.randint(spec.get("min_length", 0), spec.get("max_length", 10))
    element_spec = spec.get("element", {"type": "int", "min": 0, "max": 100})
    elements = [
        generate_from_spec(element_spec, current_depth + 1) for _ in range(length)
    ]
    return f"[{', '.join(elements)}]"


@register_type("object")
def gen_object(spec: dict, current_depth: int = 0) -> str:
    key_spec = spec.get("key", {"type": "string", "min_length": 1, "max_length": 8})
    value_spec = spec.get("value", {"type": "int", "min": 0, "max": 100})
    n_fields = random.randint(1, spec.get("max_fields", 3))

    obj = {}
    for _ in range(n_fields):
        k = generate_from_spec(key_spec, current_depth + 1)
        v = generate_from_spec(value_spec, current_depth + 1)
        obj[k] = v

    return json.dumps(obj)


@register_type("any")
def gen_any(spec: dict, current_depth: int = 0) -> str:
    return generate_any(spec, current_depth)


def generate_any(spec: dict, current_depth: int = 0) -> str:
    max_depth = spec.get("max_depth", ANY_MAX_DEPTH)

    if current_depth >= max_depth:
        terminal_options = [o for o in ANY_OPTIONS if o.get("type") in TERMINAL_TYPES]
        chosen = random.choice(terminal_options)
    else:
        chosen = random.choice(ANY_OPTIONS)

    return generate_from_spec(chosen, current_depth)


# entry point
def generate_from_spec(spec: Any, current_depth: int = 0, max_depth: int = 5) -> str:
    """
    Recursively generate a value from a grammar spec dict.
    Returns a string in all cases.
    """
    if not isinstance(spec, dict):
        return str(spec)

    t = spec.get("type", "")

    if t in TYPE_GENERATORS:
        result = TYPE_GENERATORS[t](spec, current_depth + 1)

    # Aliases
    elif t == "sequence":
        sep = str(spec.get("separator", ""))
        element_spec = spec.get("element", {"type": "int", "min": 0, "max": 9})
        count = random.randint(spec.get("min_length", 1), spec.get("max_length", 8))
        result = sep.join(
            str(generate_from_spec(element_spec, current_depth + 1, max_depth))
            for _ in range(count)
        )

    elif t == "concat":
        result = "".join(
            str(generate_from_spec(p, current_depth + 1, max_depth))
            for p in spec.get("parts", [])
        )

    elif t == "one_of":
        options = spec.get("options", [])
        result = (
            str(
                generate_from_spec(random.choice(options), current_depth + 1, max_depth)
            )
            if options
            else ""
        )
    else:
        result = ""

    return str(result)


# Context Free Grammar tree
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
    if t in TERMINAL_TYPES:
        return CFGNode(spec, value=generate_from_spec(spec))

    # one_of
    if t == "one_of":
        options = spec.get("options", [])
        if not options:
            return CFGNode(spec, value="")
        return CFGNode(
            spec, [build_tree_from_spec(random.choice(options), depth + 1, max_depth)]
        )

    # sequence
    if t == "sequence":
        return CFGNode(
            spec,
            [
                build_tree_from_spec(spec["element"], depth + 1, max_depth)
                for _ in range(
                    random.randint(spec.get("min_length", 1), spec.get("max_length", 8))
                )
            ],
        )

    # concat
    if t == "concat":
        return CFGNode(
            spec,
            [
                build_tree_from_spec(p, depth + 1, max_depth)
                for p in spec.get("parts", [])
            ],
        )

    # array
    if t == "array":
        length = random.randint(spec.get("min_length", 1), spec.get("max_length", 3))
        element_spec = spec.get("element", {"type": "any"})
        if not isinstance(element_spec, dict):
            element_spec = {"type": "any"}
        return CFGNode(
            spec,
            [
                build_tree_from_spec(element_spec, depth + 1, max_depth)
                for _ in range(length)
            ],
        )

    # object
    if t == "object":
        key_spec = spec.get("key", {"type": "string"})
        value_spec = spec.get("value", {"type": "any"})
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

    if t == "sequence":
        sep = str(spec.get("separator", ""))
        return sep.join(tree_to_string(c) for c in node.children)

    if t == "concat":
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

    if t in ("one_of"):
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
        if t in TERMINAL_TYPES:
            return CFGNode(spec, value=seed)

        # sequence
        if t == "sequence":
            sep = spec.get("separator", "")
            parts = seed.split(sep) if sep else list(seed)
            element_spec = spec.get("element", {})
            children = [parse_string_to_tree(p, element_spec) for p in parts]
            return CFGNode(spec, children)

        # array
        if t == "array":
            arr = ast.literal_eval(seed)
            element_spec = spec.get("element", {"type": "any"})
            if not isinstance(element_spec, dict):
                element_spec = {"type": "any"}
            children = [parse_string_to_tree(str(x), element_spec) for x in arr]
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

        # one_of
        if t in ("one_of"):
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
                    while i < len(remaining) and (
                        remaining[i].isdigit() or (i == 0 and remaining[i] == "-")
                    ):
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


# Grammar aware mutations
def generate_invalid_value(spec: dict) -> str:
    import string
    import random

    t = spec.get("type", "")

    if t == "int":
        min_v = spec.get("min", 0)
        max_v = spec.get("max", 100)

        return random.choice(
            [
                str(min_v - random.randint(1, 100)),  # below min
                str(max_v + random.randint(1, 100)),  # above max
                "".join(random.choices(string.ascii_letters, k=5)),  # wrong type
                "",  # empty
            ]
        )

    if t == "hex":
        valid_chars = set("0123456789abcdefABCDEF")
        invalid_chars = list(set(string.printable) - valid_chars)
        return "".join(
            random.choice(invalid_chars) for _ in range(random.randint(1, 6))
        )

    if t == "string":
        valid_chars = set(spec.get("chars", string.ascii_letters))
        invalid_chars = list(set(string.printable) - valid_chars)
        max_len = spec.get("max", 10)
        return random.choice(
            [
                "",  # too short
                "".join(
                    random.choice(list(valid_chars))
                    for _ in range(max_len + random.randint(1, 20))
                ),  # too long
                "".join(
                    random.choice(invalid_chars) for _ in range(5)
                ),  # invalid chars
            ]
        )

    if t == "boolean":
        return "".join(random.choices(string.ascii_letters, k=5))

    if t == "null":
        return random.choice(["None", "", "0"])

    if t == "float":
        min_v = spec.get("min", 0.0)
        max_v = spec.get("max", 100.0)
        return random.choice(
            [
                str(min_v - random.uniform(1, 100)),  # below min
                str(max_v + random.uniform(1, 100)),  # above max
                "".join(random.choices(string.ascii_letters, k=5)),  # wrong type
                "",  # empty
                "NaN",
                "inf",
                "-inf",
            ]
        )
    
    if t == "literal":
        expected = str(spec.get("value", ""))
        return random.choice(string.ascii_letters - set(expected))

    if t == "any":
        return random.choice(
            [
                "{",
                "[",
                ":",
                ",",
                "undefined",
            ]
        )

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

    node.children = [
        mutate_tree(c, prob) if isinstance(c, CFGNode) else c for c in node.children
    ]
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

    if t == "one_of":
        if node.children:
            node.children[0] = violate_tree(node.children[0])
        return node

    if t == "sequence":
        min_length = node.spec.get("min_length", 1)
        max_length = node.spec.get("max_length", 8)
        exceed_min = max(0, min_length - random.randint(1, 3))
        exceed_max = random.randint(1, 3) + max_length
        valid = set(range(min_length, max_length + 1))
        all_vals = set(range(exceed_min, exceed_max + 1))
        invalid = list(all_vals - valid)

        wrong_count = random.choice(invalid) if invalid else min_length
        element_spec = node.spec["element"]
        node.children = [build_tree_from_spec(element_spec) for _ in range(wrong_count)]
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
            weights=[0.3, 0.3, 0.2, 0.2],
        )[0]
        key_spec = node.spec.get("key", {"type": "string"})
        value_spec = node.spec.get("value", {"type": "int"})
        if mode == "overflow":
            extra = random.randint(1, 3)
            for _ in range(extra):
                k = build_tree_from_spec(key_spec)
                v = build_tree_from_spec(value_spec)
                node.children.append((k, v))
        elif mode == "underflow":
            node.children = node.children[
                : max(
                    0, len(node.children) - random.randint(1, len(node.children) or 1)
                )
            ]
        elif mode == "key_break":
            if node.children:
                i = random.randint(0, len(node.children) - 1)
                k, v = node.children[i]
                # corrupt key only
                node.children[i] = (
                    CFGNode(key_spec, value=generate_invalid_value(key_spec)),
                    v,
                )
        elif mode == "value_break":
            if node.children:
                i = random.randint(0, len(node.children) - 1)
                k, v = node.children[i]
                # corrupt value only
                node.children[i] = (
                    k,
                    CFGNode(value_spec, value=generate_invalid_value(value_spec)),
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


# seed genearator
def generate_seeds_from_yaml(yaml_config: dict, count: int | None = None) -> list[str]:
    """Generate seeds from a YAML grammar config and write to seeds_path."""
    global ANY_OPTIONS, ANY_MAX_DEPTH

    any_spec = yaml_config.get("any", {})
    if any_spec:
        ANY_OPTIONS = any_spec.get("options", [])
        ANY_MAX_DEPTH = any_spec.get("max_depth", 3)

    seed_count = count or yaml_config.get("seed_count", 30)
    input_spec = yaml_config.get("input")
    if not input_spec:
        print(f"[warn] No 'input:' grammar block found in config")
        return []

    seeds = [generate_from_spec(input_spec) for _ in range(seed_count)]

    seeds_path = yaml_config.get("seeds_path", "seeds.txt")
    os.makedirs(os.path.dirname(os.path.abspath(seeds_path)), exist_ok=True)
    with open(seeds_path, "w") as f:
        for s in seeds:
            f.write(str(s) + "\n")

    return seeds
