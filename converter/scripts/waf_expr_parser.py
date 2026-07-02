"""Cloudflare WAF expression parser — recursive descent.

Parses Cloudflare rule expressions into a conditions tree (nested dicts).
Also provides a serializer for round-trip validation.

Grammar:
  expr     = or_expr
  or_expr  = and_expr ("or" and_expr)*
  and_expr = not_expr ("and" not_expr)*
  not_expr = "not" not_expr | atom
  atom     = "(" expr ")" | func_call | field_op_value | bool_field
"""

from __future__ import annotations
import re
from enum import Enum, auto
from typing import Any

# ── Token types ──────────────────────────────────────────────────────────────

class TT(Enum):
    FIELD = auto()
    STRING = auto()
    NUMBER = auto()
    LBRACE = auto()     # {
    RBRACE = auto()     # }
    LPAREN = auto()     # (
    RPAREN = auto()     # )
    COMMA = auto()
    DOLLAR = auto()     # $
    AND = auto()
    OR = auto()
    NOT = auto()
    OP = auto()         # eq, ne, contains, matches, wildcard, strict_wildcard,
                        # in, gt, lt, ge, le, ==, !=, ~, >, <, >=, <=
    EOF = auto()

# Operators: English notation and C-like notation
_OP_ENGLISH = {"eq", "ne", "contains", "matches", "wildcard", "in", "gt", "lt", "ge", "le"}
_OP_CLIKE = {"==", "!=", "~", ">", "<", ">=", "<="}
_OP_NORMALIZE = {
    "==": "eq", "!=": "ne", "~": "matches",
    ">": "gt", "<": "lt", ">=": "ge", "<=": "le",
}
# Functions recognized as operators in conditions tree
_FUNC_OPS = {"starts_with", "ends_with", "lower", "upper", "len"}

# Fields that are bare booleans (used without operator)
_BOOL_FIELDS = {"ssl"}

# Known Cloudflare field prefixes (for reference — tokenizer uses character-based scanning)
# Fields are identified by isalpha/isalnum + '._' characters in the tokenizer.


# ── Tokenizer ────────────────────────────────────────────────────────────────

class Token:
    __slots__ = ("type", "value", "pos")
    def __init__(self, type: TT, value: Any, pos: int):
        self.type = type
        self.value = value
        self.pos = pos
    def __repr__(self):
        return f"Token({self.type.name}, {self.value!r}, @{self.pos})"


def tokenize(expr: str) -> list[Token]:
    tokens = []
    i = 0
    n = len(expr)

    while i < n:
        # Skip whitespace
        if expr[i].isspace():
            i += 1
            continue

        pos = i

        # Parentheses and braces
        if expr[i] == '(':
            tokens.append(Token(TT.LPAREN, '(', pos))
            i += 1
        elif expr[i] == ')':
            tokens.append(Token(TT.RPAREN, ')', pos))
            i += 1
        elif expr[i] == '{':
            tokens.append(Token(TT.LBRACE, '{', pos))
            i += 1
        elif expr[i] == '}':
            tokens.append(Token(TT.RBRACE, '}', pos))
            i += 1
        elif expr[i] == ',':
            tokens.append(Token(TT.COMMA, ',', pos))
            i += 1
        elif expr[i] == '$':
            tokens.append(Token(TT.DOLLAR, '$', pos))
            i += 1

        # Two-char C-like operators
        elif expr[i:i+2] in ('==', '!=', '>=', '<='):
            tokens.append(Token(TT.OP, expr[i:i+2], pos))
            i += 2
        elif expr[i] in ('>', '<'):
            tokens.append(Token(TT.OP, expr[i], pos))
            i += 1
        elif expr[i] == '~':
            tokens.append(Token(TT.OP, '~', pos))
            i += 1

        # Quoted string: "..." or r"..."
        elif expr[i] == '"' or (expr[i] == 'r' and i + 1 < n and expr[i+1] == '"'):
            raw = expr[i] == 'r'
            if raw:
                i += 1  # skip 'r'
            i += 1  # skip opening "
            start = i
            while i < n and expr[i] != '"':
                if not raw and expr[i] == '\\':
                    i += 2  # skip escaped char
                else:
                    i += 1
            val = expr[start:i]
            if i < n:
                i += 1  # skip closing "
            tokens.append(Token(TT.STRING, val, pos))

        # Number or IP address (starts with digit or negative number)
        elif expr[i].isdigit() or (expr[i] == '-' and i + 1 < n and expr[i+1].isdigit()):
            start = i
            if expr[i] == '-':
                i += 1
            # Consume digits, dots, colons, slashes (covers IPs, CIDRs, IPv6, IP ranges)
            while i < n and (expr[i].isalnum() or expr[i] in '.:/'):
                i += 1
            # Also consume IP ranges: 1.2.3.4..5.6.7.8
            if i < n and expr[i] == '.' and i + 1 < n and expr[i+1] == '.':
                i += 2  # skip ..
                while i < n and (expr[i].isalnum() or expr[i] in '.:/'):
                    i += 1
            val = expr[start:i]
            # Determine if it's a number or an IP/CIDR token
            if re.fullmatch(r'-?\d+', val):
                tokens.append(Token(TT.NUMBER, int(val), pos))
            elif re.fullmatch(r'-?\d+\.\d+', val):
                tokens.append(Token(TT.NUMBER, float(val), pos))
            else:
                # IP address, CIDR, IPv6, IP range — treat as FIELD token
                tokens.append(Token(TT.FIELD, val, pos))

        # Word: keyword, operator, field, or function name
        elif expr[i].isalpha() or expr[i] == '_':
            start = i
            while i < n and (expr[i].isalnum() or expr[i] in '._'):
                i += 1
            word = expr[start:i]

            # "strict wildcard" is a two-word operator
            if word == "strict":
                j = i
                while j < n and expr[j].isspace():
                    j += 1
                if expr[j:j+8] == "wildcard":
                    tokens.append(Token(TT.OP, "strict_wildcard", pos))
                    i = j + 8
                    continue

            if word == "and":
                tokens.append(Token(TT.AND, "and", pos))
            elif word == "or":
                tokens.append(Token(TT.OR, "or", pos))
            elif word == "not":
                tokens.append(Token(TT.NOT, "not", pos))
            elif word in _OP_ENGLISH:
                tokens.append(Token(TT.OP, word, pos))
            elif word in _FUNC_OPS:
                tokens.append(Token(TT.FIELD, word, pos))  # treat as FIELD, parser handles func calls
            else:
                tokens.append(Token(TT.FIELD, word, pos))
        else:
            raise ParseError(f"Unexpected character: {expr[i]!r}", pos, expr)

    tokens.append(Token(TT.EOF, None, len(expr)))
    return tokens


# ── Parser ───────────────────────────────────────────────────────────────────

class ParseError(Exception):
    def __init__(self, msg: str, pos: int = -1, expr: str = ""):
        self.pos = pos
        self.expr = expr
        super().__init__(f"{msg} (at position {pos})" if pos >= 0 else msg)


class Parser:
    def __init__(self, tokens: list[Token], expr: str):
        self.tokens = tokens
        self.expr = expr
        self.pos = 0

    def peek(self) -> Token:
        return self.tokens[self.pos]

    def advance(self) -> Token:
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def expect(self, tt: TT) -> Token:
        t = self.advance()
        if t.type != tt:
            raise ParseError(f"Expected {tt.name}, got {t.type.name} ({t.value!r})", t.pos, self.expr)
        return t

    # ── Grammar rules ──

    def parse(self) -> dict:
        result = self.parse_or()
        if self.peek().type != TT.EOF:
            t = self.peek()
            raise ParseError(f"Unexpected token after expression: {t.value!r}", t.pos, self.expr)
        return result

    def parse_or(self) -> dict:
        left = self.parse_and()
        items = [left]
        while self.peek().type == TT.OR:
            self.advance()
            items.append(self.parse_and())
        return items[0] if len(items) == 1 else {"op": "or", "items": items}

    def parse_and(self) -> dict:
        left = self.parse_not()
        items = [left]
        while self.peek().type == TT.AND:
            self.advance()
            items.append(self.parse_not())
        return items[0] if len(items) == 1 else {"op": "and", "items": items}

    def parse_not(self) -> dict:
        if self.peek().type == TT.NOT:
            self.advance()
            return {"op": "not", "item": self.parse_not()}
        return self.parse_atom()

    def parse_atom(self) -> dict:
        t = self.peek()

        # Parenthesized expression
        if t.type == TT.LPAREN:
            self.advance()
            result = self.parse_or()
            self.expect(TT.RPAREN)
            return result

        # Function call: starts_with(...), ends_with(...), lower(...), len(...)
        if t.type == TT.FIELD and t.value in _FUNC_OPS:
            return self.parse_func_call()

        # Field-based expression
        if t.type == TT.FIELD:
            return self.parse_field_expr()

        raise ParseError(f"Unexpected token: {t.type.name} ({t.value!r})", t.pos, self.expr)

    def parse_func_call(self) -> dict:
        func_tok = self.advance()  # function name
        func_name = func_tok.value

        # lower(field) op value  →  { field, op, value, transform: "lowercase" }
        if func_name == "lower":
            self.expect(TT.LPAREN)
            field = self.expect(TT.FIELD).value
            self.expect(TT.RPAREN)
            op_tok = self.expect(TT.OP)
            op = _OP_NORMALIZE.get(op_tok.value, op_tok.value)
            value = self.parse_value()
            return {"field": field, "operator": op, "value": value, "transform": "lowercase"}

        # upper(field) op value
        if func_name == "upper":
            self.expect(TT.LPAREN)
            field = self.expect(TT.FIELD).value
            self.expect(TT.RPAREN)
            op_tok = self.expect(TT.OP)
            op = _OP_NORMALIZE.get(op_tok.value, op_tok.value)
            value = self.parse_value()
            return {"field": field, "operator": op, "value": value, "transform": "uppercase"}

        # starts_with(field, value)  →  { field, operator: "starts_with", value }
        # ends_with(field, value)
        if func_name in ("starts_with", "ends_with"):
            self.expect(TT.LPAREN)
            field = self.expect(TT.FIELD).value
            self.expect(TT.COMMA)
            value = self.parse_value()
            self.expect(TT.RPAREN)
            return {"field": field, "operator": func_name, "value": value}

        # len(field) op number  →  { field, operator: op, value: number }
        if func_name == "len":
            self.expect(TT.LPAREN)
            field = self.expect(TT.FIELD).value
            self.expect(TT.RPAREN)
            op_tok = self.expect(TT.OP)
            op = _OP_NORMALIZE.get(op_tok.value, op_tok.value)
            value = self.parse_value()
            return {"field": field, "operator": op, "value": value, "size_check": True}

        raise ParseError(f"Unknown function: {func_name}", func_tok.pos, self.expr)

    def parse_field_expr(self) -> dict:
        field_tok = self.advance()
        field = field_tok.value

        # Check if next token is an operator
        if self.peek().type == TT.OP:
            op_tok = self.advance()
            op = _OP_NORMALIZE.get(op_tok.value, op_tok.value)
            value = self.parse_value()
            return {"field": field, "operator": op, "value": value}

        # Check for "in" operator (already tokenized as OP)
        # If no operator follows, it's a bare boolean field
        return {"field": field, "operator": "eq", "value": True}

    def parse_value(self) -> Any:
        t = self.peek()

        # Quoted string
        if t.type == TT.STRING:
            self.advance()
            return t.value

        # Number
        if t.type == TT.NUMBER:
            self.advance()
            return t.value

        # Named list: $list_name
        if t.type == TT.DOLLAR:
            self.advance()
            name_tok = self.expect(TT.FIELD)
            return f"${name_tok.value}"

        # Inline set: { val1 val2 val3 }
        if t.type == TT.LBRACE:
            return self.parse_inline_set()

        raise ParseError(f"Expected value, got {t.type.name} ({t.value!r})", t.pos, self.expr)

    def parse_inline_set(self) -> str:
        """Parse { ... } and return as raw string including braces."""
        self.expect(TT.LBRACE)
        items = []
        while self.peek().type != TT.RBRACE:
            t = self.peek()
            if t.type == TT.STRING:
                self.advance()
                items.append(f'"{t.value}"')
            elif t.type == TT.NUMBER:
                self.advance()
                items.append(str(t.value))
            elif t.type == TT.FIELD:
                # IP addresses, CIDR, IP ranges (e.g., 200.1.1.1, 2000::1, 10.0.0.0/24)
                self.advance()
                items.append(t.value)
            else:
                raise ParseError(f"Unexpected token in set: {t.type.name}", t.pos, self.expr)
        self.expect(TT.RBRACE)
        return "{" + " ".join(items) + "}"


# ── Serializer (conditions tree → expression string) ─────────────────────────

def serialize(cond: dict) -> str:
    """Convert a conditions tree back to a Cloudflare expression string."""
    if "op" in cond:
        op = cond["op"]
        if op == "and":
            parts = [_serialize_child(c, "and") for c in cond["items"]]
            return " and ".join(parts)
        if op == "or":
            parts = [_serialize_child(c, "or") for c in cond["items"]]
            return " or ".join(parts)
        if op == "not":
            child = _serialize_child(cond["item"], "not")
            return f"not {child}"

    # Leaf condition
    field = cond["field"]
    operator = cond["operator"]
    value = cond["value"]
    transform = cond.get("transform")

    # Function-style operators
    if operator in ("starts_with", "ends_with"):
        return f'{operator}({field}, {_format_value(value)})'

    # Transform wrapper
    if transform == "lowercase":
        return f'lower({field}) {operator} {_format_value(value)}'
    if transform == "uppercase":
        return f'upper({field}) {operator} {_format_value(value)}'

    # Size check
    if cond.get("size_check"):
        return f'len({field}) {operator} {_format_value(value)}'

    # Bare boolean
    if operator == "eq" and value is True:
        return field

    # Serializer operator name mapping (internal → Cloudflare expression syntax)
    op_out = "strict wildcard" if operator == "strict_wildcard" else operator

    return f'{field} {op_out} {_format_value(value)}'


def _serialize_child(cond: dict, parent_op: str) -> str:
    """Serialize a child, adding parens if needed for precedence."""
    s = serialize(cond)
    if "op" in cond:
        child_op = cond["op"]
        # Need parens if child has lower precedence than parent
        if parent_op == "and" and child_op == "or":
            return f"({s})"
        if parent_op == "not" and child_op in ("and", "or"):
            return f"({s})"
    return s


def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        if value.startswith("$") or value.startswith("{"):
            return value
        return f'"{value}"'
    if isinstance(value, (int, float)):
        return str(value)
    return repr(value)


# ── Round-trip structural comparison ─────────────────────────────────────────

def _normalize_tree(cond: dict) -> dict:
    """Normalize a conditions tree for structural comparison.
    Sorts AND/OR operands for order-independent comparison."""
    if "op" in cond:
        op = cond["op"]
        if op in ("and", "or"):
            items = sorted([_normalize_tree(c) for c in cond["items"]],
                           key=lambda x: _tree_sort_key(x))
            return {"op": op, "items": items}
        if op == "not":
            return {"op": "not", "item": _normalize_tree(cond["item"])}
    # Leaf — normalize value for IP sets (sort items)
    result = dict(cond)
    if isinstance(result.get("value"), str) and result["value"].startswith("{"):
        inner = result["value"][1:-1].split()
        result["value"] = "{" + " ".join(sorted(inner)) + "}"
    return result


def _tree_sort_key(cond: dict) -> str:
    """Generate a sort key for a conditions tree node."""
    if "op" in cond:
        return f"0_{cond['op']}_{serialize(cond)}"
    return f"1_{cond.get('field', '')}_{cond.get('operator', '')}_{cond.get('value', '')}"


def trees_equal(a: dict, b: dict) -> bool:
    """Structurally compare two conditions trees (order-independent for AND/OR)."""
    return _normalize_tree(a) == _normalize_tree(b)


def round_trip_validate(expr: str) -> tuple[bool, dict, str]:
    """Parse expr, serialize back, re-parse, compare trees.
    Returns (ok, conditions_tree, error_message)."""
    try:
        tree1 = parse(expr)
    except ParseError as e:
        return False, {}, f"Parse error: {e}"

    serialized = serialize(tree1)
    try:
        tree2 = parse(serialized)
    except ParseError as e:
        return False, tree1, f"Round-trip parse error on serialized form: {e}"

    if trees_equal(tree1, tree2):
        return True, tree1, ""
    return False, tree1, f"Round-trip mismatch: original parsed differently from serialized"


# ── IP address utilities ─────────────────────────────────────────────────────

def is_ipv6(addr: str) -> bool:
    return ":" in addr.split("/")[0]


def ensure_cidr(addr: str) -> str:
    if "/" in addr:
        return addr
    return f"{addr}/128" if is_ipv6(addr) else f"{addr}/32"


def extract_ip_sets(cond: dict, rule_name: str, position: int = 0) -> list[dict]:
    """Walk conditions tree, find all ip.src in {...} leaves, extract IP sets.
    Returns list of {"name": ..., "addresses": [...]} dicts.
    Also annotates each leaf node with "_ip_set_names" for generator matching."""
    ip_sets = []
    _counter = [0]

    slug = re.sub(r'[^a-z0-9]+', '_', rule_name.lower()).strip('_')
    if len(slug) < 3:
        slug = f"rule_{position}"

    def _walk(node: dict):
        if "op" in node:
            if node["op"] in ("and", "or"):
                for item in node["items"]:
                    _walk(item)
            elif node["op"] == "not":
                _walk(node["item"])
            return

        # Leaf: check for inline IP set
        if node.get("field", "") == "ip.src" and node.get("operator") in ("in", "not_in"):
            value = node.get("value", "")
            if isinstance(value, str) and value.startswith("{") and not value.startswith("${"):
                addrs = value[1:-1].split()
                addrs = [ensure_cidr(a) for a in addrs]
                v4 = [a for a in addrs if not is_ipv6(a)]
                v6 = [a for a in addrs if is_ipv6(a)]
                suffix = f"_{_counter[0]}" if _counter[0] > 0 else ""
                _counter[0] += 1
                names = []
                if v4:
                    name_v4 = f"{slug}{suffix}-ipv4"
                    ip_sets.append({"name": name_v4, "addresses": v4})
                    names.append(name_v4)
                if v6:
                    name_v6 = f"{slug}{suffix}-ipv6"
                    ip_sets.append({"name": name_v6, "addresses": v6})
                    names.append(name_v6)
                # Annotate the leaf so generator can match precisely
                node["_ip_set_names"] = names

    _walk(cond)
    return ip_sets


# ── Public API ───────────────────────────────────────────────────────────────

def parse(expr: str) -> dict:
    """Parse a Cloudflare expression string into a conditions tree."""
    tokens = tokenize(expr.strip())
    parser = Parser(tokens, expr)
    return parser.parse()
