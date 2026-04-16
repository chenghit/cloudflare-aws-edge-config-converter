#!/usr/bin/env python3
"""CDN JS code generator — deterministic Python replacement for Stage 8 LLM.

Reads all domain IRs from ir/final/<hostname>.json and generates CloudFront
Function JS (viewer_request.js, viewer_response.js) and Lambda@Edge handlers.

Usage:
    python3 cdn-generate-js.py <output_dir>
    # output_dir is e.g. "cloudflare-to-aws-cdn"
"""
import copy
import json
import os
import re
import sys
from pathlib import Path

# Add scripts dir to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from cdn_expr_parser import parse_expression_full, parse_dynamic_expression, CF_FIELD_MAP

# ── Constants ────────────────────────────────────────────────────────────────

CFF_SIZE_LIMIT = 10240  # 10 KB

# Fields always available (no existence check needed)
ALWAYS_AVAILABLE = {
    "uri.path", "uri", "host", "method", "ip.src", "uri.query",
    "uri.path.extension", "full_uri", "response_code",
}

# CFF field → JS accessor mapping (viewer-request)
CFF_ACCESSORS = {
    "uri.path": "request.uri",
    "uri": "request.uri",
    "uri.query": "request.rawQueryString()",
    "uri.path.extension": "request.uri.split('.').pop()",
    "host": "request.headers.host.value",
    "method": "request.method",
    "user_agent": ("request.headers['user-agent']", "request.headers['user-agent'].value"),
    "referer": ("request.headers.referer", "request.headers.referer.value"),
    "http_version": ("request.headers['cloudfront-viewer-http-version']", "request.headers['cloudfront-viewer-http-version'].value"),
    "ip.src": "event.viewer.ip",
    "country": ("request.headers['cloudfront-viewer-country']", "request.headers['cloudfront-viewer-country'].value"),
    "city": ("request.headers['cloudfront-viewer-city']", "request.headers['cloudfront-viewer-city'].value"),
    "region": ("request.headers['cloudfront-viewer-country-region-name']", "request.headers['cloudfront-viewer-country-region-name'].value"),
    "region_code": ("request.headers['cloudfront-viewer-country-region']", "request.headers['cloudfront-viewer-country-region'].value"),
    "latitude": ("request.headers['cloudfront-viewer-latitude']", "request.headers['cloudfront-viewer-latitude'].value"),
    "longitude": ("request.headers['cloudfront-viewer-longitude']", "request.headers['cloudfront-viewer-longitude'].value"),
    "postal_code": ("request.headers['cloudfront-viewer-postal-code']", "request.headers['cloudfront-viewer-postal-code'].value"),
    "metro_code": ("request.headers['cloudfront-viewer-metro-code']", "request.headers['cloudfront-viewer-metro-code'].value"),
    "timezone": ("request.headers['cloudfront-viewer-time-zone']", "request.headers['cloudfront-viewer-time-zone'].value"),
    "asnum": ("request.headers['cloudfront-viewer-asn']", "request.headers['cloudfront-viewer-asn'].value"),
}

# Lambda@Edge accessor overrides
LAMBDA_ACCESSORS = {
    "ip.src": "request.clientIp",
    "uri.query": "request.querystring",
    "host": "request.headers.host[0].value",
    "user_agent": ("request.headers['user-agent']", "request.headers['user-agent'][0].value"),
    "country": ("request.headers['cloudfront-viewer-country']", "request.headers['cloudfront-viewer-country'][0].value"),
}

# viewer-response accessor overrides
RESPONSE_ACCESSORS = {
    "response_code": "response.statusCode",
    "uri.path": "event.request.uri",
    "uri": "event.request.uri",
    "host": "event.request.headers.host.value",
    "method": "event.request.method",
    "ip.src": "event.viewer.ip",
}


def js_string(val):
    """Escape a value for JS string literal."""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val).replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
    return f"'{s}'"


def js_array(vals):
    """Format a list as JS array literal."""
    return "[" + ", ".join(js_string(v) for v in vals) + "]"


# ── Wildcard → JS ────────────────────────────────────────────────────────────

def _wildcard_pattern_to_regex(pattern):
    """Convert wildcard pattern to anchored regex. * → .* (greedy for conditions)."""
    result = "^"
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] == "*":
            result += "\\*"
            i += 2
        elif ch == "*":
            result += ".*"
            i += 1
        elif ch in r"\.+?^${}()|[]/":
            result += "\\" + ch
            i += 1
        else:
            result += ch
            i += 1
    result += "$"
    return result


def wildcard_to_js(accessor, pattern, strict=False):
    """Convert wildcard condition to optimal JS code."""
    stars = pattern.count("*") - pattern.count("\\*")
    if stars == 0:
        if strict:
            return f"{accessor} === {js_string(pattern)}"
        return f"{accessor}.toLowerCase() === {js_string(pattern.lower())}"
    if pattern == "*":
        return "true"
    if stars == 1:
        if pattern.endswith("*") and "*" not in pattern[:-1]:
            prefix = pattern[:-1]
            if strict:
                return f"{accessor}.startsWith({js_string(prefix)})"
            return f"{accessor}.toLowerCase().startsWith({js_string(prefix.lower())})"
        if pattern.startswith("*") and "*" not in pattern[1:]:
            suffix = pattern[1:]
            if strict:
                return f"{accessor}.endsWith({js_string(suffix)})"
            return f"{accessor}.toLowerCase().endsWith({js_string(suffix.lower())})"
    regex = _wildcard_pattern_to_regex(pattern)
    flags = "" if strict else "i"
    return f"/{regex}/{flags}.test({accessor})"


def _cf_regex_to_js(pattern):
    """Escape / in Cloudflare regex for JS regex literal."""
    return pattern.replace("/", "\\/")


# ── full_uri wildcard splitting ──────────────────────────────────────────────

def _split_full_uri_wildcard(pattern):
    """Split full_uri wildcard into (host_pattern, path_pattern) or None."""
    m = re.match(r"https?://", pattern)
    if not m:
        return None
    rest = pattern[m.end():]
    slash_idx = rest.find("/")
    if slash_idx == -1:
        return rest, "/*"
    return rest[:slash_idx], rest[slash_idx:]


# ── Condition → JS ───────────────────────────────────────────────────────────

def _get_accessor(field, target="cff"):
    """Get JS accessor for a field. Returns (check_expr, value_expr) or just value_expr."""
    if target == "lambda":
        acc = LAMBDA_ACCESSORS.get(field)
        if acc:
            return acc if isinstance(acc, tuple) else acc
    if target == "response":
        acc = RESPONSE_ACCESSORS.get(field)
        if acc:
            return acc
    acc = CFF_ACCESSORS.get(field)
    if acc is None:
        return field  # unknown field, pass through
    return acc


def _needs_check(field):
    return field not in ALWAYS_AVAILABLE


def condition_to_js(cond, target="cff", indent=2):
    """Convert a CDN condition tree to JS expression string."""
    if cond is None or cond.get("always"):
        return None  # unconditional

    if "logic" in cond:
        logic = cond["logic"]
        if logic == "and":
            parts = [condition_to_js(p, target, indent) for p in cond["parts"]]
            return " && ".join(f"({p})" if " || " in p else p for p in parts)
        if logic == "or":
            parts = [condition_to_js(p, target, indent) for p in cond["parts"]]
            return " || ".join(f"({p})" if " && " in p else p for p in parts)
        if logic == "not":
            inner = condition_to_js(cond["item"], target, indent)
            return f"!({inner})"

    field = cond.get("field", "")
    op = cond.get("op", "eq")
    value = cond.get("value")

    # Handle not_ prefix
    negated = False
    base_op = op
    if op.startswith("not_"):
        negated = True
        base_op = op[4:]

    # Special: full_uri wildcard with host/path split
    if field == "full_uri" and base_op in ("wildcard", "strict_wildcard") and "host_pattern" in cond:
        host_js = wildcard_to_js(
            _val_accessor("host", target), cond["host_pattern"], base_op == "strict_wildcard"
        )
        path_js = wildcard_to_js(
            _val_accessor("uri.path", target), cond["path_pattern"], base_op == "strict_wildcard"
        )
        expr = f"({host_js} && {path_js})" if host_js != "true" and path_js != "true" else (host_js if path_js == "true" else path_js)
        return f"!({expr})" if negated else expr

    # Special: continent / is_eu handled via preamble (not inline condition)
    # These are handled at the section level, not here.

    acc = _get_accessor(field, target)
    needs_check = _needs_check(field)

    if isinstance(acc, tuple):
        check_expr, val_expr = acc
    else:
        check_expr, val_expr = None, acc

    js_cond = _op_to_js(val_expr, base_op, value, field)

    if needs_check and check_expr:
        if negated:
            return f"!{check_expr} || !({js_cond})"
        return f"{check_expr} && {js_cond}"

    if negated:
        return f"!({js_cond})"
    return js_cond


def _val_accessor(field, target="cff"):
    """Get just the value accessor (not the check expression)."""
    acc = _get_accessor(field, target)
    if isinstance(acc, tuple):
        return acc[1]
    return acc


def _op_to_js(accessor, op, value, field=""):
    """Convert a single operator to JS expression."""
    if op == "eq":
        if value is True:
            return accessor
        return f"{accessor} === {js_string(value)}"
    if op == "ne":
        return f"{accessor} !== {js_string(value)}"
    if op == "gt":
        return f"{accessor} > {js_string(value)}"
    if op == "ge":
        return f"{accessor} >= {js_string(value)}"
    if op == "lt":
        return f"{accessor} < {js_string(value)}"
    if op == "le":
        return f"{accessor} <= {js_string(value)}"
    if op == "contains":
        return f"{accessor}.includes({js_string(value)})"
    if op == "starts_with":
        return f"{accessor}.startsWith({js_string(value)})"
    if op == "ends_with":
        return f"{accessor}.endsWith({js_string(value)})"
    if op == "in":
        if isinstance(value, list):
            return f"{js_array(value)}.includes({accessor})"
        # String set from parser
        return f"{js_array(value)}.includes({accessor})"
    if op == "in_list":
        return f"/* TODO: list {value} not resolved to KVS */ false"
    if op == "in_kvs":
        return f"await kvsHandle.exists('ip:{value}:' + {accessor})"
    if op in ("wildcard", "strict_wildcard"):
        return wildcard_to_js(accessor, value, op == "strict_wildcard")
    if op == "matches":
        return f"/{_cf_regex_to_js(value)}/.test({accessor})"
    return f"/* unknown op: {op} */ false"


# ── Dynamic expression → JS ──────────────────────────────────────────────────

def _dyn_field_to_js(cf_field, target="cff"):
    """Map a Cloudflare field name to JS accessor in dynamic expressions."""
    mapped = CF_FIELD_MAP.get(cf_field, cf_field)
    return _val_accessor(mapped, target)


def _wildcard_replace_glob_to_regex(pattern):
    """Convert wildcard_replace pattern to anchored lazy regex. * → (.*?)"""
    result = "^"
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] == "*":
            result += "\\*"
            i += 2
        elif ch == "*":
            result += "(.*?)"
            i += 1
        elif ch in r"\.+?^${}()|[]/":
            result += "\\" + ch
            i += 1
        else:
            result += ch
            i += 1
    result += "$"
    return result


def _capture_group_cf_to_js(repl):
    """Convert Cloudflare ${N} capture group refs to JS $N."""
    return re.sub(r"\$\{(\d+)\}", r"$\1", repl)


def dyn_expr_to_js(node, target="cff"):
    """Convert a parsed dynamic expression tree to JS code string."""
    if node["type"] == "literal":
        return js_string(node["value"])
    if node["type"] == "field":
        return _dyn_field_to_js(node["value"], target)
    if node["type"] != "func_call":
        return f"/* unknown node type: {node['type']} */"

    func = node["func"]
    args = node["args"]

    if func == "concat":
        parts = [dyn_expr_to_js(a, target) for a in args]
        return " + ".join(parts)

    if func == "regex_replace":
        field_js = dyn_expr_to_js(args[0], target)
        pattern = args[1]["value"]
        replacement = _capture_group_cf_to_js(args[2]["value"])
        return f"{field_js}.replace(/{_cf_regex_to_js(pattern)}/, {js_string(replacement)})"

    if func == "wildcard_replace":
        field_js = dyn_expr_to_js(args[0], target)
        pattern = args[1]["value"]
        replacement = _capture_group_cf_to_js(args[2]["value"])
        flags_val = args[3]["value"] if len(args) > 3 else ""
        regex = _wildcard_replace_glob_to_regex(pattern)
        i_flag = "" if flags_val == "s" else "i"
        return f"{field_js}.replace(/{regex}/{i_flag}, {js_string(replacement)})"

    if func == "lower":
        return f"{dyn_expr_to_js(args[0], target)}.toLowerCase()"
    if func == "upper":
        return f"{dyn_expr_to_js(args[0], target)}.toUpperCase()"
    if func == "to_string":
        return f"String({dyn_expr_to_js(args[0], target)})"
    if func == "substring":
        field_js = dyn_expr_to_js(args[0], target)
        start = dyn_expr_to_js(args[1], target)
        if len(args) > 2:
            end = dyn_expr_to_js(args[2], target)
            return f"{field_js}.substring({start}, {end})"
        return f"{field_js}.substring({start})"
    if func == "len":
        return f"{dyn_expr_to_js(args[0], target)}.length"
    if func == "url_decode":
        field_js = dyn_expr_to_js(args[0], target)
        if len(args) > 1 and "r" in str(args[1].get("value", "")):
            return f"(()=>{{let p='',c={field_js};while(c!==p){{p=c;c=decodeURIComponent(c)}}return c}})()"
        return f"decodeURIComponent({field_js})"

    if func == "encode_base64":
        inner = args[0]
        flags_val = args[1]["value"] if len(args) > 1 else ""
        # Optimize: encode_base64(sha256(...)) → digest('base64')
        if inner["type"] == "func_call" and inner["func"] == "sha256":
            sha_field = dyn_expr_to_js(inner["args"][0], target)
            enc = "base64url" if "u" in flags_val else "base64"
            result = f"crypto.createHash('sha256').update({sha_field}).digest('{enc}')"
            if "p" not in flags_val and "u" not in flags_val:
                result += ".replace(/=+$/, '')"
            return result
        field_js = dyn_expr_to_js(inner, target)
        if "u" in flags_val:
            result = f"Buffer.from({field_js}, 'utf8').toString('base64url')"
            if "p" in flags_val:
                b64_expr = f"Buffer.from({field_js}, 'utf8').toString('base64url')"
                result = f"(()=>{{const b={b64_expr};return b+'='.repeat((4-b.length%4)%4)}})()"
            return result
        if "p" in flags_val:
            return f"Buffer.from({field_js}, 'utf8').toString('base64')"
        return f"Buffer.from({field_js}, 'utf8').toString('base64').replace(/=+$/, '')"

    if func == "decode_base64":
        return f"atob({dyn_expr_to_js(args[0], target)})"

    if func == "sha256":
        field_js = dyn_expr_to_js(args[0], target)
        return f"crypto.createHash('sha256').update({field_js}).digest()"

    if func in ("lookup_json_string", "lookup_json_integer"):
        field_js = dyn_expr_to_js(args[0], target)
        keys = []
        for a in args[1:]:
            if a["type"] == "literal" and isinstance(a["value"], int):
                keys.append(f"[{a['value']}]")
            else:
                keys.append(f"[{js_string(a['value'])}]")
        chain = "".join(keys)
        default = "''" if func == "lookup_json_string" else "0"
        return f"(()=>{{try{{return JSON.parse({field_js}){chain}}}catch(e){{return {default}}}}})()"

    if func == "split":
        field_js = dyn_expr_to_js(args[0], target)
        sep = dyn_expr_to_js(args[1], target)
        if len(args) > 2:
            limit = dyn_expr_to_js(args[2], target)
            return f"{field_js}.split({sep}, {limit})"
        return f"{field_js}.split({sep})"

    if func == "join":
        items_js = dyn_expr_to_js(args[0], target)
        sep = dyn_expr_to_js(args[1], target)
        return f"{items_js}.join({sep})"

    if func == "remove_query_args":
        field_js = dyn_expr_to_js(args[0], target)
        param_names = ", ".join(js_string(a["value"]) for a in args[1:])
        return (f"(()=>{{const qs={field_js};if(!qs)return '';"
                f"const rm=new Set([{param_names}]);"
                f"return qs.split('&').filter(p=>!rm.has(p.split('=')[0])).join('&')}})()")

    if func == "remove_bytes":
        field_js = dyn_expr_to_js(args[0], target)
        bytes_str = args[1]["value"] if len(args) > 1 else ""
        chars = []
        i = 0
        while i < len(bytes_str):
            if bytes_str[i:i+2] == "\\x" and i + 3 < len(bytes_str):
                ch = chr(int(bytes_str[i+2:i+4], 16))
                chars.append(ch)
                i += 4
            else:
                chars.append(bytes_str[i])
                i += 1
        regex_chars = ""
        for ch in chars:
            if ch in r"\]^-./":
                regex_chars += "\\" + ch
            else:
                regex_chars += ch
        return f"{field_js}.replace(/[{regex_chars}]/g, '')"

    if func == "uuidv4":
        return ("(()=>{{return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>"
                "{{const r=Math.random()*16|0;return(c==='x'?r:(r&0x3|0x8)).toString(16)}})"
                "/* WARNING: not cryptographically secure */}})()")

    return f"/* unsupported function: {func} */"


# ── Header value substitution ────────────────────────────────────────────────

def _header_value_to_js(value, target="cff"):
    """Convert header value, handling $viewer_ip substitution."""
    if value == "$viewer_ip":
        return "event.viewer.ip" if target != "lambda" else "request.clientIp"
    if isinstance(value, str) and value.startswith("$"):
        return f"{js_string(value)} /* WARNING: unresolved variable */"
    return js_string(value)


# ── JS file assembly ─────────────────────────────────────────────────────────

def _resolve_dynamic_value(params, key, target="cff"):
    """Resolve a params value that may be a static string or dynamic expression."""
    val = params.get(key, "")
    if not val:
        return js_string("")
    # Check if it's a dynamic expression (contains function calls)
    if "(" in val and any(f + "(" in val for f in _DYN_FUNC_NAMES):
        try:
            tree = parse_dynamic_expression(val)
            return dyn_expr_to_js(tree, target)
        except Exception:
            return js_string(val)
    return js_string(val)


_DYN_FUNC_NAMES = {
    "concat", "regex_replace", "wildcard_replace", "lower", "upper",
    "to_string", "substring", "len", "url_decode", "encode_base64",
    "decode_base64", "lookup_json_string", "lookup_json_integer",
    "sha256", "split", "join", "remove_query_args", "remove_bytes", "uuidv4",
}


def _generate_op_js(op, target="cff", indent="  "):
    """Generate JS code for a single viewer_request op."""
    lines = []
    op_type = op.get("type", "")
    params = op.get("params", {})
    cond = op.get("condition")
    raw_expr = op.get("raw_expression")
    desc = op.get("description", "")

    # Resolve condition
    if raw_expr and not cond:
        try:
            cond = parse_expression_full(raw_expr)
        except Exception:
            lines.append(f"{indent}// TODO: could not parse condition: {raw_expr[:80]}")
            return lines

    cond_js = condition_to_js(cond, target)

    if op_type == "redirect":
        target_url = _resolve_dynamic_value(params, "target_url", target)
        if not target_url or target_url == "''":
            target_url = _resolve_dynamic_value(params, "target_expression", target)
        status = params.get("status_code", 301)
        body = f"return {{statusCode: {status}, headers: {{location: {{value: {target_url}}}}}}};"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type == "rewrite":
        new_uri = _resolve_dynamic_value(params, "path", target)
        if not new_uri or new_uri == "''":
            new_uri = _resolve_dynamic_value(params, "path_expression", target)
        body = f"request.uri = {new_uri};"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type == "origin_override":
        origin_host = params.get("origin_host", "")
        host_header = params.get("host_header", origin_host)
        port = params.get("origin_port")
        sni = params.get("sni")
        if target == "lambda":
            body_lines = [f"request.origin.custom.domainName = {js_string(origin_host)};"]
            if port:
                body_lines.append(f"request.origin.custom.port = {port};")
                body_lines.append(f"request.origin.custom.protocol = 'https';")
            body_lines.append(f"request.headers.host = [{{key: 'Host', value: {js_string(host_header)}}}];")
            body = " ".join(body_lines)
        else:
            uro_parts = [f"domainName: {js_string(origin_host)}"]
            if port:
                uro_parts.append(f"customOriginConfig: {{port: {port}, protocol: 'https', sslProtocols: ['TLSv1.2']}}")
            if sni:
                uro_parts.append(f"sni: {js_string(sni)}")
            body = f"cf.updateRequestOrigin({{{', '.join(uro_parts)}}});"
            if host_header and host_header != origin_host:
                body += f" request.headers.host = {{value: {js_string(host_header)}}};"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type == "bulk_redirect":
        # Handled as a fixed template block, not per-op
        pass

    elif op_type in ("set_request_header", "set_response_header", "set_header"):
        name = params.get("name", "").lower()
        value = params.get("value", "")
        value_expr = params.get("value_expression")
        if value_expr:
            val_js = _resolve_dynamic_value(params, "value_expression", target)
        else:
            val_js = _header_value_to_js(value, target)
        header_obj = "response.headers" if "response" in op_type else "request.headers"
        body = f"{header_obj}[{js_string(name)}] = {{value: {val_js}}};"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type in ("add_request_header", "add_response_header", "add_header"):
        name = params.get("name", "").lower()
        value = params.get("value", "")
        val_js = _header_value_to_js(value, target)
        header_obj = "response.headers" if "response" in op_type else "request.headers"
        body = f"if (!{header_obj}[{js_string(name)}]) {{ {header_obj}[{js_string(name)}] = {{value: {val_js}}}; }}"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type in ("remove_request_header", "remove_response_header", "remove_header"):
        name = params.get("name", "").lower()
        header_obj = "response.headers" if "response" in op_type else "request.headers"
        body = f"delete {header_obj}[{js_string(name)}];"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type == "serve_error_inline":
        kvs_key = params.get("kvs_key", "")
        status = params.get("status_code", 500)
        content_type = params.get("content_type", "text/html")
        body = (f"const body = await kvsHandle.get({js_string(kvs_key)}); "
                f"return {{statusCode: {status}, statusDescription: 'Custom Error', "
                f"headers: {{'content-type': {{value: {js_string(content_type)}}}}}, "
                f"body: {{encoding: 'text', data: body}}}};")
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    else:
        lines.append(f"{indent}// TODO: unsupported op type: {op_type}")

    return lines


def _needs_kvs(ir):
    """Check if any behavior needs KVS."""
    kvs = ir.get("metadata", {}).get("kvs_requirements", {})
    return any(kvs.values())


def _needs_crypto(ir):
    """Check if any op uses sha256/hmac (needs crypto import)."""
    for beh in ir.get("cache_behaviors", []):
        for op in beh.get("viewer_request_ops", []) + beh.get("viewer_response_ops", []):
            params = op.get("params", {})
            for key in ("value_expression", "target_expression", "path_expression", "target_url"):
                val = params.get(key, "")
                if val and ("sha256(" in val or "encode_base64(sha256(" in val):
                    return True
    return False


def _has_continent_or_eu(ops):
    """Check if any op condition references continent or is_eu."""
    for op in ops:
        cond = op.get("condition")
        if cond and _cond_has_field(cond, ("continent", "is_eu")):
            return True
    return False


def _cond_has_field(cond, fields):
    if cond is None:
        return False
    if cond.get("field") in fields:
        return True
    for p in cond.get("parts", []):
        if _cond_has_field(p, fields):
            return True
    if "item" in cond:
        return _cond_has_field(cond["item"], fields)
    return False


def _generate_bulk_redirect_block(indent="  "):
    """Generate the fixed bulk_redirect KVS lookup template."""
    return [
        f"{indent}const host = request.headers.host.value;",
        f"{indent}const uri = request.uri;",
        f"{indent}let kv = null;",
        f"{indent}try {{ kv = await kvsHandle.get('redirect:' + host + uri); }} catch(e) {{}}",
        f"{indent}if (kv === null && host.includes('.')) {{",
        f"{indent}  try {{ kv = await kvsHandle.get('redirect:.' + host + uri); }} catch(e) {{}}",
        f"{indent}}}",
        f"{indent}if (kv !== null) {{",
        f"{indent}  const pts = kv.split('|');",
        f"{indent}  const sc = parseInt(pts[0], 10);",
        f"{indent}  let tgt = pts[2];",
        f"{indent}  if (pts[1] === '1') {{",
        f"{indent}    const qs = request.rawQueryString();",
        f"{indent}    if (qs) {{ tgt = tgt + (tgt.includes('?') ? '&' : '?') + qs; }}",
        f"{indent}  }}",
        f"{indent}  return {{statusCode: sc, headers: {{location: {{value: tgt}}}}}};",
        f"{indent}}}",
    ]


def _generate_continent_preamble(ops, indent="  "):
    """Generate KVS lookup preamble for continent/is_eu conditions."""
    needs_continent = False
    needs_eu = False
    for op in ops:
        cond = op.get("condition")
        if cond:
            if _cond_has_field(cond, ("continent",)):
                needs_continent = True
            if _cond_has_field(cond, ("is_eu",)):
                needs_eu = True
    if not needs_continent and not needs_eu:
        return []
    lines = [
        f"{indent}const countryHeader = request.headers['cloudfront-viewer-country'];",
        f"{indent}const country = countryHeader ? countryHeader.value : '';",
    ]
    if needs_continent:
        lines.append(f"{indent}let continent = '';")
        lines.append(f"{indent}if (country) {{ try {{ continent = await kvsHandle.get('continent:' + country); }} catch(e) {{}} }}")
    if needs_eu:
        lines.append(f"{indent}let isEU = false;")
        lines.append(f"{indent}if (country) {{ try {{ isEU = await kvsHandle.exists('eu:' + country); }} catch(e) {{}} }}")
    return lines


def generate_viewer_request_js(ir, target="cff"):
    """Generate complete viewer_request.js content."""
    lines = []
    needs_kvs_flag = _needs_kvs(ir)
    needs_crypto_flag = _needs_crypto(ir)

    # Imports
    if needs_kvs_flag or any(
        op.get("type") == "origin_override"
        for beh in ir.get("cache_behaviors", [])
        for op in beh.get("viewer_request_ops", [])
    ):
        lines.append("import cf from 'cloudfront';")
    if needs_crypto_flag:
        lines.append("import crypto from 'crypto';")

    # KVS init
    kvs_id = ir.get("metadata", {}).get("kvs_id", "")
    if needs_kvs_flag:
        lines.append(f"const kvsHandle = cf.kvs('{kvs_id}');")

    lines.append("async function handler(event) {")
    lines.append("  const request = event.request;")

    # Collect all viewer_request_ops across behaviors
    all_ops = []
    for beh in ir.get("cache_behaviors", []):
        all_ops.extend(beh.get("viewer_request_ops", []))

    # Continent/EU preamble
    if _has_continent_or_eu(all_ops):
        lines.extend(_generate_continent_preamble(all_ops))

    # Group ops by type for section ordering
    redirects = [o for o in all_ops if o.get("type") == "redirect"]
    rewrites = [o for o in all_ops if o.get("type") == "rewrite"]
    origins = [o for o in all_ops if o.get("type") == "origin_override"]
    bulk = [o for o in all_ops if o.get("type") == "bulk_redirect"]
    headers = [o for o in all_ops if o.get("type", "").endswith("_header") or "header" in o.get("type", "")]
    errors = [o for o in all_ops if o.get("type") == "serve_error_inline"]

    for section_ops in [redirects, rewrites, origins]:
        for op in section_ops:
            lines.extend(_generate_op_js(op, target))

    if bulk:
        lines.extend(_generate_bulk_redirect_block())

    for op in headers:
        lines.extend(_generate_op_js(op, target))
    for op in errors:
        lines.extend(_generate_op_js(op, target))

    lines.append("  return request;")
    lines.append("}")
    return "\n".join(lines)


def generate_viewer_response_js(ir):
    """Generate viewer_response.js content. Returns None if not needed."""
    all_ops = []
    for beh in ir.get("cache_behaviors", []):
        all_ops.extend(beh.get("viewer_response_ops", []))
    if not all_ops:
        return None

    lines = []
    needs_kvs = any(
        _cond_has_field(op.get("condition"), ("continent", "is_eu"))
        or op.get("type") == "serve_error_inline"
        for op in all_ops
    )
    if needs_kvs:
        lines.append("import cf from 'cloudfront';")
        kvs_id = ir.get("metadata", {}).get("kvs_id", "")
        lines.append(f"const kvsHandle = cf.kvs('{kvs_id}');")

    lines.append("async function handler(event) {")
    lines.append("  const response = event.response;")

    for op in all_ops:
        lines.extend(_generate_op_js(op, "response"))

    lines.append("  return response;")
    lines.append("}")
    return "\n".join(lines)


def generate_lambda_origin_request_js(ops):
    """Generate Lambda@Edge origin_request_handler.js for escalated origin_override ops."""
    lines = [
        "'use strict';",
        "",
        "exports.handler = async (event, context, callback) => {",
        "  const request = event.Records[0].cf.request;",
        "  const uri = request.uri;",
    ]
    for op in ops:
        lines.extend(_generate_op_js(op, "lambda", "  "))
    lines.append("  callback(null, request);")
    lines.append("};")
    return "\n".join(lines)


# ── Minification ─────────────────────────────────────────────────────────────

def minify_js(js_code):
    """Minify JS by removing comments, whitespace, and empty lines."""
    result = []
    for line in js_code.split("\n"):
        # Remove single-line comments (but not URLs like https://)
        stripped = re.sub(r"(?<!:)//[^'\"]*$", "", line)
        stripped = stripped.strip()
        if stripped:
            result.append(stripped)
    return "\n".join(result)


# ── Main: process all domains ────────────────────────────────────────────────

def process_domain(ir, output_dir):
    """Process a single domain IR → generate JS files. Returns (hostname, status, detail)."""
    hostname = ir["metadata"]["hostname"]
    sanitized = ir["metadata"]["sanitized_name"]
    domain_dir = os.path.join(output_dir, "terraform", "domains", sanitized)
    functions_dir = os.path.join(domain_dir, "functions")
    lambda_dir = os.path.join(domain_dir, "lambda")
    os.makedirs(functions_dir, exist_ok=True)

    # Generate viewer_request.js
    vr_js = generate_viewer_request_js(ir)
    vr_size = len(vr_js.encode("utf-8"))

    # Size check + minification + escalation
    origin_ops = [
        op for beh in ir.get("cache_behaviors", [])
        for op in beh.get("viewer_request_ops", [])
        if op.get("type") == "origin_override"
    ]

    if vr_size > CFF_SIZE_LIMIT:
        vr_js = minify_js(vr_js)
        vr_size = len(vr_js.encode("utf-8"))

    if vr_size > CFF_SIZE_LIMIT and origin_ops:
        # Escalate: move origin_override to Lambda@Edge
        # Regenerate CFF without origin_override using a deep copy
        ir_no_origin = copy.deepcopy(ir)
        for beh in ir_no_origin.get("cache_behaviors", []):
            beh["viewer_request_ops"] = [
                op for op in beh.get("viewer_request_ops", [])
                if op.get("type") != "origin_override"
            ]
        vr_js = generate_viewer_request_js(ir_no_origin)
        vr_size = len(vr_js.encode("utf-8"))
        if vr_size > CFF_SIZE_LIMIT:
            vr_js = minify_js(vr_js)
            vr_size = len(vr_js.encode("utf-8"))

        if vr_size > CFF_SIZE_LIMIT:
            return hostname, "SIZE_EXCEEDED", f"{vr_size} bytes after escalation"

        # Write Lambda@Edge origin_request
        os.makedirs(lambda_dir, exist_ok=True)
        le_js = generate_lambda_origin_request_js(origin_ops)
        with open(os.path.join(lambda_dir, "origin_request_handler.js"), "w") as f:
            f.write(le_js)

        # Update functions.tf
        ft_path = os.path.join(domain_dir, "functions.tf")
        if os.path.exists(ft_path):
            with open(ft_path) as f:
                ft_content = f.read()
            lambda_block = (
                f'\nresource "aws_lambda_function" "{sanitized}_origin_request" {{\n'
                f'  filename         = "${{path.module}}/lambda/origin_request_handler.js.zip"\n'
                f'  function_name    = "{sanitized}-origin-request"\n'
                f'  role             = var.lambda_edge_role_arn\n'
                f'  handler          = "origin_request_handler.handler"\n'
                f'  runtime          = "nodejs20.x"\n'
                f'  publish          = true\n'
                f'  source_code_hash = filebase64sha256("${{path.module}}/lambda/origin_request_handler.js.zip")\n'
                f'}}\n'
            )
            ft_content = ft_content.replace("# LAMBDA_EDGE_PLACEHOLDER", lambda_block)
            with open(ft_path, "w") as f:
                f.write(ft_content)

    elif vr_size > CFF_SIZE_LIMIT:
        return hostname, "SIZE_EXCEEDED", f"{vr_size} bytes, no origin_override to escalate"

    # Write viewer_request.js
    with open(os.path.join(functions_dir, f"{sanitized}_viewer_request.js"), "w") as f:
        f.write(vr_js)

    # Generate viewer_response.js
    vresp_js = generate_viewer_response_js(ir)
    if vresp_js:
        with open(os.path.join(functions_dir, f"{sanitized}_viewer_response.js"), "w") as f:
            f.write(vresp_js)

    # Lambda@Edge origin_response (fixed template)
    le_or = ir.get("metadata", {}).get("lambda_edge", {}).get("origin_response")
    if le_or:
        os.makedirs(lambda_dir, exist_ok=True)
        # Copy template and fill in custom error mappings
        template = _generate_origin_response_template(le_or)
        with open(os.path.join(lambda_dir, "default_cache_origin_response.js"), "w") as f:
            f.write(template)

    return hostname, "OK", f"{vr_size} bytes"


def _generate_origin_response_template(config):
    """Generate Lambda@Edge origin-response handler from config."""
    lines = [
        "'use strict';",
        "",
        "exports.handler = async (event, context, callback) => {",
        "  const response = event.Records[0].cf.response;",
        "  const request = event.Records[0].cf.request;",
    ]
    mappings = config if isinstance(config, list) else config.get("error_mappings", [])
    for m in mappings:
        status = m.get("status_code", 500)
        body = m.get("body", "").replace("'", "\\'").replace("\n", "\\n")
        content_type = m.get("content_type", "text/html")
        lines.append(f"  if (response.status === '{status}') {{")
        lines.append(f"    response.body = '{body}';")
        lines.append(f"    response.headers['content-type'] = [{{key: 'Content-Type', value: '{content_type}'}}];")
        lines.append(f"  }}")
    lines.append("  callback(null, response);")
    lines.append("};")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-generate-js.py <output_dir>", file=sys.stderr)
        sys.exit(2)

    output_dir = sys.argv[1]
    ir_dir = os.path.join(output_dir, "ir", "final")

    if not os.path.isdir(ir_dir):
        print(f"---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\nCONTEXT: IR directory not found: {ir_dir}")
        sys.exit(2)

    ir_files = sorted(Path(ir_dir).glob("*.json"))
    if not ir_files:
        print(f"---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\nCONTEXT: No IR files found in {ir_dir}")
        sys.exit(2)

    results = []
    failed = []
    for ir_file in ir_files:
        with open(ir_file) as f:
            ir = json.load(f)
        hostname, status, detail = process_domain(ir, output_dir)
        results.append((hostname, status, detail))
        if status != "OK":
            failed.append((hostname, status, detail))
        print(f"[JS] {hostname}: {status} ({detail})", file=sys.stderr)

    ok_count = sum(1 for _, s, _ in results if s == "OK")
    fail_count = len(failed)

    if fail_count == 0:
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nDOMAINS: {ok_count}\nGENERATED: {ok_count}")
    elif ok_count > 0:
        failed_items = "\n".join(f"  {h}: {s} — {d}" for h, s, d in failed)
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: PARTIAL\nSUCCEEDED: {ok_count}\nFAILED: {fail_count}\nFAILED_ITEMS:\n{failed_items}\nACTION: FIX\nCONTEXT: {fail_count} domain(s) exceeded 10KB CFF size limit")
        sys.exit(3)
    else:
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\nCONTEXT: All {fail_count} domains failed JS generation")
        sys.exit(2)


if __name__ == "__main__":
    main()
