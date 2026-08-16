#!/usr/bin/env python3
"""
Validate policy.yaml for common issues:
- Invalid regex patterns in match conditions
- Rules after a catch-all allow (they'll never match)
- Unknown backend references in tool_routing
- Missing default deny rule
- Duplicate match conditions

Supports both legacy format (single policy.yaml with backends/tool_routing)
and new per-backend format (individual files with backend: section).
"""

import re
import sys

import yaml

from mcp_gateway.policy_yaml import PolicyLoader


def _flatten_match_value(value):
    """Mirror the policy loader's list normalization for validation.

    YAML aliases/anchors resolve to lists; a match field may be either a
    single regex string (unchanged) or a sequence of tokens that the loader
    joins into an anchored alternation. This helper flattens the sequence
    the same way, so each token is validated individually.
    """
    if isinstance(value, list):
        flat = []
        for v in value:
            if isinstance(v, list):
                flat.extend(str(i) for i in v)
            else:
                flat.append(str(v))
        return flat
    return [str(value)]


def validate_policy(path: str) -> bool:
    with open(path) as f:
        raw = yaml.load(f, Loader=PolicyLoader)

    # Detect format: new per-backend format has 'backend' key
    if "backend" in raw:
        return _validate_backend_policy(raw, path)
    else:
        return _validate_legacy_policy(raw, path)


def _validate_backend_policy(raw: dict, path: str) -> bool:
    """Validate a per-backend policy file."""
    ok = True
    backend = raw.get("backend", {})
    rules = raw.get("rules", [])
    default_deny = raw.get("default_deny", "")

    backend_name = backend.get("name", "unknown")

    # Validate regex in rules. List-valued match fields (YAML anchors/aliases)
    # are flattened the same way the loader joins them into an alternation,
    # so each token is validated individually.
    for i, rule in enumerate(rules):
        match = rule.get("match", {})
        for field, pattern in match.items():
            for token in _flatten_match_value(pattern):
                try:
                    re.compile(token)
                except re.error as e:
                    print(f"ERROR: Rule {i}: invalid regex '{token}' in '{field}': {e}")
                    ok = False

        # Duplicate tokens inside a list-valued match field (e.g. a whitelist
        # containing 'cat' twice) are almost always an editing mistake. The
        # loader's alternation would dedupe nothing — the duplicate is harmless
        # but smells like drift.
        for field, pattern in match.items():
            tokens = _flatten_match_value(pattern)
            if len(tokens) > 1:
                from collections import Counter
                counts = Counter(tokens)
                for tok, cnt in counts.items():
                    if cnt > 1:
                        print(f"WARNING: Rule {i}: duplicate token '{tok}' ({cnt}x) in '{field}'")

        # Validate confirm action has required template fields
        action = rule.get("action", "deny")
        if action == "confirm":
            # confirm_pending, confirm_denied, confirm_timeout, confirm_approved are optional
            # but we should warn if none are provided
            has_templates = any(
                rule.get(k) for k in ("confirm_pending", "confirm_denied", "confirm_timeout", "confirm_approved")
            )
            if not has_templates:
                print(f"WARNING: Rule {i}: confirm action has no template fields (confirm_pending, confirm_denied, confirm_timeout, confirm_approved) — defaults will be used")
            # Validate template regex patterns
            for tpl_field in ("confirm_pending", "confirm_denied", "confirm_timeout", "confirm_approved"):
                tpl = rule.get(tpl_field)
                if tpl and "${" in tpl:
                    # Check that template variables are well-formed
                    for var in re.findall(r'\$\{(.+?)\}', tpl):
                        if var not in ("tool", "reason", "result") and not var.startswith("args.") and var not in ("clientHost", "clientIp"):
                            print(f"WARNING: Rule {i}: unknown template variable '${{{var}}}' in {tpl_field}")
        elif action not in ("allow", "deny", "inject_argument", "confirm"):
            print(f"WARNING: Rule {i}: unknown action '{action}' — treated as allow")

    # Check for unreachable rules after catch-all allow
    for i, rule in enumerate(rules):
        match = rule.get("match", {})
        action = rule.get("action", "deny")
        tool_pat = match.get("tool", ".*")
        if tool_pat == ".*" and action == "allow" and len(match) == 1:
            for j in range(i + 1, len(rules)):
                print(f"WARNING: Rule {j} is unreachable (after catch-all allow at rule {i})")
            break

    # Check for catch-all deny
    for i, rule in enumerate(rules):
        match = rule.get("match", {})
        action = rule.get("action", "deny")
        tool_pat = match.get("tool", ".*")
        if tool_pat == ".*" and action == "deny" and len(match) == 1:
            for j in range(i + 1, len(rules)):
                print(f"WARNING: Rule {j} is unreachable (after catch-all deny at rule {i})")
            break

    # Check last rule is default deny
    if rules:
        last = rules[-1]
        if last.get("action") != "deny" or last.get("match", {}).get("tool") != ".*":
            print("WARNING: Last rule is not a default deny (tool: .*)")
    else:
        print("ERROR: No rules defined")
        ok = False

    # Check for duplicate rules
    seen = set()
    for i, rule in enumerate(rules):
        key = str(sorted(rule.get("match", {}).items())) + rule.get("action", "")
        if key in seen:
            print(f"WARNING: Rule {i} appears to be a duplicate")
        seen.add(key)

    if ok:
        print(f"Policy validation PASSED ({len(rules)} rules, backend: {backend_name})")
    else:
        print("Policy validation FAILED")

    return ok


def _validate_legacy_policy(raw: dict, path: str) -> bool:
    """Validate a legacy single policy.yaml file."""
    ok = True
    rules = raw.get("rules", [])
    backends = raw.get("backends", {})
    tool_routing = raw.get("tool_routing", [])

    for i, rule in enumerate(rules):
        match = rule.get("match", {})
        for field, pattern in match.items():
            try:
                re.compile(pattern)
            except re.error as e:
                print(f"ERROR: Rule {i}: invalid regex '{pattern}' in '{field}': {e}")
                ok = False

    for i, route in enumerate(tool_routing):
        try:
            re.compile(route["pattern"])
        except re.error as e:
            print(f"ERROR: tool_routing {i}: invalid regex '{route['pattern']}': {e}")
            ok = False
        if route["backend"] not in backends:
            print(f"ERROR: tool_routing {i}: unknown backend '{route['backend']}'")
            ok = False

    for i, rule in enumerate(rules):
        match = rule.get("match", {})
        action = rule.get("action", "deny")
        tool_pat = match.get("tool", ".*")
        if tool_pat == ".*" and action == "allow" and len(match) == 1:
            for j in range(i + 1, len(rules)):
                print(f"WARNING: Rule {j} is unreachable (after catch-all allow at rule {i})")
            break

    for i, rule in enumerate(rules):
        match = rule.get("match", {})
        action = rule.get("action", "deny")
        tool_pat = match.get("tool", ".*")
        if tool_pat == ".*" and action == "deny" and len(match) == 1:
            for j in range(i + 1, len(rules)):
                print(f"WARNING: Rule {j} is unreachable (after catch-all deny at rule {i})")
            break

    if rules:
        last = rules[-1]
        if last.get("action") != "deny" or last.get("match", {}).get("tool") != ".*":
            print("WARNING: Last rule is not a default deny (tool: .*)")
    else:
        print("ERROR: No rules defined")
        ok = False

    seen = set()
    for i, rule in enumerate(rules):
        key = str(sorted(rule.get("match", {}).items())) + rule.get("action", "")
        if key in seen:
            print(f"WARNING: Rule {i} appears to be a duplicate")
        seen.add(key)

    if ok:
        print(f"Policy validation PASSED ({len(rules)} rules, {len(backends)} backends, {len(tool_routing)} routes)")
    else:
        print("Policy validation FAILED")

    return ok


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "policy.yaml"
    valid = validate_policy(path)
    sys.exit(0 if valid else 1)
