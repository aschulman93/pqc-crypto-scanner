"""
scan.py

Walks a directory of Python source, parses each file into an AST,
and looks for calls that match our crypto-vulnerability rules.

Usage:
    python scan.py <path-to-scan> [--json report.json]

Design notes:
- Static analysis via `ast`, not regex. Regex breaks on formatting
  variations (multiline calls, aliasing, etc). AST parsing is the
  correct tool for "does this code call this function" questions.
- We track import aliases (e.g. `from cryptography.hazmat.primitives.asymmetric
  import rsa as _rsa`) so detection doesn't break on renamed imports.
- This is intentionally scoped to a few algorithms (RSA, ECDSA/ECDH, DH)
  rather than trying to catch everything on day one. Breadth can be
  added later; correctness on a narrow scope is more valuable for a
  portfolio piece than a broad tool full of false positives.
"""

import argparse
import ast
import json
import os
import sys
from dataclasses import asdict

from detectors import (
    CRYPTOGRAPHY_LIB_RULES,
    PYCRYPTODOME_RULES,
    WEAK_HASH_FUNCS,
    MIN_RECOMMENDED_RSA_BITS,
    Finding,
)


class ImportTracker(ast.NodeVisitor):
    """First pass: figure out what name each relevant module/function
    is bound to in this file, so `import rsa` and
    `from cryptography...asymmetric import rsa as keygen` both resolve
    to the same rule."""

    def __init__(self):
        # maps local-name -> canonical hint (e.g. "rsa", "ECC", "hashlib")
        self.aliases = {}

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[-1]
            self.aliases[local] = alias.name.split(".")[-1]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            # canonical hint is the imported name itself (rsa, ec, dh, RSA, ECC)
            self.aliases[local] = alias.name
        self.generic_visit(node)


class CryptoCallVisitor(ast.NodeVisitor):
    def __init__(self, filename, aliases):
        self.filename = filename
        self.aliases = aliases
        self.findings = []

    def _resolve_call_name(self, node):
        """Return (module_hint, func_name) for a Call node, or (None, None)."""
        func = node.func
        if isinstance(func, ast.Attribute):
            # e.g. rsa.generate_private_key(...)  -> attr chain
            if isinstance(func.value, ast.Name):
                local_name = func.value.id
                hint = self.aliases.get(local_name, local_name)
                return hint, func.attr
        elif isinstance(func, ast.Name):
            # e.g. generate_private_key(...) imported directly
            hint = self.aliases.get(func.id, func.id)
            return hint, func.id
        return None, None

    def _get_kwarg(self, node, name):
        for kw in node.keywords:
            if kw.arg == name:
                return kw.value
        return None

    def _int_value(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        return None

    def visit_Call(self, node):
        module_hint, func_name = self._resolve_call_name(node)

        if module_hint and func_name:
            self._check_rules(node, module_hint, func_name, CRYPTOGRAPHY_LIB_RULES)
            self._check_rules(node, module_hint, func_name, PYCRYPTODOME_RULES)
            self._check_weak_hash(node, module_hint, func_name)

        self.generic_visit(node)

    def _check_rules(self, node, module_hint, func_name, ruleset):
        for rule in ruleset:
            if rule["module_hint"].lower() != module_hint.lower():
                continue
            if rule["func"] != func_name:
                continue

            detail = self._build_key_size_detail(node, rule)
            severity = self._severity_for(rule, node)

            self.findings.append(Finding(
                file=self.filename,
                line=node.lineno,
                algorithm=rule["algorithm"],
                detail=detail,
                severity=severity,
                reason=rule["reason"],
                recommendation=rule["recommendation"],
            ))

    def _build_key_size_detail(self, node, rule):
        key_size = None
        if rule.get("key_size_arg"):
            kw_node = self._get_kwarg(node, rule["key_size_arg"])
            key_size = self._int_value(kw_node)
        else:
            # try first positional int arg (pycryptodome style: RSA.generate(2048))
            for arg in node.args:
                val = self._int_value(arg)
                if val:
                    key_size = val
                    break

        if key_size:
            flag = ""
            if rule["algorithm"] == "RSA" and key_size < MIN_RECOMMENDED_RSA_BITS:
                flag = f" [also undersized: below {MIN_RECOMMENDED_RSA_BITS}-bit minimum]"
            return f"key_size={key_size}{flag}"
        return "key_size=unspecified/dynamic"

    def _severity_for(self, rule, node):
        # Everything quantum-vulnerable is High by default for this v1 scanner.
        # A future version (project 3 - hybrid system) can refine this using
        # variable/context naming (long-lived cert vs ephemeral session key).
        return "High"

    def _check_weak_hash(self, node, module_hint, func_name):
        if module_hint == "hashlib" and func_name.lower() in WEAK_HASH_FUNCS:
            self.findings.append(Finding(
                file=self.filename,
                line=node.lineno,
                algorithm=f"Weak hash ({func_name})",
                detail="",
                severity="Medium",
                reason=WEAK_HASH_FUNCS[func_name.lower()],
                recommendation="Use SHA-256 or SHA-3 family. Not quantum-specific, "
                               "but worth remediating alongside PQC migration.",
            ))


def scan_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        print(f"  [skip] could not parse {path}: {e}", file=sys.stderr)
        return []

    import_tracker = ImportTracker()
    import_tracker.visit(tree)

    call_visitor = CryptoCallVisitor(path, import_tracker.aliases)
    call_visitor.visit(tree)
    return call_visitor.findings


def scan_directory(root):
    all_findings = []
    for dirpath, _, filenames in os.walk(root):
        # skip common noise directories
        if any(part in dirpath for part in (".git", "venv", "__pycache__", "node_modules")):
            continue
        for fname in filenames:
            if fname.endswith(".py"):
                full_path = os.path.join(dirpath, fname)
                all_findings.extend(scan_file(full_path))
    return all_findings


def print_report(findings):
    if not findings:
        print("No quantum-vulnerable crypto usage detected.")
        return

    print(f"\n{len(findings)} finding(s):\n" + "=" * 60)
    for f in findings:
        print(f"[{f.severity}] {f.file}:{f.line}  {f.algorithm}")
        if f.detail:
            print(f"    {f.detail}")
        print(f"    Why: {f.reason}")
        print(f"    Fix: {f.recommendation}\n")


def main():
    parser = argparse.ArgumentParser(description="Scan Python code for quantum-vulnerable crypto usage.")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", help="Write JSON report to this path", default=None)
    args = parser.parse_args()

    if os.path.isdir(args.path):
        findings = scan_directory(args.path)
    else:
        findings = scan_file(args.path)

    print_report(findings)

    if args.json:
        with open(args.json, "w") as f:
            json.dump([asdict(x) for x in findings], f, indent=2)
        print(f"JSON report written to {args.json}")


if __name__ == "__main__":
    main()
