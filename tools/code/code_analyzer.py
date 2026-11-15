"""
code_analyzer.py — Multi-language AST, symbol extractor, and diagnostics helper.

Provides token-efficient code intelligence for AI agents:
  1. inspect_code_structure(file_path) -> returns classes, functions, structs with line numbers (no need to read 2,000 lines!)
  2. extract_function_definition(file_path, symbol_name) -> extracts only that specific function body
  3. check_code_diagnostics(file_path) -> runs compiler/linter check (cargo check, py_compile, etc.)
  4. run_git_summary(repo_path) -> returns concise git status + modified files diff
"""

import os
import re
import sys
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

# Regex patterns for fast multi-language symbol extraction without heavy external dependencies
PATTERNS = {
    "rust": {
        "fn": re.compile(r'^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+([a-zA-Z0-9_]+)'),
        "struct": re.compile(r'^\s*(?:pub(?:\([^)]+\))?\s+)?struct\s+([a-zA-Z0-9_]+)'),
        "enum": re.compile(r'^\s*(?:pub(?:\([^)]+\))?\s+)?enum\s+([a-zA-Z0-9_]+)'),
        "trait": re.compile(r'^\s*(?:pub(?:\([^)]+\))?\s+)?trait\s+([a-zA-Z0-9_]+)'),
        "impl": re.compile(r'^\s*impl(?:\s*<[^>]+>)?\s+(?:([a-zA-Z0-9_:]+)\s+for\s+)?([a-zA-Z0-9_:]+)'),
    },
    "python": {
        "def": re.compile(r'^\s*def\s+([a-zA-Z0-9_]+)\s*\('),
        "class": re.compile(r'^\s*class\s+([a-zA-Z0-9_]+)'),
    },
    "cpp": {
        "class": re.compile(r'^\s*(?:class|struct)\s+([a-zA-Z0-9_]+)\b'),
        "func": re.compile(r'^\s*(?:[a-zA-Z0-9_:<>&*]+\s+)+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:const)?\s*[{;]'),
    },
    "csharp": {
        "class": re.compile(r'^\s*(?:public|private|protected|internal)?\s*(?:static|abstract|sealed)?\s*(?:class|struct|interface|enum)\s+([a-zA-Z0-9_]+)'),
        "method": re.compile(r'^\s*(?:public|private|protected|internal)?\s*(?:static|async|virtual|override)?\s*[a-zA-Z0-9_<>[\]?]+\s+([a-zA-Z0-9_]+)\s*\('),
    },
    "lua": {
        "function": re.compile(r'^\s*(?:local\s+)?function\s+([a-zA-Z0-9_.:]+)'),
    }
}

def detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    mapping = {
        ".rs": "rust",
        ".py": "python",
        ".cpp": "cpp", ".cxx": "cpp", ".cc": "cpp", ".c": "cpp", ".h": "cpp", ".hpp": "cpp",
        ".cs": "csharp",
        ".lua": "lua",
        ".js": "javascript", ".ts": "typescript",
        ".java": "java",
    }
    return mapping.get(ext, "unknown")

def inspect_code_structure(file_path: str) -> Dict[str, Any]:
    """
    Scan a source code file and return an outline of symbols (functions, structs, classes) with line numbers.
    Saves thousands of tokens by avoiding full file reads.
    """
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    lang = detect_language(file_path)
    if lang not in PATTERNS:
        # Fallback: line count and basic info
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return {
            "file": str(path),
            "language": lang,
            "total_lines": len(lines),
            "symbols": [],
            "note": f"AST symbol scanner pattern not registered for {lang}"
        }

    symbols = []
    patterns = PATTERNS[lang]
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    for idx, line in enumerate(lines, start=1):
        for kind, pat in patterns.items():
            m = pat.search(line)
            if m:
                name = m.group(1) if m.lastindex >= 1 else m.group(0).strip()
                symbols.append({
                    "kind": kind,
                    "name": name,
                    "line": idx,
                    "signature": line.strip()
                })
                break

    return {
        "file": str(path),
        "language": lang,
        "total_lines": len(lines),
        "symbol_count": len(symbols),
        "symbols": symbols
    }

def extract_function_definition(file_path: str, symbol_name: str) -> Dict[str, Any]:
    """
    Extract only the exact lines of a specific function or class by name.
    """
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start_line = None
    target = symbol_name.strip()

    for idx, line in enumerate(lines):
        if target in line and any(k in line for k in ["fn ", "def ", "function ", "class ", "void ", "int ", "bool "]):
            start_line = idx
            break

    if start_line is None:
        return {"error": f"Symbol '{symbol_name}' not found in {file_path}"}

    # Extract block based on indentation or braces
    extracted_lines = []
    base_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
    brace_count = 0
    in_braces = False

    for idx in range(start_line, min(len(lines), start_line + 500)):
        cur = lines[idx]
        extracted_lines.append(cur)
        brace_count += cur.count("{") - cur.count("}")
        if "{" in cur:
            in_braces = True

        if in_braces and brace_count <= 0 and idx > start_line:
            break
        elif not in_braces and idx > start_line:
            cur_indent = len(cur) - len(cur.lstrip())
            if cur.strip() and cur_indent <= base_indent:
                extracted_lines.pop()
                break

    return {
        "symbol": symbol_name,
        "start_line": start_line + 1,
        "line_count": len(extracted_lines),
        "content": "\n".join(extracted_lines)
    }

def check_code_diagnostics(project_or_file: str) -> Dict[str, Any]:
    """
    Run compiler diagnostics (cargo check for Rust, py_compile for Python) to verify syntax without full builds.
    """
    path = Path(project_or_file)
    if not path.exists():
        return {"error": f"Path not found: {project_or_file}"}

    # Check for Rust project
    cargo_toml = path if path.name == "Cargo.toml" else (path / "Cargo.toml" if path.is_dir() else path.parent / "Cargo.toml")
    if cargo_toml.exists():
        try:
            res = subprocess.run(["cargo", "check", "--message-format=short"], cwd=cargo_toml.parent, capture_output=True, text=True, timeout=30)
            return {
                "system": "cargo",
                "success": res.returncode == 0,
                "output": (res.stdout + res.stderr).strip() or "No errors found."
            }
        except Exception as e:
            return {"system": "cargo", "error": str(e)}

    # Python syntax check
    if path.suffix == ".py":
        try:
            res = subprocess.run([sys.executable, "-m", "py_compile", str(path)], capture_output=True, text=True, timeout=10)
            return {
                "system": "python",
                "success": res.returncode == 0,
                "output": res.stderr.strip() or "Syntax OK"
            }
        except Exception as e:
            return {"system": "python", "error": str(e)}

    return {"error": f"No automatic diagnostic runner available for {path}"}

def run_git_summary(repo_path: str) -> Dict[str, Any]:
    """
    Get concise git status and modified files list.
    """
    p = Path(repo_path)
    if not p.exists():
        return {"error": f"Path not found: {repo_path}"}

    try:
        status_res = subprocess.run(["git", "status", "--short"], cwd=p, capture_output=True, text=True, timeout=10)
        diff_res = subprocess.run(["git", "diff", "--stat"], cwd=p, capture_output=True, text=True, timeout=10)
        branch_res = subprocess.run(["git", "branch", "--show-current"], cwd=p, capture_output=True, text=True, timeout=5)

        return {
            "branch": branch_res.stdout.strip() or "HEAD",
            "status": status_res.stdout.strip() or "Working tree clean",
            "stat": diff_res.stdout.strip() or "No uncommitted changes"
        }
    except Exception as e:
        return {"error": f"Git command failed: {e}"}
