"""
Minify Python files in-place by removing comments and trimming redundant
blank lines while preserving indentation and necessary whitespace.

Usage: python3 scripts/minify_py.py

This script will skip virtualenv and git folders and will modify all .py files
in the repository tree.
"""

import io
import os
import sys
import tokenize

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXCLUDE_DIRS = {".venv", ".git", "__pycache__"}


def should_skip(path):
    parts = path.split(os.sep)
    for p in parts:
        if p in EXCLUDE_DIRS:
            return True
    return False


def minify_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception as e:
        print(f"[skip] {path}: read error {e}")
        return
    try:
        src_io = io.StringIO(src)
        out_tokens = []
        gen = tokenize.generate_tokens(src_io.readline)
        for tok in gen:
            if tok.type == tokenize.COMMENT:
                continue
            out_tokens.append((tok.type, tok.string))
        new_src = tokenize.untokenize(out_tokens)

        lines = [ln.rstrip() for ln in new_src.splitlines()]

        out_lines = []
        blank_run = 0
        for ln in lines:
            if ln.strip() == "":
                blank_run += 1
            else:
                blank_run = 0
            if blank_run > 1:
                continue
            out_lines.append(ln)
        result = "\n".join(out_lines) + ("\n" if new_src.endswith("\n") else "")

        if result != src:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(result)
            print(f"[minified] {path}")
        else:
            print(f"[unchanged] {path}")
    except Exception as e:
        print(f"[error] {path}: {e}")


def find_py_files(root):
    for dirpath, dirnames, filenames in os.walk(root):

        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            full = os.path.join(dirpath, fn)
            if should_skip(full):
                continue
            yield full


if __name__ == "__main__":
    changed = 0
    total = 0
    for p in find_py_files(ROOT):
        total += 1
        minify_file(p)
    print(f"Processed {total} .py files")
