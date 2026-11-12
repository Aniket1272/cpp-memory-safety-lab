#!/usr/bin/env python3
"""Run every case through static analyzers and sanitizers, then write a
tool-detection matrix.

For each case it records:
  * Cppcheck and clang-tidy findings on vuln.cpp and fixed.cpp
  * the plain (no sanitizer) outcome of the vulnerable binary on a trigger input
  * AddressSanitizer / UBSan reports for the vulnerable binary
  * whether the fixed program stays clean under the sanitizers

Usage:  python3 analysis/run_analysis.py --build-dir build [--check]
--check exits non-zero if a self-test expectation fails (used in CI).
"""

import argparse
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Which static-analyzer messages count as "the right finding" for a case.
# Anything else the tool prints is counted as unrelated noise.
MEMORY_RE = (
    r"after it is freed|deallocuse|doubleFree|double free|freed twice|"
    r"clang-analyzer-unix\.Malloc|clang-analyzer-cplusplus\.NewDelete"
)

CASES = [
    dict(
        id="case01",
        name="Stack buffer overflow",
        cwe="CWE-121",
        dir="01_stack_overflow",
        trigger=["A" * 64],
        benign=["alice"],
        relevant=r"insecureAPI\.strcpy|bufferAccessOutOfBounds|arrayIndexOutOfBounds|unsafe-functions",
    ),
    dict(
        id="case02",
        name="Use after free",
        cwe="CWE-416",
        dir="02_use_after_free",
        trigger=["alice"],
        benign=None,  # the bug is unconditional
        relevant=MEMORY_RE,
    ),
    dict(
        id="case03",
        name="Double free",
        cwe="CWE-415",
        dir="03_double_free",
        trigger=["fail"],
        benign=["ok"],
        relevant=MEMORY_RE,
    ),
    dict(
        id="case04",
        name="Integer overflow -> heap overflow",
        cwe="CWE-190/122",
        dir="04_integer_overflow",
        trigger=["268435457"],
        benign=["4"],
        relevant=r"integerOverflow|[Oo]verflow|MallocOverflow|TaintedAlloc",
    ),
]


def run(cmd, timeout=30):
    env = dict(
        os.environ, ASAN_OPTIONS="detect_leaks=0", UBSAN_OPTIONS="print_stacktrace=0"
    )
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    return (
        p.returncode,
        p.stdout.decode(errors="replace"),
        p.stderr.decode(errors="replace"),
    )


def version(name, cmd):
    if not shutil.which(cmd[0]):
        return f"{name}: not installed"
    _, out, err = run(cmd)
    return f"{name}: {(out or err).strip().splitlines()[0]}"


def cppcheck(src):
    if not shutil.which("cppcheck"):
        return None
    _, out, err = run(
        [
            "cppcheck",
            "-q",
            "--enable=warning,portability",
            "--inconclusive",
            "--std=c++17",
            "--template={file}:{line}: {severity}: {id}: {message}",
            str(src),
        ]
    )
    return [l for l in (out + err).splitlines() if re.match(r".+:\d+: \w+: ", l)]


def clang_tidy(src):
    if not shutil.which("clang-tidy"):
        return None
    _, out, _ = run(
        [
            "clang-tidy",
            "-quiet",
            "--checks=-*,clang-analyzer-*,bugprone-*,cert-*",
            str(src),
            "--",
            "-std=c++17",
        ]
    )
    return [
        l
        for l in out.splitlines()
        if src.name in l and re.search(r"(warning|error): .*\[[\w.,-]+\]$", l)
    ]


def diagnostic_text(line):
    """Drop the 'path:line:col:' prefix so patterns never match folder names."""
    m = re.match(r"^.*?:\d+(?::\d+)?: (.*)$", line)
    return m.group(1) if m else line


def classify(lines, pattern):
    if lines is None:
        return None, 0
    hits = [l for l in lines if re.search(pattern, diagnostic_text(l))]
    return hits, len(lines) - len(hits)


def exit_description(rc, stderr):
    if rc is None:
        return "timeout"
    if rc < 0:
        extra = (
            " (glibc: double free detected)" if "double free detected" in stderr else ""
        )
        return signal.Signals(-rc).name + extra
    return "exit 0, no crash" if rc == 0 else f"exit {rc}"


def sanitizer_findings(stderr):
    asan = re.search(r"AddressSanitizer: (attempting double-free|[\w-]+)", stderr)
    ubsan = re.search(r"runtime error: (.+)", stderr)
    return (asan.group(1) if asan else None), (ubsan.group(1) if ubsan else None)


def is_clean(rc, stderr):
    asan, ubsan = sanitizer_findings(stderr)
    return rc is not None and rc >= 0 and not asan and not ubsan


def static_cell(lines, pattern):
    hits, noise = classify(lines, pattern)
    if hits is None:
        return "n/a (not installed)"
    cell = "Detected" if hits else "Missed"
    return cell + (f" (+{noise} unrelated)" if noise else "")


def analyse(case, bindir, logdir):
    cid, srcdir = case["id"], ROOT / "vulns" / case["dir"]
    log = lambda name, text: (logdir / f"{cid}_{name}.txt").write_text(
        text, errors="replace"
    )
    row, failures = {"case": case["name"], "cwe": case["cwe"]}, []

    # Static analysis on both versions
    for variant in ("vuln", "fixed"):
        for tool, fn in (("cppcheck", cppcheck), ("clang_tidy", clang_tidy)):
            lines = fn(srcdir / f"{variant}.cpp")
            log(
                f"{variant}_{tool}",
                "n/a\n" if lines is None else "\n".join(lines) + "\n",
            )
            row[f"{variant}_{tool}"] = lines
    row["cppcheck"] = static_cell(row["vuln_cppcheck"], case["relevant"])
    row["clang_tidy"] = static_cell(row["vuln_clang_tidy"], case["relevant"])

    # Plain run of the vulnerable binary
    rc, out, err = run([str(bindir / f"{cid}_vuln"), *case["trigger"]])
    log("vuln_plain", f"exit={rc}\n--stdout--\n{out}\n--stderr--\n{err}")
    row["plain"] = exit_description(rc, err)

    # Sanitizer run of the vulnerable binary
    rc, out, err = run([str(bindir / f"{cid}_vuln_asan"), *case["trigger"]])
    log("vuln_asan", f"exit={rc}\n--stdout--\n{out}\n--stderr--\n{err}")
    asan, ubsan = sanitizer_findings(err)
    row["asan"] = asan or "Missed"
    row["ubsan"] = "Detected" if ubsan else "Missed"
    if not asan:
        failures.append(f"{cid}: ASan did not detect the vulnerable program")

    # The sanitizers must not cry wolf on benign input
    if case["benign"]:
        rc, _, err = run([str(bindir / f"{cid}_vuln_asan"), *case["benign"]])
        if not is_clean(rc, err):
            failures.append(f"{cid}: sanitizer report on BENIGN input")

    # The fixed program must be clean on trigger and benign inputs
    fixed_ok = True
    for args in (case["trigger"], case["benign"] or case["trigger"]):
        rc, out, err = run([str(bindir / f"{cid}_fixed_asan"), *args])
        log("fixed_asan", f"exit={rc}\n--stdout--\n{out}\n--stderr--\n{err}")
        fixed_ok &= is_clean(rc, err)
    hits, _ = classify(row["fixed_cppcheck"], case["relevant"])
    hits2, _ = classify(row["fixed_clang_tidy"], case["relevant"])
    static_fp = bool(hits) or bool(hits2)
    row["fixed"] = "Clean" if fixed_ok and not static_fp else "NOT CLEAN"
    if not fixed_ok:
        failures.append(f"{cid}: fixed program fails under sanitizers")
    if static_fp:
        failures.append(f"{cid}: static analyzer flags the FIXED program")
    return row, failures


def render(rows, versions):
    head = "| Case | CWE | Cppcheck | clang-tidy | Plain run (no sanitizer) | ASan | UBSan | Fixed version |\n"
    head += "|---|---|---|---|---|---|---|---|\n"
    body = "".join(
        f"| {r['case']} | {r['cwe']} | {r['cppcheck']} | {r['clang_tidy']} | "
        f"{r['plain']} | {r['asan']} | {r['ubsan']} | {r['fixed']} |\n"
        for r in rows
    )
    return (
        "# Detection matrix\n\n"
        + "\n".join(f"- {v}" for v in versions)
        + "\n\n"
        + head
        + body
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--results-dir", default=str(ROOT / "analysis" / "results"))
    ap.add_argument("--check", action="store_true", help="exit 1 if a self-test fails")
    args = ap.parse_args()

    bindir = Path(args.build_dir).resolve() / "bin"
    if not bindir.is_dir():
        sys.exit(f"build output not found: {bindir} (run cmake first)")
    logdir = Path(args.results_dir)
    logdir.mkdir(parents=True, exist_ok=True)

    versions = [
        f"Platform: {platform.platform()}",
        version("g++", ["g++", "--version"]),
        version("cppcheck", ["cppcheck", "--version"]),
        version("clang-tidy", ["clang-tidy", "--version"]),
    ]

    rows, failures = [], []
    for case in CASES:
        row, fails = analyse(case, bindir, logdir)
        rows.append(row)
        failures += fails

    matrix = render(rows, versions)
    (logdir / "detection_matrix.md").write_text(matrix)
    (logdir / "results.json").write_text(json.dumps(rows, indent=2))
    print(matrix)
    if failures:
        print("SELF-TEST FAILURES:\n  " + "\n  ".join(failures))
        if args.check:
            sys.exit(1)


if __name__ == "__main__":
    main()
