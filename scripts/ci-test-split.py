#!/usr/bin/env python3
"""Split one Go package's top-level tests across CI jobs without dropping any.

  list FILE              filter `go test -list '.*'` output into test names
  select N K TIMINGS     names (stdin) assigned to part K of N
  regex                  names (stdin) as an anchored `go test -run` pattern
  ran PACKAGE            top-level tests that passed or skipped in `go test -json` (stdin)
  verify N TIMINGS DIR   check parts DIR/part-K/{list,assigned,ran}.txt cover the list exactly
  selftest               check the partition properties on synthetic lists

The split is a greedy longest-first assignment on recorded per-test seconds
(TIMINGS, a JSON object). Tests missing from TIMINGS weigh the median, so a
new test still lands in exactly one part. Benchmarks are not run by `go test`
without -bench, so they are left out, as before the split.
"""

import json
import pathlib
import re
import statistics
import sys

NAME = re.compile(r"^(Test|Fuzz|Example)[A-Za-z0-9_]*$")
NOT_RUN = re.compile(r"^Benchmark[A-Za-z0-9_]*$")


def parse_list(lines):
    names = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("ok ") or NOT_RUN.match(line):
            continue
        if not NAME.match(line):
            raise ValueError(f"unexpected `go test -list` line: {line!r}")
        names.append(line)
    if len(names) != len(set(names)):
        raise ValueError("duplicate test names in the list")
    if not names:
        raise ValueError("the package lists no tests")
    return sorted(names)


def partition(names, parts, timings):
    known = [float(timings[n]) for n in names if n in timings]
    default = statistics.median(known) if known else 1.0
    weight = {n: max(0.01, float(timings.get(n, default))) for n in names}
    loads = [0.0] * parts
    assigned = [[] for _ in range(parts)]
    for name in sorted(names, key=lambda n: (-weight[n], n)):
        target = min(range(parts), key=lambda i: (loads[i], i))
        assigned[target].append(name)
        loads[target] += weight[name]
    return [sorted(a) for a in assigned], loads


def ran_tests(lines, package):
    done = set()
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        test = event.get("Test")
        if (event.get("Package") == package and test and "/" not in test
                and event.get("Action") in ("pass", "skip")):
            done.add(test)
    return sorted(done)


def read_names(path):
    return [l.strip() for l in pathlib.Path(path).read_text().splitlines() if l.strip()]


def verify(parts, timings, root):
    root = pathlib.Path(root)
    lists = [read_names(root / f"part-{k}" / "list.txt") for k in range(1, parts + 1)]
    full = lists[0]
    if any(l != full for l in lists[1:]):
        raise SystemExit("parts listed different tests; they did not test the same tree")
    expected, _ = partition(full, parts, timings)
    union = set()
    for k in range(1, parts + 1):
        assigned = read_names(root / f"part-{k}" / "assigned.txt")
        ran = read_names(root / f"part-{k}" / "ran.txt")
        if assigned != expected[k - 1]:
            raise SystemExit(f"part {k} ran a different selection than the deterministic split")
        if union & set(assigned):
            raise SystemExit(f"part {k} overlaps another part: {sorted(union & set(assigned))}")
        union |= set(assigned)
        missing = sorted(set(assigned) - set(ran))
        extra = sorted(set(ran) - set(assigned))
        if missing or extra:
            raise SystemExit(f"part {k}: assigned but not passed {missing}; passed but not assigned {extra}")
    if union != set(full):
        raise SystemExit(f"union differs from the list: missing {sorted(set(full) - union)}, "
                         f"extra {sorted(union - set(full))}")
    return len(full)


def selftest():
    timings = {"TestSlow": 90, "TestA": 5, "TestB": 4, "TestC": 3, "TestD": 1}
    base = sorted(timings)
    for parts in (1, 2, 3, 5, 7):
        for names in (base, base + ["TestBrandNew"], base + ["FuzzSeed", "ExampleX"]):
            split, _ = partition(names, parts, timings)
            flat = sum(split, [])
            assert sorted(flat) == sorted(names) and len(flat) == len(set(flat)), (parts, names)
            assert partition(list(reversed(names)), parts, timings)[0] == split, "not deterministic"
    split, loads = partition(base, 2, timings)
    assert split[0] == ["TestSlow"], split
    assert regex(["TestA", "TestB"]) == "^(TestA|TestB)$"
    assert parse_list(["TestB", "BenchmarkX", "TestA", "ok  \tpkg\t0.1s", ""]) == ["TestA", "TestB"]
    for bad in (["TestA", "TestA"], ["Test(A)"], []):
        try:
            parse_list(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad}")
    log = [json.dumps({"Action": a, "Package": "p", "Test": t}) for a, t in
           (("pass", "TestA"), ("pass", "TestA/sub"), ("fail", "TestB"), ("skip", "TestC"))]
    assert ran_tests(log + ['{"Action":"pass","Package":"q","Test":"TestD"}'], "p") == ["TestA", "TestC"]
    print("ci-test-split selftest: ok")


def regex(names):
    return "^(" + "|".join(names) + ")$"


def main(argv):
    command = argv[1] if len(argv) > 1 else ""
    if command == "list" and len(argv) == 3:
        print("\n".join(parse_list(pathlib.Path(argv[2]).read_text().splitlines())))
    elif command == "select" and len(argv) == 5:
        parts, part = int(argv[2]), int(argv[3])
        if not 1 <= part <= parts:
            raise SystemExit("part out of range")
        timings = json.loads(pathlib.Path(argv[4]).read_text())
        split, _ = partition(parse_list(sys.stdin), parts, timings)
        print("\n".join(split[part - 1]))
    elif command == "regex" and len(argv) == 2:
        names = [l.strip() for l in sys.stdin if l.strip()]
        if not names or not all(NAME.match(n) for n in names):
            raise SystemExit("regex needs at least one plain test name")
        print(regex(names))
    elif command == "ran" and len(argv) == 3:
        print("\n".join(ran_tests(sys.stdin, argv[2])))
    elif command == "verify" and len(argv) == 5:
        timings = json.loads(pathlib.Path(argv[3]).read_text())
        count = verify(int(argv[2]), timings, argv[4])
        print(f"all {count} tests ran in exactly one of {argv[2]} parts")
    elif command == "selftest" and len(argv) == 2:
        selftest()
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
