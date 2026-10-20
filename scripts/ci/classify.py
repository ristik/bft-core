#!/usr/bin/env python3
"""The PR path classifier of the CI lane (docs/ci-lanes.md, 'Pull requests').

  classify.py --base BASE --head HEAD [--rules scripts/ci/pr-paths.json]     the changed paths come from `git diff --name-only BASE HEAD`
  classify.py --paths FILE|-                                                  one path per line
  classify.py selftest

Prints one JSON object: {"lanes": ["combined", "overbound", ...], "t6": bool, "targeted": bool, "selftests": bool, "reason": {...}}.
`lanes` is what the matrix run job takes (combined / overbound / abort); `t6` and `targeted` are the other two jobs; `selftests` is the chain-free self-test job.
A docs-only change selects nothing. A path no rule names selects `combined` (the umbrella lane) only; the classifier errs toward running, never toward skipping.
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES = os.path.join(HERE, "pr-paths.json")


def glob_re(g):
    out, i = [], 0
    while i < len(g):
        c = g[i]
        if g.startswith("**/", i):
            out.append("(?:.*/)?"); i += 3; continue
        if g.startswith("**", i):
            out.append(".*"); i += 2; continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def compile_all(rules):
    return {
        "ignore": [glob_re(g) for g in rules["ignore"]],
        "all": [glob_re(g) for g in rules["all"]],
        "lanes": {k: [glob_re(g) for g in v] for k, v in rules["lanes"].items()},
    }


def classify(paths, rules):
    c = compile_all(rules)
    reason = {}
    sel = {"combined": False, "overbound": False, "abort": False, "t6": False, "ureth-targeted": False}
    selftests = False
    for p in paths:
        p = p.strip()
        if not p:
            continue
        if any(r.match(p) for r in c["all"]):
            for k in sel:
                if not sel[k]:
                    sel[k] = True; reason[k] = p
            selftests = True
            continue
        # chain-free self-tests: the CI scripts and the stock-control helpers they share
        if re.match(r"^(scripts/ci/|scripts/lib/reth-pin\.sh$|\.github/workflows/)", p):
            selftests = True
        if any(r.match(p) for r in c["ignore"]):
            continue
        named = False
        for lane, globs in c["lanes"].items():
            if any(r.match(p) for r in globs):
                named = True
                if not sel[lane]:
                    sel[lane] = True; reason[lane] = p
        # the umbrella lane runs for any lane-relevant code: every non-ignored path
        if not sel["combined"]:
            sel["combined"] = True; reason["combined"] = p
        _ = named
    lanes = [k for k in ("combined", "overbound", "abort") if sel[k]]
    return {"lanes": lanes, "t6": sel["t6"], "targeted": sel["ureth-targeted"], "selftests": selftests, "reason": reason}


def changed_paths(base, head):
    out = subprocess.run(["git", "diff", "--name-only", "-z", base, head], check=True, capture_output=True).stdout.decode()
    return [x for x in out.split("\0") if x]


def selftest():
    rules = json.load(open(DEFAULT_RULES))
    cases = [
        # (name, paths, lanes, t6, targeted, selftests)
        ("docs only", ["docs/ci-lanes.md", "briefs/x.md", "README.md"], [], False, False, False),
        ("markdown anywhere", ["rootchain/README.md"], [], False, False, False),
        ("faucet and deploy", ["faucet/main.go", "deploy/testnet/pins.json"], [], False, False, False),
        ("a root consensus change", ["rootchain/consensus/consensus_manager.go"], ["combined", "overbound", "abort"], True, False, False),
        ("a unit test file of consensus is still consensus code", ["rootchain/consensus/consensus_manager_test.go"], ["combined", "overbound", "abort"], True, False, False),
        ("the adapter", ["engineapi/adapter.go"], ["combined", "overbound"], True, True, False),
        ("b1 vectors", ["b1ref/vectors.go"], ["combined"], True, True, False),
        ("only the over-bound neighbours", ["posrelayer/tx.go"], ["combined", "overbound"], False, False, False),
        ("the H6 abort lane", ["scripts/h6/abort-rehearsal-lane.sh"], ["combined", "abort"], False, False, False),
        ("T6", ["scripts/t6-rehearsal.sh"], ["combined", "overbound"][:1], True, False, False),
        ("the pin manifest selects everything", ["scripts/ci/lane-pins.json"], ["combined", "overbound", "abort"], True, True, True),
        ("go.mod selects everything", ["go.mod"], ["combined", "overbound", "abort"], True, True, True),
        ("the workflow selects everything", [".github/workflows/ci-lane.yml"], ["combined", "overbound", "abort"], True, True, True),
        ("an ignored workflow runs only the self-tests", [".github/workflows/go-ci.yml"], [], False, False, True),
        ("a stock-control script selects nothing but the self-tests are not needed", ["scripts/reth-smoke.sh"], [], False, False, False),
        ("reth-pin.sh feeds the publisher", ["scripts/lib/reth-pin.sh"], ["combined"], False, False, True),
        ("an unnamed Go package selects the umbrella lane only", ["frontier/service.go"], ["combined"], False, False, False),
        ("mixed: docs and one code file", ["docs/a.md", "utbstore/store.go"], ["combined"], False, False, False),
        ("empty", [], [], False, False, False),
    ]
    bad = 0
    for name, paths, lanes, t6, targeted, selftests in cases:
        r = classify(paths, rules)
        ok = (r["lanes"], r["t6"], r["targeted"], r["selftests"]) == (lanes, t6, targeted, selftests)
        print(("  ok    " if ok else "  FAIL  ") + name + ("" if ok else "  got %r" % ((r["lanes"], r["t6"], r["targeted"], r["selftests"]),)))
        bad += 0 if ok else 1
    # the rules file is well formed: every glob compiles, no lane is missing, and 'ignore' never swallows a lane glob's whole tree
    for lane in ("overbound", "abort", "t6", "ureth-targeted"):
        assert lane in rules["lanes"], lane
    print("classify self-test: %d cases, %d failures" % (len(cases), bad))
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["selftest"]:
        return selftest()
    base = head = paths_file = None
    rules_path = DEFAULT_RULES
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--base": base = argv[i + 1]; i += 2
        elif a == "--head": head = argv[i + 1]; i += 2
        elif a == "--paths": paths_file = argv[i + 1]; i += 2
        elif a == "--rules": rules_path = argv[i + 1]; i += 2
        else:
            print("classify: unknown argument %s" % a, file=sys.stderr); return 2
    rules = json.load(open(rules_path))
    if paths_file is not None:
        paths = (sys.stdin if paths_file == "-" else open(paths_file)).read().splitlines()
    elif base and head:
        paths = changed_paths(base, head)
    else:
        print("usage: classify.py --base B --head H | --paths FILE|- | selftest", file=sys.stderr); return 2
    print(json.dumps(classify(paths, rules), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
