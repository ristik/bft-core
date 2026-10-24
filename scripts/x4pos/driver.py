#!/usr/bin/env python3
"""X4 #58 step B: the resumable PoS scenario driver (briefs/x4-shadow-campaign-design.md section 3, briefs/x4-pos-driver-plan.md).

A checked-in campaign manifest declares the experiment: the interval, the policy windows the schedule must respect, the required counts, and the ordered scenario
steps with their offsets, budgets, dependencies, exclusivity and idempotent `check` commands. The driver executes the steps against ONE accumulated chain state, with a
durable cursor, and can be killed and resumed at any point.

    driver.py preflight MANIFEST [--commands]     validate the schedule (refuses a profile that cannot finish) and print it
    driver.py run MANIFEST --dir DIR              execute (or resume) the campaign; exit 0 only on PASS
    driver.py report --dir DIR                    the report of what the cursor records

Rules this file enforces and its tests prove:
  * the cursor is only ever a claim: on resume a step the cursor calls DONE is VERIFIED by its check command (a regressed effect fails the campaign), and a step that
    was interrupted is adopted only if its check says the effect is already there, re-run only if it is declared restartable, and otherwise FAILS;
  * the manifest is sealed by its sha256 into the cursor: a changed manifest refuses to resume (no late changes to the declared experiment);
  * a step that finishes after its deadline is a deadline violation (FAIL), a campaign that stops early is INCOMPLETE, never a shorter successful one;
  * steps with no implementation are reported and refuse the run: nothing is stubbed into a pass;
  * a `lane` step (`"lane": true`, no `cmd`, every lane step before the first driver step in step order) is a phase of the lane's own shell (chain-dictated timing: the install, the offences, the recovery, the exit request): the driver never starts or schedules it,
    and counts it done only if its `check` shows the lane's evidence. A lane step without a check is refused, and its deadline is not judged here (it is the lane's);
  * `notCovered` lists what this campaign does not exercise, each with where it is covered; the report carries it, so a PASS never reads as covering it.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import accounting  # noqa: E402

PENDING, RUNNING, DONE, FAILED = "pending", "running", "done", "failed"
FORMAT = "UNICITY_X4_POS_CAMPAIGN/v1"


class ManifestError(Exception):
    pass


class CursorError(Exception):
    pass


# ---- the manifest and its preflight ------------------------------------------------------------------------------------------------------------------------

def load_manifest(path):
    raw = Path(path).read_bytes()
    m = json.loads(raw)
    if m.get("format") != FORMAT:
        raise ManifestError(f"not a {FORMAT} manifest")
    return m, hashlib.sha256(raw).hexdigest()


def exit_maturity_seconds(policy):
    """The least time between an exit request and a claim the policy allows: the hold in rounds at the declared round time, never below the UC-time floor."""
    return max(policy["timeFloorSeconds"], policy["holdRounds"] * policy["roundSeconds"]) + policy["safetySeconds"]


def preflight(m, commands=False, root=None):
    """Returns the schedule [{id, start, end, deadline, ...}] or raises ManifestError naming every violation. The campaign that cannot finish inside its interval,
    with the final hold, is refused here, before any chain exists."""
    errs = []
    steps = m["steps"]
    ids = [s["id"] for s in steps]
    if len(set(ids)) != len(ids):
        errs.append("duplicate step ids")
    by = {s["id"]: s for s in steps}
    interval, tail, policy = m["intervalSeconds"], m["tailSeconds"], m["policy"]
    for n in m.get("notCovered", []):
        if not str(n.get("what", "")).strip() or not str(n.get("coveredBy", "")).strip():
            errs.append(f"notCovered entry {n!r}: needs 'what' and 'coveredBy' (where it is covered instead)")
    for s in steps:
        if "lane" in s and not isinstance(s["lane"], bool):
            errs.append(f"{s['id']}: 'lane' must be true or false, not {s['lane']!r}")
        if s.get("lane") is True and not s.get("check"):
            errs.append(f"{s['id']}: a lane step is verified by its check only; it needs a command check")
        if s.get("lane") is True and "cmd" in s:
            errs.append(f"{s['id']}: a lane step has no 'cmd' (the lane runs it; the driver would ignore it silently)")
        if "check" not in s:
            errs.append(f"{s['id']}: no 'check' declared (a command, or an explicit null with an 'uncheckedReason')")
        elif s["check"] is None and not str(s.get("uncheckedReason", "")).strip():
            errs.append(f"{s['id']}: 'check' is null without an 'uncheckedReason'")
        if s["budgetSeconds"] <= 0 or s["at"] < 0:
            errs.append(f"{s['id']}: a non-positive budget or negative offset")
        limit = interval if s.get("phase") == "final" else interval - tail
        if s["at"] + s["budgetSeconds"] > limit:
            errs.append(f"{s['id']}: ends at {s['at'] + s['budgetSeconds']} s, after {limit} s ({'the interval' if s.get('phase') == 'final' else 'the start of the final hold'})")
        for dep in s.get("dependsOn", []):
            if dep not in by:
                errs.append(f"{s['id']}: unknown dependency {dep}")
            elif by[dep]["at"] + by[dep]["budgetSeconds"] > s["at"]:
                errs.append(f"{s['id']}: starts before its dependency {dep} can have finished")
        after = s.get("after")
        if after:
            if after["step"] not in by:
                errs.append(f"{s['id']}: unknown 'after' step {after['step']}")
            else:
                delay = exit_maturity_seconds(policy) if after.get("delay") == "exitMaturity" else after["delaySeconds"]
                earliest = by[after["step"]]["at"] + by[after["step"]]["budgetSeconds"] + delay
                if s["at"] < earliest:
                    errs.append(f"{s['id']}: starts at {s['at']} s, before the {delay} s the policy needs after {after['step']} (earliest {earliest} s)")
    # a lane step is checked when the driver reaches it in step order, so the lane's phase must already be over: every lane step comes before the first driver step
    order = [s for s in sorted(steps, key=lambda s: (s["at"], s["id"]))]
    seen_driver = None
    for s in order:
        if s.get("lane") is True and seen_driver:
            errs.append(f"{s['id']}: a lane step comes after the driver step {seen_driver} (it would be checked before the lane's phase is over)")
        elif s.get("lane") is not True and seen_driver is None:
            seen_driver = s["id"]
    ex = sorted((s for s in steps if s.get("exclusive")), key=lambda s: s["at"])
    for a, b in zip(ex, ex[1:]):
        if b["at"] < a["at"] + a["budgetSeconds"] + policy["settleSeconds"]:
            errs.append(f"exclusive steps {a['id']} and {b['id']} are closer than the {policy['settleSeconds']} s settle time (the intended quorum would not stay available)")
    have = {}
    for s in steps:
        for k, v in s.get("counts", {}).items():
            have[k] = have.get(k, 0) + v
    for k, need in m["required"].items():
        if have.get(k, 0) < need:
            errs.append(f"the plan yields {have.get(k, 0)} of the required {need} {k}")
    if commands:
        for s in steps:
            for key in ("cmd", "check"):
                argv = s.get(key)
                if key == "cmd" and s.get("lane") is True:
                    continue   # the lane runs it
                if argv and not (Path(root or ".") / argv[0]).exists():
                    errs.append(f"{s['id']}: {key} {argv[0]} does not exist (not implemented)")
    if errs:
        raise ManifestError("\n".join(errs))
    return sorted(({"id": s["id"], "start": s["at"], "end": s["at"] + s["budgetSeconds"], "exclusive": bool(s.get("exclusive"))} for s in steps), key=lambda r: r["start"])


# ---- the durable cursor ------------------------------------------------------------------------------------------------------------------------------------

def _fsync_dir(d):
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Cursor:
    """cursor.json is written whole (tmp, fsync, rename, fsync of the directory) with a checksum over its body; events.jsonl is append-only with an fsync per event."""

    def __init__(self, d):
        self.dir = Path(d)
        self.path = self.dir / "cursor.json"
        self.events = self.dir / "events.jsonl"
        self.body = None

    def exists(self):
        return self.path.exists()

    def create(self, manifest_sha, steps, now):
        self.dir.mkdir(parents=True, exist_ok=True)
        self.body = {"format": "UNICITY_X4_POS_CURSOR/v1", "manifestSha256": manifest_sha, "startedUtc": now.isoformat(), "seq": 0,
                     "steps": {s["id"]: {"state": PENDING, "attempts": 0} for s in steps}}
        self.save()

    def load(self):
        try:
            doc = json.loads(self.path.read_text())
        except (OSError, ValueError) as e:
            raise CursorError(f"unreadable cursor: {e}") from e
        body = doc.get("body")
        if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != doc.get("sha256"):
            raise CursorError("the cursor's checksum does not match its body (corrupt or edited)")
        self.body = body
        return body

    def save(self):
        self.body["seq"] += 1
        doc = {"body": self.body, "sha256": hashlib.sha256(json.dumps(self.body, sort_keys=True).encode()).hexdigest()}
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            fh.write(json.dumps(doc, sort_keys=True))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        _fsync_dir(self.dir)

    def event(self, now, **kw):
        with open(self.events, "a") as fh:
            fh.write(json.dumps(dict(kw, utc=now.isoformat(), seq=self.body["seq"]), sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())


# ---- execution ---------------------------------------------------------------------------------------------------------------------------------------------

class Clock:
    def now(self):
        return datetime.now(timezone.utc)

    def sleep(self, seconds):
        time.sleep(seconds)


def run_command(argv, env, log):
    with open(log, "ab") as fh:
        return subprocess.run(argv, env=env, stdout=fh, stderr=subprocess.STDOUT, check=False).returncode


class Driver:
    def __init__(self, manifest, sha, d, clock=None, runner=run_command, root="."):
        self.m, self.sha, self.dir, self.clock, self.runner, self.root = manifest, sha, Path(d), clock or Clock(), runner, root
        self.cursor = Cursor(d)
        self.steps = sorted(manifest["steps"], key=lambda s: (s["at"], s["id"]))
        self.by = {s["id"]: s for s in self.steps}

    def _env(self, s):
        env = dict(os.environ, X4_STEP_ID=s["id"], X4_STEP_DIR=str(self.dir / "steps" / s["id"]), X4_CURSOR_DIR=str(self.dir), X4_SEED=str(self.m["seed"]),
                   X4_STEP_ARGS=json.dumps(s.get("args", {})))
        os.makedirs(env["X4_STEP_DIR"], exist_ok=True)
        return env

    def _sh(self, s, key):
        env = self._env(s)
        return self.runner(s[key], env, str(self.dir / "steps" / s["id"] / f"{key}.log"))

    def _start(self):
        return datetime.fromisoformat(self.cursor.body["startedUtc"])

    def open(self):
        """Fresh cursor, or the existing one after reconciliation with the world."""
        now = self.clock.now()
        if not self.cursor.exists():
            self.cursor.create(self.sha, self.steps, now)
            self.cursor.event(now, event="created", manifestSha256=self.sha)
            return
        body = self.cursor.load()
        if body["manifestSha256"] != self.sha:
            raise CursorError("the manifest changed since the campaign began: the declared experiment cannot be edited in flight")
        self.cursor.event(now, event="resumed")
        self.reconcile()

    def reconcile(self):
        for s in self.steps:
            st = self.cursor.body["steps"][s["id"]]
            now = self.clock.now()
            if st["state"] == RUNNING:   # interrupted: the cursor does not know whether the effect happened
                if s.get("check") and self._sh(s, "check") == 0:
                    # the effect's true time is unknown: the deadline is judged at the adoption, which is conservative
                    due = self._start() + timedelta(seconds=s["at"])
                    late = max(0.0, (now - (due + timedelta(seconds=s["budgetSeconds"]))).total_seconds())
                    st.update(state=DONE, finishedUtc=now.isoformat(), adopted=True, lateSeconds=late)
                    self.cursor.event(now, event="adopted", step=s["id"])
                elif s.get("restartable"):
                    st["state"] = PENDING
                    self.cursor.event(now, event="requeued", step=s["id"])
                else:
                    st.update(state=FAILED, reason="interrupted, not restartable, and its check does not show the effect")
                    self.cursor.event(now, event="failed", step=s["id"], reason=st["reason"])
            elif st["state"] == DONE and s.get("check") and self._sh(s, "check") != 0:
                st.update(state=FAILED, reason="regressed: the cursor says done but the step's check no longer shows the effect")
                self.cursor.event(now, event="regressed", step=s["id"])
            self.cursor.save()

    def run(self):
        self.open()
        for s in self.steps:
            st = self.cursor.body["steps"][s["id"]]
            if st["state"] == DONE:
                continue
            if st["state"] == FAILED:
                break
            if any(self.cursor.body["steps"][d]["state"] != DONE for d in s.get("dependsOn", [])):
                st.update(state=FAILED, reason="a dependency is not done")
                self.cursor.save()
                break
            if s.get("lane") is True:   # executed by the lane, not by the driver: done iff the lane's evidence shows it
                ok = bool(s.get("check")) and self._sh(s, "check") == 0
                now = self.clock.now()
                if ok:
                    st.update(state=DONE, finishedUtc=now.isoformat(), external=True, lateSeconds=0.0)
                else:
                    st.update(state=FAILED, finishedUtc=now.isoformat(), reason="lane step: the lane's evidence does not show it")
                self.cursor.save()
                self.cursor.event(now, event="done" if ok else "failed", step=s["id"], external=True)
                if not ok:
                    break
                continue
            due = self._start() + timedelta(seconds=s["at"])
            wait = (due - self.clock.now()).total_seconds()
            if wait > 0:
                self.clock.sleep(wait)
            st.update(state=RUNNING, attempts=st["attempts"] + 1, startedUtc=self.clock.now().isoformat())
            self.cursor.save()
            self.cursor.event(self.clock.now(), event="start", step=s["id"], attempt=st["attempts"])
            rc = self._sh(s, "cmd")
            end = self.clock.now()
            if rc == 0 and s.get("check") and self._sh(s, "check") != 0:
                rc = -1   # the command succeeded and its effect cannot be shown
            late = max(0.0, (end - (due + timedelta(seconds=s["budgetSeconds"]))).total_seconds())
            if rc == 0:
                st.update(state=DONE, finishedUtc=end.isoformat(), lateSeconds=late)
            else:
                st.update(state=FAILED, finishedUtc=end.isoformat(), rc=rc, reason="the command failed" if rc != -1 else "the command succeeded but its check does not show the effect")
            self.cursor.save()
            self.cursor.event(end, event="done" if rc == 0 else "failed", step=s["id"], rc=rc, lateSeconds=late)
            if rc != 0:
                break
        return self.report()

    def report(self):
        """PASS only when every step is done on time and every required count is met; a failed step or a deadline violation is FAIL; anything else INCOMPLETE."""
        body = self.cursor.body
        counts, late, failed, pending, unverified = {}, [], [], [], []
        for s in self.steps:
            st = body["steps"][s["id"]]
            if st["state"] == DONE:
                if not s.get("check"):
                    unverified.append({"step": s["id"], "reason": s.get("uncheckedReason")})
                for k, v in s.get("counts", {}).items():
                    counts[k] = counts.get(k, 0) + v
                if st.get("lateSeconds", 0) > 0:
                    late.append({"step": s["id"], "lateSeconds": st["lateSeconds"]})
            elif st["state"] == FAILED:
                failed.append({"step": s["id"], "reason": st.get("reason")})
            else:
                pending.append(s["id"])
        short = {k: {"required": n, "done": counts.get(k, 0)} for k, n in self.m["required"].items() if counts.get(k, 0) < n}
        status = "FAIL" if failed or late else "INCOMPLETE" if pending or short else "PASS"
        acct = None
        if self.m.get("accounting"):   # the accumulated-state checker (accounting.py) over the collector's snapshots: no snapshots, or too few, is not a pass
            snaps = self.dir / "snapshots.jsonl"
            acct = accounting.run(snaps) if snaps.exists() else {"status": "INCOMPLETE", "reason": "no snapshots.jsonl: the collector did not run"}
            (self.dir / "accounting.json").write_text(json.dumps(acct, indent=1, sort_keys=True))
            if acct["status"] == "FAIL":
                status = "FAIL"
            elif acct["status"] != "PASS" and status == "PASS":
                status = "INCOMPLETE"
        rep = {"status": status, "accounting": acct, "manifestSha256": self.sha, "startedUtc": body["startedUtc"], "counts": counts, "failed": failed, "late": late, "pending": pending, "shortOfRequired": short, "unverified": unverified,
               "external": [s["id"] for s in self.steps if body["steps"][s["id"]].get("external")], "notCovered": self.m.get("notCovered", [])}
        (self.dir / "report.json").write_text(json.dumps(rep, indent=1, sort_keys=True))
        return rep


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    pf = sub.add_parser("preflight")
    pf.add_argument("manifest")
    pf.add_argument("--commands", action="store_true", help="also require every step's command and check to exist")
    r = sub.add_parser("run")
    r.add_argument("manifest")
    r.add_argument("--dir", required=True)
    rp = sub.add_parser("report")
    rp.add_argument("--dir", required=True)
    a = p.parse_args(argv)
    if a.cmd == "report":
        print(Path(a.dir, "report.json").read_text())
        return 0
    m, sha = load_manifest(a.manifest)
    try:
        sched = preflight(m, commands=a.cmd == "run" or a.commands)
    except ManifestError as e:
        print(f"preflight refused:\n{e}", file=sys.stderr)
        return 2
    if a.cmd == "preflight":
        for row in sched:
            print(json.dumps(row))
        return 0
    rep = Driver(m, sha, a.dir).run()
    print(json.dumps(rep, indent=1))
    return 0 if rep["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
