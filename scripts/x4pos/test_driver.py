#!/usr/bin/env python3
"""Self-tests of the X4 PoS scenario driver (stdlib unittest; CI: x4-pos-driver-selftest). No chain: the steps are simulated against an in-memory 'world', so what is
tested is the driver's own contract: the preflight refusals, the durable cursor, kill-and-resume at every boundary, verification instead of trust on resume,
the sealed manifest, deadlines, and honest statuses."""
import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import driver  # noqa: E402

REAL = HERE / "campaign.json"


class Crash(Exception):
    """The process dies here (no cleanup runs in the driver after it)."""


class FakeClock:
    def __init__(self):
        self.t = datetime(2026, 10, 21, 0, 0, tzinfo=timezone.utc)
        self.slept = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += timedelta(seconds=s)

    def advance(self, s):
        self.t += timedelta(seconds=s)


class World:
    """The chain, reduced to a set of effects; a step's cmd adds its effect, its check looks for it. Crash points are (step, 'before'|'after') of the cmd."""

    def __init__(self, crash=None, cost=0, clock=None):
        self.effects, self.crash, self.cost, self.clock, self.ran = set(), crash, cost, clock, []

    def runner(self, argv, env, log):
        sid, kind = env["X4_STEP_ID"], argv[0]
        if kind == "check":
            return 0 if sid in self.effects else 1
        self.ran.append(sid)
        if self.crash == (sid, "before"):
            self.crash = None
            raise Crash()
        if self.clock and self.cost:
            self.clock.advance(self.cost)
        self.effects.add(sid)
        if self.crash == (sid, "after"):
            self.crash = None
            raise Crash()
        return 0


def small(restartable=True, check=True):
    def st(id, at, deps=(), counts=None, **kw):
        s = {"id": id, "kind": "k", "at": at, "budgetSeconds": 100, "cmd": ["cmd"], "restartable": restartable, "counts": counts or {id: 1}, "dependsOn": list(deps)}
        if check:
            s["check"] = ["check"]
        s.update(kw)
        return s
    return {"format": driver.FORMAT, "name": "t", "seed": 1, "intervalSeconds": 1000, "tailSeconds": 200,
            "policy": {"evidenceWindowRounds": 10, "holdRounds": 20, "timeFloorSeconds": 100, "roundSeconds": 1.0, "safetySeconds": 10, "settleSeconds": 20, "recoveryBudgetSeconds": 5},
            "required": {"a": 1, "b": 1, "c": 1}, "steps": [st("a", 0), st("b", 150, ["a"]), st("c", 400, ["b"])]}


def write(d, m):
    p = Path(d) / "m.json"
    p.write_text(json.dumps(m))
    return p


class Preflight(unittest.TestCase):
    def test_the_checked_in_campaign_is_a_valid_schedule_that_meets_every_required_count(self):
        m, _ = driver.load_manifest(REAL)
        sched = driver.preflight(m)
        self.assertEqual(len(sched), len(m["steps"]))
        self.assertEqual(m["intervalSeconds"], 14400)
        self.assertEqual(driver.exit_maturity_seconds(m["policy"]), 3900)
        for s in m["steps"]:
            if s.get("phase") != "final":
                self.assertLessEqual(s["at"] + s["budgetSeconds"], 14400 - m["tailSeconds"], s["id"])
        # the minimum scenario of the design
        r = m["required"]
        self.assertTrue(r["replacements"] >= 2 and r["offences"] >= 2 and r["exits"] >= 2 and r["rewardIntervals"] >= 4 and r["recoveries"] >= 1 and r["aborts"] >= 1)

    def test_the_real_campaign_is_refused_to_run_until_every_step_exists(self):
        m, _ = driver.load_manifest(REAL)
        with self.assertRaises(driver.ManifestError) as e:
            driver.preflight(m, commands=True, root=HERE.parent.parent)
        self.assertIn("not implemented", str(e.exception))

    def refused(self, mutate, needle):
        m = small()
        mutate(m)
        with self.assertRaises(driver.ManifestError) as e:
            driver.preflight(m)
        self.assertIn(needle, str(e.exception))

    def test_every_rule_refuses(self):
        self.refused(lambda m: m["steps"][2].update(at=850), "after 800 s")                                   # into the final hold
        self.refused(lambda m: m["steps"][1].update(at=50), "before its dependency a can have finished")
        self.refused(lambda m: m["steps"][1].update(dependsOn=["zz"]), "unknown dependency")
        self.refused(lambda m: m["steps"][1].update(id="a"), "duplicate step ids")
        self.refused(lambda m: m["required"].update(a=2), "the plan yields 1 of the required 2 a")
        self.refused(lambda m: m["steps"][1].update(budgetSeconds=0), "non-positive budget")
        self.refused(lambda m: m["steps"][1].update(after={"step": "a", "delay": "exitMaturity"}), "before the 110 s the policy needs after a")
        self.refused(lambda m: (m["steps"][0].update(exclusive=True), m["steps"][1].update(exclusive=True, at=110, dependsOn=[])), "closer than the 20 s settle time")

    def test_the_maturity_rule_accepts_a_claim_that_waits_long_enough(self):
        m = small()
        m["steps"][2].update(at=400, after={"step": "a", "delay": "exitMaturity"})   # 0 + 100 + max(100, 20 * 1.0) + 10 = 210
        driver.preflight(m)
        m["steps"][2].update(at=209)
        with self.assertRaises(driver.ManifestError):
            driver.preflight(m)


class Execution(unittest.TestCase):
    def drive(self, m, d, world, clock):
        sha = driver.load_manifest(write(d, m))[1]
        return driver.Driver(m, sha, Path(d) / "run", clock=clock, runner=world.runner)

    def test_a_full_run_passes_and_waits_for_each_offset(self):
        with tempfile.TemporaryDirectory() as d:
            clock = FakeClock()
            world = World()
            rep = self.drive(small(), d, world, clock).run()
            self.assertEqual((rep["status"], rep["counts"]), ("PASS", {"a": 1, "b": 1, "c": 1}))
            self.assertEqual(world.ran, ["a", "b", "c"])
            self.assertEqual(clock.slept, [150, 250])   # b at 150, c at 400, no wait for a at 0

    def test_kill_at_every_boundary_and_resume_reaches_the_same_final_state(self):
        for step in "abc":
            for when in ("before", "after"):
                with self.subTest(step=step, when=when), tempfile.TemporaryDirectory() as d:
                    clock = FakeClock()
                    world = World(crash=(step, when))
                    with self.assertRaises(Crash):
                        self.drive(small(), d, world, clock).run()
                    rep = self.drive(small(), d, world, clock).run()   # a new process: only the cursor and the world survive
                    self.assertEqual(rep["status"], "PASS", rep)
                    self.assertEqual(world.effects, {"a", "b", "c"})
                    # an effect that already exists is adopted, not done twice
                    self.assertEqual(world.ran.count(step), 1 if when == "after" else 2)

    def test_an_interrupted_step_that_cannot_be_restarted_and_shows_no_effect_fails(self):
        with tempfile.TemporaryDirectory() as d:
            clock, world = FakeClock(), World(crash=("b", "before"))
            m = small(restartable=False)
            with self.assertRaises(Crash):
                self.drive(m, d, world, clock).run()
            rep = self.drive(m, d, world, clock).run()
            self.assertEqual(rep["status"], "FAIL")
            self.assertEqual(rep["failed"][0]["step"], "b")
            self.assertEqual(world.ran, ["a", "b"], "nothing ran after the failure")

    def test_an_interrupted_step_without_a_check_is_requeued_only_if_restartable(self):
        for restartable, want in ((True, "PASS"), (False, "FAIL")):
            with self.subTest(restartable=restartable), tempfile.TemporaryDirectory() as d:
                clock, world = FakeClock(), World(crash=("a", "after"))
                m = small(restartable=restartable, check=False)
                with self.assertRaises(Crash):
                    self.drive(m, d, world, clock).run()
                self.assertEqual(self.drive(m, d, world, clock).run()["status"], want)

    def test_a_done_step_whose_effect_disappeared_is_a_failure_not_a_skip(self):
        with tempfile.TemporaryDirectory() as d:
            clock, world = FakeClock(), World(crash=("c", "before"))
            with self.assertRaises(Crash):
                self.drive(small(), d, world, clock).run()
            world.effects.discard("a")   # the chain lost step a's effect (restored from an older state)
            rep = self.drive(small(), d, world, clock).run()
            self.assertEqual(rep["status"], "FAIL")
            self.assertIn("regressed", rep["failed"][0]["reason"])

    def test_a_command_that_succeeds_without_its_effect_is_a_failure(self):
        class NoEffect(World):
            def runner(self, argv, env, log):
                if argv[0] == "cmd" and env["X4_STEP_ID"] == "b":
                    self.ran.append("b")
                    return 0   # reports success, changes nothing
                return super().runner(argv, env, log)
        with tempfile.TemporaryDirectory() as d:
            rep = self.drive(small(), d, NoEffect(), FakeClock()).run()
            self.assertEqual(rep["status"], "FAIL")
            self.assertIn("check does not show the effect", rep["failed"][0]["reason"])

    def test_a_dependency_that_is_not_done_stops_the_run_even_without_a_preflight(self):
        m = small()
        m["steps"][0]["at"], m["steps"][1]["at"] = 150, 0   # b (depends on a) would run first
        with tempfile.TemporaryDirectory() as d:
            world = World()
            rep = self.drive(m, d, world, FakeClock()).run()
            self.assertEqual(rep["status"], "FAIL")
            self.assertEqual(world.ran, [], "b did not run before a")
            self.assertIn("dependency", rep["failed"][0]["reason"])

    def test_the_manifest_is_sealed_into_the_cursor(self):
        with tempfile.TemporaryDirectory() as d:
            clock, world = FakeClock(), World(crash=("b", "before"))
            with self.assertRaises(Crash):
                self.drive(small(), d, world, clock).run()
            changed = small()
            changed["required"]["a"] = 0
            with self.assertRaises(driver.CursorError):
                self.drive(changed, d, world, clock).run()

    def test_a_corrupt_or_edited_cursor_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            clock, world = FakeClock(), World(crash=("b", "before"))
            with self.assertRaises(Crash):
                self.drive(small(), d, world, clock).run()
            path = Path(d) / "run" / "cursor.json"
            doc = json.loads(path.read_text())
            doc["body"]["steps"]["b"]["state"] = "done"   # a hand edit to skip a step
            path.write_text(json.dumps(doc))
            with self.assertRaises(driver.CursorError):
                self.drive(small(), d, world, clock).run()

    def test_a_late_step_is_a_deadline_failure_and_a_stopped_campaign_is_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            clock = FakeClock()
            rep = self.drive(small(), d, World(cost=150, clock=clock), clock).run()   # budget 100, takes 150
            self.assertEqual(rep["status"], "FAIL")
            self.assertEqual([x["step"] for x in rep["late"]][0], "a")
        with tempfile.TemporaryDirectory() as d:
            clock, world = FakeClock(), World(crash=("b", "before"))
            with self.assertRaises(Crash):
                self.drive(small(), d, world, clock).run()
            drv = self.drive(small(), d, world, clock)
            drv.open()
            self.assertEqual(drv.report()["status"], "INCOMPLETE")   # the process never came back: not a shorter successful campaign

    def test_a_resume_after_a_long_outage_runs_overdue_steps_at_once_and_marks_them_late(self):
        with tempfile.TemporaryDirectory() as d:
            clock, world = FakeClock(), World(crash=("a", "before"))
            with self.assertRaises(Crash):
                self.drive(small(), d, world, clock).run()
            clock.advance(600)   # the host was down for ten minutes
            rep = self.drive(small(), d, world, clock).run()
            self.assertEqual(rep["status"], "FAIL")
            self.assertTrue(rep["late"])

    def test_the_events_log_records_every_start_and_resume(self):
        with tempfile.TemporaryDirectory() as d:
            clock, world = FakeClock(), World(crash=("b", "after"))
            with self.assertRaises(Crash):
                self.drive(small(), d, world, clock).run()
            self.drive(small(), d, world, clock).run()
            ev = [json.loads(line) for line in (Path(d) / "run" / "events.jsonl").read_text().splitlines()]
            kinds = [e["event"] for e in ev]
            self.assertIn("resumed", kinds)
            self.assertIn("adopted", kinds)
            self.assertEqual(kinds.count("created"), 1)


if __name__ == "__main__":
    unittest.main()
