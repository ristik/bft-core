#!/usr/bin/env python3
"""Capture Go stacks when an owned rehearsal root stops advancing its round."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from http.client import HTTPConnection, HTTPException
from pathlib import Path
import signal
import time


PAUSE_MAX_AGE = 10 * 60


class Pause(Enum):
    ABSENT = auto()
    ACTIVE = auto()
    EXPIRED = auto()
    FAILED = auto()


def marker_generation(path):
    try:
        stat = path.stat()
        return stat.st_ino, stat.st_mtime_ns
    except OSError:
        return None


def read_root(port, pid, path, timeout):
    connection = HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"X-Root-Pid": str(pid)})
        with connection.getresponse() as reply:
            if reply.status == 200 and reply.getheader("X-Root-Pid") == str(pid):
                return reply.read()
    except (OSError, HTTPException):
        pass  # An unavailable probe also fails to demonstrate progress.
    finally:
        connection.close()
    return None


@dataclass
class Root:
    home: Path
    pid: int
    port: int
    progressed: float
    round_number: int | None = None
    dumped: bool = False
    last_attempt: float | None = None
    paused: bool = False
    completion_generation: tuple[int, int] | None = None

    def restart_pause(self):
        # A rolling restart can delay peers that were never stopped, so the marker covers the lane.
        nodes = self.home.parent
        started = marker_generation(nodes / ".stall-watch-pause")
        if started is not None:
            age = time.time() - started[1] / 1_000_000_000
            if 0 <= age < PAUSE_MAX_AGE:
                self.paused = True
                self.dumped = False
                return Pause.ACTIVE, started
            if age >= PAUSE_MAX_AGE:
                self.paused = False
                return Pause.EXPIRED, started

        failed = marker_generation(nodes / ".stall-watch-failed")
        if failed is not None:
            if failed != self.completion_generation:
                self.dumped = False
            self.completion_generation = failed
            self.paused = False
            return Pause.FAILED, failed

        resumed = marker_generation(nodes / ".stall-watch-resumed")
        if self.paused or (resumed is not None and resumed != self.completion_generation):
            self.progressed = time.monotonic()
            self.dumped = False
            self.last_attempt = None
        self.paused = False
        self.completion_generation = resumed
        return Pause.ABSENT, resumed

    def sample(self, threshold, stopping=False):
        pause, _ = self.restart_pause()
        if pause is Pause.ACTIVE:
            return
        current = read_root(self.port, self.pid, "/debug/consensus/round", 0.5)
        pause, generation = self.restart_pause()
        if pause is Pause.ACTIVE:
            return
        now = time.monotonic()
        round_available = current is not None and current.strip().isdigit()
        if round_available:
            round_number = int(current)
            if self.round_number != round_number:
                self.round_number = round_number
                self.progressed = now
                self.dumped = False
        elif pause not in (Pause.EXPIRED, Pause.FAILED):
            return
        progressed = self.progressed
        elapsed = now - progressed
        failed_at_teardown = stopping and pause is Pause.FAILED and not round_available
        if self.dumped or (elapsed < threshold and not failed_at_teardown):
            return
        if self.last_attempt is not None and now - self.last_attempt < threshold:
            return
        self.last_attempt = now
        try:
            pidfile = self.home / "pid"
            if int(pidfile.read_text()) != self.pid:
                return
            stacks = read_root(self.port, self.pid, "/debug/pprof/goroutine?debug=2", 2)
            if not stacks:
                return
            after, after_generation = self.restart_pause()
            rearmed = self.progressed != progressed
            # The same expired pause may be renamed as the already-eligible request completes.
            resumed_expired_pause = pause is Pause.EXPIRED and after_generation == generation
            if after is Pause.ACTIVE or (rearmed and not resumed_expired_pause):
                return
            if int(pidfile.read_text()) != self.pid:
                return  # The lane has replaced this root since we began sampling it.
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            round_info = f"round {self.round_number}" if round_available else "round unavailable"
            if not round_available and self.round_number is not None:
                round_info += f", last round {self.round_number}"
            reason = f"{elapsed:.1f}s without round progress ({round_info}, pid {self.pid})"
            marker = f"\n=== #1063 stall dump: {reason}, pprof at {stamp} ===\n"
            log = self.home / "debug.log"
            with log.open("ab", buffering=0) as evidence:
                evidence.write(marker.encode() + stacks + b"\n")
        except (OSError, ValueError) as err:
            print(f"STALL: could not save stacks for {self.home}: {err}", flush=True)
            return
        self.dumped = not rearmed
        print(f"STALL: root {self.home}, {reason}: goroutine dump in {log}", flush=True)


def watch(nodes, base_port, threshold, should_stop):
    roots = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        while True:
            stopping = should_stop()
            # The lane waits for the watcher before stopping roots or cleaning up the marker.
            if stopping and not (nodes / ".stall-watch-failed").is_file():
                return
            current = {}
            for pidfile in nodes.glob("root[0-9]*/pid"):
                home = pidfile.parent
                try:
                    number = int(home.name.removeprefix("root"))
                    pid = int(pidfile.read_text())
                except (OSError, ValueError):
                    continue
                if number < 1 or pid < 1:
                    continue
                root = roots.get(home)
                if root is None or root.pid != pid:
                    root = Root(home, pid, base_port + number - 1, time.monotonic())
                current[home] = root
            roots = current
            # Sample roots in parallel so their timeouts do not add up.
            for _ in pool.map(lambda root: root.sample(threshold, stopping), roots.values()):
                pass
            if stopping:
                return
            if not should_stop():
                time.sleep(min(1, threshold / 2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nodes", type=Path)
    parser.add_argument("base_port", type=int)
    parser.add_argument("stall_seconds", type=int)
    args = parser.parse_args()
    if args.stall_seconds <= 0:
        parser.error("stall_seconds must be positive")

    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    watch(args.nodes, args.base_port, args.stall_seconds, lambda: stopped)


if __name__ == "__main__":
    main()
