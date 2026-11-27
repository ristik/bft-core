#!/usr/bin/env python3
"""Capture Go stacks when an owned rehearsal root stops advancing its round."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPException
from pathlib import Path
import signal
import time


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

    def sample(self, threshold):
        current = read_root(self.port, self.pid, "/debug/consensus/round", 0.5)
        if current is None or not current.strip().isdigit():
            return
        now = time.monotonic()
        round_number = int(current)
        if self.round_number != round_number:
            self.round_number = round_number
            self.progressed = now
            self.dumped = False
        elapsed = now - self.progressed
        if self.dumped or elapsed < threshold:
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
            if int(pidfile.read_text()) != self.pid:
                return  # The lane has replaced this root since we began sampling it.
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            reason = f"{elapsed:.1f}s without round progress (round {self.round_number}, pid {self.pid})"
            marker = f"\n=== #1063 stall dump: {reason}, pprof at {stamp} ===\n"
            log = self.home / "debug.log"
            with log.open("ab", buffering=0) as evidence:
                evidence.write(marker.encode() + stacks + b"\n")
        except (OSError, ValueError) as err:
            print(f"STALL: could not save stacks for {self.home}: {err}", flush=True)
            return
        self.dumped = True
        print(f"STALL: root {self.home}, {reason}: goroutine dump in {log}", flush=True)


def watch(nodes, base_port, threshold, should_stop):
    roots = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        while not should_stop():
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
            for _ in pool.map(lambda root: root.sample(threshold), roots.values()):
                pass
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
