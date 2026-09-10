#!/usr/bin/env python3
"""One implementation of "which log lines fall in this interval", for the #92 acceptance lanes.

There were three, and the differences between them were defects rather than choices:

  * RFC3339 compared as TEXT is wrong at second boundaries. `22:03:24.575417Z` sorts BEFORE
    `22:03:24Z`, because `.` precedes `Z`, so an event inside the marked second lands outside a
    window that starts there and inside one that ends there. Review found this in the window count;
    the same line, written again in a trace extraction, produced an EMPTY trace for a run in which
    every event happened inside one second — evidence that looks like "nothing happened" and means
    "nothing was compared".
  * A log has lines that are not events. reth prints a chain-spec banner before it prints anything
    timestamped, and a parser that treats those as corruption declares the whole file unreadable.
    Lines without a parseable leading instant are skipped; a file with NO parseable line at all is
    not an event log and is refused, which is the distinction that matters.
  * Unreadable input is a failed observation, never an empty result. These counts are the evidence
    for negative claims — "no session was established in this window" — so "I could not look" must
    never render as zero.

Usage:
  f6b_events.py --mode count|show --from <ts> [--to <ts>] [--pattern <text>] <file>...

An end marker with no fractional part covers that whole second, so `--to 22:03:24Z` includes
`22:03:24.999Z`; one with a fractional part is an exact instant and is inclusive.
"""
import argparse
import sys
from datetime import datetime, timedelta


def instant(value):
    return datetime.fromisoformat(value.removeprefix("time=").replace("Z", "+00:00"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("count", "show"), required=True)
    ap.add_argument("--from", dest="start", required=True)
    ap.add_argument("--to", dest="end")
    ap.add_argument("--pattern", default="")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()

    try:
        start = instant(args.start)
        end = None
        if args.end:
            end = instant(args.end)
            if "." not in args.end:
                end += timedelta(seconds=1)
                exclusive_end = True
            else:
                exclusive_end = False

        parsed = 0
        out = []
        for path in args.files:
            with open(path) as source:
                for line in source:
                    fields = line.split()
                    if not fields:
                        continue
                    try:
                        stamp = instant(fields[0])
                    except ValueError:
                        continue  # a banner line, not an event
                    parsed += 1
                    if args.pattern and args.pattern not in line:
                        continue
                    if stamp < start:
                        continue
                    if end is not None:
                        if exclusive_end:
                            if stamp >= end:
                                continue
                        elif stamp > end:
                            continue
                    out.append(line.rstrip("\n"))
        if parsed == 0:
            print("no timestamped lines in %s" % ", ".join(args.files), file=sys.stderr)
            return 1
        print(len(out) if args.mode == "count" else "\n".join(out))
        return 0
    except (OSError, ValueError, IndexError, TypeError) as err:
        print("cannot read event stream: %s" % err, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
