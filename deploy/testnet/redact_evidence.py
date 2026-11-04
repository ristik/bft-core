#!/usr/bin/env python3
"""Redact a log file in place before it is uploaded as evidence: `redact_evidence.py <generation> <file>...`. The same rules as the rehearsal's stop-window captures
(rehearse.py, at CAPTURE_SERVICES). Fails closed: when the generation's secrets cannot be scanned, or a known literal survives, the file keeps one line that says so and none
of its content. A failure it cannot catch (it does not start, an import fails, the rewrite fails) exits non-zero, and each workflow line then overwrites the file itself: never `|| true`."""
import sys
from pathlib import Path

from rehearse import known_secrets, redact_log


def redact_file(gen, path):
    """Rewrite `path`; returns what was done, for the job log."""
    path = Path(path)
    if not path.is_file():
        return f'{path}: no such file'
    try:
        secrets = known_secrets(gen)
        lines, scrubbed, withheld = redact_log(path.read_text(errors='replace'), secrets)
        body = '\n'.join(lines)
        if any(secret in body for secret in secrets):
            raise ValueError('a known secret literal survived the redaction')
    except Exception as error:
        path.write_text(f'[log withheld: {type(error).__name__}]\n')   # the message can name paths, not secrets, but it has no use here
        return f'{path}: withheld whole: {error}'
    path.write_text(body + '\n')
    return f'{path}: {len(lines)} lines, {scrubbed} literals scrubbed, {withheld} lines withheld'


if __name__ == '__main__':
    for name in sys.argv[2:]:
        print(redact_file(sys.argv[1], name))
