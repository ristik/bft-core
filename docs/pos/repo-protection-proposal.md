# Repository enforcement decision

Status: accepted on 2026-09-06, following the repository owner's explicit instruction:
"we’ll leave branch protection off; only trusted developers and agents."

Branch protection and ruleset enforcement remain off. R0 and F1 do not enable protected
branches, required status checks, CODEOWNER enforcement, or review-count requirements.
No repository settings are changed by this documentation decision.

Trusted contributors follow `CONTRIBUTING.md` and `PROCESS.md`: claim work, use reviewable
PRs, obtain independent review, run the relevant checks and record acceptance evidence.
Trust in contributors does not turn a passing smoke test into protocol-design acceptance.

F1 still owns PR-triggered CI, baseline reconciliation and a pinned real-reth integration
lane. Check failures must be resolved or explicitly assessed before a maintainer merges;
GitHub branch rules do not enforce this workflow. FFI coverage remains a documented F1
choice. Fake-executor tests remain useful but are not real-reth integration evidence.

Merge commits may be used to preserve ancestry in the current stacked PRs. Keep dependency
branches until children are retargeted, and verify each resulting diff. No global merge-method
or automatic branch-deletion setting is changed.

The earlier protection proposal is superseded by this decision. Enabling protection later
would require a new explicit owner instruction.
