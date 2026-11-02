# Processing upgrade validation — 2 November 2026

Baseline: `0d32a0d75c68db38070aa4c8ecd029fb49e7378d`.
Branch: `feat/reliable-incremental-processing-20261102`.

- Baseline supplied suite before changes: **159 passed**, Python 3.11.16.
- Upgraded full suite: **194 passed**, Python **3.11.9**, using the locked dependency constraints.
- New controls run independently: **35 passed**, Python 3.11.9.
- `uv pip check` against the production-version virtual environment: all installed packages compatible.
- `git diff --check`, Python AST parsing and Railway JSON parsing passed.

The 35 added controls cover late cold starts and restart persistence; state write/read failures;
canonical replay after an orphaned claim; legacy hashless-state migration; checkpoint hash failures
and mid-measurement reorgs; missing/changed/zero decimals and exact raw deltas at large balances;
required-chain and position-state coverage; default omission of the wallet matrix and explorer probes;
exposure-only pricing and temporary miss memoisation; failed log ranges and quiet holder cursors;
atomic publication, pinned reads and competing writers; large-file reads; deadlines;
redaction; and status endpoint access.

Existing history fixtures were encoded explicitly in the new verified raw-unit format so their
original rate, completeness and discovery assertions continue to apply. Legacy history rejection has
a separate regression test.

All tests use fake chain data and a simulated GitHub publisher. No real collector/publisher run,
on-chain transaction, Railway change, production data edit or billing benchmark was performed.
The auditor's sealed reproductions were unavailable locally; the new controls independently exercise
the supplied mechanisms rather than claiming to rerun that sealed suite.

Commands (inside the temporary development checkout):

```sh
LOG_LEVEL=CRITICAL PYTHONDONTWRITEBYTECODE=1 /private/tmp/iaero-cpb-upgrade-venv3119-20261102/bin/python -m unittest discover -s tests -q
LOG_LEVEL=CRITICAL PYTHONDONTWRITEBYTECODE=1 /private/tmp/iaero-cpb-upgrade-venv3119-20261102/bin/python -m unittest discover -s tests -p test_processing_upgrade.py -q
/opt/homebrew/bin/uv --no-cache pip check --python /private/tmp/iaero-cpb-upgrade-venv3119-20261102/bin/python
git diff --check
```

CI configuration uses pinned GitHub action commits, installs the constrained requirements, and runs
the offline suite on Python 3.11.9. Repository branch-protection settings were not changed.

Migration intentionally rebuilds unverified legacy measurement history. After the initial
since-allocation fallback period, a fresh rate needs a complete six-to-eight-day reference point.
The prior headline is not relabelled fresh to cover that interval. See README for configuration,
state persistence, deadline and compatibility-export behaviour.


## PR #6 follow-up at reviewed head 275fd8b

The initial four follow-up safety controls fail against 275fd8b, reproducing the isolated secondary-read abort,
lost reorg invalidation and funding-index reorg cases. The complete upgraded suite passes **209 tests on
Python 3.11.9**, including 15 follow-up tests (with additional subcases). The original 194 remain passing.

The new controls use the real publication transaction against a simulated Git repository to verify that valid core
state and forecast move together despite secondary errors. They also cover replay failures before/after the first call,
restart and disabled-output cases, canonical recovery, same-height funding reorgs, failed migration, lagging providers,
a changed scan tip, deployment-anchor checks, core-before-repair scheduling, and block-pinned funding reads.

No production publisher or deployment was run. A manual public-RPC header probe returned HTTP 403, so it does not
establish live verification of the configured anchor; provenance is the app's existing two-provider deployment record,
and the implementation checks that hash against its configured RPC before a rebuild. A clean deployment image was
not built in this follow-up. The sealed auditor fixtures were not present locally; these are independent regressions.


## CPB-PR6-FIX-L01 follow-up at reviewed head 0b025fed2f

A second canonical hash check runs after optional funding valuation and before attaching its results.
A changed hash or failed post-check marks only that attachment unavailable; core history and the measured rate
still commit together. The positive control retains an available attachment for a stable block.

All **212 tests pass on Python 3.11.9**. The three new controls also run independently.
On reviewed head 0b025fed2f, the reorg and unreadable-hash controls fail while the stable-block control passes.
The controls assert the measured rate is unchanged and core publication remains atomic.
No live publisher, deployment, or clean deployment-image build was performed. The sealed auditor fixtures were
not present locally; these are independently written controls for the supplied finding.
