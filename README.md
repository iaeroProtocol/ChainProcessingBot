# ChainProcessingBot

A one-shot, read-only chain collector and GitHub publisher for iAERO protocol earnings.
The normal Railway schedule is daily at 02:30 UTC. It does not execute claims, swaps or approvals.

## Normal pipeline

1. Continue the funded-epoch index from its saved complete block range.
2. Measure the protocol position on the required chains, with block-pinned reads and canonical claims checkpoints.
3. Persist raw-unit cumulative measurement history and claims state together in `data/live_state.json`.
4. Publish an eligible headline and measured weekly history, preserving unavailable/stale status when necessary.
5. Commit related measurement outputs as one GitHub generation. Reads during collection are pinned to the input commit;
   a concurrent writer to the same output causes an error instead of an overwrite.

Earnings processing precedes the optional global wallet export. The default job does not enumerate holders, preview every
wallet/epoch, run explorer probes or require an explorer credential. Existing compatibility files and spam-feed URLs remain.

## Reliability and migration

- **CPB-R01:** measurement history persists without a previous or new APY headline. A late cold start can build its
  seven-day window across restarts.
- **CPB-R02:** claim checkpoints contain a canonical block hash. A mismatch or legacy hashless checkpoint triggers a
  canonical replay from the configured first allocation. The current block is checked before and after measurement.
  A hash read failure does not authorise an incremental resume. Reorg-affected history is discarded.
- **CPB-R03:** unknown token decimals remain unknown. Material unknown units make a measurement incomplete.
  Version 2 history stores exact integer raw amounts; deltas are normalised using verified consistent units.
  Human amounts remain presentation fields.
- Legacy human-only history and public history without its coherent checkpoint are not eligible for new rates.
  On migration, the bot rebuilds verified points rather than manufacturing a forecast. When the initial allocation
  fallback period has expired, a fresh trailing headline requires a complete point six to eight days old.
- A previous public headline affected by canonical-state rebuilding has null income/rate fields and an explicit stale
  reason. The previous figure is retained only as diagnostic provenance; current app/Twitter readers reject the null
  forecast. Measurement persistence continues while the window rebuilds.
- Unreadable or malformed state is not treated as a blank bootstrap. Failed log ranges never advance the index past
  unread data. A lagging provider cannot reset a newer checkpoint.
- A failed required measurement makes the one-shot job fail. A complete measurement awaiting its initial history
  window is reported as `warming_up`, not as a fresh APY.

Do not delete `live_state.json` as a routine retry. It contains both the claim cursor and the independent measurement
history. A missing state file requires canonical replay and rebuilding a verified window.

## Configuration

Required for the core job:

| Variable | Purpose |
| --- | --- |
| `BASE_RPC_URL` | Base RPC endpoint. |
| `GITHUB_TOKEN` | Repository read/write contents permission; never printed. |
| `GITHUB_REPO` | Repository containing the published JSON, normally `iaeroProtocol/ChainProcessingBot`. |
| `EPOCH_STAKING_DISTRIBUTOR` | Distributor used for the stake denominator and funding reconciliation. |

Relevant settings:

| Variable | Default / behaviour |
| --- | --- |
| `GITHUB_BRANCH` | `main`. Read snapshots are pinned within publication transactions. |
| `ETH_RPC_URL`, `ROBINHOOD_RPC_URL` | Configured RPCs preferred; existing public fallbacks retained. |
| `PROTOCOL_AERO_STAKE_ID` | `1584`. An explicit inventory/configuration review is needed when protocol backing changes. |
| `PROTOCOL_AERO_STAKE_SINCE` | Existing first-allocation configuration. |
| `REQUIRED_EARNINGS_CHAIN_IDS` | `8453,1,4663`. Missing required chains make coverage incomplete; do not shrink this list to hide an outage. |
| `EPOCHS_START_BLOCK` | Required only for a genuinely empty funding index; use its verified deployment anchor. |
| `GLOBAL_WALLET_EXPORT_ENABLED` | `false`. Explicitly opt into the expensive legacy export. |
| `BASE_EXPLORER_API_KEY`, `REWARD_TOKEN_REGISTRY` | Needed only for the optional global export. |
| `STAKERS_START_BLOCK` | Required to bootstrap a genuinely empty optional holder index. |
| `USE_PRICES` | Legacy export's valuation switch, independent of required earnings pricing. |
| `MAX_JOB_SECONDS` | `1200`. A whole-cycle deadline escapes per-phase error handlers and exits nonzero. |
| `LOOP` | `0`. `1` is an explicit operator compatibility mode; every iteration has its own deadline. |
| `STATUS_HTTP_ENABLED` | `false`. Cron has no listening status server by default. |
| `STATUS_TOKEN` | Required bearer token for detailed `/status` when HTTP is enabled. `/health` reveals only process/phase. |
| `LLAMA_MAX_URL_CHARS` | Existing 8,000-character batching budget. |

The optional distributor refresh prices only nonzero exposures. Non-core unsuccessful lookups are memoised for 30 seconds
inside a fetcher; zero prices are not persisted as valid financial prices. Core prices keep their freshness, liquidity and
fallback protections. Zero-decimal tokens are valid; DEX pricing cannot assume 18 after a failed metadata read.

Keep generated `data/**` outside Railway watch paths. The watch list includes source, requirements/constraints, runtime
and Railway configuration. Preserve the existing installer attestation workaround until a separately validated builder
change replaces it.

## Development and validation

Use Python 3.11 and an isolated virtual environment:

```sh
python3.11 -m venv /tmp/cpb-venv
/tmp/cpb-venv/bin/python -m pip install -r requirements.txt
LOG_LEVEL=CRITICAL /tmp/cpb-venv/bin/python -m unittest discover -s tests -q
```

`requirements.lock` constrains the tested dependency set. Pandas was unused and has been removed.
The GitHub workflow runs offline tests on the production Python version and uses pinned action commits.
Tests do not need RPC, GitHub or wallet credentials. Do not run `src/main.py` as a test: it is the real publisher.

Regression controls cover cold starts/restarts, reorg replay, failed hashes, metadata recovery and changed units,
precision in large balances, canonical-state migration, cursor failures, default compute behaviour, atomic publication,
concurrent writers, large-file reads, deadlines, redaction and status authentication.

This change does not alter public spam feeds, completed wallet transactions, swap routing or execution permissions.
