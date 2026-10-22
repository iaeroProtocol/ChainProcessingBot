import os, sys
import json
import logging
import base64
import hashlib
import time
import threading
from collections import deque
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

from dotenv import load_dotenv
from github import Github, Auth

from chain_scanner import ChainScanner
from github_updater import GitHubUpdater
from price_fetcher import PriceFetcher

from eth_utils import keccak
TRANSFER_TOPIC = keccak(text="Transfer(address,address,uint256)").hex()
SEL_BALANCE_OF = bytes.fromhex("70a08231")  # balanceOf(address)


logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# --------------- status log (in-memory ring buffer) ---------------
_status_log = deque(maxlen=200)
_status_lock = threading.Lock()

def _log_status(entry: dict):
    entry.setdefault("ts", datetime.now(timezone.utc).isoformat())
    with _status_lock:
        _status_log.append(entry)

class _StatusHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with _status_lock:
            entries = list(_status_log)
        body = json.dumps({"status": "ok", "log": entries}, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # suppress request logs

def _start_status_server():
    port = int(os.environ.get("PORT", "8080"))
    try:
        server = HTTPServer(("0.0.0.0", port), _StatusHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        logger.info(f"Status server listening on port {port}")
    except OSError as e:
        logger.warning(f"Could not start status server on port {port}: {e}")

def _default_state():
    return {"last_tx_hash": None, "last_update": 0}


def load_last_state_from_github(repo, branch="main"):
    """
    Backward compatible:
      - returns a tuple: (epoch_state, liq_state)
      - if liqState missing, returns default for it
    """
    try:
        f = repo.get_contents("data/active_reward_tokens.json", ref=branch)
        content = base64.b64decode(f.content).decode("utf-8")
        data = json.loads(content)
        epoch_state = data.get("state", _default_state())
        liq_state = data.get("liqState", _default_state())
        return epoch_state, liq_state
    except Exception as e:
        logger.info(f"No existing active file found in GitHub: {e}")
        return _default_state(), _default_state()

def _load_stakers_state(repo, branch: str, path: str) -> dict:
    try:
        f = repo.get_contents(path, ref=branch)
        import base64, json
        return json.loads(base64.b64decode(f.content).decode("utf-8"))
    except Exception:
        return {}

def _load_json(repo, branch: str, path: str) -> dict:
    try:
        f = repo.get_contents(path, ref=branch)
        import base64, json
        return json.loads(base64.b64decode(f.content).decode("utf-8"))
    except Exception:
        return {}

def _is_not_found(e: Exception) -> bool:
    # PyGithub raises UnknownObjectException (status 404, str "404 {...}") for a missing file
    return isinstance(e, FileNotFoundError) or getattr(e, "status", None) == 404 or str(e).startswith("404")

def _load_json_strict(repo, branch: str, path: str) -> dict:
    """Like _load_json, but only a missing (404) or unparseable file reads as {}; any other read error raises."""
    try:
        f = repo.get_contents(path, ref=branch)
    except Exception as e:
        if _is_not_found(e):
            return {}
        raise
    try:
        doc = json.loads(base64.b64decode(f.content).decode("utf-8"))
    except Exception as e:
        logger.warning(f"[GitHub] {path} is not valid JSON ({e}); treating it as empty")
        return {}
    return doc if isinstance(doc, dict) else {}

def _update_stakers(repo, updater: GitHubUpdater, scanner: ChainScanner) -> bool:
    """
    Incrementally track stiAERO holders via Transfer logs and publish balances.
    Returns True if GitHub file changed.
    """
    path = os.environ.get("STAKERS_JSON_PATH", "data/stakers.json")
    token = os.environ.get("STIAERO_ADDRESS", "0x72C135B8eEBC57A3823f0920233e1A90FF4D683D")
    token_lc = token.lower()
    min_units_env = os.environ.get("MIN_STAKER_UNITS")  # optional: filter dust (raw units)
    min_units = int(min_units_env) if (min_units_env and min_units_env.isdigit()) else 0
    bal_chunk = int(os.environ.get("STAKERS_BAL_CHUNK", "200"))

    state = _load_stakers_state(repo, updater.branch, path)
    holders = {h["address"].lower() for h in state.get("holders", [])}  # previous set
    checkpoint = state.get("checkpoint", {}) or {}
    last_block = int(checkpoint.get("last_block", 0))

    latest = scanner.latest_block()
    if last_block <= 0 or last_block > latest:
        # bootstrap: look back a safe window
        lookback = int(os.environ.get("STAKERS_BOOTSTRAP_BLOCKS", "100000"))
        last_block = max(0, latest - lookback)

    from_block = last_block + 1 if last_block > 0 else last_block
    if from_block > latest:
        logger.info("[stakers] up to date; no new blocks to scan.")
        from_block = latest

    # 1) Scan new Transfer logs to update holder set
    added = removed = 0
    zero = "0x" + "00" * 20
    for lg in scanner.erc20_transfer_logs(token, from_block, latest):
        topics = lg["topics"]
        if not topics:
            continue
        # from/to addresses are in topics[1] and [2] (indexed)
        frm = "0x" + topics[1].hex()[-40:]
        to  = "0x" + topics[2].hex()[-40:]
        if frm.lower() != zero:
            # leaving frm, might drop to zero later after balance fetch
            holders.add(frm.lower())
        if to.lower() != zero:
            holders.add(to.lower())
        last_block = int(lg["blockNumber"])

    logger.info(f"[stakers] holders tracked set size: {len(holders)} (scanned blocks {from_block}..{latest})")

    # 2) Fetch decimals once and balances for all holders; drop zero/dust
    decimals = scanner.decimals_map([token_lc], chunk_size=1).get(token_lc, 18)
    # We already have a balances_map(holder, token[]) but here it's token fixed, many holders.
    # Reuse existing helper by swapping semantics: call token.balanceOf(holder)
    # => We'll build calls manually using _call_chunk to avoid changing helper signatures.
    # Build calls in chunks
    calls = []
    hold_list = sorted(list(holders))
    for addr in hold_list:
        try:
            holder_cs = scanner.w3.to_checksum_address(addr)
            token_cs = scanner.w3.to_checksum_address(token)
        except Exception:
            continue
        # balanceOf(holder)
        addr32 = bytes(12) + bytes.fromhex(holder_cs[2:])
        calldata = SEL_BALANCE_OF + addr32.rjust(32, b"\x00")
        calls.append({"target": token_cs, "allowFailure": True, "callData": calldata})
        # batch-send later

    results = {}
    # chunked call via internal multicall
    for i in range(0, len(calls), bal_chunk):
        chunk_calls = calls[i:i+bal_chunk]
        ret = scanner._call_chunk(chunk_calls)
        for j, res in enumerate(ret):
            haddr = hold_list[i + j].lower()
            success, data = bool(res[0]), bytes(res[1])
            if not success or len(data) < 32:
                continue
            bal = int.from_bytes(data[-32:], "big")
            results[haddr] = bal

    # Filter zeros/dust and build holder list
    filtered = []
    for addr in hold_list:
        bal = int(results.get(addr, 0))
        if bal <= min_units:
            continue
        filtered.append({"address": addr, "balance": str(bal)})

    total_supply = scanner.total_supply(token)
    payload = {
        "token": token_lc,
        "decimals": int(decimals),
        "asOf": int(datetime.now(timezone.utc).timestamp()),
        "checkpoint": {"last_block": int(last_block)},
        "totalSupply": str(total_supply),
        "holderCount": len(filtered),
        "holders": filtered
    }

    # Use the same normalized, “only push if changed” helper you added earlier
    return _push_if_changed(repo, updater, path, payload)

def _update_epochs(repo, updater: GitHubUpdater, scanner: ChainScanner) -> bool:
    path = os.environ.get("EPOCHS_JSON_PATH", "data/epochs.json")
    distributor = os.environ.get("EPOCH_STAKING_DISTRIBUTOR")
    if not distributor:
        return False

    tip = scanner.latest_block()
    cur = _load_json(repo, updater.branch, path)

    # bootstrap or continue from last scanned block
    state = cur.get("state", {}) or {}
    last_scanned = int(state.get("last_block", 0))
    if last_scanned <= 0 or last_scanned > tip:
        lookback = int(os.environ.get("EPOCHS_BOOTSTRAP_BLOCKS", "200000"))
        last_scanned = max(0, tip - lookback)

    from_block = last_scanned + 1 if last_scanned > 0 else last_scanned
    if from_block > tip:
        return False

    epochs, epoch_tokens = scanner.funded_epochs_and_tokens(distributor, from_block, tip)
    if not epoch_tokens:
        # still advance last_block to avoid rescanning the same span
        cur.setdefault("state", {})["last_block"] = tip
        return _push_if_changed(repo, updater, path, cur)

    # merge into file (append-only per epoch)
    cur.setdefault("distributorAddress", distributor.lower())
    cur.setdefault("epochs", {})

    for eid, tokens in epoch_tokens.items():
        key = str(eid)
        # normalize to lowercase + dedupe + sort
        new_lc = sorted({ (t or "").lower() for t in tokens if t })
        cur.setdefault("epochs", {})
        if key not in cur["epochs"]:
            cur["epochs"][key] = {"tokens": new_lc}
        else:
            prev = { (t or "").lower() for t in cur["epochs"][key].get("tokens", []) }
            cur["epochs"][key]["tokens"] = sorted(prev.union(new_lc))


    # nice-to-have: current/previous epoch markers (based on wall-clock)
    WEEK = 7 * 24 * 60 * 60
    now_epoch = (int(time.time()) // WEEK) * WEEK
    cur["currentEpoch"] = now_epoch
    cur["previousEpoch"] = now_epoch - WEEK

    cur["state"] = {"last_block": tip, "last_update": int(time.time())}
    cur["summary"] = {
        "totalEpochs": len(cur["epochs"])
    }

    return _push_if_changed(repo, updater, path, cur)

def _sync_data_from_github(repo, branch: str, data_dir: str = "data"):
    """Download latest data files from GitHub so local reads stay current."""
    os.makedirs(data_dir, exist_ok=True)
    for fname in ("epochs.json", "stakers.json", "active_reward_tokens.json"):
        try:
            f = repo.get_contents(f"{data_dir}/{fname}", ref=branch)
            content = base64.b64decode(f.content).decode("utf-8")
            with open(os.path.join(data_dir, fname), "w") as fh:
                fh.write(content)
        except Exception as e:
            logger.warning(f"[sync] failed to download {fname}: {e}")

def _update_staker_rewards(repo, updater: GitHubUpdater) -> bool:
    DATA_DIR = "data"
    out_path = f"{DATA_DIR}/staker_rewards.json"

    # Sync latest data from GitHub before computing rewards
    _sync_data_from_github(repo, updater.branch, DATA_DIR)

    # envs (reuse the ones you already set)
    rpc_url = os.environ.get("BASE_RPC_URL") or os.environ.get("RPC_URL")
    chain_id = int(os.environ.get("CHAIN_ID", "8453"))
    use_prices = os.environ.get("USE_PRICES", "false").lower() == "true"
    aerodrome_factory = os.environ.get("AERODROME_FACTORY")
    usdc_addr = os.environ.get("USDC_ADDRESS") or "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    weth_addr = os.environ.get("WETH_ADDRESS") or "0x4200000000000000000000000000000000000006"
    max_price_usd = float(os.environ.get("MAX_PRICE_USD", "10000000"))

    from staker_rewards import build_staker_rewards
    payload = build_staker_rewards(
        rpc=rpc_url,
        chain_id=chain_id,
        epochs_path=f"{DATA_DIR}/epochs.json",
        stakers_path=f"{DATA_DIR}/stakers.json",
        active_path=f"{DATA_DIR}/active_reward_tokens.json",
        use_prices=use_prices,
        aerodrome_factory=aerodrome_factory,
        usdc_addr=usdc_addr,
        weth_addr=weth_addr,
        max_price_usd=max_price_usd,
    )
    # write locally
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)

    # push only if changed
    return _push_if_changed(repo, updater, out_path, payload)

def _stake_accrual_start():
    """When the protocol's Aero stake started earning: env PROTOCOL_AERO_STAKE_SINCE, else its first allocation
    (position_earnings.FIRST_ALLOCATION). None if unknown."""
    from position_earnings import DEFAULT_STAKE_ID, FIRST_ALLOCATION
    raw = (os.environ.get("PROTOCOL_AERO_STAKE_SINCE") or "").strip()
    if raw:
        try:
            return int(float(raw))
        except (ValueError, OverflowError):
            logger.error(f"[realized_yield] PROTOCOL_AERO_STAKE_SINCE={raw!r} is not unix seconds; ignored")
    try:
        return FIRST_ALLOCATION.get(int(os.environ.get("PROTOCOL_AERO_STAKE_ID") or DEFAULT_STAKE_ID))
    except ValueError:
        return None

LIVE_STATE_REWRITE_SEC = 3600   # the claims state is rewritten when its claims change, or when this much newer

def _claims_state_due(old: dict, new: dict) -> bool:
    """Write the claims state when anything but the scanned-to block changed, or a chain's block moved >= 1 h on."""
    if not isinstance(new, dict) or not new.get("chains"):
        return False
    if not isinstance(old, dict) or old.get("stakeId") != new.get("stakeId"):
        return True
    oc, nc = old.get("chains") or {}, new.get("chains") or {}
    if set(oc) != set(nc):
        return True
    for cid, n in nc.items():
        o = oc.get(cid) or {}
        if o.get("since") != n.get("since") or o.get("vrms") != n.get("vrms"):
            return True
        if int(n.get("blockTimestamp") or 0) - int(o.get("blockTimestamp") or 0) >= LIVE_STATE_REWRITE_SEC:
            return True
    return False

def _update_realized_yield(repo, updater: GitHubUpdater, scanner: ChainScanner, price_fetcher: PriceFetcher) -> bool:
    """
    Staking APY -> data/estimated_rewards_usd.json (replaces the legacy EnhancedOptimizedVotesKeeper; same schema plus
    new fields) and -> data/yield_history.json (replaces the rewards keeper's weekly snapshot).
    Headline: the measured earnings of the protocol's Aero stake (realized_yield.measured_headline: trailing 7 days
    if complete, else since its first allocation, else the previous headline kept with a staleReason). The
    distributor fundings of the last completed epoch go under fundedRealized only. data/live_state.json keeps the
    claims scan state per chain (incremental scans).
    """
    er_enabled = os.environ.get("ESTIMATED_REWARDS_ENABLED", "true").lower() == "true"
    yh_enabled = os.environ.get("YIELD_HISTORY_ENABLED", "true").lower() == "true"
    distributor = os.environ.get("EPOCH_STAKING_DISTRIBUTOR")
    if not (er_enabled or yh_enabled) or not distributor:
        return False

    from realized_yield import (build_estimated_rewards, stake_payload, apply_measured, measured_headline,
                                measured_unavailable_reason, kept_headline, funded_realized, sanity_problems,
                                epoch_start, last_completed_epoch, AERO_ADDRESS, WEEK)
    from position_earnings import epoch_rate
    dec_chunk = int(os.environ.get("DEC_CHUNK_SIZE", "75"))
    decimals_fn = lambda toks: scanner.decimals_map(toks, chunk_size=dec_chunk, default_decimals=18)
    aero = os.environ.get("AERO_ADDRESS") or AERO_ADDRESS
    iaero = os.environ.get("IAERO_ADDRESS")

    path = os.environ.get("ESTIMATED_REWARDS_JSON_PATH", "data/estimated_rewards_usd.json")
    try:
        prev_doc = _load_json_strict(repo, updater.branch, path)
    except Exception as e:
        # publishing now could drop the live block (and its history) and the headline to keep
        logger.error(f"[realized_yield] could not read {path} ({str(e)[:160]}); NOT publishing this run.")
        _log_status({"event": "realized_yield_blocked", "reasons": [f"{path} unreadable"]})
        return False
    for name in ("ROLLING_SINCE_TS", "ROLLING_CUTOFF_TS", "LIVE_YIELD_ENABLED"):
        if (os.environ.get(name) or "").strip():
            logger.info(f"[realized_yield] {name} is no longer used (the headline is the measured rate); ignored")

    now = int(time.time())
    hist_epoch = last_completed_epoch(now)

    # 1. stake and prices at the current epoch's start (the distributor's payout denominator)
    try:
        base = stake_payload(scanner.w3, distributor, epoch_start(now), price_fetcher, decimals_fn, aero, iaero, now)
    except Exception as e:
        base = None
        logger.exception(f"[realized_yield] stake / price read failed: {e}")

    # 2. the live measurement of the stake's earnings (claims scanned from data/live_state.json on)
    state_path = os.environ.get("LIVE_STATE_JSON_PATH", "data/live_state.json")
    claims_state = _load_json(repo, updater.branch, state_path)
    prev_live = prev_doc.get("live")
    live = live_prices = new_claims_state = None
    if base is not None:
        try:
            live = _build_live_block(scanner, price_fetcher, base, prev_live, claims_state)
            new_claims_state = live.pop("_claimsState", None)
            live_prices = live.pop("_prices", None)
        except Exception as e:
            logger.exception(f"[position] live block failed: {e}")
    if live is None and isinstance(prev_live, dict):
        live = dict(prev_live, stale=True)              # keep its history and gauge list
    if _claims_state_due(claims_state, new_claims_state):
        try:
            updater.update_file(state_path, json.dumps(new_claims_state, indent=2), commit_message="Live claims state")
        except Exception as e:
            logger.warning(f"[position] could not write {state_path}: {e}")

    # 3. the headline: measured, or the previous one kept
    payload, stale_reason = None, None
    m = measured_headline(live) if base is not None else None
    if m:
        payload = apply_measured(base, *m, now_ts=now)
        problems = sanity_problems(payload)
        if problems:
            stale_reason = f"the measured figure fails the sanity guard ({'; '.join(problems)}; apyPct={payload['apyPct']})"
            payload = None
    else:
        stale_reason = "stake / price read failed" if base is None else measured_unavailable_reason(live)
    if payload is None:
        payload = kept_headline(prev_doc, stale_reason)
        logger.error(f"[realized_yield] no measured headline this run ({stale_reason}); "
                     f"{'keeping the previous headline figures' if payload else 'no previous headline: NOT publishing'}")
        _log_status({"event": "realized_yield_kept", "reasons": [stale_reason]})
    else:
        logger.info(f"[realized_yield] headline {payload['apySource']}: ${payload['measuredUsdPerDay']:.2f}/day -> "
                    f"apy={payload['apyPct']:.2f}% stakersWeekly=${payload['stakersWeeklyUSD_human']} "
                    f"staked=${payload['stakedUSD_human']} window={payload['apyWindow']}")

    # 4. secondary: the distributor fundings booked to the last completed epoch
    if payload is not None and er_enabled:
        epochs_doc = _load_json(repo, updater.branch, os.environ.get("EPOCHS_JSON_PATH", "data/epochs.json"))
        if epochs_doc.get("epochs"):
            try:
                fr = build_estimated_rewards(w3=scanner.w3, distributor=distributor, epochs_doc=epochs_doc,
                                             price_fetcher=price_fetcher, decimals_fn=decimals_fn, aero=aero,
                                             iaero=iaero, epoch=hist_epoch, epoch_mode="last_completed", now_ts=now)
                payload["fundedRealized"] = funded_realized(fr)
            except Exception as e:
                logger.warning(f"[realized_yield] fundedRealized for epoch {hist_epoch} failed: {e}")

    changed = False
    # 5. yield_history: the completed epoch's measured earnings (complete points near both of its ends)
    if yh_enabled and isinstance(live, dict) and not live.get("stale") and live_prices is not None:
        price = lambda cid, t: float((live_prices.get(cid) or {}).get(t, 0.0) or 0.0)
        er = epoch_rate(live.get("history") or [], hist_epoch, hist_epoch + WEEK, price)
        if er is None:
            logger.info(f"[yield_history] epoch {hist_epoch}: no complete history points near both of its ends "
                        f"(or something left out between them); no entry")
        else:
            try:
                hb = stake_payload(scanner.w3, distributor, hist_epoch, price_fetcher, decimals_fn, aero, iaero, now)
                hp = apply_measured(hb, er["usdPerDay"], "measured-epoch",
                                    {"from": er["from"], "to": er["to"], "days": round(er["days"], 6)}, now_ts=now)
                hist_problems = sanity_problems(hp)
                if hist_problems:
                    logger.error(f"[yield_history] epoch {hist_epoch}: {'; '.join(hist_problems)}; not writing its entry.")
                else:
                    changed = _update_yield_history(repo, updater, hp) or changed
            except Exception as e:
                logger.exception(f"[yield_history] epoch {hist_epoch} read failed; no entry this run: {e}")

    # 6. publish
    if er_enabled and payload is not None:
        if live is not None:
            payload["live"] = live
        changed = _push_if_changed(repo, updater, path, payload) or changed
    return changed

def _build_live_block(scanner: ChainScanner, price_fetcher: PriceFetcher, payload: dict, prev_live,
                      claims_state=None) -> dict:
    """Real-time earnings of the protocol's Aero stake (Base, Ethereum, Robinhood) -> estimated_rewards_usd.json
    `live`, plus "_claimsState" and "_prices" for the caller. A chain whose RPC can't be reached is unmeasured."""
    from web3 import Web3
    from position_earnings import (ChainReader, build_live, staked_aero, DEFAULT_STAKE_ID, FACTORY_REGISTRY_BASE,
                                   VOTING_ESCROW, ROBINHOOD_CHAIN_ID, ROBINHOOD_RPC, ROBINHOOD_PRICE_MAP)
    from price_fetcher import MappedPriceFetcher
    token_id = int(os.environ.get("PROTOCOL_AERO_STAKE_ID") or DEFAULT_STAKE_ID)

    base = ChainReader(scanner.w3, 8453)
    readers = [(base, os.environ.get("AERO_FACTORY_REGISTRY") or FACTORY_REGISTRY_BASE)]
    price_fetchers = {8453: price_fetcher}
    unreachable = []
    for cid, url, lag, pf in (
        (1, os.environ.get("ETH_RPC_URL") or "https://ethereum-rpc.publicnode.com", 3,
         lambda: PriceFetcher(chain_slug="ethereum", cache_file="price_cache_ethereum.json", ttl_sec=300)),
        (ROBINHOOD_CHAIN_ID, os.environ.get("ROBINHOOD_RPC_URL") or ROBINHOOD_RPC, 20,
         lambda: MappedPriceFetcher(PriceFetcher(chain_slug="robinhood", cache_file="price_cache_robinhood.json",
                                                 ttl_sec=300), ROBINHOOD_PRICE_MAP)),
    ):
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 20}))
            readers.append((ChainReader(w3, cid, block=max(0, int(w3.eth.block_number) - lag)), None))
            price_fetchers[cid] = pf()
        except Exception as e:
            logger.warning(f"[position] chain {cid} RPC unavailable ({str(e)[:120]}); unmeasured this run")
            unreachable.append(cid)

    return build_live(
        readers, token_id, price_fetchers,
        staked_aero_raw=staked_aero(base, token_id, os.environ.get("AERO_VOTING_ESCROW") or VOTING_ESCROW),
        aero_price=int(payload["aeroPrice_1e18"]) / 1e18,
        staked_iaero_usd=int(payload["stakedUSD_1e18"]) / 1e18,      # same denominator as apyPct
        stakers_bps=int((payload.get("splitBps") or {}).get("stakers", 8000)),
        prev_live=prev_live,
        first_allocation=_stake_accrual_start(),
        claims_state=claims_state,
        unreachable=unreachable,
    )

def _update_yield_history(repo, updater: GitHubUpdater, payload: dict) -> bool:
    """Append/update only the realized entry for payload's epoch; keeper-published entries are never rewritten."""
    from realized_yield import merge_yield_history, dump_yield_history
    path = os.environ.get("YIELD_HISTORY_JSON_PATH", "data/yield_history.json")
    cur = _load_json(repo, updater.branch, path)
    doc, reason = merge_yield_history(cur, payload, int(time.time()))
    logger.info(f"[yield_history] {reason}")
    if doc is None:
        return False
    # keep the keeper's exact file format (JSON.stringify(..., null, 2)) so old entries stay byte-identical
    updater.update_file(path, dump_yield_history(doc), commit_message=f"Yield snapshot {payload['epoch']}")
    return True

def _stable_json_bytes(obj) -> bytes:
    # stable formatting ensures reproducible hashes
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _strip_volatile(d: dict) -> dict:
    """Remove fields that legitimately change every run, so we compare only the stable payload."""
    import copy
    x = copy.deepcopy(d) if isinstance(d, dict) else {}
    # top-level
    x.pop("lastUpdated", None)
    x.pop("updateTimestamp", None)
    x.pop("asOf", None)
    # nested states: keep last_tx_hash for checkpointing compare, but drop last_update (a timestamp)
    if isinstance(x.get("state"), dict):
        x["state"].pop("last_update", None)
    if isinstance(x.get("liqState"), dict):
        x["liqState"].pop("last_update", None)
    return x

def _push_if_changed(repo, updater: GitHubUpdater, path: str, payload: dict) -> bool:
    """
    Compare normalized (non-volatile) content; only push if meaningfully different.
    Returns True if a commit was made, False otherwise.
    """
    import json, base64, hashlib

    new_norm = _strip_volatile(payload)
    new_bytes = json.dumps(new_norm, sort_keys=True, separators=(",", ":")).encode("utf-8")

    try:
        cur = repo.get_contents(path, ref=updater.branch)
        cur_text = base64.b64decode(cur.content).decode("utf-8")
        try:
            cur_json = json.loads(cur_text)
        except Exception:
            cur_json = {}
        cur_norm = _strip_volatile(cur_json)
        cur_bytes = json.dumps(cur_norm, sort_keys=True, separators=(",", ":")).encode("utf-8")

        if hashlib.sha256(cur_bytes).digest() == hashlib.sha256(new_bytes).digest():
            logger.info(f"[GitHub] {path} unchanged (stable compare); skipping commit.")
            return False
    except Exception:
        # file may not exist yet -> proceed to create
        pass

    # Write: your updater will add lastUpdated/updateTimestamp; that's fine.
    updater.update_json(path, payload)
    return True



def _run_once() -> bool:
    """
    Runs a single scan/publish cycle.
    Returns True if a GitHub update happened (content changed), else False.
    """
    load_dotenv()

    # Core env
    rpc_url = os.environ.get("BASE_RPC_URL")
    explorer_api_key = os.environ.get("BASE_EXPLORER_API_KEY")
    github_token = os.environ.get("GITHUB_TOKEN")
    github_repo = os.environ.get("GITHUB_REPO")
    github_branch = os.environ.get("GITHUB_BRANCH", "main")

    # Distributors
    epoch_distributor = os.environ.get("EPOCH_STAKING_DISTRIBUTOR")
    liq_distributor = os.environ.get(
        "LIQ_STAKING_DISTRIBUTOR",
        "0xb81efc6be6622bf4086566210a6ad134cd0cdda4"
    )

    registry_address = os.environ.get("REWARD_TOKEN_REGISTRY")
    multicall3_addr = os.environ.get("MULTICALL3")

    # Pricing env (DEX)
    aerodrome_factory = os.environ.get("AERODROME_FACTORY")
    usdc_addr = os.environ.get("USDC_ADDRESS") or "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    weth_addr = os.environ.get("WETH_ADDRESS") or "0x4200000000000000000000000000000000000006"
    max_price_usd = float(os.environ.get("MAX_PRICE_USD", "10000000"))   # BTC wrappers trade above $50k

    # Behavior / filters
    force_update = os.environ.get("FORCE_UPDATE", "false").lower() == "true"
    dust_units_env = os.environ.get("MIN_TOKEN_UNITS")
    dust_units = int(dust_units_env) if (dust_units_env and dust_units_env.isdigit()) else None
    min_usd = float(os.environ.get("MIN_USD_IN_DISTRIBUTOR", "1"))

    logger.info(f"Config - GitHub repo: {github_repo}")
    logger.info(f"Distributor (epoch): {epoch_distributor}")
    logger.info(f"Distributor (LIQ):   {liq_distributor}")
    logger.info(f"Registry:            {registry_address}")
    logger.info(f"Min USD filter: ${min_usd:.2f}")

    if not all([rpc_url, explorer_api_key, github_token, github_repo, epoch_distributor, liq_distributor, registry_address]):
        logger.error("Missing required env (RPC, EXPLORER KEY, GITHUB, DISTRIBUTORS, REGISTRY).")
        return False

    gh = Github(auth=Auth.Token(github_token))
    repo = gh.get_repo(github_repo)
    epoch_state, liq_state = load_last_state_from_github(repo, github_branch)
    last_update = max(epoch_state.get("last_update", 0), liq_state.get("last_update", 0))

    scanner = ChainScanner(rpc_url, explorer_api_key, chain_id=8453, multicall3=multicall3_addr)

    updater = GitHubUpdater(github_token, github_repo, github_branch)

    _log_status({"event": "run_start"})

    epochs_changed = False
    try:
        epochs_changed = _update_epochs(repo, updater, scanner)
        if epochs_changed:
            logger.info("[epochs] Published/updated epochs.json")
        else:
            logger.info("[epochs] No new funded epochs; skipped commit.")
        _log_status({"event": "epochs", "changed": epochs_changed})
    except Exception as e:
        logger.exception(f"[epochs] failed: {e}")
        _log_status({"event": "epochs", "error": str(e)})


    # Decide whether to update rewards (but do not return early)
    new_epoch_tx = epoch_state.get("last_tx_hash")
    new_liq_tx   = liq_state.get("last_tx_hash")

    epoch_has_new = False
    liq_has_new   = False

    if not force_update:
        try:
            epoch_has_new, epoch_newest_hash = scanner.check_for_new_incoming_erc20(
                epoch_distributor, last_seen_tx=new_epoch_tx
            )
        except TypeError:
            epoch_has_new, epoch_newest_hash = scanner.check_for_new_incoming_erc20(epoch_distributor)

        try:
            liq_has_new, liq_newest_hash = scanner.check_for_new_incoming_erc20(
                liq_distributor, last_seen_tx=new_liq_tx
            )
        except TypeError:
            liq_has_new, liq_newest_hash = scanner.check_for_new_incoming_erc20(liq_distributor)

        logger.info(
            f"Probe: epoch_new={epoch_has_new} (last={new_epoch_tx}, head={epoch_newest_hash}), "
            f"liq_new={liq_has_new} (last={new_liq_tx}, head={liq_newest_hash})"
        )

        if epoch_newest_hash:
            new_epoch_tx = epoch_newest_hash
        if liq_newest_hash:
            new_liq_tx = liq_newest_hash

        age_days = (datetime.now(timezone.utc).timestamp() - last_update) / 86400 if last_update else 999
        rewards_needed = bool(epoch_has_new or liq_has_new or (age_days >= 1.0))
    else:
        logger.info("FORCE_UPDATE=true — running full rewards update.")
        rewards_needed = True

    # --- Check for claims (outgoing transfers from distributors) ---
    epoch_claim_tx = epoch_state.get("last_claim_tx")
    liq_claim_tx = liq_state.get("last_claim_tx")
    claims_detected = False

    try:
        epoch_claim_new, epoch_claim_hash = scanner.check_for_new_outgoing_erc20(
            epoch_distributor, last_seen_tx=epoch_claim_tx
        )
        if epoch_claim_hash:
            epoch_claim_tx = epoch_claim_hash
    except Exception:
        epoch_claim_new = False

    try:
        liq_claim_new, liq_claim_hash = scanner.check_for_new_outgoing_erc20(
            liq_distributor, last_seen_tx=liq_claim_tx
        )
        if liq_claim_hash:
            liq_claim_tx = liq_claim_hash
    except Exception:
        liq_claim_new = False

    claims_detected = bool(epoch_claim_new or liq_claim_new)
    if claims_detected:
        logger.info(f"Claims detected: epoch={epoch_claim_new}, liq={liq_claim_new}")
    else:
        logger.info(f"No new claims (epoch_last={epoch_claim_tx}, liq_last={liq_claim_tx})")

    _log_status({
        "event": "probes",
        "rewards_needed": rewards_needed,
        "epoch_has_new": epoch_has_new if not force_update else "forced",
        "liq_has_new": liq_has_new if not force_update else "forced",
        "claims_detected": claims_detected,
        "epoch_claim_new": epoch_claim_new,
        "liq_claim_new": liq_claim_new,
    })

    changed_rewards = False
    st_changed = False
    if rewards_needed:
        # 1) registry tokens
        reg_tokens = sorted({ (t or "").lower() for t in scanner.registry_all_tokens(registry_address) })
        logger.info(f"Registry tokens: {len(reg_tokens)}")

        # 2) decimals (shared) & balances (per distributor)
        decimals = scanner.decimals_map(reg_tokens, chunk_size=int(os.environ.get("DEC_CHUNK_SIZE", "75")), default_decimals=18)
        balances_epoch = scanner.balances_map(epoch_distributor, reg_tokens, chunk_size=int(os.environ.get("BAL_CHUNK_SIZE", "50")))
        balances_liq   = scanner.balances_map(liq_distributor,   reg_tokens, chunk_size=int(os.environ.get("BAL_CHUNK_SIZE", "50")))

        # 3) prices
        pf = PriceFetcher(
            chain_slug="base",
            cache_file="price_cache.json",
            ttl_sec=300,
            rpc_url=rpc_url,
            aerodrome_factory=aerodrome_factory,
            usdc=usdc_addr,
            weth=weth_addr,
            max_price_usd=max_price_usd,
        )
        price_map = pf.fetch_batch(reg_tokens)  # addr -> {priceUsd, ...}

        # 4) compute USD + filter to ≥ min_usd, build snapshots (per distributor)
        def build_active(balances_map: dict) -> tuple[list[str], list[dict]]:
            active = []
            snap = []
            for addr in reg_tokens:
                a = addr.lower()
                bal = int(balances_map.get(a, 0))
                if dust_units is not None and bal <= dust_units:
                    continue
                dec = int(decimals.get(a, 18))
                px = float(price_map.get(a, {}).get("priceUsd", 0.0))  # never null
                usd = (bal / (10 ** dec)) * px if px > 0 else 0.0
                if usd:
                    usd = float(f"{usd:.12f}")
                if usd >= min_usd:
                    active.append(a)
                snap.append({
                    "address": a,
                    "decimals": dec,
                    "balance": str(bal),
                    "priceUsd": px,
                    "balanceUsd": usd
                })
            return active, snap

        active_epoch, snapshot_epoch = build_active(balances_epoch)
        active_liq,   snapshot_liq   = build_active(balances_liq)

        logger.info(f"Active (≥ ${min_usd:.2f}) tokens on epoch distributor: {len(active_epoch)}")
        logger.info(f"Active (≥ ${min_usd:.2f}) tokens on LIQ   distributor: {len(active_liq)}")

        # 5) publish
        now_ts = int(datetime.now(timezone.utc).timestamp())
        active_payload = {
            "chainId": 8453,

            # epoch distributor
            "distributor": epoch_distributor.lower(),
            "asOf": now_ts,
            "tokens": [
                {
                    "address": a,
                    "decimals": int(decimals.get(a, 18)),
                    "priceUsd": float(price_map.get(a, {}).get("priceUsd", 0.0)),
                    "source":   price_map.get(a, {}).get("source", "none")
                } for a in active_epoch
            ],
            "snapshot": {
                "minUsd": min_usd,
                "balances": snapshot_epoch
            },
            "state": {"last_tx_hash": new_epoch_tx, "last_update": now_ts, "last_claim_tx": epoch_claim_tx},

            # LIQ distributor
            "liqDistributor": liq_distributor.lower(),
            "liqTokens": [
                {
                    "address": a,
                    "decimals": int(decimals.get(a, 18)),
                    "priceUsd": float(price_map.get(a, {}).get("priceUsd", 0.0)),
                    "source":   price_map.get(a, {}).get("source", "none")
                } for a in active_liq
            ],
            "liqSnapshot": {
                "minUsd": min_usd,
                "balances": snapshot_liq
            },
            "liqState": {"last_tx_hash": new_liq_tx, "last_update": now_ts, "last_claim_tx": liq_claim_tx},
        }

        changed_rewards = _push_if_changed(repo, updater, "data/active_reward_tokens.json", active_payload)

        if changed_rewards:
            rewards_needed = True
            logger.info(
                f"Pushed data/active_reward_tokens.json "
                f"(epoch_active={len(active_epoch)}, liq_active={len(active_liq)}, "
                f"epoch_tx={new_epoch_tx}, liq_tx={new_liq_tx})"
            )
        else:
            logger.info("Rewards: no content change; skipped commit.")
    else:
        logger.info("Rewards: no update needed; skipping balances/prices.")
        # Persist claim state even if full rewards pipeline didn't run
        if claims_detected:
            try:
                cur_active = _load_json(repo, updater.branch, "data/active_reward_tokens.json")
                # Only update if we got a real payload (has distributor key), not an empty dict from API failure
                if cur_active.get("distributor"):
                    cur_active.setdefault("state", {})["last_claim_tx"] = epoch_claim_tx
                    cur_active.setdefault("liqState", {})["last_claim_tx"] = liq_claim_tx
                    _push_if_changed(repo, updater, "data/active_reward_tokens.json", cur_active)
                else:
                    logger.warning("Skipping claim state persist: active_reward_tokens.json load returned empty/invalid data")
            except Exception as e:
                logger.warning(f"Failed to persist claim state: {e}")

    # === stiAERO stakers publish ALWAYS runs ===
    try:
        st_changed = _update_stakers(repo, updater, scanner)
        if st_changed:
            logger.info("[stakers] Published updated stakers.json")
        else:
            logger.info("[stakers] No meaningful change; skipped commit.")
    except Exception as e:
        logger.exception(f"[stakers] failed: {e}")

    sr_changed = False

    # Check if staker_rewards is stale (>4 hours old)
    sr_stale = False
    try:
        sr_data = _load_json(repo, updater.branch, "data/staker_rewards.json")
        sr_last = sr_data.get("updateTimestamp", 0)
        sr_age_hours = (datetime.now(timezone.utc).timestamp() - sr_last) / 3600 if sr_last else 999
        sr_stale = sr_age_hours >= 4.0
        if sr_stale:
            logger.info(f"[staker_rewards] Stale ({sr_age_hours:.1f}h old) — forcing recalc")
    except Exception:
        sr_stale = True

    sr_triggers = {
        "rewards_needed": rewards_needed, "changed_rewards": changed_rewards,
        "epochs_changed": epochs_changed, "st_changed": st_changed,
        "claims_detected": claims_detected, "force_update": force_update,
        "sr_stale": sr_stale,
    }
    sr_should_run = any(sr_triggers.values())
    try:
        if sr_should_run:
            sr_changed = _update_staker_rewards(repo, updater)
        if sr_changed:
            logger.info("[staker_rewards] Published/updated staker_rewards.json")
        else:
            logger.info("[staker_rewards] No change; skipped commit.")
        _log_status({"event": "staker_rewards", "ran": sr_should_run, "changed": sr_changed, "triggers": sr_triggers})
    except Exception as e:
        logger.exception(f"[staker_rewards] failed: {e}")
        _log_status({"event": "staker_rewards", "error": str(e), "triggers": sr_triggers})

    # === realized APY -> data/estimated_rewards_usd.json + data/yield_history.json (daily) ===
    er_changed = False
    try:
        er_pf = PriceFetcher(
            chain_slug="base",
            cache_file="price_cache.json",
            ttl_sec=300,
            rpc_url=rpc_url,
            aerodrome_factory=aerodrome_factory,
            usdc=usdc_addr,
            weth=weth_addr,
            max_price_usd=max_price_usd,
        )
        er_changed = _update_realized_yield(repo, updater, scanner, er_pf)
        if er_changed:
            logger.info("[realized_yield] Published realized APY (estimated_rewards_usd.json / yield_history.json)")
        else:
            logger.info("[realized_yield] No change; skipped commit.")
        _log_status({"event": "realized_yield", "changed": er_changed})
    except Exception as e:
        logger.exception(f"[realized_yield] failed: {e}")
        _log_status({"event": "realized_yield", "error": str(e)})

    _log_status({"event": "run_end", "any_changed": bool(changed_rewards or st_changed or epochs_changed or sr_changed or er_changed)})
    return changed_rewards or st_changed or epochs_changed or sr_changed or er_changed



def main():
    """
    Default behaviour: LISTEN & LOOP.
    Set LOOP=0 to run once and exit.
    """
    _start_status_server()

    loop = os.environ.get("LOOP", "0") == "1"
    delay = int(os.environ.get("POLL_INTERVAL", "60"))

    if not loop:
        _run_once()
        return

    logger.info(f"Starting in loop mode (POLL_INTERVAL={delay}s)")
    while True:
        try:
            _run_once()
        except Exception as e:
            logger.exception(f"run_once failed: {e}")
            _log_status({"event": "run_error", "error": str(e)})
        time.sleep(delay)


if __name__ == "__main__":
    main()
