import os
import json
import logging
import base64
import hashlib
import time
from datetime import datetime, timezone

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
    max_price_usd = float(os.environ.get("MAX_PRICE_USD", "50000"))

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

    # >>> REPLACE your current “Decide whether to update” block with this one <<<
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

    changed_rewards = False
    st_changed = False
    if rewards_needed:
        # 1) registry tokens
        reg_tokens = scanner.registry_all_tokens(registry_address)
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
            "state": {"last_tx_hash": new_epoch_tx, "last_update": now_ts},

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
            "liqState": {"last_tx_hash": new_liq_tx, "last_update": now_ts},
        }

        changed_rewards = _push_if_changed(repo, updater, "data/active_reward_tokens.json", active_payload)

        if changed_rewards:
            logger.info(
                f"Pushed data/active_reward_tokens.json "
                f"(epoch_active={len(active_epoch)}, liq_active={len(active_liq)}, "
                f"epoch_tx={new_epoch_tx}, liq_tx={new_liq_tx})"
            )
        else:
            logger.info("Rewards: no content change; skipped commit.")
    else:
        logger.info("Rewards: no update needed; skipping balances/prices.")

    # === stiAERO stakers publish ALWAYS runs ===
    try:
        st_changed = _update_stakers(repo, updater, scanner)
        if st_changed:
            logger.info("[stakers] Published updated stakers.json")
        else:
            logger.info("[stakers] No meaningful change; skipped commit.")
    except Exception as e:
        logger.exception(f"[stakers] failed: {e}")

    return changed_rewards or st_changed



def main():
    """
    Default behaviour: LISTEN & LOOP.
    Set LOOP=0 to run once and exit.
    """
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
        time.sleep(delay)


if __name__ == "__main__":
    main()
