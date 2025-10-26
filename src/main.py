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

    # >>> REPLACE your current “Decide whether to update” block with this one <<<
    # Decide whether to update
    new_epoch_tx = epoch_state.get("last_tx_hash")
    new_liq_tx   = liq_state.get("last_tx_hash")

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
        do_update = bool(epoch_has_new or liq_has_new or (age_days >= 1.0))
        if not do_update:
            logger.info(f"No update needed; age_days={age_days:.2f}.")
            return False
    else:
        logger.info("FORCE_UPDATE=true — running full update.")
        epoch_has_new = liq_has_new = True


    # 1) registry tokens
    reg_tokens = scanner.registry_all_tokens(registry_address)
    logger.info(f"Registry tokens: {len(reg_tokens)}")

    # 2) decimals (shared) & balances (per distributor)
    decimals = scanner.decimals_map(reg_tokens, chunk_size=int(os.environ.get("DEC_CHUNK_SIZE", "75")), default_decimals=18)
    balances_epoch = scanner.balances_map(epoch_distributor, reg_tokens, chunk_size=int(os.environ.get("BAL_CHUNK_SIZE", "50")))
    balances_liq   = scanner.balances_map(liq_distributor,   reg_tokens, chunk_size=int(os.environ.get("BAL_CHUNK_SIZE", "50")))

    # 3) prices (Llama -> CG -> DEX), *never null*
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

    # 4) compute USD + filter to >= min_usd, build snapshots (per distributor)
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

    # 5) publish (same file; keep original keys and add LIQ siblings)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    active_payload = {
        "chainId": 8453,

        # epoch distributor (original keys kept)
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

        # LIQ distributor (new keys)
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

    updater = GitHubUpdater(github_token, github_repo, github_branch)
    changed = _push_if_changed(repo, updater, "data/active_reward_tokens.json", active_payload)

    if changed:
        logger.info(
            f"Pushed data/active_reward_tokens.json "
            f"(epoch_active={len(active_epoch)}, liq_active={len(active_liq)}, "
            f"epoch_tx={new_epoch_tx}, liq_tx={new_liq_tx})"
        )
    else:
        logger.info("No content change detected after scan; nothing pushed.")

    return changed


def main():
    """
    Default behaviour: LISTEN & LOOP.
    Set LOOP=0 to run once and exit.
    """
    loop = os.environ.get("LOOP", "1") != "0"
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
