import os
import json
import logging
from datetime import datetime, timezone

from chain_scanner import ChainScanner
from github_updater import GitHubUpdater

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("rewards_runner")


def load_last_state(file_path='last_state.json'):
    """Load the last processed state (local fallback)"""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {'last_block': 0, 'last_tx_hash': None, 'last_update': 0}


def save_last_state(state, file_path='last_state.json'):
    """Save the current state (local fallback)"""
    with open(file_path, 'w') as f:
        json.dump(state, f)


def load_last_state_from_github(repo, branch='main'):
    """
    Load state embedded inside data/reward_tokens.json in GitHub.
    Returns { last_block, last_tx_hash, last_update }.
    """
    try:
        file = repo.get_contents('data/reward_tokens.json', ref=branch)
        import base64
        content = base64.b64decode(file.content).decode('utf-8')
        data = json.loads(content)
        return data.get('state', {'last_block': 0, 'last_tx_hash': None, 'last_update': 0})
    except Exception as e:
        logger.info(f"No existing state found in GitHub: {e}")
        return {'last_block': 0, 'last_tx_hash': None, 'last_update': 0}


def has_new_reward_events(scanner: ChainScanner, distributor_address: str, last_block: int) -> tuple[bool, int]:
    """
    Quick log-based check over a small recent window.
    Returns (has_new, highest_block_seen).
    """
    end_block = scanner.w3.eth.block_number
    window_from = max(last_block + 1, end_block - 12_000)  # ~6-7h on Base
    if window_from > end_block:
        return False, last_block

    logger.info(f"[quick-check] scanning logs window [{window_from}, {end_block}] for new RewardFunded")
    try:
        data, highest = scanner.extract_reward_funded_events_via_logs(
            distributor_address,
            start_block=window_from,
            end_block=end_block,
            chunk=2_000
        )
    except Exception:
        logger.exception("[quick-check] logs failed; treating as no new")
        return False, last_block

    if not data:
        logger.info("[quick-check] no RewardFunded logs in the recent window")
        return False, last_block

    highest_seen = max(
        [int(v.get("block_number", 0)) for v in data.values()],
        default=last_block
    )
    logger.info(f"[quick-check] found RewardFunded logs; highest block seen: {highest_seen}")
    return (highest_seen > last_block), highest_seen


def main():
    # Config
    rpc_url             = os.environ.get('BASE_RPC_URL')
    explorer_api_key    = os.environ.get('BASE_EXPLORER_API_KEY')
    github_token        = os.environ.get('GITHUB_TOKEN')
    github_repo         = os.environ.get('GITHUB_REPO')
    github_branch       = os.environ.get('GITHUB_BRANCH', 'main')
    distributor_address = os.environ.get('EPOCH_STAKING_DISTRIBUTOR')

    # Force knobs
    force_update        = os.environ.get('FORCE_UPDATE', 'false').lower() == 'true'
    force_from_block    = os.environ.get('FORCE_FROM_BLOCK')

    logger.info(f"Config check - RPC URL present: {bool(rpc_url)}")
    logger.info(f"Config check - GitHub repo: {github_repo}")
    logger.info(f"Config check - Distributor: {distributor_address}")

    if not all([rpc_url, explorer_api_key, github_token, github_repo, distributor_address]):
        logger.error("Missing required environment variables")
        return

    logger.info(f"Processing rewards for distributor: {distributor_address}")

    try:
        # GitHub/state
        from github import Github
        g = Github(github_token)  # deprecation warning is harmless; can be migrated later
        repo = g.get_repo(github_repo)
        state = load_last_state_from_github(repo, github_branch)

        last_block_saved   = int(state.get('last_block', 0) or 0)
        last_tx_saved      = state.get('last_tx_hash')
        last_update_saved  = int(state.get('last_update', 0) or 0)

        logger.info(f"Loaded last state: last_block={last_block_saved}, last_update={last_update_saved}")

        # Scanner
        scanner = ChainScanner(rpc_url, explorer_api_key)

        # Decide start block
        if force_update:
            start_block = int(force_from_block) if (force_from_block and force_from_block.isdigit()) else 35164965
            logger.info(f"[force] Ignoring saved state; scanning from block {start_block} (inclusive)")
        else:
            has_new, _ = has_new_reward_events(scanner, distributor_address, last_block_saved)
            if not has_new:
                days_since = (
                    (datetime.now(timezone.utc).timestamp() - last_update_saved) / 86400
                    if last_update_saved else 999
                )
                if days_since < 7:
                    logger.info("No new RewardFunded events and < 7 days since last update; skipping.")
                    return
                logger.info(f"Force update due to age: {days_since:.1f} days since last update")
            start_block = last_block_saved

        logger.info(f"Scanning from block {start_block} (inclusive)")

        # Primary: logs
        try:
            rewards_data, max_block_seen = scanner.extract_reward_funded_events_via_logs(
                distributor_address, start_block=start_block
            )
        except Exception:
            logger.exception("[logs] fatal error, using transfer-heuristic")
            rewards_data, max_block_seen = {}, start_block

        # Fallback: transfers
        if not rewards_data:
            logger.info("No RewardFunded logs found; using transfer-heuristic scan")
            rewards_data = scanner.extract_reward_funded_events(distributor_address, start_block)
            # If transfer path can't compute max, keep start_block
            if not max_block_seen:
                max_block_seen = start_block

        # Epochs
        current_ts     = int(datetime.now(timezone.utc).timestamp())
        current_epoch  = (current_ts // 604800) * 604800
        previous_epoch = current_epoch - 604800

        # State
        if rewards_data:
            max_block = max_block_seen or max(
                (v.get('block_number', 0) for v in rewards_data.values()),
                default=last_block_saved
            )
        else:
            max_block = max_block_seen or last_block_saved

        # Output
        output = {
            'distributorAddress': distributor_address.lower(),
            'currentEpoch': current_epoch,
            'previousEpoch': previous_epoch,
            'epochs': rewards_data or {},
            'summary': {
                'totalEpochs': len(rewards_data or {}),
                'currentEpochTokens': (rewards_data or {}).get(str(current_epoch), {}).get('tokens', []),
                'previousEpochTokens': (rewards_data or {}).get(str(previous_epoch), {}).get('tokens', [])
            },
            'state': {
                'last_block': max_block,
                'last_tx_hash': last_tx_saved,
                'last_update': int(datetime.now(timezone.utc).timestamp())
            }
        }

        # Push
        logger.info("Updating GitHub repository…")
        updater = GitHubUpdater(github_token, github_repo, github_branch)
        updater.update_json('data/reward_tokens.json', output)
        logger.info(f"✅ Completed update | state: last_block={max_block}, last_tx={last_tx_saved}")

    except Exception as e:
        logger.error(f"Error in main process: {e}")
        raise


if __name__ == "__main__":
    main()
        from github import Github
        file = repo.get_contents('data/reward_tokens.json', ref=branch)
        content = base64.b64decode(file.content).decode('utf-8')
        data = json.loads(content)
        return data.get('state', {'last_block': 0, 'last_tx_hash': None, 'last_update': 0})
    except Exception as e:
        logger.info(f"No existing state found in GitHub: {e}")
        return {'last_block': 0, 'last_tx_hash': None, 'last_update': 0}

def check_for_new_transactions(scanner, distributor_address, last_tx_hash):
    """Quick check for new incoming ERC20 transactions"""
    try:
        # Get just the most recent page of token transactions
        params = {
            'module': 'account',
            'action': 'tokentx',
            'address': distributor_address,
            'page': 1,
            'offset': 100,
            'sort': 'desc',  # Most recent first
            'apikey': scanner.explorer_api_key
        }
        
        response = requests.get(scanner.explorer_base_url, params=params, timeout=30)
        data = response.json()
        
        if data.get('status') != '1':
            return False, None
            
        txs = data.get('result', [])
        if not txs:
            return False, None
            
        # Find the most recent incoming transaction
        for tx in txs:
            if tx.get('to', '').lower() == distributor_address.lower():
                current_hash = tx.get('hash')
                if current_hash != last_tx_hash:
                    logger.info(f"New transaction detected: {current_hash}")
                    return True, current_hash
                else:
                    logger.info("No new transactions since last check")
                    return False, last_tx_hash
                    
        return False, last_tx_hash
        
    except Exception as e:
        logger.error(f"Error checking for new transactions: {e}")
        # On error, proceed with full scan to be safe
        return True, None

def main():
    # Configuration
    rpc_url = os.environ.get('BASE_RPC_URL')
    explorer_api_key = os.environ.get('BASE_EXPLORER_API_KEY')
    github_token = os.environ.get('GITHUB_TOKEN')
    github_repo = os.environ.get('GITHUB_REPO')
    github_branch = os.environ.get('GITHUB_BRANCH', 'main')
    distributor_address = os.environ.get('EPOCH_STAKING_DISTRIBUTOR')
    force_update = os.environ.get('FORCE_UPDATE', 'false').lower() == 'true'
    
    # Debug logging
    logger.info(f"Config check - RPC URL present: {bool(rpc_url)}")
    logger.info(f"Config check - GitHub repo: {github_repo}")
    
    if not all([rpc_url, explorer_api_key, github_token, github_repo, distributor_address]):
        logger.error("Missing required environment variables")
        return
    
    logger.info(f"Processing rewards for distributor: {distributor_address}")
    
    try:
        # Initialize GitHub connection first to load state
        from github import Github
        g = Github(github_token)
        repo = g.get_repo(github_repo)
        
        # Load state from GitHub
        state = load_last_state_from_github(repo, github_branch)
        logger.info(f"Loaded state: last_block={state.get('last_block')}, last_update={state.get('last_update')}")
        
        # Initialize scanner
        scanner = ChainScanner(rpc_url, explorer_api_key)
        
        # Initialize new_tx_hash with the last known value
        new_tx_hash = state.get('last_tx_hash')
        
        # Check for new transactions first (unless forcing update)
        if not force_update:
            has_new_tx, detected_tx_hash = check_for_new_transactions(
                scanner,
                distributor_address,
                state.get('last_tx_hash')
            )
            
            # Update new_tx_hash if we found a new one
            if has_new_tx and detected_tx_hash:
                new_tx_hash = detected_tx_hash
            
            # Fixed time check logic
            last_update = state.get('last_update', 0)
            if last_update == 0:
                logger.info("First run detected, proceeding with update")
            else:
                days_since_update = (datetime.now(timezone.utc).timestamp() - last_update) / 86400
                
                if not has_new_tx and days_since_update < 7:
                    logger.info(f"No new transactions and {days_since_update:.1f} days since last update. Skipping.")
                    return
                
                if days_since_update >= 7:
                    logger.info(f"Force update: {days_since_update:.1f} days since last update")
        
        # Extract reward funded events
        start_block = state.get('last_block', 0)
        logger.info(f"Scanning from block {start_block}")
        rewards_data = scanner.extract_reward_funded_events(
            distributor_address,
            start_block
        )
        
        # Get current and previous epoch for easy filtering
        current_timestamp = int(datetime.now(timezone.utc).timestamp())
        current_epoch = (current_timestamp // 604800) * 604800
        previous_epoch = current_epoch - 604800
        
        # Calculate new state values
        if rewards_data:
            max_block = max(
                data.get('block_number', 0)
                for data in rewards_data.values()
            )
        else:
            max_block = state.get('last_block', 0)
        
        # Prepare output data WITH STATE INCLUDED
        output = {
            'distributorAddress': distributor_address.lower(),
            'currentEpoch': current_epoch,
            'previousEpoch': previous_epoch,
            'epochs': rewards_data,
            'summary': {
                'totalEpochs': len(rewards_data),
                'currentEpochTokens': rewards_data.get(str(current_epoch), {}).get('tokens', []),
                'previousEpochTokens': rewards_data.get(str(previous_epoch), {}).get('tokens', [])
            },
            'state': {  # Include state in the output
                'last_block': max_block,
                'last_tx_hash': new_tx_hash,
                'last_update': int(datetime.now(timezone.utc).timestamp())
            }
        }
        
        # Update GitHub - NOW create the updater
        logger.info("Updating GitHub repository")
        updater = GitHubUpdater(github_token, github_repo, github_branch)
        updater.update_json('data/reward_tokens.json', output)
        
        logger.info(f"Successfully completed update with state: block={max_block}, tx={new_tx_hash}")
        
    except Exception as e:
        logger.error(f"Error in main process: {e}")
        raise


if __name__ == "__main__":
    main()
