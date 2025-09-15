import os
import json
import logging
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
import base64

from chain_scanner import ChainScanner
from github_updater import GitHubUpdater

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_last_state(file_path='last_state.json'):
    """Load the last processed state"""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except:
            pass
    return {'last_block': 0, 'last_tx_hash': None, 'last_update': 0}

def save_last_state(state, file_path='last_state.json'):
    """Save the current state"""
    with open(file_path, 'w') as f:
        json.dump(state, f)
        
def load_last_state_from_github(repo, branch='main'):
    """Load state from the main reward tokens file"""
    try:
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
