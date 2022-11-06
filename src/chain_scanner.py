import requests
import json
import time
from datetime import datetime
from web3 import Web3
import logging

logger = logging.getLogger(__name__)

class ChainScanner:
    def __init__(self, rpc_url, explorer_api_key, chain_id=8453):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.explorer_api_key = explorer_api_key
        self.chain_id = chain_id
        # Use Etherscan v2 unified endpoint
        self.explorer_base_url = "https://api.etherscan.io/v2/api"
    
    def get_recent_block_range(self):
        """Get current block and calculate range for last 30 days"""
        try:
            current_block = self.w3.eth.block_number
            blocks_per_day = 43200  # Base has ~2 second block time
            start_block = max(1, current_block - (blocks_per_day * 30))
            logger.info(f"Current block: {current_block}, Starting from block: {start_block}")
            return start_block, current_block
        except Exception as e:
            logger.error(f"Error getting block range: {e}")
            return 35000000, 99999999
    
    def get_token_transactions(self, contract_address, start_block=0):
        """Fetch ERC20 token transactions using Etherscan v2 API"""
        all_txs = []
        page = 1
        
        if start_block == 0:
            start_block, end_block = self.get_recent_block_range()
        else:
            end_block = 99999999
        
        while True:
            params = {
                'chainid': self.chain_id,
                'module': 'account',
                'action': 'tokentx',
                'address': contract_address,
                'startblock': start_block,
                'endblock': end_block,
                'page': page,
                'offset': 10000,
                'sort': 'asc',
                'apikey': self.explorer_api_key
            }
            
            try:
                response = requests.get(self.explorer_base_url, params=params, timeout=30)
                
                if response.status_code != 200:
                    logger.error(f"API returned status {response.status_code}: {response.text[:500]}")
                    break
                
                data = response.json()
                
                if data.get('status') != '1':
                    if data.get('message') == 'No transactions found':
                        logger.info(f"No transactions found for this range")
                        break
                    else:
                        logger.error(f"API Error: {data}")
                        break
                
                txs = data.get('result', [])
                if not txs:
                    break
                
                logger.info(f"Page {page}: Got {len(txs)} transactions")
                all_txs.extend(txs)
                
                if len(txs) < 10000:
                    break
                    
                page += 1
                time.sleep(0.1)  # v2 has better rate limits
                
            except Exception as e:
                logger.error(f"Error fetching token transactions: {e}")
                break
        
        logger.info(f"Total token transactions fetched: {len(all_txs)}")
        return all_txs
    
    def get_contract_transactions(self, contract_address, start_block=0):
        """Fetch all transactions to a contract address using Etherscan v2 API"""
        all_txs = []
        page = 1
        
        if start_block == 0:
            start_block, end_block = self.get_recent_block_range()
        else:
            end_block = 99999999
        
        while True:
            params = {
                'chainid': self.chain_id,
                'module': 'account',
                'action': 'txlist',
                'address': contract_address,
                'startblock': start_block,
                'endblock': end_block,
                'page': page,
                'offset': 10000,
                'sort': 'asc',
                'apikey': self.explorer_api_key
            }
            
            try:
                response = requests.get(self.explorer_base_url, params=params, timeout=30)
                
                if response.status_code != 200:
                    logger.error(f"API returned status {response.status_code}")
                    break
                    
                data = response.json()
                
                if data.get('status') != '1':
                    if data.get('message') == 'No transactions found':
                        logger.info(f"No transactions found for this range")
                    else:
                        logger.error(f"API Error: {data}")
                    break
                    
                txs = data.get('result', [])
                if not txs:
                    break
                    
                all_txs.extend(txs)
                
                if len(txs) < 10000:
                    break
                    
                page += 1
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error fetching transactions: {e}")
                break
                
        return all_txs
    
    # Rest of your extract_reward_funded_events method remains the same
    def extract_reward_funded_events(self, distributor_address, start_block=0):
        """Extract RewardFunded events from the distributor contract"""
        
        rewards_by_epoch = {}
        distributor_lower = distributor_address.lower()
        
        logger.info("Using transaction parsing method...")
        
        # Get token transfers
        token_txs = self.get_token_transactions(distributor_address, start_block)
        logger.info(f"Found {len(token_txs)} token transfers")
        
        # Process token transfers - look for INCOMING transfers only
        incoming_count = 0
        for tx in token_txs:
            # IMPORTANT: Check if this is TO the distributor (incoming rewards)
            if tx.get('to', '').lower() == distributor_lower:
                incoming_count += 1
                
                token = tx.get('contractAddress', '').lower()
                timestamp = int(tx.get('timeStamp', '0'))
                epoch_id = (timestamp // 604800) * 604800
                
                if epoch_id not in rewards_by_epoch:
                    rewards_by_epoch[epoch_id] = {
                        'tokens': set(),
                        'block_number': int(tx.get('blockNumber', '0')),
                        'timestamp': timestamp
                    }
                
                rewards_by_epoch[epoch_id]['tokens'].add(token)
                
                # Log for debugging
                logger.info(f"Found incoming token {tx.get('tokenSymbol', 'UNKNOWN')} ({token[:10]}...) for epoch {epoch_id}")
        
        logger.info(f"Found {incoming_count} incoming token transfers out of {len(token_txs)} total")
        
        # Add delay between API calls to avoid rate limit
        time.sleep(1)
        
        # Also check for ETH transfers
        txs = self.get_contract_transactions(distributor_address, start_block)
        logger.info(f"Found {len(txs)} total transactions")
        
        eth_incoming = 0
        for tx in txs:
            # Skip failed transactions
            if tx.get('isError', '0') == '1':
                continue
                
            # Check for incoming ETH with value
            value = int(tx.get('value', '0'))
            if value > 0 and tx.get('to', '').lower() == distributor_lower:
                eth_incoming += 1
                token = '0x0000000000000000000000000000000000000000'
                timestamp = int(tx.get('timeStamp', '0'))
                epoch_id = (timestamp // 604800) * 604800
                
                if epoch_id not in rewards_by_epoch:
                    rewards_by_epoch[epoch_id] = {
                        'tokens': set(),
                        'block_number': int(tx.get('blockNumber', '0')),
                        'timestamp': timestamp
                    }
                
                rewards_by_epoch[epoch_id]['tokens'].add(token)
                logger.info(f"Found ETH transfer for epoch {epoch_id}")
        
        logger.info(f"Found {eth_incoming} incoming ETH transfers")
        
        # Convert sets to lists for JSON serialization
        result = {}
        for epoch_id, data in rewards_by_epoch.items():
            result[str(epoch_id)] = {
                'tokens': list(data['tokens']),
                'block_number': data['block_number'],
                'timestamp': data['timestamp'],
                'date': datetime.fromtimestamp(data['timestamp']).isoformat()
            }
        
        logger.info(f"Total epochs with rewards: {len(result)}")
        
        return result
