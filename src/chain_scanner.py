import time
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from web3 import Web3
from web3.types import FilterParams, LogReceipt
import requests

logger = logging.getLogger(__name__)

REWARD_FUNDED_SIG = "RewardFunded(address,uint256,uint256)"  # token (indexed), epochId (indexed), amount (unindexed)

def keccak_topic(sig: str) -> str:
    from eth_utils import keccak, to_hex
    return to_hex(keccak(text=sig))

TOPIC0_REWARD_FUNDED = keccak_topic(REWARD_FUNDED_SIG)


class ChainScanner:
    """
    Robust scanner:
      - tries eth_getLogs in shrinking chunks
      - etherscan logs fallback
      - transfers heuristic fallback
    """
    def __init__(self, rpc_url: str, explorer_api_key: str, chain_id: int = 8453):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.explorer_api_key = explorer_api_key
        self.chain_id = chain_id
        self.explorer_base_url = "https://api.etherscan.io/v2/api"

        ok = self.w3.is_connected()
        try:
            cid = self.w3.eth.chain_id
        except Exception:
            cid = None
        logger.info(f"Web3 connected={ok} chain_id={cid}")

    # ---------------- block helpers ----------------

    def get_recent_block_range(self) -> Tuple[int, int]:
        try:
            current_block = self.w3.eth.block_number
            blocks_per_day = 43200  # ~2s
            start_block = max(1, current_block - (blocks_per_day * 30))
            logger.info(f"Current block: {current_block}, scanning from: {start_block}")
            return start_block, current_block
        except Exception as e:
            logger.error(f"Error getting block range: {e}")
            return 35_000_000, 99_999_999

    # --------------- low-level getLogs ---------------

    def _eth_get_logs(
        self,
        address: str,
        from_block: int,
        to_block: int,
        topics: List[Optional[str]],
    ) -> List[LogReceipt]:
        params: FilterParams = {
            "address": Web3.to_checksum_address(address),
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
            "topics": topics,
        }
        return self.w3.eth.get_logs(params)

    def _fetch_logs_chunked(
        self,
        address: str,
        start_block: int,
        end_block: int,
        base_chunk: int = 2_000,
        sleep_between_chunks: float = 0.03,
    ) -> List[LogReceipt]:
        all_logs: List[LogReceipt] = []
        ladder = [base_chunk, 500, 100, 25, 5]
        cur = start_block

        while cur <= end_block:
            success = False
            for size in ladder:
                from_b = cur
                to_b = min(end_block, cur + size - 1)
                try:
                    logs = self._eth_get_logs(
                        address=address,
                        from_block=from_b,
                        to_block=to_b,
                        topics=[TOPIC0_REWARD_FUNDED, None, None],
                    )
                    all_logs.extend(logs)
                    success = True
                    break
                except Exception as e:
                    logger.warning(
                        f"get_logs failed for [{from_b},{to_b}] (size={size}) -> {e}"
                    )
                    time.sleep(0.2)

            if not success:
                cur += ladder[-1]  # avoid infinite loop
            else:
                cur = to_b + 1

            time.sleep(sleep_between_chunks)

        return all_logs

    # --------------- etherscan fallback ---------------

    def _etherscan_get_logs(self, address: str, start_block: int, end_block: int) -> List[Dict]:
        out: List[Dict] = []
        page = 1
        while True:
            params = {
                "chainid": self.chain_id,
                "module": "logs",
                "action": "getLogs",
                "address": address,
                "fromBlock": start_block,
                "toBlock": end_block,
                "topic0": TOPIC0_REWARD_FUNDED,
                "page": page,
                "offset": 1000,
                "apikey": self.explorer_api_key,
            }
            try:
                r = requests.get(self.explorer_base_url, params=params, timeout=30)
                if r.status_code != 200:
                    logger.error(f"Etherscan logs status {r.status_code}: {r.text[:300]}")
                    break
                j = r.json()
                if j.get("status") != "1":
                    if j.get("message") == "No records found":
                        break
                    logger.error(f"Etherscan logs API error: {j}")
                    break
                logs = j.get("result", [])
                out.extend(logs)
                if len(logs) < 1000:
                    break
                page += 1
                time.sleep(0.15)
            except Exception as e:
                logger.error(f"Etherscan logs error: {e}")
                break
        return out

    def _parse_etherscan_logs(self, es_logs: List[Dict]) -> List[LogReceipt]:
        out: List[LogReceipt] = []
        for l in es_logs:
            try:
                out.append({
                    "address": l.get("address"),
                    "blockNumber": int(l.get("blockNumber", "0"), 16) if isinstance(l.get("blockNumber"), str) and l.get("blockNumber", "").startswith("0x") else int(l.get("blockNumber", "0")),
                    "transactionHash": l.get("transactionHash"),
                    "data": l.get("data"),
                    "topics": l.get("topics", []),
                    "timeStamp": int(l.get("timeStamp", "0"), 16) if isinstance(l.get("timeStamp"), str) and l.get("timeStamp", "").startswith("0x") else int(l.get("timeStamp", "0")),
                })  # type: ignore
            except Exception:
                pass
        return out

    # --------------- legacy transfer paths ---------------

    def get_token_transactions(self, contract_address: str, start_block: int = 0) -> List[Dict]:
        all_txs: List[Dict] = []
        page = 1
        if start_block == 0:
            start_block, end_block = self.get_recent_block_range()
        else:
            end_block = 99_999_999

        while True:
            params = {
                "chainid": self.chain_id,
                "module": "account",
                "action": "tokentx",
                "address": contract_address,
                "startblock": start_block,
                "endblock": end_block,
                "page": page,
                "offset": 10000,
                "sort": "asc",
                "apikey": self.explorer_api_key,
            }
            try:
                response = requests.get(self.explorer_base_url, params=params, timeout=30)
                if response.status_code != 200:
                    logger.error(f"tokentx status {response.status_code}: {response.text[:300]}")
                    break
                data = response.json()
                if data.get("status") != "1":
                    if data.get("message") == "No transactions found":
                        break
                    logger.error(f"tokentx API error: {data}")
                    break
                txs = data.get("result", [])
                if not txs:
                    break
                all_txs.extend(txs)
                if len(txs) < 10000:
                    break
                page += 1
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"tokentx fetch error: {e}")
                break
        return all_txs

    def get_contract_transactions(self, contract_address: str, start_block: int = 0) -> List[Dict]:
        all_txs: List[Dict] = []
        page = 1
        if start_block == 0:
            start_block, end_block = self.get_recent_block_range()
        else:
            end_block = 99_999_999

        while True:
            params = {
                "chainid": self.chain_id,
                "module": "account",
                "action": "txlist",
                "address": contract_address,
                "startblock": start_block,
                "endblock": end_block,
                "page": page,
                "offset": 10000,
                "sort": "asc",
                "apikey": self.explorer_api_key,
            }
            try:
                response = requests.get(self.explorer_base_url, params=params, timeout=30)
                if response.status_code != 200:
                    logger.error(f"txlist status {response.status_code}: {response.text[:300]}")
                    break
                data = response.json()
                if data.get("status") != "1":
                    if data.get("message") == "No transactions found":
                        break
                    logger.error(f"txlist API error: {data}")
                    break
                txs = data.get("result", [])
                if not txs:
                    break
                all_txs.extend(txs)
                if len(txs) < 10000:
                    break
                page += 1
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"txlist fetch error: {e}")
                break
        return all_txs

    # ---------------- main extractors ----------------

    def extract_reward_funded_events(
        self,
        distributor_address: str,
        start_block: int = 0,
        end_block: Optional[int] = None,
        chunk_size: int = 2_000,
        sleep_between_chunks: float = 0.03,
        token_filter: Optional[str] = None,
        epoch_filter: Optional[int] = None,
    ) -> Dict[str, Dict]:
        """
        Returns dict keyed by epochId (string) => { tokens: [...], block_number, timestamp, date }.
        Tries node logs, then etherscan logs, then transfers heuristic.
        """
        dist = Web3.to_checksum_address(distributor_address)
        if end_block is None:
            try:
                end_block = self.w3.eth.block_number
            except Exception:
                end_block = start_block + 10_000

        logger.info(
            f"Scanning RewardFunded logs: addr={dist} range=[{start_block},{end_block}] chunk={chunk_size} topics={[TOPIC0_REWARD_FUNDED, None, None]}"
        )
        logs: List[LogReceipt] = self._fetch_logs_chunked(
            address=dist,
            start_block=start_block,
            end_block=end_block,
            base_chunk=chunk_size,
            sleep_between_chunks=sleep_between_chunks,
        )

        if not logs:
            logger.info("No native logs found or node rejected windows; trying Etherscan logs fallback...")
            es_logs = self._etherscan_get_logs(dist, start_block, end_block)
            logs = self._parse_etherscan_logs(es_logs)

        if not logs:
            logger.info("No logs from node or etherscan; using transfer heuristics (may miss some tokens).")
            return self._fallback_via_transfers(dist, start_block)

        out = self._reduce_reward_logs(logs, token_filter, epoch_filter)
        logger.info(
            "Total RewardFunded entries discovered: %d across %d epoch(s)",
            sum(len(v['tokens']) for v in out.values()), len(out)
        )
        return out

    def _reduce_reward_logs(
        self,
        logs: List[LogReceipt],
        token_filter: Optional[str],
        epoch_filter: Optional[int],
    ) -> Dict[str, Dict]:
        """
        Reduce RewardFunded logs into epoch -> { tokens, block_number, timestamp, date }.
        Expects topics:
        [0] keccak("RewardFunded(address,uint256,uint256)")
        [1] indexed token (address)
        [2] indexed epochId (uint256)
        """
        from datetime import datetime
        from eth_utils import to_hex
        from hexbytes import HexBytes

        def as_hex(x) -> str:
            # Normalize to "0x..." string
            if isinstance(x, (bytes, bytearray, HexBytes)):
                return to_hex(x)
            if isinstance(x, int):
                return hex(x)
            if isinstance(x, str):
                return x if x.startswith("0x") else ("0x" + x)
            # Fallback via web3
            return Web3.to_hex(x)

        def parse_ts(ts_val) -> int:
            # ts_val can be int, hex string, decimal string, or None
            if ts_val is None:
                return 0
            try:
                if isinstance(ts_val, int):
                    return ts_val
                s = str(ts_val)
                if s.startswith("0x"):
                    return int(s, 16)
                return int(s)
            except Exception:
                return 0

        rewards_by_epoch: Dict[int, Dict] = {}

        for l in logs:
            topics = l.get("topics") or []
            if len(topics) < 3:
                continue

            t0 = as_hex(topics[0]).lower()
            if t0 != TOPIC0_REWARD_FUNDED.lower():
                continue

            # topics[1] = indexed address, topics[2] = indexed uint256
            t1 = as_hex(topics[1])
            token_addr = "0x" + t1[-40:]  # last 20 bytes of the 32-byte topic
            if token_filter and token_addr.lower() != token_filter.lower():
                continue

            t2 = as_hex(topics[2])
            try:
                epoch_id = int(t2, 16)
            except Exception:
                continue

            if epoch_filter and epoch_id != epoch_filter:
                continue

            # block number can be int, HexBytes, etc.
            bn_raw = l.get("blockNumber")
            try:
                bn = int(bn_raw)
            except Exception:
                try:
                    bn = int(as_hex(bn_raw), 16)
                except Exception:
                    bn = 0

            # timestamp: prefer block timestamp; fall back to log payload's timeStamp
            ts = 0
            if bn:
                try:
                    blk = self.w3.eth.get_block(bn)
                    ts = int(blk["timestamp"])
                except Exception:
                    pass
            if not ts:
                ts = parse_ts(l.get("timeStamp"))

            rec = rewards_by_epoch.setdefault(
                epoch_id,
                {"tokens": set(), "block_number": bn, "timestamp": ts or 0},
            )
            rec["tokens"].add(token_addr.lower())
            # If we didn’t have a ts when the entry was created, and we got one now, set it
            if ts and rec["timestamp"] == 0:
                rec["timestamp"] = ts

        # Serialize: epoch_id (int) -> key (str)
        result: Dict[str, Dict] = {}
        for epoch_id, data in rewards_by_epoch.items():
            ts = data["timestamp"] or int(epoch_id)  # week boundary fallback
            result[str(epoch_id)] = {
                "tokens": sorted(list(data["tokens"])),
                "block_number": data["block_number"],
                "timestamp": ts,
                "date": datetime.utcfromtimestamp(ts).isoformat() if ts else None,
            }

        # Optional: useful debug
        if result:
            total_tokens = sum(len(v["tokens"]) for v in result.values())
            logger.info(
                "Reduced RewardFunded logs -> %d epochs, %d token entries",
                len(result), total_tokens
            )
            # log a peek at the most recent epoch for sanity
            try:
                peek_key = max(result.keys(), key=lambda k: int(k))
                logger.info("Most recent epoch %s -> %s", peek_key, result[peek_key])
            except Exception:
                pass
        else:
            logger.info("Reduced RewardFunded logs -> 0 epochs")

        return result





    def _fallback_via_transfers(self, dist: str, start_block: int) -> Dict[str, Dict]:
        rewards_by_epoch: Dict[int, Dict] = {}

        token_txs = self.get_token_transactions(dist, start_block)
        for tx in token_txs:
            if tx.get("to", "").lower() != dist.lower():
                continue
            token = tx.get("contractAddress", "").lower()
            ts = int(tx.get("timeStamp", "0"))
            epoch_id = (ts // 604800) * 604800
            if epoch_id not in rewards_by_epoch:
                rewards_by_epoch[epoch_id] = {"tokens": set(), "block_number": int(tx.get("blockNumber", "0")), "timestamp": ts}
            rewards_by_epoch[epoch_id]["tokens"].add(token)

        txs = self.get_contract_transactions(dist, start_block)
        for tx in txs:
            if tx.get("isError", "0") == "1":
                continue
            value = int(tx.get("value", "0"))
            if value > 0 and tx.get("to", "").lower() == dist.lower():
                ts = int(tx.get("timeStamp", "0"))
                epoch_id = (ts // 604800) * 604800
                if epoch_id not in rewards_by_epoch:
                    rewards_by_epoch[epoch_id] = {"tokens": set(), "block_number": int(tx.get("blockNumber", "0")), "timestamp": ts}
                rewards_by_epoch[epoch_id]["tokens"].add("0x0000000000000000000000000000000000000000")

        result: Dict[str, Dict] = {}
        for epoch_id, data in rewards_by_epoch.items():
            ts = data["timestamp"]
            result[str(epoch_id)] = {
                "tokens": sorted(list(data["tokens"])),
                "block_number": data["block_number"],
                "timestamp": ts,
                "date": datetime.utcfromtimestamp(ts).isoformat() if ts else None,
            }
        return result

    # --------- compat shim that always returns a tuple ---------

    # in chain_scanner.py (inside ChainScanner)

    from eth_utils import to_hex
    from hexbytes import HexBytes

    def _to_hex_str(x) -> str:
        if isinstance(x, (bytes, bytearray, HexBytes)):
            return to_hex(x)
        if isinstance(x, str) and x.startswith("0x"):
            return x
        # numbers to 0x
        if isinstance(x, int):
            return hex(x)
        # fallback
        return to_hex(x)

    def extract_reward_funded_events_via_logs(
        self,
        distributor_address: str,
        start_block: int = 0,
        end_block: Optional[int] = None,
        chunk: int = 2000,
    ) -> Tuple[Dict[str, Dict], int]:
        """
        Scan RewardFunded(address indexed token, uint256 indexed epochId, uint256 amount)
        via eth_getLogs with chunking. Always returns (result_dict, max_block_seen).
        """
        from datetime import datetime
        logger = logging.getLogger(__name__)

        addr = Web3.to_checksum_address(distributor_address)
        if end_block is None:
            end_block = self.w3.eth.block_number

        topic0 = TOPIC0_REWARD_FUNDED  # keccak('RewardFunded(address,uint256,uint256)')

        logger.info(
            "Scanning RewardFunded logs: addr=%s range=[%s,%s] chunk=%d topics=[%s,None,None]",
            addr, start_block, end_block, chunk, topic0
        )

        rewards_by_epoch: Dict[int, Dict] = {}
        max_block_seen = start_block

        def scan_range(a: int, b: int):
            nonlocal max_block_seen
            flt = {
                "fromBlock": a,
                "toBlock": b,
                "address": addr,
                "topics": [topic0, None, None],
            }
            logs = self.w3.eth.get_logs(flt)
            for lg in logs:
                max_block_seen = max(max_block_seen, int(lg["blockNumber"]))

                # Normalize topics/data to hex strings
                topics = [ _to_hex_str(t) for t in lg.get("topics", []) ]
                data_hex = _to_hex_str(lg.get("data", "0x"))

                if not topics or topics[0].lower() != topic0.lower():
                    continue

                # topics[1] = indexed token (address), topics[2] = indexed epochId (uint256)
                # Both are 32-byte values; address is right-aligned in the last 20 bytes.
                token_topic = topics[1]
                epoch_topic = topics[2]

                token_addr = "0x" + token_topic[-40:]  # last 20 bytes of topics[1]
                epoch_id = int(epoch_topic, 16)

                # data = ABI-encoded non-indexed args; here it's just `amount` (uint256)
                # 32-byte word starting at offset 0
                if not data_hex.startswith("0x"):
                    continue
                if len(data_hex) < 2 + 64:
                    # not enough data to hold a uint256
                    continue
                amount = int(data_hex[2:2+64], 16)  # we don't actually need 'amount' to build the token list

                # Best-effort timestamp from block (falls back to the 'timeStamp' if present)
                ts = 0
                try:
                    blk = self.w3.eth.get_block(int(lg["blockNumber"]))
                    ts = int(blk["timestamp"])
                except Exception:
                    ts_raw = lg.get("timeStamp")
                    if ts_raw is not None:
                        try:
                            # could be int-like or hex str
                            ts = int(ts_raw, 16) if isinstance(ts_raw, str) and ts_raw.startswith("0x") else int(ts_raw)
                        except Exception:
                            pass

                rec = rewards_by_epoch.setdefault(epoch_id, {
                    "tokens": set(),
                    "block_number": int(lg["blockNumber"]),
                    "timestamp": ts or 0,
                })
                rec["tokens"].add(token_addr.lower())
                if ts and rec["timestamp"] == 0:
                    rec["timestamp"] = ts

        # Sweep the range in chunks, shrinking on errors
        a = start_block
        while a <= end_block:
            b = min(a + chunk - 1, end_block)
            try:
                scan_range(a, b)
            except Exception as e:
                # log and shrink the window
                msg = getattr(getattr(e, "response", None), "text", str(e))
                logger.warning("get_logs error for [%d,%d]: %s", a, b, msg)
                if (b - a + 1) <= 10:
                    a = b + 1
                    continue
                mid = (a + b) // 2
                # try halves best-effort (ignore errors)
                try: scan_range(a, mid)
                except Exception as e2: logger.warning("left-half failed: %s", e2)
                try: scan_range(mid + 1, b)
                except Exception as e3: logger.warning("right-half failed: %s", e3)
            a = b + 1

        if not rewards_by_epoch:
            logger.info("Total RewardFunded entries discovered: 0 across 0 epoch(s)")
            return {}, max_block_seen

        # Serialize
        out: Dict[str, Dict] = {}
        for epoch_id, rec in rewards_by_epoch.items():
            ts = rec["timestamp"] or epoch_id  # epoch aligns to week boundary
            out[str(epoch_id)] = {
                "tokens": sorted(list(rec["tokens"])),
                "block_number": rec["block_number"],
                "timestamp": ts,
                "date": datetime.utcfromtimestamp(ts).isoformat() if ts else None,
            }
        logger.info(
            "Total RewardFunded entries discovered: %d across %d epoch(s)",
            sum(len(v["tokens"]) for v in out.values()), len(out)
        )
        return out, max_block_seen



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
