import os
import requests
from web3 import Web3
import logging
import time
from typing import List, Dict
from eth_utils import keccak

logger = logging.getLogger(__name__)

REGISTRY_ABI = [
    {"inputs": [], "name": "allTokens", "outputs": [{"internalType":"address[]","name":"out","type":"address[]"}], "stateMutability":"view", "type":"function"}
]
ERC20_ABI = [
    {"inputs":[{"internalType":"address","name":"account","type":"address"}], "name":"balanceOf", "outputs":[{"internalType":"uint256","name":"","type":"uint256"}], "stateMutability":"view", "type":"function"}
]

MULTICALL3_ABI = [
    {
        "inputs":[
            {"components":[
                {"internalType":"address","name":"target","type":"address"},
                {"internalType":"bool","name":"allowFailure","type":"bool"},
                {"internalType":"bytes","name":"callData","type":"bytes"}
            ],"internalType":"struct Multicall3.Call3[]","name":"calls","type":"tuple[]"}
        ],
        "name":"aggregate3","outputs":[
            {"components":[
                {"internalType":"bool","name":"success","type":"bool"},
                {"internalType":"bytes","name":"returnData","type":"bytes"}
            ],"internalType":"struct Multicall3.Result[]","name":"returnData","type":"tuple[]"}
        ],
        "stateMutability":"payable","type":"function"
    }
]

DEFAULT_MULTICALL3 = os.environ.get("MULTICALL3", "0xCA11bde05977b3631167028862bE2a173976CA11")

# Function selectors
SEL_BALANCE_OF = bytes.fromhex("70a08231")  # balanceOf(address)
SEL_DECIMALS   = bytes.fromhex("313ce567")  # decimals()
SEL_TOTAL_SUPPLY = bytes.fromhex("18160ddd")  # totalSupply()
TRANSFER_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()
REWARDFUNDED_TOPIC = "0x" + keccak(text="RewardFunded(address,uint256,uint256)").hex()

def _topic_to_uint256(topic_hex: str) -> int:
    return int(topic_hex, 16)

class ChainScanner:
    """
    - probe new incoming ERC-20s via Etherscan v2 (for triggers)
    - read RewardTokenRegistry
    - multicall balances & decimals
    """

    def __init__(self, rpc_url: str, explorer_api_key: str, chain_id: int = 8453, multicall3: str | None = None):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20}))
        self.explorer_api_key = explorer_api_key
        self.chain_id = chain_id
        # Etherscan v2 supports multi-chain via the 'chainid' param; keep base URL static.
        self.explorer_base_url = "https://api.etherscan.io/v2/api"
        self.multicall3_addr = self.w3.to_checksum_address(multicall3 or DEFAULT_MULTICALL3)
        self._multicall = self.w3.eth.contract(address=self.multicall3_addr, abi=MULTICALL3_ABI)

    # ---------- trigger probe ----------
    def check_for_new_incoming_erc20(self, distributor_address: str, last_seen_tx: str | None = None) -> tuple[bool, str | None]:
        """
        Returns (has_new, newest_tx_hash).
        - If Etherscan returns a head tx equal to last_seen_tx, returns (False, None).
        - If there is a newer inbound token transfer to distributor_address, returns (True, <hash>).
        - On probe failure, returns (False, None) to avoid spamming updates.
        """
        try:
            to_addr_lc = distributor_address.lower()
            params = {
                "chainid": self.chain_id,
                "module": "account",
                "action": "tokentx",
                "address": distributor_address,
                "page": 1,
                "offset": 1,         # only need the newest tx
                "sort": "desc",
                "apikey": self.explorer_api_key,
            }
            r = requests.get(self.explorer_base_url, params=params, timeout=30)
            if r.status_code != 200:
                logger.warning(f"Etherscan probe HTTP {r.status_code}: {r.text[:200]}")
                return False, None

            data = r.json()
            if data.get("status") != "1" or "result" not in data or not data["result"]:
                # No token txs found or API returned empty; treat as no new activity.
                return False, None

            head = data["result"][0]
            # must be inbound to the distributor (defensive filter)
            if head.get("to", "").lower() != to_addr_lc:
                return False, None

            head_hash = head.get("hash")
            if not head_hash:
                return False, None

            # Idempotence: compare with last_seen_tx
            if last_seen_tx and str(head_hash).lower() == str(last_seen_tx).lower():
                return False, None

            return True, head_hash

        except Exception as e:
            logger.warning(f"[check_for_new_incoming_erc20] probe failed: {e}")
            # fail-closed to avoid noisy commits on transient errors
            return False, None

    def latest_block(self) -> int:
        try:
            return int(self.w3.eth.block_number)
        except Exception as e:
            logger.warning(f"latest_block failed: {e}")
            return 0

    def funded_epochs_and_tokens(self, distributor: str, from_block: int, to_block: int):
        """
        Scan RewardFunded logs for the distributor and return:
        epochs: sorted list of epochIds (int)
        epoch_tokens: dict[int, list[str]] epochId -> unique token list (checksum addresses)
        """
        distributor = self.w3.to_checksum_address(distributor)
        epochs = set()
        epoch_tokens: dict[int, set[str]] = {}

        for lg in self._get_logs_chunked(distributor, [REWARDFUNDED_TOPIC], from_block, to_block):
            # topics[1]=token (indexed address); topics[2]=epochId (indexed uint256)
            token = "0x" + lg["topics"][1].hex()[-40:]
            epoch_id = _topic_to_uint256(lg["topics"][2].hex())
            epochs.add(epoch_id)
            s = epoch_tokens.setdefault(epoch_id, set())
            s.add(self.w3.to_checksum_address(token))

        return sorted(epochs), {e: sorted(list(ts)) for e, ts in epoch_tokens.items()}

    
    def _get_logs_chunked(self, address: str, topics: list, from_block: int, to_block: int, step: int = 50_000):
        """
        Yield logs in chunks to avoid provider limits.
        """
        address = self.w3.to_checksum_address(address)
        fb = max(0, int(from_block))
        tb = int(to_block)
        while fb <= tb:
            end = min(tb, fb + step)
            try:
                logs = self.w3.eth.get_logs({
                    "address": address,
                    "fromBlock": fb,
                    "toBlock": end,
                    "topics": topics
                })
                for lg in logs:
                    yield lg
            except Exception as e:
                logger.warning(f"get_logs chunk {fb}-{end} failed: {e}")
                # back off to smaller step
                if step > 5_000:
                    step //= 2
                    continue
                else:
                    # give up this slice, advance to avoid infinite loop
                    pass
            fb = end + 1

    def erc20_transfer_logs(self, token: str, from_block: int, to_block: int):
        """
        Return iterator of Transfer logs (any from/to) for token in [from_block, to_block].
        """
        topic0 = TRANSFER_TOPIC
        return self._get_logs_chunked(token, [topic0], from_block, to_block)

    def total_supply(self, token: str) -> int:
        try:
            token_cs = self.w3.to_checksum_address(token)
            # single call (no multicall)
            data = self.w3.eth.call({
                "to": token_cs,
                "data": SEL_TOTAL_SUPPLY
            })
            if not data or len(data) < 32:
                return 0
            return int.from_bytes(data[-32:], "big")
        except Exception as e:
            logger.warning(f"total_supply({token}) failed: {e}")
            return 0

    # ---------- registry ----------
    def registry_all_tokens(self, registry_address: str) -> List[str]:
        try:
            reg = self.w3.eth.contract(address=self.w3.to_checksum_address(registry_address), abi=REGISTRY_ABI)
            tokens = reg.functions.allTokens().call()
            return [t.lower() for t in tokens]
        except Exception as e:
            logger.error(f"registry_all_tokens failed: {e}")
            return []

    # ---------- active rewards (registry + distributor balance) ----------
    def active_token_balances(
        self,
        registry_address: str,
        distributor_address: str,
        *,
        min_units: int = 1,
        chunk_size: int = 120,
    ) -> Dict[str, int]:
        """
        Return a map of { tokenLower: balance } for tokens found in the on-chain
        RewardTokenRegistry that also have balance > min_units in the distributor.
        """
        try:
            reg_tokens = self.registry_all_tokens(registry_address)
            if not reg_tokens:
                logger.info("active_token_balances: registry returned 0 tokens")
                return {}
            # checksum once for multicall; keep original lowercaes list for keys
            dist_cs = self.w3.to_checksum_address(distributor_address)
            # fetch balances in batches
            balances: Dict[str, int] = {}
            total = len(reg_tokens)
            for i in range(0, total, chunk_size):
                chunk = reg_tokens[i:i + chunk_size]
                # balances_map expects lower/any; returns lower-keyed map
                bm = self.balances_map(dist_cs, chunk, chunk_size=len(chunk))
                for k, v in bm.items():
                    if v is None:
                        continue
                    if int(v) > int(min_units):
                        balances[k] = int(v)
            if not balances:
                logger.info("active_token_balances: no tokens had balance > min_units")
            return dict(sorted(balances.items()))
        except Exception as e:
            logger.error(f"active_token_balances failed: {e}")
            return {}

    def active_tokens_from_registry(
        self,
        registry_address: str,
        distributor_address: str,
        *,
        min_units: int = 1,
        chunk_size: int = 120,
    ) -> List[str]:
        """
        Convenience wrapper: return a sorted list of LOWERCASE token addresses
        that are present in the on-chain registry AND have balance > min_units
        in the distributor.
        """
        m = self.active_token_balances(
            registry_address,
            distributor_address,
            min_units=min_units,
            chunk_size=chunk_size,
        )
        return list(m.keys())

    # ---------- multicall helpers ----------
    def _call_chunk(self, calls: List[dict]) -> List[tuple]:
        # returns list of (success: bool, returnData: bytes)
        try:
            return self._multicall.functions.aggregate3(calls).call()
        except Exception as e:
            logger.warning(f"Multicall aggregate3 failed for chunk({len(calls)}): {e}")
            raise

    def balances_map(self, holder: str, token_addrs: List[str], chunk_size: int = 50) -> Dict[str, int]:
        holder_cs = self.w3.to_checksum_address(holder)
        results: Dict[str, int] = {}
        total = len(token_addrs)
        for i in range(0, total, chunk_size):
            chunk = token_addrs[i:i+chunk_size]
            calls = []
            for a in chunk:
                try:
                    target = self.w3.to_checksum_address(a)
                except Exception:
                    continue
                # ABI encode balanceOf(address)
                addr32 = bytes(12) + bytes.fromhex(holder_cs[2:])
                calldata = SEL_BALANCE_OF + addr32.rjust(32, b"\x00")
                calls.append({"target": target, "allowFailure": True, "callData": calldata})
            ret = self._call_chunk(calls)
            for addr, res in zip(chunk, ret):
                success, data = bool(res[0]), bytes(res[1])
                if not success or len(data) < 32:
                    continue
                bal = int.from_bytes(data[-32:], "big")
                results[addr.lower()] = bal
        return results

    def decimals_map(self, token_addrs: List[str], chunk_size: int = 50, default_decimals: int = 18) -> Dict[str, int]:
        out: Dict[str, int] = {}
        total = len(token_addrs)
        for i in range(0, total, chunk_size):
            chunk = token_addrs[i:i+chunk_size]
            calls = []
            for a in chunk:
                try:
                    target = self.w3.to_checksum_address(a)
                except Exception:
                    continue
                calldata = SEL_DECIMALS  # no args
                calls.append({"target": target, "allowFailure": True, "callData": calldata})
            ret = self._call_chunk(calls)
            for addr, res in zip(chunk, ret):
                success, data = bool(res[0]), bytes(res[1])
                dec = default_decimals
                if success and len(data) >= 32:
                    dec = int.from_bytes(data[-32:], "big") & 0xFF  # uint8 in the low byte
                    if dec == 0:  # guard against broken tokens
                        dec = default_decimals
                out[addr.lower()] = dec
        return out
