# Review 9 helpers: the author's simulated world (tests/test_measured_headline.py) plus extra Base gauges whose
# allocation changes at re-votes (joined / left / re-joined), the harvester's daily claims on them, and optional
# spoofed claim events. No network. (Adopted from review 9 unchanged, except the import paths.)
import os
import sys
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

import test_measured_headline as tmh  # noqa: E402
from test_measured_headline import (World, SimReader, daily_harvests, daily_fundings, usd_per_day, _addr,  # noqa: E402
                                    STAKED_USD, RUN0, T0, E22, DAY, E18, WETH, USDC)
import position_earnings as pe  # noqa: E402

NOTSET = object()


class Extra:
    """A Base gauge #1584 holds during `intervals` [(on, off)], earning `usd_day` of USDC a day while allocated."""

    def __init__(self, tag, usd_day, intervals):
        # tag: one hex digit (addresses d<tag>.., e<tag>.., f<tag>..)
        self.g, self.v, self.p = _addr("d" + tag, 8453), _addr("e" + tag, 8453), _addr("f" + tag, 8453)
        self.rate = round(usd_day * 1e6 / DAY)              # raw USDC per second
        self.iv = list(intervals)
        self.claims = []                                    # (block, amount)

    def earned(self, ts):
        return sum(self.rate * max(0, min(ts, off) - on) for on, off in self.iv)

    def on(self, ts):
        return any(on <= ts < off for on, off in self.iv)

    def claimed(self, block):
        return sum(a for b, a in self.claims if b <= block)


class MultiWorld(World):
    """World + extra Base gauges + spoof emitters. `revotes` are the times #1584 re-voted on Base (lastAllocated)."""

    def __init__(self, extras, revotes=(), spoofs=(), seed_extras=(), **kw):
        super().__init__(harvests=daily_harvests(last_day=40), fundings=daily_fundings(last_day=40),
                         first_gauges={8453: [x.g for x in seed_extras]}, **kw)
        self.extras, self.revotes = list(extras), sorted(revotes)
        self.spoofs = list(spoofs)                          # [(ts, address)]: a contract emits ClaimFees(1584, ...)
        self.harvested_to = 0
        self.log_calls = []                                 # (chainId, address-less?, from_block, to_block)

    def harvest_extras(self, now):
        base = self.sims[8453]
        d = (self.harvested_to - E22) // DAY + 1 if self.harvested_to else 1
        while E22 + d * DAY + 300 <= now:
            ts = E22 + d * DAY + 300
            b = base.block_of(ts)
            for x in self.extras:
                left = x.earned(base.ts_of(b)) - x.claimed(b)
                if left > 0:
                    x.claims.append((b, left))
            self.harvested_to = ts
            d += 1

    def last_alloc(self, ts):
        return max([T0] + [r for r in self.revotes if r <= ts])

    def run(self, now, **kw):
        self.harvest_extras(now)
        world = self

        class R(SimReader):
            def many(self, calls):
                for t, sig, args, _ in calls:
                    if sig == "gauge()" and (t or "").lower() in {a for _, a in world.spoofs}:
                        # Multicall3.aggregate3 reverts out of gas (probe/spoof_oog.py: >= 6 such targets on
                        # Tenderly's / mainnet.base.org's caps, >= 3 on publicnode's 50M cap)
                        raise ValueError("{'code': -32003, 'message': 'out of gas: gas required exceeds: 500000000'}")
                return [self.hook(self, (t or "").lower(), sig, list(args)) for t, sig, args, _ in calls]

            def hook(self, rd, target, sig, args):
                if rd.chain_id != 8453:
                    return rd._one(target, sig, args)
                ts = rd.block_ts
                xs = {x.g: x for x in world.extras}
                vs = {x.v: x for x in world.extras}
                if sig == "allocatedGauges(uint256)":
                    return [tmh.Web3.to_checksum_address(g) for g in [rd.sim.gauge] + [x.g for x in world.extras if x.on(ts)]]
                if sig == "tokenStates(uint256)":
                    return (pe.ZERO, world.last_alloc(ts), False, 1_000_000 * E18)
                if target in xs:
                    x = xs[target]
                    return {"votingRewardsManager()": x.v, "pool()": x.p, "stakingToken()": None}.get(sig)
                if target in vs:
                    x = vs[target]
                    return {"gauge()": x.g, "token0()": USDC, "token1()": WETH, "incentiveCount()": 0,
                            "earnedFees(uint256,uint256)": (x.earned(ts) - x.claimed(rd.block), 0)}.get(sig)
                if sig == "tickSpacing()" and target in {x.p for x in world.extras}:
                    return 100
                if args and str(args[-1]).lower() in xs:
                    x = xs[str(args[-1]).lower()]
                    return {"gaugeToRewards(address)": x.v,
                            "allocations(uint256,address)": 500_000 * E18 if x.on(ts) else 0,
                            "gaugeStates(address)": (0, 0, 0, True, True, 0, 0, 0, 0, 0, 0, 0)}.get(sig)
                return rd._one(target, sig, args)

            def logs(self, addresses, topics, from_block, to_block=None, **kw):
                world.log_calls.append((self.chain_id, addresses is None, int(from_block),
                                        self.block if to_block is None else int(to_block)))
                out = SimReader.logs(self, addresses, topics, from_block, to_block)
                if out is None or self.chain_id != 8453:
                    return out
                tb = self.block if to_block is None else min(to_block, self.block)
                want = None if addresses is None else {a.lower() for a in addresses}
                tid = (1584).to_bytes(32, "big")
                for x in world.extras:
                    if want is None or x.v in want:
                        out += [{"address": tmh.Web3.to_checksum_address(x.v),
                                 "topics": [bytes.fromhex(pe.CLAIM_FEES_TOPIC[2:]), tid, bytes(32),
                                            bytes(12) + bytes.fromhex(USDC[2:])],
                                 "data": a.to_bytes(32, "big"), "blockNumber": b}
                                for b, a in x.claims if from_block <= b <= tb]
                if want is None:
                    for ts_, a in world.spoofs:
                        b = self.sim.block_of(ts_)
                        if from_block <= b <= tb:
                            out.append({"address": tmh.Web3.to_checksum_address(a),
                                        "topics": [bytes.fromhex(pe.CLAIM_FEES_TOPIC[2:]), tid, bytes(32),
                                                   bytes(12) + bytes.fromhex(USDC[2:])],
                                        "data": (1).to_bytes(32, "big"), "blockNumber": b})
                return out

        with mock.patch.object(tmh, "SimReader", R):
            return super().run(now, **kw)

    def true_usd_day(self, t, days=7):
        """#1584's true trailing earning rate over the `days` before t (all gauges, claimed + unclaimed)."""
        extra = sum(x.earned(t) - x.earned(t - days * DAY) for x in self.extras) / 1e6 / days
        return usd_per_day() + extra


def apy_of(usd_day):
    return usd_day * 365 * 0.8 / STAKED_USD * 100


SAT = T0 + 2 * DAY - 3600          # Sat 24 Oct 01:11:03, #1584's cooldown expiry (first re-vote)


# Review 8's measured launch profile of #1584 (relative to the post-launch rate R): day 0 ~2.67 R, day 1 ~1.86 R,
# then R (2-day launch programs ending Sat 24 Oct; vote dilution). Applied to the world's three base gauges.
PROFILE = ((DAY, 2.67), (2 * DAY, 1.86))


def integ(e):
    """Seconds-at-rate-R earned in the first e seconds after the allocation."""
    f, prev = 0.0, 0
    for bound, m in PROFILE:
        seg = min(e, bound) - prev
        if seg > 0:
            f += seg * m
        prev = bound
    return f + max(0, e - prev)


class FrontLoadedChain(tmh.SimChain):
    def accrued(self, ts):
        e = integ(max(0, int(ts) - T0))
        return {("fee", self.t0): int(self.r0 * e), ("fee", self.t1): int(self.r1 * e), ("inc", self.inc): int(self.ri * e)}


class FrontLoadedWorld(MultiWorld):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.sims = {cid: FrontLoadedChain(cid) for cid in (8453, 1, 4663)}

    def true_usd_day(self, t, days=7):
        e = t - T0
        base = usd_per_day() * (integ(e) - integ(max(0, e - days * DAY))) / (days * DAY)
        return base + sum(x.earned(t) - x.earned(t - days * DAY) for x in self.extras) / 1e6 / days
