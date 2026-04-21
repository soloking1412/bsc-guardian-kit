# Architecture

How the three components fit together, and what the code actually looks like.

## The three-layer picture

```
          Your Protocol (Venus fork / AMM / vault / whatever)
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       CircuitBreaker    Invariant Suite   (integration
         (on-chain)       (CI / Foundry)     surface)
              ▲
              │ guardian role — narrow, risk-reducing only
              │
        Guardian Agent  ←── mempool + state detectors
         (off-chain)
```

Each layer is independently useful:

- Deploy just the CircuitBreaker and you get per-block outflow caps. That alone would have bounded the Venus donation attack and the Hyperbridge bridge drain.
- Add the Guardian Agent and you get early detection + automatic response.
- Add the Invariant Suite and you catch a class of bugs in CI before they ever ship.

Protocols opt into whichever layers fit their threat model. Nothing is mandatory.

## CircuitBreaker — the core primitive

The whole design lives around one question: what's the smallest on-chain surface a protocol needs to survive an in-progress exploit?

Answer: a rate limit per token, plus three response modes, plus a narrow role that can tighten but never loosen.

### Sketch

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Rate-limits outflows per token. EIP-7265 compatible with BSC extensions.
abstract contract CircuitBreaker {
    enum Mode { Revert, Delay, Pause }

    struct TokenConfig {
        uint128 cap;               // max outflow per epoch, in token units
        uint64  epochLength;       // seconds
        uint64  epochStart;        // unix time when current epoch began
        uint128 outflowThisEpoch;  // accumulated in current epoch
        Mode    mode;
        bool    registered;
    }

    struct DelayedWithdrawal {
        address token;
        address recipient;
        uint128 amount;
        uint64  unlockAt;
        bool    claimed;
    }

    mapping(address => TokenConfig)        internal _tokenCfg;
    mapping(bytes32 => DelayedWithdrawal)  internal _delayed;

    address public guardian;           // can tighten, cannot loosen
    uint64  public constant DELAY_WINDOW = 24 hours;

    error NotRegistered(address token);
    error CapExceeded(address token, uint256 attempted, uint256 remaining);
    error Paused(address token);
    error NotGuardian();
    error CannotLoosen();

    event TokenRegistered(address indexed token, uint128 cap, uint64 epochLength, Mode mode);
    event OutflowRecorded(address indexed token, uint128 amount, uint64 epochStart);
    event CircuitBreakerTripped(address indexed token, uint128 attempted, uint128 cap);
    event OutflowDelayed(bytes32 indexed key, address token, address recipient, uint128 amount, uint64 unlockAt);
    event DelayedClaimed(bytes32 indexed key);
    event GuardianAction(address indexed guardian, bytes4 selector, address token);

    // ---------- protocol-facing hooks ----------

    function _registerToken(address token, uint128 cap, uint64 epochLength, Mode mode) internal {
        _tokenCfg[token] = TokenConfig({
            cap: cap,
            epochLength: epochLength,
            epochStart: uint64(block.timestamp),
            outflowThisEpoch: 0,
            mode: mode,
            registered: true
        });
        emit TokenRegistered(token, cap, epochLength, mode);
    }

    /// @dev Call this before moving tokens out. Returns delayKey != bytes32(0) if the
    ///      outflow was queued for delayed settlement; caller must not transfer in that case.
    function _beforeOutflow(address token, uint128 amount, address recipient)
        internal
        returns (bytes32 delayKey)
    {
        TokenConfig storage cfg = _tokenCfg[token];
        if (!cfg.registered) revert NotRegistered(token);

        _rollEpochIfNeeded(cfg);

        uint128 next = cfg.outflowThisEpoch + amount;

        if (next <= cfg.cap) {
            cfg.outflowThisEpoch = next;
            emit OutflowRecorded(token, amount, cfg.epochStart);
            return bytes32(0);
        }

        // cap would be exceeded — apply mode
        if (cfg.mode == Mode.Revert) {
            revert CapExceeded(token, amount, cfg.cap - cfg.outflowThisEpoch);
        }
        if (cfg.mode == Mode.Pause) {
            revert Paused(token);
        }
        // Mode.Delay: queue the *excess* and let the within-cap portion through
        uint128 withinCap = cfg.cap - cfg.outflowThisEpoch;
        uint128 excess    = amount - withinCap;
        cfg.outflowThisEpoch = cfg.cap;

        delayKey = keccak256(
            abi.encode(token, recipient, excess, block.timestamp, blockhash(block.number - 1))
        );
        _delayed[delayKey] = DelayedWithdrawal({
            token: token,
            recipient: recipient,
            amount: excess,
            unlockAt: uint64(block.timestamp) + DELAY_WINDOW,
            claimed: false
        });

        emit CircuitBreakerTripped(token, amount, cfg.cap);
        emit OutflowDelayed(delayKey, token, recipient, excess, uint64(block.timestamp) + DELAY_WINDOW);
    }

    function _rollEpochIfNeeded(TokenConfig storage cfg) private {
        uint64 elapsed = uint64(block.timestamp) - cfg.epochStart;
        if (elapsed >= cfg.epochLength) {
            cfg.epochStart = uint64(block.timestamp);
            cfg.outflowThisEpoch = 0;
        }
    }

    // ---------- delayed-claim flow ----------

    function claimDelayed(bytes32 key) external {
        DelayedWithdrawal storage w = _delayed[key];
        require(!w.claimed, "claimed");
        require(block.timestamp >= w.unlockAt, "locked");
        require(msg.sender == w.recipient, "not recipient");
        w.claimed = true;
        _settleDelayed(w.token, w.recipient, w.amount);
        emit DelayedClaimed(key);
    }

    /// @dev Protocol implements how delayed amounts actually leave the contract.
    ///      Typically: IERC20(token).transfer(recipient, amount);
    function _settleDelayed(address token, address recipient, uint128 amount) internal virtual;

    // ---------- guardian role ----------

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert NotGuardian();
        _;
    }

    function lowerCap(address token, uint128 newCap) external onlyGuardian {
        TokenConfig storage cfg = _tokenCfg[token];
        if (newCap >= cfg.cap) revert CannotLoosen();
        cfg.cap = newCap;
        emit GuardianAction(msg.sender, this.lowerCap.selector, token);
    }

    function tightenMode(address token, Mode newMode) external onlyGuardian {
        TokenConfig storage cfg = _tokenCfg[token];
        // ordering: Revert(0) < Delay(1) < Pause(2) — higher ordinal = stricter
        if (uint8(newMode) <= uint8(cfg.mode)) revert CannotLoosen();
        cfg.mode = newMode;
        emit GuardianAction(msg.sender, this.tightenMode.selector, token);
    }

    function pauseToken(address token) external onlyGuardian {
        _tokenCfg[token].mode = Mode.Pause;
        emit GuardianAction(msg.sender, this.pauseToken.selector, token);
    }
}
```

### Why this shape

A few choices worth calling out:

**Cap accounting per token, not per user.** Per-user rate limits are what most naive implementations reach for, but they don't help in the exploit case — an attacker who's already inside the protocol can split across addresses trivially. What they can't easily manipulate is the aggregate outflow from the contract. So we meter at the contract level.

**Three modes, not one.** Revert is what most people assume a circuit breaker is. It's the strictest — and for some protocols it's the wrong choice, because it DoS's legitimate users when the cap's already consumed. Delay is the interesting middle ground: within-cap withdrawals go through immediately, the excess sits for 24h, and the guardian has room to kill it if the pattern is adversarial. Pause is the nuclear option.

**Guardian can only tighten.** This is the single most important design constraint. If the guardian key gets compromised, the worst case is griefing — the attacker can pause tokens but can't drain them, upgrade anything, or raise caps to enable a later drain. That's a fundamentally different blast radius than a normal admin multisig.

**Storage packing.** `uint128` for amounts and `uint64` for timestamps/epoch lengths fits the whole `TokenConfig` in two storage slots. Saves about 5k gas per registered token on writes. Doesn't matter for M1 correctness but matters for M1 gas benchmarks.

**No reentrancy guards in the library.** Protocols bring their own. Adding one here means paying the SSTORE cost on every guarded call. Instead, the library requires `_beforeOutflow` to be called *before* the external transfer, and the protocol handles CEI.

### Integration example — lending market

```solidity
contract MyLendingMarket is CircuitBreaker {
    using SafeERC20 for IERC20;

    constructor(address _guardian) {
        guardian = _guardian;
        _registerToken(USDT, 500_000e18, 1 hours, Mode.Delay);
        _registerToken(BUSD, 500_000e18, 1 hours, Mode.Delay);
    }

    function withdraw(address token, uint128 amount) external nonReentrant {
        // ... existing accounting / health checks ...
        bytes32 delayKey = _beforeOutflow(token, amount, msg.sender);
        if (delayKey == bytes32(0)) {
            IERC20(token).safeTransfer(msg.sender, amount);
        }
        // if delayKey != 0, excess is queued; user calls claimDelayed(key) after 24h
    }

    function _settleDelayed(address token, address recipient, uint128 amount) internal override {
        IERC20(token).safeTransfer(recipient, amount);
    }
}
```

One line added to the withdraw path. One override. Done.

## Guardian Agent — the watcher

### Process shape

```
     ┌─ WebSocket to BSC node ─┐
     │                          │
     ▼                          ▼
  Mempool stream          Finalized-block stream
     │                          │
     └──────┬───────────────────┘
            ▼
    Event normalizer
            │
            ▼
    Detector pipeline  ──────┐
            │                │
            ▼                │
    Verdict aggregator       │
            │                ▼
            ▼           Alert sink
    Action router       (Discord / TG / webhook)
            │
            ▼
    Guardian signer
    (calls lowerCap / tightenMode / pauseToken)
```

One process. No Redis, no message queue, no cluster. A compromised node is fine — the process re-subscribes and keeps running. A compromised *protocol* is what we're protecting against, and the guardian key living in a local hardware signer or KMS is what limits that blast.

### Detector contract

```typescript
export interface Detector {
  name: string;
  subscribeTo: Array<'mempool' | 'pending' | 'finalized' | 'state'>;
  evaluate(ctx: EventContext): Promise<Verdict>;
}

export interface Verdict {
  severity: 'info' | 'warning' | 'critical';
  action?: GuardianAction;
  evidence: EvidenceBlob;
}

export type GuardianAction =
  | { type: 'lowerCap'; token: string; newCap: bigint }
  | { type: 'tightenMode'; token: string; mode: 'Delay' | 'Pause' }
  | { type: 'pause'; token: string };
```

Detectors are pure-ish functions — they read an event context and emit a verdict. Only `critical` produces on-chain calls. Everything else is telemetry.

### Why the detectors ship as copyable files

The default thresholds in the ten shipped detectors are calibrated off real incidents, but every protocol's risk surface is different. A vault with $2M TVL shouldn't use the same oracle-divergence threshold as one with $200M. So the detectors aren't a black-box npm package — they're TypeScript files a team copies into their own repo, reads, and tunes.

This is a deliberate choice against "just pip install and trust us." Security tooling you can't read isn't security tooling.

### Action router logic

Three detectors going `critical` on the same token within a 30-second window = execute the most restrictive action any of them asked for. One detector firing critical in isolation = raise to `tightenMode: Delay` and alert a human, don't pause outright. This kills most false-positive pauses while still responding fast to coordinated signals.

## Invariant Suite Generator — the CI floor

### What it's not

Not a replacement for an audit. Not a replacement for thinking. Not a claim of correctness.

### What it is

A tool that takes an ABI plus a few annotations and produces a Foundry invariant test file that covers the obvious properties any protocol of that shape should maintain. Something like "total supply equals sum of balances" or "share price is monotonically non-decreasing in a yield vault with no loss mechanism."

Most small teams don't write invariant tests because the activation energy is high — they have to learn Foundry's invariant framework, figure out what properties matter, and plumb handlers. This tool gets them from zero to a running invariant suite in one command. From there they write more as they go.

### Flow

```
forge guardian-init 0xYourProtocol
    │
    ▼
Fetch ABI from BscScan (or local file)
    │
    ▼
Classify protocol shape (lending / amm / vault / token / bridge / generic)
    │
    ▼
Match ABI signatures against template library (20+ templates)
    │
    ▼
Emit Solidity test file: test/invariants/Guardian_{Type}.t.sol
    │
    ▼
User runs: forge test --mt invariant_
```

### A sample of what gets emitted

For a detected ERC-4626 vault:

```solidity
// AUTO-GENERATED — this is a floor, not an audit.
// Tune thresholds, add handlers, review before trusting.

function invariant_sharePriceMonotonic() public {
    uint256 pps = vault.convertToAssets(1e18);
    assertGe(pps, lastPricePerShare, "share price decreased");
    lastPricePerShare = pps;
}

function invariant_totalAssetsCoversShares() public {
    assertGe(vault.totalAssets(), vault.convertToAssets(vault.totalSupply()));
}

function invariant_noUnauthorizedMint() public {
    assertEq(vault.totalSupply(), handler.sumOfDeposits() - handler.sumOfRedemptions());
}
```

The banner comment is not optional — it's in every generated file, every time.

## How the three components compose

Common deployment pattern for a new BSC lending market:

1. Inherit `CircuitBreaker`, register tokens, deploy. Guardian starts as a multisig.
2. Stand up the Guardian Agent locally or on a cheap VPS. Wire detectors 1–5 (donation, oracle, flash-loan, reentrancy, admin). Default thresholds.
3. Run `forge guardian-init` against your deployed address. Drop the generated files into CI.
4. Over the next few weeks, tune detector thresholds based on observed false positives, tighten cap values based on real withdrawal patterns, and add protocol-specific invariants to the generated suite.

The whole kit is designed around that progression. Week 1 you get coarse protection. Week 6 you have it dialed in. No ongoing SaaS bill, no data leaving your infra.