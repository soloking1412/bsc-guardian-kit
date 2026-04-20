# SPEC

Technical spec for BSC Guardian Kit. Draft v0.1.

## 1. What's in scope

Three components:

1. **CircuitBreaker** — Solidity library, on-chain
2. **Guardian Agent SDK** — off-chain monitor, TypeScript primary, Rust bindings for hot paths
3. **Invariant Suite Generator** — Foundry-integrated CLI

Target: BSC mainnet (BEP-20 + EVM). opBNB is a stretch for M3.

## 2. Threat model

Derived from reading BSC post-mortems from 2024 to 2026. Detector defaults and circuit breaker parameters are calibrated against these classes:

| Class | Representative incident | Defense |
|---|---|---|
| Donation / share-price manipulation | Venus Q1 2026, ~$2.15M | CircuitBreaker + donation detector |
| Oracle manipulation | Recurring on BSC lending forks | Oracle detector + cap |
| Flash-loan drain | Recurring pattern | Flash-loan detector + CB |
| Reentrancy variant | Cross-fn / cross-contract | Reentrancy detector |
| Unauthorized admin call | Compromised deployer | Admin-call detector |
| Governance takeover | Vote concentration attacks | Governance detector |
| Bridge replay | Hyperbridge April 2026, ~$2.5M | Bridge detector |
| Collateral factor jump | Flash-governance param changes | Param-change detector |
| Liquidation cascade | Market-wide bad debt | Rate-of-change detector |
| Unusual mint/burn | Supply inflation | Supply-conservation detector |

Not in scope: private key theft, front-end compromise, supply-chain attacks on deps, social engineering. Those are other tools' jobs.

## 3. Component 1 — CircuitBreaker

### Goals

- EIP-7265 compliant with a few BSC-specific extensions
- No trust assumptions beyond the protocol's existing admin model
- Under 5k gas overhead on the happy path
- Drops into existing contracts without wrecking the interface

### Interface

```solidity
abstract contract CircuitBreaker {
    enum Mode { Revert, Delay, Pause }

    struct TokenConfig {
        uint256 cap;
        uint256 epochLength;
        uint256 currentEpoch;
        uint256 outflowThisEpoch;
        Mode mode;
    }

    mapping(address => TokenConfig) internal _tokenConfig;
    mapping(bytes32 => DelayedWithdrawal) internal _delayed;

    function _registerToken(address token, uint256 cap, uint256 epochLength) internal;
    function _beforeOutflow(address token, uint256 amount) internal returns (bytes32 delayKey);
    function _claimDelayed(bytes32 delayKey) external;

    event OutflowRecorded(address indexed token, uint256 amount, uint256 epoch);
    event CircuitBreakerTripped(address indexed token, uint256 attempted, uint256 cap);
    event OutflowDelayed(bytes32 indexed delayKey, address token, uint256 amount, uint256 unlockAt);
}
```

### Modes

- **Revert** — tx fails outright if cap would be exceeded. Simple, strict, best for small protocols.
- **Delay** — excess outflow is queued for a configurable window (default 24h). Gives guardians room to respond without a full DoS on users.
- **Pause** — one breach pauses the token globally. Highest safety, worst UX.

Protocols pick mode per token.

### Extensions over the base EIP

- Per-token epoch length. The reference implementation assumes one global clock, but BSC's 0.75s blocks mean some tokens benefit from much shorter epochs (e.g. 15 min) while others stay at hours.
- Delayed-settlement mode with per-user claim. The base EIP leaves this underspecified.
- Guardian role hook. A pre-authorized address can lower caps or tighten mode. It cannot raise caps, widen modes, or move funds.

### Gas target

Under 5k gas overhead vs unprotected baseline for `transfer`, `borrow`, `redeem`. Full benchmark report ships with M1.

## 4. Component 2 — Guardian Agent SDK

### Architecture

```
BSC Node (WSS) → Event Stream → Detector Pipeline → Action Router → Guardian Signer
                                      │
                                      └─→ Telemetry (optional, local)
```

One process. Event-driven. Stateless by default, with optional local SQLite for detectors that need history (rate-of-change, governance).

### Detector interface

```typescript
interface Detector {
  name: string;
  subscribeTo: ('mempool' | 'pending' | 'finalized' | 'state')[];
  evaluate(ctx: EventContext): Promise<Verdict>;
}

interface Verdict {
  severity: 'info' | 'warning' | 'critical';
  action?: GuardianAction;
  evidence: EvidenceBlob;
}
```

Only `critical` verdicts produce on-chain actions. `warning` goes to webhooks / Discord / Telegram. `info` is local telemetry.

### Ten detectors in M2

Every one of these is a single TypeScript file a protocol team can copy and tune. Defaults are calibrated off real incidents.

1. **Donation** — share-price jumps on 4626-style vaults, direct ERC-20 transfers to protocol addresses
2. **Oracle** — TWAP divergence, single-block price spikes on Pyth / Chainlink
3. **Flash-loan drain** — loan-in + large-outflow pattern in one tx
4. **Reentrancy** — cross-function and cross-contract patterns
5. **Admin call** — admin-gated calls from unexpected addresses or without governance trail
6. **Governance** — vote concentration past threshold, suspicious calldata
7. **Bridge replay** — duplicate message hashes, unexpected source chains
8. **Param jump** — collateral factor / interest rate / fee changes outside safe bands or skipping timelock
9. **Liquidation cascade** — liquidation rate anomalies
10. **Supply anomaly** — mint / burn delta past per-epoch threshold

### Guardian role scope

The guardian key can call:

- `pause(token)`
- `lowerCap(token, newCap)` — new cap must be strictly lower
- `switchMode(token, Mode.Delay | Mode.Pause)` — strictly tighter

It cannot:

- Move funds
- Upgrade contracts
- Change ownership
- Raise caps or loosen modes

Compromised guardian = griefing by pause. Not theft.

## 5. Component 3 — Invariant Suite Generator

### CLI

```
forge guardian-init <address | abi-path> [flags]
  --out <dir>            default: test/invariants/
  --chain bsc | opbnb
  --protocol-type lending | amm | vault | bridge | generic
  --include-fuzzing      also emit differential-fuzz targets
```

Output: `.t.sol` files runnable via `forge test --mt invariant_`.

### Templates

Twenty hazard templates grouped by protocol type. The tool inspects the ABI and stitches in the relevant ones.

- Supply conservation (mint / burn / total supply)
- Share-price monotonicity (4626 vaults)
- Collateral-ratio bounds (lending)
- No-unauthorized-mint (tokens)
- Timelock integrity (governance)
- Access-control completeness (admin coverage)
- Bridge message uniqueness
- ... and 13 more

### Disclaimer

Generated files ship with a banner comment stating clearly: this is a floor, not an audit. The README says the same. Making that obvious to users is part of the design.

## 6. Integrations

Two BSC protocols integrated in M3, each shipped with a case study (integration diff, gas impact, a live mainnet-fork replay).

Candidates sourced from:

- MVB S9 cohort (via BNB Chain DevRel intros)
- Past audit clients open to public case studies
- Smaller lending markets that have asked for safety tooling in public

## 7. Audit + release

Component 1 (CircuitBreaker) gets an external audit in M3 before GA. Targeting Trail of Bits, Spearbit, or Zellic depending on availability. Audit budget lives in M3.

Components 2 and 3 ship as beta at end of M3 with an open issue tracker. Commitment to a stable 1.0 within 90 days post-grant based on real-world feedback.

## 8. Licensing

MIT across the board. No wrappers, no dual license, no CLA. PRs welcome.

## 9. After the grant

Grant funds the initial build. Maintenance after that comes from:

- My ongoing audit work — which funds maintainer time directly
- Protocol integrations where the integrating team covers the integration work
- Follow-on grants for specific extensions (opBNB, more detector packs, formal verification of the library)

No token, no SaaS tier, no commercial fork. This stays a public good.

## 10. References

- EIP-7265: https://github.com/ethereum/EIPs/pull/7265
- BNB Chain Builder Grant Wishlist H2 2025
- Post-mortems used for detector calibration: full list available on request