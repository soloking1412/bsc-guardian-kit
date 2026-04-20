# BSC Guardian Kit

Open-source safety toolkit for BNB Chain protocols. MIT.

Built by [@soloking1412](https://github.com/soloking1412) while auditing too many BSC post-mortems.

---

Three pieces. Use one, use all three, fork whatever you want.

- **CircuitBreaker** — Solidity library. Caps how much can leave a contract per block or per epoch. EIP-7265 with some BSC-specific additions.
- **Guardian Agent SDK** — off-chain watcher. Ten detectors ship in-box. When something matches, it trips the circuit breaker through a pre-authorized role that can only *reduce* risk (pause, lower caps) — never move funds, never upgrade, never take ownership.
- **Invariant Suite Generator** — Foundry CLI. Point it at an ABI, get a starter invariant + fuzzing suite with BSC hazard templates pre-loaded. Runs in CI.

No SaaS, no token, no telemetry phoning home. Self-host the whole thing.

## Why bother

Phalcon, Hexagate, Hypernative, Forta, Venn — all real, all good, all paid, all chain-agnostic. They work great for protocols that can spend $5k–$20k a month. Most BSC protocols can't.

The long tail runs with nothing. Venus ate a $2.15M donation attack in Q1 2026. Hyperbridge lost $2.5M in April. In both cases a per-block outflow cap would have bounded the loss to a fraction of what actually left the contracts.

This repo is the floor. It's what every BSC protocol should have in place before they even think about paying for monitoring.

## Status

Week 0. Under a BNB Chain Builder Grant proposal. Targeting mainnet-ready at Week 12.

Roadmap:

- [ ] M1 — Circuit Breaker library, Foundry tests, two reference integrations, gas report
- [ ] M2 — Guardian Agent SDK, 10 detectors, exploit replay suite
- [ ] M3 — Invariant Suite Generator, external audit of the library, two live integrations

Track progress in [SPEC.md](./SPEC.md) and the issues.

## How it looks

### Circuit breaker in a lending market

```solidity
import {CircuitBreaker} from "@bsc-guardian-kit/contracts/CircuitBreaker.sol";

contract MyMarket is CircuitBreaker {
    constructor() {
        _registerToken(USDT, 500_000e18, 1 hours);
        _registerToken(BUSD, 500_000e18, 1 hours);
    }

    function withdraw(address token, uint256 amount) external {
        _beforeOutflow(token, amount);
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

If someone tries to drain more than 500k in an hour, the breaker trips. You choose what "trip" means: revert, delay the excess 24h, or pause the token entirely.

### Guardian agent

```bash
npx @bsc-guardian-kit/agent init \
  --protocol 0xYourProtocol \
  --detectors donation,oracle,flashloan \
  --guardian-key $GUARDIAN_KEY
```

Runs as a single process. Reads mempool and state. Fires guardian actions when detectors agree.

### Invariants

```bash
forge guardian-init 0xYourProtocol --out test/invariants/
forge test --mt invariant_
```

Gets you from "no invariant tests" to "reasonable invariant tests in CI" in one command. Not a replacement for an audit. A floor.

## Architecture

```
          Your Protocol
               │
     ┌─────────┴─────────┐
     ▼                   ▼
CircuitBreaker     Invariant Suite
  (on-chain)       (CI / Foundry)
     ▲
     │ pre-authorized
     │ guardian role
     │
Guardian Agent  ←── mempool + state detectors
 (off-chain)
```

Each layer stands alone. Mix and match.

## License

MIT. Ship it.

## Getting in touch

- X: [@soloking1412](https://twitter.com/lord_soloking)
- Email: maheswar141203@gmail.com

If you run a BSC protocol and want to integrate during the grant period, it's free. Open an issue or email me.