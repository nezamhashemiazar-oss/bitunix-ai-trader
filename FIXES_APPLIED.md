# Safety Fixes Applied — Bitunix AI Trader

This patch addresses the five priority areas from the initial audit. It does not claim the project is production-ready; the complete dependency-backed test suite and live exchange contract tests still need to pass.

## Changes

1. **Entry authorization:** `openFromSignal()` now checks `auto_trade` at the execution boundary. MCP/AI callers cannot bypass the switch. `reverse()` checks the switch before closing the existing position.
2. **Restart behavior:** `auto_trade` defaults to `false`. `seedSettings()` forces the persisted setting OFF at boot unless `AUTO_TRADE_PERSIST=1` is explicitly enabled.
3. **Liquidation data:** new entries fail closed if position-tier data is missing or invalid. `resolveEffectiveLiqPrice()` treats `liqPrice: "0"` as unreported and derives an estimate only with valid leverage and maintenance-margin data. Position guard paths use the same resolver and skip liquidation-sensitive changes when required data is unavailable. Entry also rejects invalid price/ATR data.
4. **TP/SL:** every entry order now includes both a finite, exchange-rounded TP and SL. Adaptive trend runners receive a protective 3R exchange TP cap instead of sending an entry without TP.
5. **Fill/DB correctness:** if order detail cannot confirm a fill, the executor reconciles against live positions. If it still cannot confirm the filled quantity, it does not create a trade record or assume the requested quantity filled. The PostgreSQL pool no longer overrides URL `sslmode` with a hard-coded SSL object.

Also added `npm run check`, `npm run harness`, and static regression checks for the key safety invariants.

## Verification

Passed:
- `npm run check` — syntax validation of 56 JavaScript files.
- `node tests/test-safety-static.js` — all static safety invariants passed.
- `node tests/test-sign.js` — 15 assertions passed.
- `node tests/test-error-codes.js` — 29 assertions passed.
- `node tests/test-reporter.js` — 76 assertions passed.

Not verified:
- Full `npm test`: incomplete because the supplied `node_modules` directory was partial and `npm ci --ignore-scripts --no-audit --no-fund` timed out in this environment. Missing package files included `dotenv`, `pg`, and `ws`; tests requiring those modules could not start.
- Live Bitunix testnet/mainnet calls: not run. No credentials were read, and no orders were placed.
- Complete endpoint/parameter parity: not certified by this safety patch.

## Deployment notes

- Keep `AUTO_TRADE_PERSIST=false` (or unset). Use `/autotrade on` only when deliberately authorizing live entries.
- Do not enable live trading until a clean `npm ci`, full `npm test`, exchange testnet contract tests, and manual review pass.
- This uploaded application remains JavaScript/Node.js, not the separate Go J+rock agent requested in the project brief.
