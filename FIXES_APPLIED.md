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

## Follow-up fixes (2026-10-31)

Three defects surfaced by running the suite end to end (`node_modules` is now
installable, so `npm test` actually executes). Two were real bugs in shipped
code; the third was a suite that had drifted out of date with the safety patch
above.

1. **A dead 1m candle feed killed the whole guard loop** (`src/trading/manager.js`).
   The pass ATR selection — execution-TF (1m) ATR, falling back to the
   structure-TF ATR via `stopAtrFor()` — was computed *after* the price/ATR gate,
   and that gate tested the raw 1m `atr`. When the 1m kline fetch failed (its own
   `try/catch` swallows it, leaving `atr` null), every position was skipped with
   "valid price/ATR unavailable; guard pass fails closed": no rescue bracket, no
   breakeven, no trailing — while the structure-TF candles that the fallback
   wanted were fine. The fallback was unreachable dead code. The selection is now
   resolved before the gate, the gate tests the resolved `guardAtr`, and the
   rescue attach path sizes off the same value.
2. **The WebSocket feed pinned every process alive** (`src/exchange/ws.js`).
   `BitunixSocket`'s constructor started a *ref'd* 250 ms out-queue pump, and
   `MarketFeed` builds two sockets at module load. So any process that merely
   imported the feed printed its last line and then hung: `npm test` never
   finished (its last suite passed every assertion and then sat in `epoll_wait`),
   and a SIGINT `stop()` could not complete while a reconnect was pending. The
   pump, the 5 s ping timer and the reconnect timer are now unref'd, `close()`
   clears all three, and `connect()`/the `close` event refuse to reconnect once
   `close()` has been called. New regression suite:
   `node tests/test-ws-timers.js` (verified to fail 6 assertions against the old
   module).

Suite-only corrections, no production behavior changed:

- `tests/test-leverage-sync.js` seeds `auto_trade: true`. The execution-boundary
  authorization gate (change 1 above) refuses every entry before the leverage
  logic it was written to measure; `test-safety-static.js` still owns the gate's
  own regression check. Its `get_order_detail` stub also returned
  `{ status: 'FILLED', tradeQty: 0 }`, i.e. a "fill" of zero quantity, which the
  fill-confirmation guard (change 5) correctly refuses; the stub now reports the
  quantity actually placed.

Verification after these fixes:

- `npm test` — all 22 suites pass, and the run terminates on its own.
- `npm run check` — syntax validation of 57 JavaScript files.
- `node tests/test-manage-loop.js` — 60/60 (the structure-TF ATR fallback case
  previously failed 1).
- `node tests/test-ws-timers.js` — 9/9.
- No live exchange calls were made.
