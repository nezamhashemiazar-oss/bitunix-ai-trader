/** Static regression guards for the critical live-trading safety invariants. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');
const executor = read('src/trading/executor.js');
const config = read('src/config.js');
const db = read('src/db/index.js');
const manager = read('src/trading/manager.js');
const risk = read('src/trading/risk.js');
const assert = (condition, label) => {
  if (!condition) throw new Error(`FAIL: ${label}`);
  console.log(`ok  ${label}`);
};
assert(/auto_trade:\s*bool\(process\.env\.AUTO_TRADE,\s*false\)/.test(config), 'auto_trade defaults OFF');
assert(/autoTradePersist:\s*bool\(process\.env\.AUTO_TRADE_PERSIST,\s*false\)/.test(config), 'persistence requires explicit opt-in');
assert(/boot-safety/.test(db) && /value = 'false'::jsonb/.test(db), 'boot resets persisted authorization OFF by default');
assert(/live entries are disabled/.test(executor), 'entry execution boundary checks authorization');
assert(/reversal is disabled/.test(executor), 'reversal cannot close first and then fail to reopen');
assert(/position tiers unavailable.*refusing entry/s.test(executor), 'missing tier data refuses entry');
assert(/order\.tpPrice = tpPrice/.test(executor) && /order\.slPrice|slPrice,/.test(executor), 'entry order carries exchange-side TP and SL');
assert(/fill quantity could not be confirmed/.test(executor), 'unconfirmed fill is never booked as requested quantity');
assert(/resolveEffectiveLiqPrice/.test(risk) && /effectiveLiqPrice/.test(risk), 'shared effective liquidation price resolver exists');
assert(/guard pass fails closed/.test(manager), 'position guard fails closed without tier/liquidation data');
assert(!/ssl:\s*config\.db\.url/.test(db), 'PostgreSQL SSL mode is not overridden in code');
console.log('Safety static regression checks passed.');
