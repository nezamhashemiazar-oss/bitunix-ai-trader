/**
 * The market feed must never be the reason a process stays alive.
 *
 * BUG (measured 2026-10-31): BitunixSocket's constructor started a ref'd 250ms
 * "pump" interval. MarketFeed builds two of those at MODULE LOAD, so any process
 * that merely imported the feed — every suite under tests/, a one-shot script,
 * or the bot after stop() — printed its last line and then hung forever.
 * `npm test` never finished: test-scan-report.js passes every assertion and then
 * sits in epoll_wait. The same ref'd interval also meant a SIGINT shutdown could
 * not complete while the socket was down and a reconnect was pending.
 *
 * What must hold now:
 *   - a bare `import ws.js` exits on its own, with no network and no exit call
 *   - the pump, the ping timer and the reconnect timer are all unref'd
 *   - close() stops the timers and cancels any reconnect the 'close' event
 *     handler would otherwise schedule
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import feed from '../src/exchange/ws.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const wsPath = resolve(root, 'src/exchange/ws.js');

let passed = 0, failed = 0;
const assert = (c, m) => { c ? (passed++, console.log(`  ok  ${m}`)) : (failed++, console.log(`  FAIL ${m}`)); };
const ref = (t) => (typeof t?.hasRef === 'function' ? t.hasRef() : null);

console.log('=== WebSocket feed timers do not hold a process open ===\n');

console.log('A bare import exits by itself');
{
  // A child process is the only honest way to prove this: if the module kept
  // the loop alive, the parent's own handles would mask it.
  const r = spawnSync(
    process.execPath,
    ['--input-type=module', '-e', `import ${JSON.stringify(wsPath)}; console.log('imported');`],
    { cwd: root, timeout: 10_000, encoding: 'utf8' },
  );
  assert(r.status === 0,
    `the process exited on its own (status ${r.status}${r.signal ? `, signal ${r.signal}` : ''})`);
  assert(String(r.signal || '') === '', 'it was not killed for hanging');
  assert(/imported/.test(r.stdout || ''), 'the import itself completed');
}

console.log('\nEvery timer the feed owns is unref\u2019d');
{
  const pub = feed.pub;
  assert(pub && pub._pump, 'the socket owns an out-queue pump');
  assert(ref(pub._pump) === false, `the 250ms pump is unref'd (hasRef ${ref(pub._pump)})`);

  pub._startPing();
  assert(pub.pingTimer && ref(pub.pingTimer) === false,
    `the 5s ping timer is unref'd (hasRef ${ref(pub.pingTimer)})`);
}

console.log('\nclose() stops the timers and cancels reconnects');
{
  const pub = feed.pub;
  pub.close();
  assert(pub._closed === true, 'the socket is marked closed');
  // The exchange is unreachable here, so the 'close' handler is the shape that
  // matters: it must not queue another connect() after stop().
  assert(pub._retryTimer === null || pub._retryTimer === undefined,
    'no reconnect timer survives close()');
  pub.connect();
  assert(pub.ws === null || pub.ws === undefined,
    'connect() after close() does not open a new socket');
}

console.log(`\npassed ${passed}, failed ${failed}`);
process.exit(failed ? 1 : 0);
