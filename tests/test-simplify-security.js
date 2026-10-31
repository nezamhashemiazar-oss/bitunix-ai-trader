/**
 * Security test for /simplify command — path traversal mitigation.
 *
 * The /simplify command reads files from disk. Before the fix, an attacker could
 * supply a path like "../../../etc/passwd" to read arbitrary files outside the
 * project directory.
 *
 * The mitigation (src/telegram/commands.js) now:
 *   1. Resolves the base directory (process.cwd())
 *   2. Joins the user-supplied path to the base
 *   3. Computes the relative path from base to the joined result
 *   4. Rejects if the relative path is "..", starts with "../", or is absolute
 *
 * This test verifies that all common path traversal attack vectors are blocked.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let passed = 0, failed = 0;
const assert = (c, m) => { 
  c ? (passed++, console.log(`  ok  ${m}`)) : (failed++, console.log(`  FAIL ${m}`)); 
};

const CHAT = 12345;

async function test() {
  console.log('=== /simplify command — path traversal security ===\n');

  // A bot that captures instead of sending.
  const sent = [];
  const fakeBot = {
    sendMessage: (chatId, text) => { sent.push({ chatId, text }); return []; },
    sendTyping: async () => {},
  };

  const { createCommandHandler } = await import('../src/telegram/commands.js');
  const handle = createCommandHandler({ bot: fakeBot, orchestrator: null });

  /** Send a raw "/simplify ..." message and return the last reply's text. */
  const run = async (text) => {
    sent.length = 0;
    await handle({ chat: { id: CHAT }, text });
    return String(sent.at(-1)?.text ?? '');
  };

  // Create a test file in the project directory that we CAN read
  const testDir = path.join(process.cwd(), 'tests');
  const testFile = path.join(testDir, 'test-simplify-dummy.txt');
  fs.writeFileSync(testFile, 'function test() { return 42; }', 'utf8');

  console.log('Legitimate file access (baseline)');
  const legitimate = await run('/simplify tests/test-simplify-dummy.txt');
  assert(
    !legitimate.includes('Invalid file path') && !legitimate.startsWith('❌'),
    'legitimate relative path is allowed'
  );
  assert(
    legitimate.includes('Simplification analysis') || legitimate.includes('test-simplify-dummy.txt'),
    'legitimate file is processed'
  );

  console.log('\nPath traversal attacks (must be blocked)');

  // Attack 1: Classic parent directory traversal
  const attack1 = await run('/simplify ../package.json');
  assert(
    attack1.includes('Invalid file path'),
    'blocks "../package.json" (parent directory escape)'
  );

  // Attack 2: Multiple levels of traversal
  const attack2 = await run('/simplify ../../etc/passwd');
  assert(
    attack2.includes('Invalid file path'),
    'blocks "../../etc/passwd" (multi-level traversal)'
  );

  // Attack 3: Traversal after legitimate path component
  const attack3 = await run('/simplify tests/../../package.json');
  assert(
    attack3.includes('Invalid file path'),
    'blocks "tests/../../package.json" (traversal after valid component)'
  );

  // Attack 4: Absolute path (Unix-style)
  const attack4 = await run('/simplify /etc/passwd');
  // Note: On some systems, path.join with an absolute path might behave differently.
  // The important thing is that the file is NOT read. Either "Invalid file path"
  // or "File not found" indicates the attack was blocked (file not read).
  // However, "Invalid file path" is preferred as it catches the attack earlier.
  const attack4Blocked = attack4.includes('Invalid file path') || attack4.includes('File not found');
  assert(
    attack4Blocked,
    `blocks "/etc/passwd" (absolute Unix path) - got: ${attack4.slice(0, 50)}`
  );
  // Verify the file was NOT successfully read
  assert(
    !attack4.includes('Simplification analysis'),
    'absolute path does not result in file being analyzed'
  );

  // Attack 5: Absolute path (Windows-style, if applicable)
  if (process.platform === 'win32') {
    const attack5 = await run('/simplify C:\\Windows\\System32\\config\\sam');
    assert(
      attack5.includes('Invalid file path'),
      'blocks "C:\\Windows\\..." (absolute Windows path)'
    );
  }

  // Attack 6: URL-encoded traversal (basic)
  const attack6 = await run('/simplify ..%2F..%2Fetc%2Fpasswd');
  assert(
    attack6.includes('Invalid file path') || attack6.includes('File not found'),
    'blocks URL-encoded traversal (..%2F..%2F...)'
  );

  // Attack 7: Double-encoded traversal
  const attack7 = await run('/simplify ..%252F..%252Fetc%252Fpasswd');
  assert(
    attack7.includes('Invalid file path') || attack7.includes('File not found'),
    'blocks double-encoded traversal'
  );

  // Attack 8: Null byte injection (historical attack, may not apply to modern Node.js)
  const attack8 = await run('/simplify ../../../etc/passwd\x00.txt');
  assert(
    attack8.includes('Invalid file path') || attack8.includes('File not found'),
    'blocks null byte injection'
  );

  // Attack 9: Backslash traversal (Windows-style on Unix)
  const attack9 = await run('/simplify ..\\..\\etc\\passwd');
  assert(
    attack9.includes('Invalid file path') || attack9.includes('File not found'),
    'blocks backslash traversal'
  );

  // Attack 10: Mixed separators
  const attack10 = await run('/simplify ../tests\\../package.json');
  assert(
    attack10.includes('Invalid file path') || attack10.includes('File not found'),
    'blocks mixed separator traversal'
  );

  console.log('\nEdge cases');

  // Edge case 1: Empty path
  const edge1 = await run('/simplify');
  assert(
    edge1.includes('Usage: /simplify'),
    'empty path shows usage'
  );

  // Edge case 2: Just ".."
  const edge2 = await run('/simplify ..');
  assert(
    edge2.includes('Invalid file path'),
    'blocks bare ".." (parent directory)'
  );

  // Edge case 3: Current directory reference
  const edge3 = await run('/simplify ./tests/test-simplify-dummy.txt');
  assert(
    !edge3.includes('Invalid file path'),
    'allows "./" prefix (current directory reference)'
  );

  // Edge case 4: Nonexistent file (should fail with "File not found", not "Invalid")
  const edge4 = await run('/simplify tests/nonexistent-file-xyz.js');
  assert(
    edge4.includes('File not found') && !edge4.includes('Invalid file path'),
    'nonexistent file in valid location shows "File not found", not "Invalid"'
  );

  console.log('\nSecurity property verification');

  // Verify that the mitigation logic is actually present in the code
  const commandsSource = fs.readFileSync(
    path.join(process.cwd(), 'src/telegram/commands.js'),
    'utf8'
  );
  
  assert(
    commandsSource.includes('path.relative') && 
    commandsSource.includes('path.resolve') &&
    commandsSource.includes('Invalid file path'),
    'mitigation code (path.relative, path.resolve, validation) is present in commands.js'
  );

  assert(
    commandsSource.includes('rel === \'..\' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)'),
    'exact validation logic (checking for "..", "../", and absolute paths) is present'
  );

  // Clean up test file
  try {
    fs.unlinkSync(testFile);
  } catch (e) {
    // Ignore cleanup errors
  }

  console.log(`\npassed ${passed}, failed ${failed}`);
  process.exit(failed ? 1 : 0);
}

test().catch((e) => { console.error(e); process.exit(1); });
