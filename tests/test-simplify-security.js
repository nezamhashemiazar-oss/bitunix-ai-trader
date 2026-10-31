/**
 * Security test for /simplify command - Path Traversal Mitigation
 *
 * Tests that the /simplify command properly prevents file inclusion attacks
 * via path traversal attempts. The mitigation checks that resolved paths
 * stay within the process.cwd() boundary.
 *
 * Attack vectors tested:
 *   1. Classic path traversal with ../
 *   2. Absolute path injection
 *   3. Multiple levels of traversal
 *   4. Mixed traversal patterns
 * Security test for /simplify command — path traversal mitigation.
 *
 * This test verifies that the /simplify command properly rejects attempts to
 * read files outside the project directory via path traversal attacks.
 *
 * The mitigation (applied in src/telegram/commands.js) validates that the
 * resolved file path stays within the project root by checking:
 *   1. The relative path from baseFull to filePath
 *   2. Rejecting if rel === '..' or starts with '../' or is absolute
 *
 * Attack vectors tested:
 *   - Classic path traversal: ../../../etc/passwd
 *   - Absolute paths: /etc/passwd
 *   - Windows absolute paths: C:\Windows\System32\config\sam
 *   - Mixed traversal: src/../../etc/passwd
 *   - URL-encoded traversal: ..%2F..%2Fetc%2Fpasswd (decoded by shell/bot)
 *
 * The test does NOT attempt to actually read sensitive files; it only verifies
 * that the validation logic rejects the malicious paths before fs.readFileSync.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let passed = 0, failed = 0;
const assert = (c, m) => { 
  c ? (passed++, console.log(`  ok  ${m}`)) : (failed++, console.log(`  FAIL ${m}`)); 
};
const here = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(here, '..');

let passed = 0, failed = 0;
const assert = (c, m) => { c ? (passed++, console.log(`  ok  ${m}`)) : (failed++, console.log(`  FAIL ${m}`)); };

async function test() {
  console.log('=== /simplify command Security - Path Traversal Mitigation ===\n');
  console.log('=== /simplify command — path traversal security ===\n');
  console.log('=== /simplify security — path traversal mitigation ===\n');

  // Capture sent messages
  const sent = [];
  const fakeBotCapture = {
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

  console.log('Baseline: valid file within project is accepted');
  // Create a temporary test file in the project
  const testFile = path.join(projectRoot, 'test-temp-file.js');
  fs.writeFileSync(testFile, '// test file\nfunction hello() { return "world"; }\n', 'utf8');
  
  try {
    const valid = await run('/simplify test-temp-file.js');
    assert(!includes(valid, '❌ Invalid file path'), 'valid relative path is accepted');
    assert(includes(valid, '🧹 Simplification analysis') || includes(valid, '❌ File not found'), 
      'valid path proceeds to file check or analysis');
  } finally {
    // Clean up test file
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  }

  console.log('\nPath traversal attacks are rejected');
  
  // Test 1: Classic upward traversal
  let result = await run('/simplify ../../../etc/passwd');
  assert(includes(result, '❌ Invalid file path'), 
    'rejects ../../../etc/passwd (classic traversal)');
  assert(!includes(result, 'root:'), 
    'does not leak /etc/passwd content');

  // Test 2: Absolute Unix path
  // Note: Absolute paths may be rejected as "File not found" rather than 
  // "Invalid file path" because path.join() with an absolute second argument
  // returns that absolute path, which then fails the existence check.
  // This is still secure - the file is not read.
  result = await run('/simplify /etc/passwd');
  assert(includes(result, '❌ Invalid file path') || includes(result, '❌ File not found'), 
    'rejects /etc/passwd (absolute Unix path)');

  // Test 3: Absolute Windows path
  result = await run('/simplify C:\\Windows\\System32\\config\\sam');
  assert(includes(result, '❌ Invalid file path') || includes(result, '❌ File not found'), 
    'rejects C:\\Windows\\System32\\config\\sam (absolute Windows path)');

  // Test 4: Mixed traversal (valid prefix, then escape)
  result = await run('/simplify src/../../etc/passwd');
  assert(includes(result, '❌ Invalid file path'), 
    'rejects src/../../etc/passwd (mixed traversal)');

  // Test 5: Parent directory reference
  result = await run('/simplify ..');
  assert(includes(result, '❌ Invalid file path'), 
    'rejects .. (parent directory)');

  // Test 6: Parent with trailing separator
  result = await run('/simplify ../');
  assert(includes(result, '❌ Invalid file path'), 
    'rejects ../ (parent with separator)');

  // Test 7: Hidden file traversal
  result = await run('/simplify ../../.ssh/id_rsa');
  assert(includes(result, '❌ Invalid file path'), 
    'rejects ../../.ssh/id_rsa (SSH key traversal)');

  // Test 8: Traversal to project parent
  result = await run('/simplify ../package.json');
  assert(includes(result, '❌ Invalid file path'), 
    'rejects ../package.json (one level up)');

  console.log('\nEdge cases are handled correctly');

  // Test 9: Empty path
  result = await run('/simplify');
  assert(includes(result, 'Usage: /simplify'), 
    'empty path shows usage (not a security issue, but good UX)');

  // Test 10: Whitespace-only path
  result = await run('/simplify    ');
  assert(includes(result, 'Usage: /simplify'), 
    'whitespace-only path shows usage');

  // Test 11: Path with null bytes (if not sanitized by Telegram)
  result = await run('/simplify test\x00.js');
  // Null bytes should either be rejected or treated as end-of-string
  assert(includes(result, '❌ Invalid file path') || includes(result, '❌ File not found'), 
    'null byte in path is handled safely');

  console.log('\nValid paths within project are still allowed');

  // Test 12: Subdirectory access
  result = await run('/simplify src/telegram/commands.js');
  assert(!includes(result, '❌ Invalid file path'), 
    'src/telegram/commands.js is accepted (valid subdirectory)');
  assert(includes(result, '🧹 Simplification analysis') || includes(result, 'File not found'), 
    'valid subdirectory path proceeds to analysis');

  // Test 13: Nested subdirectory
  result = await run('/simplify src/ai/agent.js');
  assert(!includes(result, '❌ Invalid file path'), 
    'src/ai/agent.js is accepted (nested subdirectory)');

  // Test 14: Tests directory
  result = await run('/simplify tests/run.js');
  assert(!includes(result, '❌ Invalid file path'), 
    'tests/run.js is accepted (tests directory)');

  console.log('\nPath normalization edge cases');

  // Test 15: Redundant separators
  result = await run('/simplify src//telegram//commands.js');
  assert(!includes(result, '❌ Invalid file path'), 
    'src//telegram//commands.js is accepted (redundant separators normalized)');

  // Test 16: Current directory prefix
  result = await run('/simplify ./src/telegram/commands.js');
  assert(!includes(result, '❌ Invalid file path'), 
    './src/telegram/commands.js is accepted (current dir prefix)');

  // Test 17: Traversal that stays within project
  result = await run('/simplify src/../package.json');
  assert(!includes(result, '❌ Invalid file path'), 
    'src/../package.json is accepted (normalizes to package.json)');

  console.log(`\npassed ${passed}, failed ${failed}`);
  process.exit(failed ? 1 : 0);
}

test();
test().catch((e) => { console.error(e); process.exit(1); });
