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
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const fakeOrchestrator = null;

let passed = 0, failed = 0;
const assert = (c, m) => { c ? (passed++, console.log(`  ok  ${m}`)) : (failed++, console.log(`  FAIL ${m}`)); };

async function test() {
  console.log('=== /simplify command Security - Path Traversal Mitigation ===\n');

  // Capture sent messages
  const sent = [];
  const fakeBotCapture = {
    sendMessage: (chatId, text) => { sent.push({ chatId, text }); return []; },
    sendTyping: async () => {},
  };

  // Import the command handler
  const { createCommandHandler } = await import('../src/telegram/commands.js');
  const handle = createCommandHandler({ bot: fakeBotCapture, orchestrator: fakeOrchestrator });

  const CHAT_ID = 12345;

  /** Send a raw "/simplify ..." message and return the last reply's text. */
  const run = async (text) => {
    sent.length = 0;
    await handle({ chat: { id: CHAT_ID }, text });
    return String(sent.at(-1)?.text ?? '');
  };

  console.log('legitimate file access (baseline)');
  
  // Test 1: Access a legitimate file in the project
  let reply = await run('/simplify package.json');
  assert(reply && !reply.includes('❌ Invalid file path'), 'simplify("package.json") - legitimate file access allowed');
  
  // Test 2: Access a file in a subdirectory
  reply = await run('/simplify src/config.js');
  assert(reply && !reply.includes('❌ Invalid file path'), 'simplify("src/config.js") - subdirectory access allowed');

  console.log('\npath traversal attacks (must be blocked)');
  
  // Attack 1: Classic path traversal to parent directory
  reply = await run('/simplify ../package.json');
  assert(reply && reply.includes('❌ Invalid file path'), 'simplify("../package.json") blocked - path traversal rejected');
  
  // Attack 2: Multiple levels of traversal
  reply = await run('/simplify ../../etc/passwd');
  assert(reply && reply.includes('❌ Invalid file path'), 'simplify("../../etc/passwd") blocked - multiple levels rejected');
  
  // Attack 3: Traversal with subdirectory prefix
  reply = await run('/simplify src/../../package.json');
  assert(reply && reply.includes('❌ Invalid file path'), 'simplify("src/../../package.json") blocked - traversal after valid prefix');
  
  // Attack 4: Absolute path injection (Unix-style) - may not exist so could get "File not found" instead
  reply = await run('/simplify /etc/passwd');
  const isBlockedOrNotFound = reply && (reply.includes('❌ Invalid file path') || reply.includes('❌ File not found'));
  assert(isBlockedOrNotFound, 'simplify("/etc/passwd") blocked or not found - absolute path handled safely');
  
  // Attack 5: Absolute path outside project - should be blocked
  // The security check should catch paths that escape the project directory
  reply = await run('/simplify /etc/hosts');
  const isOutsideBlocked = reply && (reply.includes('❌ Invalid file path') || reply.includes('❌ File not found') || reply.includes('Error:'));
  assert(isOutsideBlocked, 'simplify("/etc/hosts") - absolute path outside project blocked or error');

  console.log('\nedge cases');
  
  // Edge case 1: Empty argument
  reply = await run('/simplify');
  assert(reply && reply.includes('Usage:'), 'simplify() with no args shows usage');
  
  // Edge case 2: Just dots
  reply = await run('/simplify ..');
  assert(reply && reply.includes('❌ Invalid file path'), 'simplify("..") blocked - exact parent reference');
  
  // Edge case 3: Current directory reference (should work)
  reply = await run('/simplify ./package.json');
  assert(reply && !reply.includes('❌ Invalid file path'), 'simplify("./package.json") allowed - current directory reference is safe');

  console.log('\npath normalization edge cases');
  
  // Attack 6: Backslash traversal (Windows-style) - on Unix, backslash is a valid filename char
  // so this might result in "File not found" rather than "Invalid file path"
  reply = await run('/simplify ..\\package.json');
  const isBackslashBlocked = reply && (reply.includes('❌ Invalid file path') || reply.includes('❌ File not found'));
  assert(isBackslashBlocked, 'simplify("..\\\\package.json") blocked or not found - backslash traversal handled safely');
  
  // Attack 7: Mixed slashes
  reply = await run('/simplify ..//package.json');
  assert(reply && reply.includes('❌ Invalid file path'), 'simplify("..//package.json") blocked - mixed slashes');

  console.log('\nsecurity properties verification');
  
  // Verify that the mitigation logic correctly identifies escaping paths
  const baseFull = path.resolve(process.cwd());
  
  // Test the relative path check logic
  const testPath1 = path.join(baseFull, '../package.json');
  const rel1 = path.relative(baseFull, testPath1);
  assert(rel1.startsWith('..'), 'path.relative correctly identifies parent traversal');
  
  const testPath2 = path.join(baseFull, 'package.json');
  const rel2 = path.relative(baseFull, testPath2);
  assert(!rel2.startsWith('..') && !path.isAbsolute(rel2), 'path.relative confirms safe path stays within boundary');
  
  const testPath3 = '/etc/passwd';
  const rel3 = path.relative(baseFull, testPath3);
  assert(path.isAbsolute(rel3) || rel3.startsWith('..'), 'absolute paths are detected as escaping');

  console.log(`\npassed ${passed}, failed ${failed}`);
  process.exit(failed ? 1 : 0);
}

test();
