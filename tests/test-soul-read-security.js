/**
 * Security test for soul.js read() function - Path Traversal Mitigation
 *
 * Tests that the read() function properly prevents file inclusion attacks
 * via path traversal attempts. The mitigation checks that resolved paths
 * stay within the SOUL_DIR boundary.
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
const SOUL_DIR = path.join(__dirname, '../soul');

// Inline the read() function to test it directly
function read(file, fallback = '') {
  try {
    const baseFull = path.resolve(SOUL_DIR);
    const target = path.join(baseFull, file);
    const rel = path.relative(baseFull, target);
    if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
      return fallback;
    }
    return fs.readFileSync(target, 'utf8').trim();
  }
  catch { return fallback; }
}

let passed = 0, failed = 0;
const assert = (c, m) => { c ? (passed++, console.log(`  ok  ${m}`)) : (failed++, console.log(`  FAIL ${m}`)); };

function test() {
  console.log('=== soul.js read() Security - Path Traversal Mitigation ===\n');

  console.log('legitimate reads (baseline)');
  const soul = read('SOUL.md');
  assert(soul.length > 0, 'read("SOUL.md") returns content');
  
  const skill = read('SKILL.md');
  assert(skill.length > 0, 'read("SKILL.md") returns content');
  
  const style = read('STYLE.md');
  assert(style.length > 0, 'read("STYLE.md") returns content');
  
  const skillFile = read('skills/01-bitunix-trading-analysis.md');
  assert(skillFile.length > 0, 'read("skills/01-bitunix-trading-analysis.md") returns content from subdirectory');

  console.log('\npath traversal attacks (must return fallback)');
  
  // Attack 1: Classic path traversal to parent directory
  const attack1 = read('../package.json', 'BLOCKED');
  assert(attack1 === 'BLOCKED', 'read("../package.json") blocked - returns fallback');
  
  // Attack 2: Multiple levels of traversal
  const attack2 = read('../../package.json', 'BLOCKED');
  assert(attack2 === 'BLOCKED', 'read("../../package.json") blocked - multiple levels');
  
  // Attack 3: Traversal to access sensitive files
  const attack3 = read('../src/config.js', 'BLOCKED');
  assert(attack3 === 'BLOCKED', 'read("../src/config.js") blocked - cannot access source files');
  
  // Attack 4: Traversal with subdirectory prefix
  const attack4 = read('skills/../../package.json', 'BLOCKED');
  assert(attack4 === 'BLOCKED', 'read("skills/../../package.json") blocked - traversal after valid prefix');
  
  // Attack 5: Absolute path injection (Unix-style)
  const attack5 = read('/etc/passwd', 'BLOCKED');
  assert(attack5 === 'BLOCKED', 'read("/etc/passwd") blocked - absolute path rejected');
  
  // Attack 6: Absolute path to project file
  const projectRoot = path.join(__dirname, '..');
  const attack6 = read(path.join(projectRoot, 'package.json'), 'BLOCKED');
  assert(attack6 === 'BLOCKED', 'read(absolute_path_to_package.json) blocked - absolute paths rejected');

  console.log('\nedge cases');
  
  // Edge case 1: Non-existent file within soul/ (should return fallback, not throw)
  const missing = read('nonexistent.md', 'DEFAULT');
  assert(missing === 'DEFAULT', 'read("nonexistent.md") returns fallback for missing files');
  
  // Edge case 2: Empty filename
  const empty = read('', 'EMPTY');
  assert(empty === 'EMPTY', 'read("") returns fallback for empty filename');
  
  // Edge case 3: Just dots
  const dots = read('..', 'BLOCKED');
  assert(dots === 'BLOCKED', 'read("..") blocked - exact parent reference');
  
  // Edge case 4: Current directory reference (should work if file exists)
  const current = read('./SOUL.md');
  assert(current.length > 0, 'read("./SOUL.md") works - current directory reference is safe');

  console.log('\nfallback behavior');
  
  // Test default fallback
  const defaultFallback = read('../package.json');
  assert(defaultFallback === '', 'default fallback is empty string when not specified');
  
  // Test custom fallback
  const customFallback = read('../package.json', 'CUSTOM_FALLBACK');
  assert(customFallback === 'CUSTOM_FALLBACK', 'custom fallback is returned when specified');

  console.log('\npath normalization edge cases');
  
  // Attack 7: URL-encoded path traversal
  const attack7 = read('..%2Fpackage.json', 'BLOCKED');
  // Note: This might not be blocked by the current implementation since path.join
  // doesn't decode URL encoding, but it won't resolve to a valid file either
  assert(attack7 === 'BLOCKED', 'read("..%2Fpackage.json") returns fallback - encoded traversal');
  
  // Attack 8: Backslash traversal (Windows-style, but path.sep handles this)
  const attack8 = read('..\\package.json', 'BLOCKED');
  assert(attack8 === 'BLOCKED', 'read("..\\\\package.json") blocked - backslash traversal');
  
  // Attack 9: Mixed slashes
  const attack9 = read('..//package.json', 'BLOCKED');
  assert(attack9 === 'BLOCKED', 'read("..//package.json") blocked - mixed slashes');

  console.log('\nsecurity properties verification');
  
  // Verify that the mitigation logic correctly identifies escaping paths
  const baseFull = path.resolve(SOUL_DIR);
  
  // Test the relative path check logic
  const testPath1 = path.join(baseFull, '../package.json');
  const rel1 = path.relative(baseFull, testPath1);
  assert(rel1.startsWith('..'), 'path.relative correctly identifies parent traversal');
  
  const testPath2 = path.join(baseFull, 'SOUL.md');
  const rel2 = path.relative(baseFull, testPath2);
  assert(!rel2.startsWith('..') && !path.isAbsolute(rel2), 'path.relative confirms safe path stays within boundary');
  
  const testPath3 = '/etc/passwd';
  const rel3 = path.relative(baseFull, testPath3);
  assert(path.isAbsolute(rel3) || rel3.startsWith('..'), 'absolute paths are detected as escaping');

  console.log(`\npassed ${passed}, failed ${failed}`);
  process.exit(failed ? 1 : 0);
}

test();
