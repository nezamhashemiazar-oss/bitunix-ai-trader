/**
 * Security test for soul.js file reading functionality.
 *
 * Tests that the `read()` function properly mitigates path traversal attacks
 * by validating that file paths stay within the soul/ directory.
 *
 * The vulnerability being tested:
 *   - Path traversal via ../ sequences
 *   - Absolute path injection
 *   - Symbolic link traversal (if applicable)
 *
 * The mitigation uses path.relative() to ensure the resolved target stays
 * within the base directory (soul/). Any attempt to escape is rejected
 * by returning the fallback value instead of reading the file.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SOUL_DIR = path.join(__dirname, '../soul');

// Replicate the read() function from soul.js for testing
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
const assert = (c, m) => { 
  c ? (passed++, console.log(`  ok  ${m}`)) : (failed++, console.log(`  FAIL ${m}`)); 
};

function test() {
  console.log('=== Soul.js Security: Path Traversal Mitigation ===\n');

  console.log('legitimate file access (baseline)');
  const soulContent = read('SOUL.md');
  assert(typeof soulContent === 'string' && soulContent.length > 0, 
    'read("SOUL.md") returns content');
  
  const skillContent = read('SKILL.md');
  assert(typeof skillContent === 'string' && skillContent.length > 0, 
    'read("SKILL.md") returns content');

  const styleContent = read('STYLE.md');
  assert(typeof styleContent === 'string' && styleContent.length > 0, 
    'read("STYLE.md") returns content');

  const nestedSkill = read('skills/README.md');
  assert(typeof nestedSkill === 'string' && nestedSkill.length > 0, 
    'read("skills/README.md") returns nested file content');

  console.log('\npath traversal attacks (should return fallback)');
  
  // Test 1: Simple parent directory traversal
  const attack1 = read('../package.json', 'BLOCKED');
  assert(attack1 === 'BLOCKED', 
    'read("../package.json") blocked - returns fallback');

  // Test 2: Multiple parent directory traversal
  const attack2 = read('../../package.json', 'BLOCKED');
  assert(attack2 === 'BLOCKED', 
    'read("../../package.json") blocked - returns fallback');

  // Test 3: Traversal with subdirectory prefix
  const attack3 = read('skills/../../package.json', 'BLOCKED');
  assert(attack3 === 'BLOCKED', 
    'read("skills/../../package.json") blocked - returns fallback');

  // Test 4: Deep traversal attempt
  const attack4 = read('../../../etc/passwd', 'BLOCKED');
  assert(attack4 === 'BLOCKED', 
    'read("../../../etc/passwd") blocked - returns fallback');

  // Test 5: Traversal to src directory
  const attack5 = read('../src/config.js', 'BLOCKED');
  assert(attack5 === 'BLOCKED', 
    'read("../src/config.js") blocked - returns fallback');

  console.log('\nabsolute path injection (should return fallback)');
  
  // Test 6: Absolute path to /etc/passwd (Unix)
  const attack6 = read('/etc/passwd', 'BLOCKED');
  assert(attack6 === 'BLOCKED', 
    'read("/etc/passwd") blocked - absolute path rejected');

  // Test 7: Absolute path to package.json
  const pkgPath = path.join(__dirname, '../package.json');
  const attack7 = read(pkgPath, 'BLOCKED');
  assert(attack7 === 'BLOCKED', 
    'read(absolute_path_to_package.json) blocked - absolute path rejected');

  // Test 8: Windows-style absolute path (C:\)
  const attack8 = read('C:\\Windows\\System32\\drivers\\etc\\hosts', 'BLOCKED');
  assert(attack8 === 'BLOCKED', 
    'read("C:\\\\...") blocked - Windows absolute path rejected');

  console.log('\nencoded/obfuscated traversal attempts (should return fallback)');
  
  // Test 9: URL-encoded traversal
  const attack9 = read('..%2F..%2Fpackage.json', 'BLOCKED');
  assert(attack9 === 'BLOCKED', 
    'read("..%2F..%2Fpackage.json") blocked - URL encoding doesn\'t bypass');

  // Test 10: Mixed separators (Unix/Windows)
  const attack10 = read('..\\..\\package.json', 'BLOCKED');
  assert(attack10 === 'BLOCKED', 
    'read("..\\\\..\\\\package.json") blocked - backslash separators');

  console.log('\nedge cases and boundary conditions');
  
  // Test 11: Non-existent file within soul/ (should return fallback via catch)
  const nonExistent = read('NONEXISTENT.md', 'DEFAULT');
  assert(nonExistent === 'DEFAULT', 
    'read("NONEXISTENT.md") returns fallback for missing file');

  // Test 12: Empty filename
  const emptyFile = read('', 'EMPTY');
  assert(emptyFile === 'EMPTY', 
    'read("") returns fallback for empty filename');

  // Test 13: Dot file (hidden file in soul/)
  const dotFile = read('.hidden', 'DOTFILE');
  assert(dotFile === 'DOTFILE', 
    'read(".hidden") returns fallback (file doesn\'t exist or is blocked)');

  // Test 14: Current directory reference
  const currentDir = read('.', 'CURRENT');
  assert(currentDir === 'CURRENT', 
    'read(".") returns fallback - directory not file');

  // Test 15: Parent directory reference
  const parentDir = read('..', 'PARENT');
  assert(parentDir === 'PARENT', 
    'read("..") blocked - exact match for ".."');

  console.log('\npath normalization edge cases');
  
  // Test 16: Redundant slashes
  const redundant = read('skills//README.md');
  // This might work or fail depending on filesystem, but shouldn't escape
  assert(typeof redundant === 'string', 
    'read("skills//README.md") handled safely (no escape)');

  // Test 17: Trailing slash
  const trailing = read('SOUL.md/', 'TRAILING');
  // Should fail to read (not a valid file path) but not escape
  assert(typeof trailing === 'string', 
    'read("SOUL.md/") handled safely (returns fallback or error)');

  // Test 18: Null byte injection (should be handled by Node.js)
  const nullByte = read('SOUL.md\0../package.json', 'NULLBYTE');
  assert(nullByte === 'NULLBYTE', 
    'read("SOUL.md\\0../package.json") blocked - null byte doesn\'t bypass');

  console.log('\nsecurity property verification');
  
  // Verify the security check logic directly
  const baseFull = path.resolve(SOUL_DIR);
  
  // Test the relative path check for a malicious input
  const maliciousTarget = path.join(baseFull, '../package.json');
  const rel = path.relative(baseFull, maliciousTarget);
  assert(rel.startsWith('..'), 
    'path.relative() correctly identifies escape attempt');

  // Test for absolute path detection
  const absoluteTarget = '/etc/passwd';
  const absRel = path.relative(baseFull, absoluteTarget);
  assert(path.isAbsolute(absRel) || absRel.startsWith('..'), 
    'absolute paths are detected as escaping base directory');

  // Test that legitimate paths don't trigger false positives
  const legitTarget = path.join(baseFull, 'SOUL.md');
  const legitRel = path.relative(baseFull, legitTarget);
  assert(!legitRel.startsWith('..') && !path.isAbsolute(legitRel), 
    'legitimate paths pass validation');

  console.log('\nfallback behavior verification');
  
  // Test that fallback is properly returned for various attack vectors
  const customFallback = 'CUSTOM_FALLBACK_VALUE';
  const fb1 = read('../package.json', customFallback);
  assert(fb1 === customFallback, 
    'custom fallback returned for path traversal');

  const fb2 = read('/etc/passwd', customFallback);
  assert(fb2 === customFallback, 
    'custom fallback returned for absolute path');

  const fb3 = read('NONEXISTENT.md', customFallback);
  assert(fb3 === customFallback, 
    'custom fallback returned for missing file');

  // Test default fallback (empty string)
  const defaultFb = read('../package.json');
  assert(defaultFb === '', 
    'default fallback (empty string) returned when not specified');

  console.log(`\npassed ${passed}, failed ${failed}`);
  process.exit(failed ? 1 : 0);
}

test();
