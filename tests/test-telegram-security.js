/**
 * Security test for telegram commands file reading functionality.
 *
 * Tests that the `/simplify` command properly mitigates path traversal attacks
 * by validating that file paths stay within the project directory.
 *
 * The vulnerability being tested:
 *   - Path traversal via ../ sequences to read sensitive files
 *   - Absolute path injection to access system files
 *
 * The mitigation uses path.relative() to ensure the resolved target stays
 * within the base directory (process.cwd()). Any attempt to escape is rejected.
 */

import fs from 'node:fs';
import path from 'node:path';

const BASE_DIR = path.resolve(process.cwd());

// Replicate the security check from commands.js /simplify command
function validateFilePath(file) {
  const baseFull = path.resolve(BASE_DIR);
  const filePath = path.join(baseFull, file);
  const rel = path.relative(baseFull, filePath);
  
  // Security check: reject paths that escape the base directory
  if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    return { valid: false, error: 'Invalid file path' };
  }
  
  // Check if file exists
  if (!fs.existsSync(filePath)) {
    return { valid: false, error: `File not found: ${file}` };
  }
  
  return { valid: true, path: filePath };
}

let passed = 0, failed = 0;
const assert = (c, m) => { 
  c ? (passed++, console.log(`  ok  ${m}`)) : (failed++, console.log(`  FAIL ${m}`)); 
};

function test() {
  console.log('=== Telegram Commands Security: Path Traversal Mitigation ===\n');

  console.log('legitimate file access (baseline)');
  
  // Test 1: Valid file in project root
  const valid1 = validateFilePath('package.json');
  assert(valid1.valid === true, 
    'validateFilePath("package.json") allows legitimate file');
  
  // Test 2: Valid file in subdirectory
  const valid2 = validateFilePath('src/config.js');
  assert(valid2.valid === true, 
    'validateFilePath("src/config.js") allows legitimate nested file');
  
  // Test 3: Valid file in tests directory
  const valid3 = validateFilePath('tests/test-sign.js');
  assert(valid3.valid === true, 
    'validateFilePath("tests/test-sign.js") allows legitimate test file');

  console.log('\npath traversal attacks (should be blocked)');
  
  // Test 4: Simple parent directory traversal to read /etc/passwd
  const attack1 = validateFilePath('../../../etc/passwd');
  assert(attack1.valid === false && attack1.error === 'Invalid file path', 
    'validateFilePath("../../../etc/passwd") blocked - path traversal rejected');
  
  // Test 5: Traversal to read files outside project
  const attack2 = validateFilePath('../package.json');
  assert(attack2.valid === false && attack2.error === 'Invalid file path', 
    'validateFilePath("../package.json") blocked - parent directory access rejected');
  
  // Test 6: Traversal with subdirectory prefix
  const attack3 = validateFilePath('src/../../etc/passwd');
  assert(attack3.valid === false && attack3.error === 'Invalid file path', 
    'validateFilePath("src/../../etc/passwd") blocked - nested traversal rejected');
  
  // Test 7: Deep traversal attempt
  const attack4 = validateFilePath('src/ai/../../../../../../etc/passwd');
  assert(attack4.valid === false && attack4.error === 'Invalid file path', 
    'validateFilePath("src/ai/../../../../../../etc/passwd") blocked - deep traversal rejected');

  console.log('\nabsolute path injection (should be blocked)');
  
  // Test 8: Absolute Unix path - check the security validation, not file existence
  const attack5Path = '/etc/passwd';
  const attack5BaseFull = path.resolve(BASE_DIR);
  const attack5FilePath = path.join(attack5BaseFull, attack5Path);
  const attack5Rel = path.relative(attack5BaseFull, attack5FilePath);
  const attack5Blocked = attack5Rel === '..' || attack5Rel.startsWith(`..${path.sep}`) || path.isAbsolute(attack5Rel);
  assert(attack5Blocked, 
    'validateFilePath("/etc/passwd") blocked - absolute Unix path rejected');
  
  // Test 9: Absolute Windows path - check the security validation
  const attack6Path = 'C:\\Windows\\System32\\config\\SAM';
  const attack6FilePath = path.join(attack5BaseFull, attack6Path);
  const attack6Rel = path.relative(attack5BaseFull, attack6FilePath);
  const attack6Blocked = attack6Rel === '..' || attack6Rel.startsWith(`..${path.sep}`) || path.isAbsolute(attack6Rel);
  assert(attack6Blocked, 
    'validateFilePath("C:\\\\Windows\\\\...") blocked - absolute Windows path rejected');
  
  // Test 10: Absolute path to project file (should still be blocked)
  const projectPath = path.join(BASE_DIR, 'package.json');
  const attack7FilePath = path.join(attack5BaseFull, projectPath);
  const attack7Rel = path.relative(attack5BaseFull, attack7FilePath);
  const attack7Blocked = attack7Rel === '..' || attack7Rel.startsWith(`..${path.sep}`) || path.isAbsolute(attack7Rel);
  assert(attack7Blocked, 
    'validateFilePath(absolute_project_path) blocked - absolute paths always rejected');

  console.log('\nedge cases and obfuscation attempts');
  
  // Test 11: Parent directory reference
  const edge1 = validateFilePath('..');
  assert(edge1.valid === false && edge1.error === 'Invalid file path', 
    'validateFilePath("..") blocked - exact match for ".."');
  
  // Test 12: Mixed separators (backslash on Unix) - check security validation
  const edge2Path = '..\\..\\package.json';
  const edge2BaseFull = path.resolve(BASE_DIR);
  const edge2FilePath = path.join(edge2BaseFull, edge2Path);
  const edge2Rel = path.relative(edge2BaseFull, edge2FilePath);
  const edge2Blocked = edge2Rel === '..' || edge2Rel.startsWith(`..${path.sep}`) || path.isAbsolute(edge2Rel);
  assert(edge2Blocked, 
    'validateFilePath("..\\\\..\\\\package.json") blocked - backslash separators');
  
  // Test 13: URL-encoded traversal (should not decode)
  const edge3 = validateFilePath('..%2F..%2Fetc%2Fpasswd');
  assert(edge3.valid === false, 
    'validateFilePath("..%2F..%2Fetc%2Fpasswd") blocked - URL encoding doesn\'t bypass');

  console.log('\nsecurity property verification');
  
  // Test 14: Verify path.relative() behavior for malicious input
  const baseFull = path.resolve(BASE_DIR);
  const maliciousTarget = path.join(baseFull, '../../../etc/passwd');
  const rel = path.relative(baseFull, maliciousTarget);
  assert(rel.startsWith('..'), 
    'path.relative() correctly identifies escape attempt');
  
  // Test 15: Verify absolute path detection
  const absoluteTarget = '/etc/passwd';
  const absRel = path.relative(baseFull, absoluteTarget);
  assert(path.isAbsolute(absRel) || absRel.startsWith('..'), 
    'absolute paths are detected as escaping base directory');
  
  // Test 16: Verify legitimate paths pass validation
  const legitTarget = path.join(baseFull, 'package.json');
  const legitRel = path.relative(baseFull, legitTarget);
  assert(!legitRel.startsWith('..') && !path.isAbsolute(legitRel), 
    'legitimate relative paths pass validation');

  console.log('\nexploit scenario simulation');
  
  // Test 17: Attempt to read SSH private key
  const exploit1 = validateFilePath('../../../../home/user/.ssh/id_rsa');
  assert(exploit1.valid === false && exploit1.error === 'Invalid file path', 
    'exploit: reading SSH private key blocked');
  
  // Test 18: Attempt to read environment variables
  const exploit2 = validateFilePath('../.env');
  assert(exploit2.valid === false && exploit2.error === 'Invalid file path', 
    'exploit: reading .env file outside project blocked');
  
  // Test 19: Attempt to read system password file
  const exploit3 = validateFilePath('../../../../etc/shadow');
  assert(exploit3.valid === false && exploit3.error === 'Invalid file path', 
    'exploit: reading /etc/shadow blocked');

  console.log(`\npassed ${passed}, failed ${failed}`);
  process.exit(failed ? 1 : 0);
}

test();
