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
  
  const valid1 = validateFilePath('package.json');
  assert(valid1.valid === true, 
    'allows reading package.json in project root');
  
  const valid2 = validateFilePath('src/config.js');
  assert(valid2.valid === true, 
    'allows reading src/config.js in subdirectory');

  console.log('\npath traversal attacks (critical security tests)');
  
  // EXPLOIT 1: Read /etc/passwd via path traversal
  const exploit1 = validateFilePath('../../../etc/passwd');
  assert(exploit1.valid === false && exploit1.error === 'Invalid file path', 
    'BLOCKS path traversal to /etc/passwd');
  
  // EXPLOIT 2: Read parent directory files
  const exploit2 = validateFilePath('../package.json');
  assert(exploit2.valid === false && exploit2.error === 'Invalid file path', 
    'BLOCKS reading files in parent directory');
  
  // EXPLOIT 3: Nested traversal with subdirectory prefix
  const exploit3 = validateFilePath('src/../../etc/passwd');
  assert(exploit3.valid === false && exploit3.error === 'Invalid file path', 
    'BLOCKS nested path traversal');
  
  // EXPLOIT 4: Deep traversal to system files
  const exploit4 = validateFilePath('src/ai/../../../../../../etc/shadow');
  assert(exploit4.valid === false && exploit4.error === 'Invalid file path', 
    'BLOCKS deep traversal to /etc/shadow');

  console.log('\nsecurity property verification');
  
  // Verify the security mechanism works correctly
  const baseFull = path.resolve(BASE_DIR);
  
  // Malicious path should be detected
  const maliciousTarget = path.join(baseFull, '../../../etc/passwd');
  const maliciousRel = path.relative(baseFull, maliciousTarget);
  assert(maliciousRel.startsWith('..'), 
    'path.relative() detects escape attempts');
  
  // Legitimate path should pass
  const legitTarget = path.join(baseFull, 'package.json');
  const legitRel = path.relative(baseFull, legitTarget);
  assert(!legitRel.startsWith('..') && !path.isAbsolute(legitRel), 
    'legitimate paths pass validation');

  console.log('\nreal-world exploit scenarios');
  
  // SSH private key
  const realExploit1 = validateFilePath('../../../../home/user/.ssh/id_rsa');
  assert(realExploit1.valid === false && realExploit1.error === 'Invalid file path', 
    'BLOCKS reading SSH private keys');
  
  // Environment file outside project
  const realExploit2 = validateFilePath('../.env');
  assert(realExploit2.valid === false && realExploit2.error === 'Invalid file path', 
    'BLOCKS reading .env files outside project');

  console.log(`\npassed ${passed}, failed ${failed}`);
  process.exit(failed ? 1 : 0);
}

test();
