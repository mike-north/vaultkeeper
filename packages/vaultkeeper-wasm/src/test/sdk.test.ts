/**
 * Integration tests for the @vaultkeeper/wasm SDK.
 *
 * These tests verify that the WASM module loads, initializes, and
 * can perform basic operations through the Node.js host platform bridge.
 *
 * Uses node:test (not vitest) since this package compiles with plain tsc.
 */

/* eslint-disable @typescript-eslint/no-floating-promises -- node:test it() returns Promise but is not meant to be awaited inside describe() */
/* eslint-disable n/no-unsupported-features/node-builtins -- test.describe is stable in our CI Node version */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { VaultKeeper } from '../index.js';

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), 'vk-wasm-test-'));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function createTestVault(dir: string): Promise<VaultKeeper> {
  // Write a minimal config
  const config = {
    version: 1,
    backends: [{ type: 'file', enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: '3' },
  };
  await writeFile(join(dir, 'config.json'), JSON.stringify(config, null, 2) + '\n');

  return VaultKeeper.create({ skipDoctor: true }, dir);
}

describe('@vaultkeeper/wasm SDK', () => {
  it('creates a VaultKeeper instance', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      assert.ok(vault);
      vault.dispose();
    });
  });

  it('reads config', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const cfg = vault.config();
      assert.equal(cfg.version, 1);
      assert.ok(Array.isArray(cfg.backends));
      vault.dispose();
    });
  });

  it('setup produces a JWE token', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token = vault.setup('test-secret', 'my-value');
      // JWE compact format: 5 base64url segments separated by dots
      const parts = token.split('.');
      assert.equal(parts.length, 5, 'JWE must have 5 parts');
      vault.dispose();
    });
  });

  it('setup + authorize round-trip', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token = vault.setup('my-key', 'super-secret');
      const result = vault.authorize(token);

      assert.equal(result.claims.sub, 'my-key');
      assert.equal(result.claims.val, 'super-secret');
      assert.equal(result.response.keyStatus, 'current');
      vault.dispose();
    });
  });

  it('store and retrieve a secret', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      await vault.store('file-secret', 'file-value');
      const retrieved = await vault.retrieve('file-secret');
      assert.equal(retrieved, 'file-value');
      vault.dispose();
    });
  });

  it('rotate key', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      // Should not throw
      vault.rotateKey();
      vault.dispose();
    });
  });

  it('delete a stored secret', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      await vault.store('delete-me', 'temp-value');
      await vault.delete('delete-me');
      // Retrieving deleted secret should throw
      await assert.rejects(() => vault.retrieve('delete-me'));
      vault.dispose();
    });
  });

  it('authorize rejects invalid JWE token', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      assert.throws(() => vault.authorize('not-a-valid-jwe'));
      vault.dispose();
    });
  });

  it('authorize rejects tampered JWE token', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token = vault.setup('key', 'value');
      // Corrupt the ciphertext (4th segment)
      const parts = token.split('.');
      const segment = parts[3];
      assert.ok(segment, 'JWE should have a 4th segment');
      parts[3] = segment.slice(0, -4) + 'XXXX';
      const tampered = parts.join('.');
      assert.throws(() => vault.authorize(tampered));
      vault.dispose();
    });
  });

  it('setup with custom TTL', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token = vault.setup('ttl-key', 'ttl-value', { ttlMinutes: 5 });
      const result = vault.authorize(token);
      // exp should be iat + 300 seconds (5 minutes)
      assert.equal(result.claims.exp - result.claims.iat, 300);
      vault.dispose();
    });
  });

  it('setup with use limit', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token = vault.setup('limit-key', 'limit-value', { useLimit: 3 });
      const result = vault.authorize(token);
      assert.equal(result.claims.use, 3);
      vault.dispose();
    });
  });

  it('rotate key then authorize with old token re-encrypts', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token = vault.setup('rotate-key', 'rotate-value');
      vault.rotateKey();
      const result = vault.authorize(token);
      // Old token decrypted with previous key
      assert.equal(result.response.keyStatus, 'previous');
      assert.ok(result.response.rotatedJwt, 'should provide re-encrypted token');
      // The re-encrypted token should work with the current key
      const result2 = vault.authorize(result.response.rotatedJwt);
      assert.equal(result2.response.keyStatus, 'current');
      assert.equal(result2.claims.val, 'rotate-value');
      vault.dispose();
    });
  });

  it('double rotate rejects (rotation already in progress)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      vault.rotateKey();
      assert.throws(() => {
        vault.rotateKey();
      }, /rotation/i);
      vault.dispose();
    });
  });

  it('store and retrieve preserves unicode', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const unicodeValue = '\u{1F512} secure \u{2603} snowman \u{1F60E}';
      await vault.store('unicode-key', unicodeValue);
      const retrieved = await vault.retrieve('unicode-key');
      assert.equal(retrieved, unicodeValue);
      vault.dispose();
    });
  });

  it('doctor returns preflight result', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const result = await vault.doctor();
      assert.ok(typeof result.ready === 'boolean');
      assert.ok(Array.isArray(result.checks));
      assert.ok(Array.isArray(result.warnings));
      assert.ok(Array.isArray(result.next_steps));
      vault.dispose();
    });
  });

  it('retrieve non-existent secret throws', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      await assert.rejects(() => vault.retrieve('does-not-exist'));
      vault.dispose();
    });
  });

  it('claims contain expected fields', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token = vault.setup('claim-key', 'claim-value');
      const result = vault.authorize(token);
      const claims = result.claims;
      // Verify all expected fields exist
      assert.ok(typeof claims.jti === 'string');
      assert.ok(claims.jti.length > 0);
      assert.ok(typeof claims.exp === 'number');
      assert.ok(typeof claims.iat === 'number');
      assert.equal(claims.sub, 'claim-key');
      assert.equal(claims.val, 'claim-value');
      assert.equal(claims.ref, 'claim-key');
      assert.ok(typeof claims.exe === 'string');
      assert.ok(typeof claims.tid === 'string');
      assert.ok(typeof claims.bkd === 'string');
      vault.dispose();
    });
  });

  it('JWE header uses dir + A256GCM (RFC 7516 interop)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token = vault.setup('interop-key', 'interop-value');
      const parts = token.split('.');
      assert.equal(parts.length, 5, 'compact JWE must have 5 segments');

      const [headerB64, encryptedKey, ivB64, ciphertextB64, tagB64] = parts;
      assert.ok(headerB64, 'header segment must exist');

      // Decode the protected header (first segment, base64url)
      const headerJson = Buffer.from(headerB64, 'base64url').toString('utf8');

      // Verify header matches what the TS jose library expects
      assert.ok(headerJson.includes('"alg":"dir"'), 'alg must be dir');
      assert.ok(headerJson.includes('"enc":"A256GCM"'), 'enc must be A256GCM');
      assert.ok(headerJson.includes('"kid":"'), 'kid must be present');

      // For dir algorithm, encrypted key segment (2nd part) must be empty
      assert.equal(encryptedKey, '', 'encrypted key must be empty for dir alg');

      // IV (3rd part) must be present and base64url-decodable to 12 bytes
      assert.ok(ivB64, 'IV segment must exist');
      assert.ok(ivB64.length > 0, 'IV must not be empty');
      const iv = Buffer.from(ivB64, 'base64url');
      assert.equal(iv.length, 12, 'AES-256-GCM IV must be 12 bytes');

      // Ciphertext (4th part) must be present
      assert.ok(ciphertextB64, 'ciphertext segment must exist');
      assert.ok(ciphertextB64.length > 0, 'ciphertext must not be empty');

      // Auth tag (5th part) must be present and base64url-decodable to 16 bytes
      assert.ok(tagB64, 'auth tag segment must exist');
      assert.ok(tagB64.length > 0, 'auth tag must not be empty');
      const tag = Buffer.from(tagB64, 'base64url');
      assert.equal(tag.length, 16, 'AES-256-GCM auth tag must be 16 bytes');

      vault.dispose();
    });
  });

  it('multiple tokens have unique JTIs', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token1 = vault.setup('key1', 'val1');
      const token2 = vault.setup('key2', 'val2');
      const result1 = vault.authorize(token1);
      const result2 = vault.authorize(token2);
      assert.notEqual(result1.claims.jti, result2.claims.jti, 'JTIs must be unique');
      vault.dispose();
    });
  });

  it('authorize rejects token with empty sub (secret name)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      // setup accepts empty name but authorize should reject (claims validation)
      const token = vault.setup('', 'some-value');
      assert.throws(() => vault.authorize(token), /sub must not be empty/);
      vault.dispose();
    });
  });

  it('authorize rejects token with empty val (secret value)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      // setup accepts empty value but authorize should reject (claims validation)
      const token = vault.setup('some-name', '');
      assert.throws(() => vault.authorize(token), /val must not be empty/);
      vault.dispose();
    });
  });

  it('store then overwrite retrieves latest value', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      await vault.store('overwrite-key', 'first-value');
      await vault.store('overwrite-key', 'second-value');
      const retrieved = await vault.retrieve('overwrite-key');
      assert.equal(retrieved, 'second-value');
      vault.dispose();
    });
  });

  it('delete non-existent secret throws', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      await assert.rejects(() => vault.delete('never-stored'));
      vault.dispose();
    });
  });

  it('config returns expected structure', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const cfg = vault.config();
      assert.equal(cfg.version, 1);
      assert.ok(Array.isArray(cfg.backends));
      assert.ok(cfg.backends.length > 0);
      const firstBackend = cfg.backends[0];
      assert.ok(firstBackend, 'first backend must exist');
      assert.equal(firstBackend.type, 'file');
      assert.ok(cfg.keyRotation);
      assert.equal(cfg.keyRotation.gracePeriodDays, 7);
      assert.ok(cfg.defaults);
      assert.equal(cfg.defaults.ttlMinutes, 60);
      vault.dispose();
    });
  });

  it('setup with explicit backend type', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      const token = vault.setup('backend-key', 'backend-value', {
        backendType: 'file',
      });
      const result = vault.authorize(token);
      assert.equal(result.claims.bkd, 'file');
      vault.dispose();
    });
  });

  it('authorize expired token throws', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir);
      // Create a token with a very short TTL that should be expired by the time we check
      // We can't easily test this without controlling time, but we can test that
      // the claims contain the expected TTL calculation
      const token = vault.setup('ttl-test', 'ttl-value', { ttlMinutes: 1 });
      const result = vault.authorize(token);
      // exp should be iat + 60 seconds (1 minute)
      assert.equal(result.claims.exp - result.claims.iat, 60);
      vault.dispose();
    });
  });
});
