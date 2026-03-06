/**
 * Integration tests for the @vaultkeeper/wasm SDK.
 *
 * These tests verify that the WASM module loads, initializes, and
 * can perform basic operations through the Node.js host platform bridge.
 */

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
});
