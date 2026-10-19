import assert from 'node:assert/strict';
import { test } from 'node:test';
import { encryptHost } from '../src/accounts/crypto.ts';
import { brokerGetHost, brokerListHosts, brokerResolveHost } from '../src/accounts/mcp-broker-core.ts';
import type { Env } from '../src/types.ts';

const cloudcone = 'df4cb05d-30e9-4436-9948-33c05a26cb79';
const other = 'bcafc813-5d7f-469c-a4e3-0fccf681507b';
const owner = '11111111-1111-4111-8111-111111111111';
const key = Buffer.alloc(32, 7).toString('base64');
const token = 'broker-auth-token-for-isolated-tests-only-1234567890';
const pin = 'SHA256:' + 'A'.repeat(43);
const host = {
  name: 'CloudCone', group: 'Personal', host: 'example.com', port: 22, username: 'root',
  authMethod: 'password', password: 'synthetic-sensitive-credential', fingerprint: pin,
  initialCommand: '', termType: 'xterm', encoding: 'utf-8', location: null,
} as const;

async function fixture(options: { enabled?: string; allow?: string; credential?: string; pinned?: string } = {}) {
  const payload = { ...host, password: options.credential ?? host.password, fingerprint: options.pinned ?? host.fingerprint };
  const ciphertext = await encryptHost(payload, key, owner, cloudcone);
  const rows: Record<string, unknown>[] = [];
  const statements: string[] = [];
  const env = {
    MCP_BROKER_ENABLED: options.enabled ?? 'true',
    MCP_BROKER_HOST_IDS: options.allow ?? cloudcone,
    MCP_BROKER_TOKEN: token,
    ENCRYPTION_KEY: key,
    DB: {
      prepare(sql: string) {
        statements.push(sql);
        const first = async (args: unknown[]) => {
          if (sql.includes('workspace_state')) return { account_id: owner, auth_provider: 'github', auth_revision: 1, access_not_before: 0 };
          if (sql.includes('FROM hosts')) {
            const id = args[0];
            if (id !== cloudcone || args[1] !== owner) return null;
            return { id, account_id: owner, encrypted_payload: ciphertext };
          }
          throw new Error('Unexpected SQL');
        };
        return {
          first: () => first([]),
          bind(...args: unknown[]) { return { first: () => first(args) }; },
        };
      },
    },
  } as unknown as Env;
  return { env, statements, rows };
}

test('default-disabled and incorrect caller token fail before ANY D1 read', async () => {
  const f = await fixture({ enabled: 'false' });
  assert.deepEqual(await brokerGetHost(f.env, token, cloudcone), { ok: false, error: 'broker_forbidden' });
  const enabled = await fixture();
  assert.deepEqual(await brokerResolveHost(enabled.env, 'wrong-token', cloudcone), { ok: false, error: 'broker_forbidden' });
  assert.deepEqual(await brokerGetHost(enabled.env, token, other), { ok: false, error: 'broker_forbidden' });
  assert.equal(f.statements.length, 0);
  assert.equal(enabled.statements.length, 0);
});

test('empty allowlist cannot enable credential access', async () => {
  const f = await fixture({ allow: '' });
  assert.deepEqual(await brokerResolveHost(f.env, token, cloudcone), { ok: false, error: 'broker_forbidden' });
  assert.equal(f.statements.length, 0);
});

test('metadata is sanitized and production D1 is never written', async () => {
  const f = await fixture();
  const meta = await brokerGetHost(f.env, token, cloudcone);
  const list = await brokerListHosts(f.env, token, undefined, 5);
  assert.equal(meta.ok, true);
  assert.equal(list.ok, true);
  assert.equal(JSON.stringify(meta).includes(host.password), false);
  assert.equal(JSON.stringify(list).includes(host.password), false);
  if (meta.ok) {
    assert.equal(meta.value.trustReady, true);
    assert.equal(meta.value.username, 'root');
  }
  if (list.ok) {
    assert.equal(list.value.hosts.length, 1);
    assert.equal(list.value.nextCursor, null);
  }
  assert.ok(f.statements.every(x => /^SELECT\s/i.test(x)));
});

test('the one allowed host has its credential only in the resolver result', async () => {
  const f = await fixture();
  const reply = await brokerResolveHost(f.env, token, cloudcone);
  assert.equal(reply.ok, true);
  if (reply.ok) assert.equal(reply.value.password, host.password);
  assert.equal(JSON.stringify(await brokerResolveHost(f.env, token, other)).includes(host.password), false);
});

test('wrong fingerprint and invalid record fail closed', async () => {
  const untrusted = await fixture({ pinned: '' });
  assert.deepEqual(await brokerResolveHost(untrusted.env, token, cloudcone), { ok: false, error: 'host_untrusted' });
  const missing = await fixture({ credential: '' });
  assert.deepEqual(await brokerResolveHost(missing.env, token, cloudcone), { ok: false, error: 'host_untrusted' });
});

test('invalid input rejected and no credential leaks in failures', async () => {
  const f = await fixture();
  assert.equal((await brokerListHosts(f.env, token, 'not-uuid', 4)).ok, false);
  assert.equal((await brokerListHosts(f.env, token, undefined, 1000)).ok, false);
  assert.equal(JSON.stringify(await brokerResolveHost(f.env, token, 'wrong-id')).includes(host.password), false);
});
