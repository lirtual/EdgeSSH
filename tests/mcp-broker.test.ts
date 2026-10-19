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

async function fixture(options: { credential?: string; pinned?: string; callerToken?: string } = {}) {
  const first = { ...host, password: options.credential ?? host.password, fingerprint: options.pinned ?? host.fingerprint };
  const second = { ...host, name: 'Backup', host: 'backup.example.com', password: 'second-synthetic-credential' };
  const records = [
    { id: cloudcone, account_id: owner, encrypted_payload: await encryptHost(first, key, owner, cloudcone) },
    { id: other, account_id: owner, encrypted_payload: await encryptHost(second, key, owner, other) },
  ];
  const statements: string[] = [];
  const env = {
    MCP_BROKER_TOKEN: options.callerToken ?? token,
    ENCRYPTION_KEY: key,
    DB: {
      prepare(sql: string) {
        statements.push(sql);
        const get = async (args: unknown[]) => {
          if (sql.includes('workspace_state')) return { account_id: owner, auth_provider: 'github', auth_revision: 1, access_not_before: 0 };
          if (sql.includes('FROM hosts')) return records.find(r => r.id === args[0] && r.account_id === args[1]) ?? null;
          throw new Error('Unexpected SQL: ' + sql);
        };
        const all = async (args: unknown[]) => {
          if (!sql.includes('FROM hosts')) throw new Error('Unexpected list SQL: ' + sql);
          const [accountId, cursor, limit] = args;
          return {
            results: records.filter(r => r.account_id === accountId && r.id > String(cursor))
              .sort((a, b) => a.id.localeCompare(b.id)).slice(0, Number(limit)),
          };
        };
        return {
          first: () => get([]),
          bind(...args: unknown[]) { return { first: () => get(args), all: () => all(args) }; },
        };
      },
    },
  } as unknown as Env;
  return { env, statements };
}

test('missing or incorrect Broker token refuses all operations before any D1 read', async () => {
  const noToken = await fixture({ callerToken: '' });
  assert.deepEqual(await brokerGetHost(noToken.env, token, cloudcone), { ok: false, error: 'broker_forbidden' });
  assert.deepEqual(await brokerListHosts(noToken.env, token), { ok: false, error: 'broker_forbidden' });
  const wrong = await fixture();
  assert.deepEqual(await brokerResolveHost(wrong.env, 'wrong-token', other), { ok: false, error: 'broker_forbidden' });
  assert.equal(noToken.statements.length, 0);
  assert.equal(wrong.statements.length, 0);
});

test('all saved workspace hosts are returned, with bounded pagination and no duplicate', async () => {
  const f = await fixture();
  const full = await brokerListHosts(f.env, token, undefined, 50);
  assert.equal(full.ok, true);
  if (!full.ok) return;
  assert.deepEqual(full.value.hosts.map(h => h.id), [other, cloudcone]);
  assert.equal(full.value.nextCursor, null);
  const page1 = await brokerListHosts(f.env, token, undefined, 1);
  assert.equal(page1.ok, true);
  if (!page1.ok) return;
  assert.deepEqual(page1.value.hosts.map(h => h.id), [other]);
  assert.equal(page1.value.nextCursor, other);
  const page2 = await brokerListHosts(f.env, token, page1.value.nextCursor, 1);
  assert.equal(page2.ok, true);
  if (!page2.ok) return;
  assert.deepEqual(page2.value.hosts.map(h => h.id), [cloudcone]);
  assert.equal(page2.value.nextCursor, null);
  assert.ok(f.statements.every(sql => /^SELECT\s/i.test(sql)));
});

test('metadata is sanitized; both existing hosts can be resolved only by authenticated caller', async () => {
  const f = await fixture();
  const first = await brokerGetHost(f.env, token, cloudcone);
  const second = await brokerGetHost(f.env, token, other);
  const list = await brokerListHosts(f.env, token);
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(list.ok, true);
  for (const value of [first, second, list]) {
    assert.equal(JSON.stringify(value).includes(host.password), false);
    assert.equal(JSON.stringify(value).includes('second-synthetic-credential'), false);
  }
  if (second.ok) assert.equal(second.value.name, 'Backup');
  const cred1 = await brokerResolveHost(f.env, token, cloudcone);
  const cred2 = await brokerResolveHost(f.env, token, other);
  assert.equal(cred1.ok, true);
  assert.equal(cred2.ok, true);
  if (cred1.ok) assert.equal(cred1.value.password, host.password);
  if (cred2.ok) assert.equal(cred2.value.password, 'second-synthetic-credential');
  assert.deepEqual(await brokerGetHost(f.env, token, 'ffffffff-ffff-4fff-8fff-ffffffffffff'), { ok: false, error: 'host_not_found' });
});

test('missing host pin or credential fails closed before SSH connection', async () => {
  const untrusted = await fixture({ pinned: '' });
  assert.deepEqual(await brokerResolveHost(untrusted.env, token, cloudcone), { ok: false, error: 'host_untrusted' });
  const missing = await fixture({ credential: '' });
  assert.deepEqual(await brokerResolveHost(missing.env, token, cloudcone), { ok: false, error: 'host_untrusted' });
});

test('invalid input is rejected without leaking credentials', async () => {
  const f = await fixture();
  assert.equal((await brokerListHosts(f.env, token, 'not-uuid', 4)).ok, false);
  assert.equal((await brokerListHosts(f.env, token, undefined, 1000)).ok, false);
  assert.equal(JSON.stringify(await brokerResolveHost(f.env, token, 'wrong-id')).includes(host.password), false);
});
