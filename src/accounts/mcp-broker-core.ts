import type { Env } from '../types';
import { decryptHost } from './crypto.ts';
import { workspaceState } from './workspace.ts';
import type { HostPayload } from './hosts';

const HOST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PIN = /^SHA256:[A-Za-z0-9+/]{43}$/;

export type BrokerError = 'broker_forbidden' | 'host_not_found' | 'host_untrusted' | 'broker_unavailable';
export type BrokerReply<T> = { ok: true; value: T } | { ok: false; error: BrokerError };
export interface BrokerHostView {
  id: string;
  name: string;
  group: string;
  host: string;
  port: number;
  username: string;
  authMethod: 'password' | 'publickey';
  trustReady: boolean;
  readinessReason: 'ready' | 'host_untrusted' | 'credential_missing';
}
export interface BrokerCredentials {
  id: string;
  host: string;
  port: number;
  username: string;
  authMethod: 'password' | 'publickey';
  fingerprint: string;
  password?: string;
  privateKey?: string;
}
type BrokerEnv = Pick<Env, 'DB' | 'ENCRYPTION_KEY' | 'MCP_BROKER_ENABLED' | 'MCP_BROKER_TOKEN' | 'MCP_BROKER_HOST_IDS'>;
interface HostRow { id: string; account_id: string; encrypted_payload: string }

function denied(): BrokerReply<never> { return { ok: false, error: 'broker_forbidden' }; }
function isHostId(id: unknown): id is string { return typeof id === 'string' && HOST_ID.test(id); }
async function equalTokens(a: string, b: string): Promise<boolean> {
  if (a.length < 32 || b.length < 32 || a.length > 256 || b.length > 256) return false;
  const data = new TextEncoder();
  const [aHash, bHash] = await Promise.all([
    crypto.subtle.digest('SHA-256', data.encode(a)),
    crypto.subtle.digest('SHA-256', data.encode(b)),
  ]);
  const left = new Uint8Array(aHash);
  const right = new Uint8Array(bHash);
  let mismatch = 0;
  for (let i = 0; i < left.length; i++) mismatch |= left[i]! ^ right[i]!;
  return mismatch === 0;
}
async function allow(env: BrokerEnv, token: unknown): Promise<Set<string> | null> {
  if (env.MCP_BROKER_ENABLED !== 'true' || typeof token !== 'string'
      || !env.MCP_BROKER_TOKEN || !(await equalTokens(token, env.MCP_BROKER_TOKEN))) return null;
  const ids = (env.MCP_BROKER_HOST_IDS ?? '').split(',').map(id => id.trim().toLowerCase());
  if (ids.length === 0 || ids.some(id => !isHostId(id))) return null;
  return new Set(ids);
}
async function findHost(env: BrokerEnv, id: string): Promise<HostPayload | null> {
  const workspace = await workspaceState(env);
  const row = await env.DB.prepare(
    'SELECT id, account_id, encrypted_payload FROM hosts WHERE id = ? AND account_id = ?',
  ).bind(id, workspace.accountId).first<HostRow>();
  if (!row) return null;
  if (row.account_id !== workspace.accountId || row.id !== id || typeof row.encrypted_payload !== 'string') {
    throw new Error('invalid_host_row');
  }
  return decryptHost<HostPayload>(row.encrypted_payload, env.ENCRYPTION_KEY, workspace.accountId, id);
}
function metadata(id: string, p: HostPayload): BrokerHostView {
  const credentialPresent = p.authMethod === 'password'
    ? typeof p.password === 'string' && p.password.length > 0
    : typeof p.privateKey === 'string' && p.privateKey.length > 0;
  const trustReady = typeof p.fingerprint === 'string' && PIN.test(p.fingerprint);
  return {
    id, name: p.name, group: p.group, host: p.host, port: p.port,
    username: p.username, authMethod: p.authMethod,
    trustReady, readinessReason: !trustReady ? 'host_untrusted' : credentialPresent ? 'ready' : 'credential_missing',
  };
}
function validHost(p: HostPayload): boolean {
  return typeof p.host === 'string' && p.host.length <= 253 && p.host.length > 0
    && Number.isInteger(p.port) && p.port > 0 && p.port <= 65535 && p.port !== 25
    && typeof p.username === 'string' && p.username.length > 0 && p.username.length <= 128
    && !/[\0\r\n]/.test(p.username)
    && (p.authMethod === 'password' || p.authMethod === 'publickey')
    && typeof p.fingerprint === 'string' && PIN.test(p.fingerprint)
    && (p.authMethod === 'password'
      ? typeof p.password === 'string' && p.password.length > 0 && p.password.length <= 4096
      : typeof p.privateKey === 'string' && p.privateKey.includes('BEGIN OPENSSH PRIVATE KEY')
        && p.privateKey.length <= 128 * 1024);
}

/** These functions never use hostsRoute(), because its GET performs D1 location backfills. */
export async function brokerGetHost(env: BrokerEnv, token: unknown, hostId: unknown): Promise<BrokerReply<BrokerHostView>> {
  const allowed = await allow(env, token);
  if (!allowed || !isHostId(hostId) || !allowed.has(hostId.toLowerCase())) return denied();
  try {
    const p = await findHost(env, hostId.toLowerCase());
    return p ? { ok: true, value: metadata(hostId.toLowerCase(), p) } : { ok: false, error: 'host_not_found' };
  } catch { return { ok: false, error: 'broker_unavailable' }; }
}
export async function brokerListHosts(env: BrokerEnv, token: unknown, cursor?: unknown, limit?: unknown):
  Promise<BrokerReply<{ hosts: BrokerHostView[]; nextCursor: string | null }>> {
  const allowed = await allow(env, token);
  if (!allowed || (cursor !== undefined && !isHostId(cursor))
    || (limit !== undefined && (!Number.isInteger(limit) || (limit as number) < 1 || (limit as number) > 50))) return denied();
  const ids = [...allowed].sort().filter(id => cursor === undefined || id > String(cursor).toLowerCase());
  const page = ids.slice(0, (limit as number | undefined ?? 50) + 1);
  const hosts: BrokerHostView[] = [];
  try {
    for (const id of page.slice(0, limit as number | undefined ?? 50)) {
      const p = await findHost(env, id);
      if (p) hosts.push(metadata(id, p));
    }
    return { ok: true, value: { hosts, nextCursor: page.length > (limit as number | undefined ?? 50)
      ? page[(limit as number | undefined ?? 50) - 1]! : null } };
  } catch { return { ok: false, error: 'broker_unavailable' }; }
}
export async function brokerResolveHost(env: BrokerEnv, token: unknown, hostId: unknown): Promise<BrokerReply<BrokerCredentials>> {
  const allowed = await allow(env, token);
  if (!allowed || !isHostId(hostId) || !allowed.has(hostId.toLowerCase())) return denied();
  try {
    const p = await findHost(env, hostId.toLowerCase());
    if (!p) return { ok: false, error: 'host_not_found' };
    if (!validHost(p)) return { ok: false, error: 'host_untrusted' };
    return { ok: true, value: {
      id: hostId.toLowerCase(), host: p.host, port: p.port, username: p.username,
      authMethod: p.authMethod, fingerprint: p.fingerprint,
      ...(p.authMethod === 'password' ? { password: p.password } : { privateKey: p.privateKey }),
    } };
  } catch { return { ok: false, error: 'broker_unavailable' }; }
}
