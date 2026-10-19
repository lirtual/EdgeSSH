import { WorkerEntrypoint } from 'cloudflare:workers';
import type { Env } from '../types';
import { brokerGetHost, brokerListHosts, brokerResolveHost } from './mcp-broker-core.ts';

/**
 * Named RPC entrypoint, NOT a public fetch route. Requires both a Service
 * Binding and the independent MCP_BROKER_TOKEN; default is disabled.
 */
export class HostBrokerEntrypoint extends WorkerEntrypoint<Env> {
  async listHostMetadata(request: { token: string; cursor?: string; limit?: number }) {
    return brokerListHosts(this.env, request?.token, request?.cursor, request?.limit);
  }
  async getHostMetadata(request: { token: string; hostId: string }) {
    return brokerGetHost(this.env, request?.token, request?.hostId);
  }
  async resolveHostForConnection(request: { token: string; hostId: string }) {
    return brokerResolveHost(this.env, request?.token, request?.hostId);
  }
}
