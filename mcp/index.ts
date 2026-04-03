/**
 * Aegis MCP Module
 *
 * Registers Aegis as a module in the Pi5 orchestrator.
 * Exposes threat intelligence, deception control, supply chain, and attribution tools.
 *
 * Run on Pi5; communicates with ThinkPad via SSH tunnel / WireGuard.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { logger } from '../shared/logger.js';

const server = new McpServer({
  name: 'aegis',
  version: '0.1.0',
});

// ── Threat Intelligence Tools ──────────────────────────────────────────────

server.tool(
  'aegis_active_sessions',
  'List live attacker sessions with tier/tool classification',
  {},
  async () => {
    // TODO: query classifier session store (Redis / GUN)
    return { content: [{ type: 'text', text: JSON.stringify({ sessions: [] }) }] };
  },
);

server.tool(
  'aegis_attacker_profile',
  'Get full dossier for a source IP',
  { ip: z.string().describe('Source IP address') },
  async ({ ip }) => {
    // TODO: query attacker profile store
    return { content: [{ type: 'text', text: JSON.stringify({ ip, profile: null }) }] };
  },
);

server.tool(
  'aegis_canary_events',
  'Recent canary token callbacks',
  { limit: z.number().optional().default(50) },
  async ({ limit }) => {
    // TODO: query GUN or local DB
    return { content: [{ type: 'text', text: JSON.stringify({ events: [], limit }) }] };
  },
);

// ── Deception Control Tools ────────────────────────────────────────────────

server.tool(
  'aegis_honeypot_status',
  'Check status of all fake deception services',
  {},
  async () => {
    // TODO: query Docker API on ThinkPad via SSH
    return { content: [{ type: 'text', text: JSON.stringify({ services: [] }) }] };
  },
);

server.tool(
  'aegis_add_canary',
  'Create a new canary token',
  {
    type: z.enum(['credential', 'document', 'dns', 'url', 'image']),
    label: z.string().describe('Human-readable label for this canary'),
  },
  async ({ type, label }) => {
    const { v4: uuidv4 } = await import('uuid');
    const tokenId = uuidv4().replace(/-/g, '').slice(0, 16).toUpperCase();
    const canaryUrl = `https://${process.env.CANARY_BASE_DOMAIN}/canary/${tokenId}?type=${type}`;
    return {
      content: [{ type: 'text', text: JSON.stringify({ tokenId, type, label, canaryUrl }) }],
    };
  },
);

// ── Supply Chain Tools ─────────────────────────────────────────────────────

server.tool(
  'aegis_cve_exposure',
  'List active CVE exposures across the mesh',
  {},
  async () => {
    // TODO: query correlator / GUN
    return { content: [{ type: 'text', text: JSON.stringify({ exposures: [] }) }] };
  },
);

server.tool(
  'aegis_confirm_isolation',
  'Execute a recommended isolation plan',
  { planId: z.string() },
  async ({ planId }) => {
    const { executeIsolation } = await import('../supply-chain/isolation-trigger.js');
    await executeIsolation(planId);
    return { content: [{ type: 'text', text: `Isolation plan ${planId} executed.` }] };
  },
);

server.tool(
  'aegis_check_package',
  'Manually check a specific package/version for known vulnerabilities',
  {
    name: z.string(),
    version: z.string(),
    ecosystem: z.enum(['npm', 'PyPI', 'crates.io', 'Go', 'Debian']),
  },
  async ({ name, version, ecosystem }) => {
    const axios = (await import('axios')).default;
    const res = await axios.post(
      'https://api.osv.dev/v1/query',
      { package: { name, ecosystem }, version },
      { timeout: 10_000 },
    );
    return {
      content: [{ type: 'text', text: JSON.stringify(res.data) }],
    };
  },
);

// ── Attribution Tools ──────────────────────────────────────────────────────

server.tool(
  'aegis_vpn_check',
  'Run VPN/Tor/proxy detection on an IP',
  { ip: z.string() },
  async ({ ip }) => {
    const { detectVPN } = await import('../attribution/vpn-detector.js');
    const result = await detectVPN(ip, null);
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  },
);

server.tool(
  'aegis_ip_intelligence',
  'Full threat intel lookup for an IP',
  { ip: z.string() },
  async ({ ip }) => {
    const { enrichProfile } = await import('../attribution/threat-intel.js');
    const profile = await enrichProfile(ip);
    return { content: [{ type: 'text', text: JSON.stringify(profile) }] };
  },
);

// ── Server startup ─────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('Aegis MCP server started');
}

main().catch((err) => {
  logger.error('MCP server crashed', { err });
  process.exit(1);
});
