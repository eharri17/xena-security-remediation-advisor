'use strict';

// Minimal MCP Streamable HTTP client and Wiz OAuth (authorization code + PKCE) helper.
// Zero dependencies (Node >= 18, global fetch). Tokens are kept in memory only and are never logged.

const crypto = require('node:crypto');
const http = require('node:http');
const { spawn } = require('node:child_process');

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = { name: 'xena-advisor-live-smoke', version: '0.1.0' };

/** Parses a JSON or SSE (`data:` lines) response body into a list of JSON-RPC messages. */
function parseMcpBody(text, contentType = '') {
  const body = String(text || '').trim();
  if (!body) return [];
  if (/application\/json/i.test(contentType) || body.startsWith('{') || body.startsWith('[')) {
    const parsed = JSON.parse(body);
    return Array.isArray(parsed) ? parsed : [parsed];
  }
  const messages = [];
  for (const event of body.split(/\r?\n\r?\n/)) {
    const data = event
      .split(/\r?\n/)
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).replace(/^ /, ''))
      .join('\n');
    if (!data) continue;
    try {
      messages.push(JSON.parse(data));
    } catch {
      // Ignore keep-alives and non-JSON events.
    }
  }
  return messages;
}

/** Shortens server text for error messages without echoing anything that looks like a credential. */
function safeSnippet(text, max = 300) {
  return String(text || '')
    .replace(/(bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]')
    .replace(/("?(?:access_token|refresh_token|id_token|token|authorization)"?\s*[:=]\s*"?)[^",\s}]+/gi, '$1[REDACTED]')
    .replace(/\s+/g, ' ')
    .slice(0, max);
}

class McpClient {
  /**
   * @param {{ url: string, headers?: Record<string,string>, fetchImpl?: typeof fetch, timeoutMs?: number }} opts
   * `headers` may contain credentials; they are sent but never logged or included in errors.
   */
  constructor({ url, headers = {}, fetchImpl = globalThis.fetch, timeoutMs = 60000 }) {
    if (typeof fetchImpl !== 'function') throw new Error('global fetch is unavailable; Node.js >= 18 is required.');
    this.url = url;
    this.headers = headers;
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.sessionId = null;
    this.nextId = 0;
    this.serverInfo = null;
  }

  async post(message) {
    const headers = {
      ...this.headers,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    };
    if (message.method !== 'initialize') headers['MCP-Protocol-Version'] = PROTOCOL_VERSION;
    if (this.sessionId) headers['Mcp-Session-Id'] = this.sessionId;
    const res = await this.fetch(this.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(message),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const sid = res.headers.get('mcp-session-id');
    if (sid) this.sessionId = sid;
    const text = await res.text();
    if (!res.ok) {
      const err = new Error(`${message.method}: HTTP ${res.status} ${safeSnippet(text)}`.trim());
      err.status = res.status;
      throw err;
    }
    return { text, contentType: res.headers.get('content-type') || '' };
  }

  async request(method, params = {}) {
    const id = ++this.nextId;
    const { text, contentType } = await this.post({ jsonrpc: '2.0', id, method, params });
    const reply = parseMcpBody(text, contentType).find((m) => m && m.id === id);
    if (!reply) throw new Error(`${method}: no JSON-RPC response with id ${id} (${safeSnippet(text, 120)})`);
    if (reply.error) {
      const err = new Error(`${method}: JSON-RPC error ${reply.error.code}: ${safeSnippet(reply.error.message)}`);
      err.rpcError = reply.error;
      throw err;
    }
    return reply.result;
  }

  async notify(method, params = {}) {
    await this.post({ jsonrpc: '2.0', method, params });
  }

  async initialize() {
    const result = await this.request('initialize', { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO });
    this.serverInfo = result?.serverInfo || null;
    await this.notify('notifications/initialized');
    return result;
  }

  async listTools() {
    const tools = [];
    let cursor;
    do {
      const result = await this.request('tools/list', cursor ? { cursor } : {});
      tools.push(...(result?.tools || []));
      cursor = result?.nextCursor;
    } while (cursor);
    return tools;
  }

  callTool(name, args = {}) {
    return this.request('tools/call', { name, arguments: args });
  }
}

// ---------------------------------------------------------------------------------------------
// Wiz OAuth (MCP authorization flow): metadata discovery, dynamic client registration, PKCE S256.

const WIZ_MCP_URL = 'https://mcp.app.wiz.io';
const WIZ_RESOURCE = 'https://mcp.app.wiz.io/';
const WIZ_SCOPE = 'read:all';

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function fetchJson(url, fetchImpl = globalThis.fetch) {
  const res = await fetchImpl(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return res.json();
}

/** Discovers OAuth authorization server metadata for an MCP server origin. */
async function discoverAuthServer(mcpUrl = WIZ_MCP_URL, fetchImpl = globalThis.fetch) {
  const origin = new URL(mcpUrl).origin;
  try {
    return await fetchJson(`${origin}/.well-known/oauth-authorization-server`, fetchImpl);
  } catch (first) {
    const prm = await fetchJson(`${origin}/.well-known/oauth-protected-resource`, fetchImpl);
    const issuer = [].concat(prm.authorization_servers || [])[0];
    if (!issuer) throw new Error(`No authorization server advertised by ${origin} (${first.message})`);
    const base = String(issuer).replace(/\/+$/, '');
    try {
      return await fetchJson(`${base}/.well-known/oauth-authorization-server`, fetchImpl);
    } catch {
      return fetchJson(`${base}/.well-known/openid-configuration`, fetchImpl);
    }
  }
}

function openBrowser(url) {
  const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'explorer' : 'xdg-open';
  try {
    spawn(cmd, [url], { stdio: 'ignore', detached: true }).unref();
  } catch {
    // The URL is printed as well, so the user can open it manually.
  }
}

/** Starts a one-shot callback server on 127.0.0.1 with an ephemeral port. */
function startCallbackServer() {
  return new Promise((resolve, reject) => {
    let settle;
    const result = new Promise((res) => (settle = res));
    const server = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://127.0.0.1');
      if (u.pathname !== '/callback') {
        res.writeHead(404).end();
        return;
      }
      const params = Object.fromEntries(u.searchParams);
      const ok = !params.error && params.code;
      res.writeHead(ok ? 200 : 400, { 'Content-Type': 'text/html; charset=utf-8', Connection: 'close' });
      res.end(`<p>${ok ? 'Wiz sign-in complete. You can close this tab.' : 'Wiz sign-in failed. Check the terminal.'}</p>`);
      settle(params);
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, result }));
  });
}

/**
 * Signs in to the Wiz MCP server as the current user and returns an access token (memory only).
 * Requests only `read:all`; the write scope `create:penetration_test_findings` is never requested.
 */
async function wizOAuthLogin({ mcpUrl = WIZ_MCP_URL, resource = WIZ_RESOURCE, scope = WIZ_SCOPE, timeoutMs = 180000, log = console.log, fetchImpl = globalThis.fetch, open = openBrowser } = {}) {
  if (scope.split(/\s+/).some((s) => s !== 'read:all')) throw new Error(`Refusing to request scope "${scope}"; only read:all is allowed.`);
  const meta = await discoverAuthServer(mcpUrl, fetchImpl);
  for (const k of ['authorization_endpoint', 'token_endpoint']) if (!meta[k]) throw new Error(`Authorization server metadata is missing ${k}.`);
  if (meta.code_challenge_methods_supported && !meta.code_challenge_methods_supported.includes('S256')) {
    throw new Error('Authorization server does not support PKCE S256.');
  }

  const { server, port, result } = await startCallbackServer();
  const redirectUri = `http://127.0.0.1:${port}/callback`;
  let timer;
  try {
    let clientId = process.env.WIZ_OAUTH_CLIENT_ID;
    if (!clientId) {
      if (!meta.registration_endpoint) throw new Error('No registration_endpoint; set WIZ_OAUTH_CLIENT_ID to a pre-registered public client.');
      const reg = await fetchImpl(meta.registration_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          client_name: 'XENA Security Remediation Advisor (live smoke)',
          redirect_uris: [redirectUri],
          grant_types: ['authorization_code'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none',
          scope,
        }),
        signal: AbortSignal.timeout(15000),
      });
      const regText = await reg.text();
      if (!reg.ok) throw new Error(`Client registration failed: HTTP ${reg.status} ${safeSnippet(regText)}`);
      clientId = JSON.parse(regText).client_id;
      if (!clientId) throw new Error('Client registration returned no client_id.');
    }

    const verifier = b64url(crypto.randomBytes(48));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
    const state = b64url(crypto.randomBytes(24));
    const authUrl = new URL(meta.authorization_endpoint);
    authUrl.search = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource,
    }).toString();

    log(`Wiz sign-in: opening your browser (scope "${scope}" only). If it does not open, visit:\n  ${authUrl}`);
    open(authUrl.toString());

    const timeout = new Promise((_, rej) => {
      timer = setTimeout(() => rej(new Error(`Timed out after ${Math.round(timeoutMs / 1000)}s waiting for the Wiz sign-in callback.`)), timeoutMs);
    });
    const params = await Promise.race([result, timeout]);
    if (params.error) throw new Error(`Wiz authorization failed: ${safeSnippet(params.error)} ${safeSnippet(params.error_description || '')}`.trim());
    if (!params.state || params.state !== state) throw new Error('OAuth state mismatch; possible CSRF. Aborting.');
    if (!params.code) throw new Error('No authorization code received.');

    const tokenRes = await fetchImpl(meta.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: params.code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
        resource,
      }).toString(),
      signal: AbortSignal.timeout(15000),
    });
    const tokenText = await tokenRes.text();
    if (!tokenRes.ok) throw new Error(`Token exchange failed: HTTP ${tokenRes.status} ${safeSnippet(tokenText)}`);
    const token = JSON.parse(tokenText);
    if (!token.access_token) throw new Error('Token response contained no access_token.');
    return { accessToken: token.access_token, tokenType: token.token_type || 'Bearer', expiresIn: token.expires_in, scope: token.scope || scope };
  } finally {
    clearTimeout(timer);
    server.closeAllConnections?.();
    server.close();
  }
}

module.exports = {
  PROTOCOL_VERSION,
  WIZ_MCP_URL,
  WIZ_RESOURCE,
  WIZ_SCOPE,
  McpClient,
  parseMcpBody,
  safeSnippet,
  discoverAuthServer,
  wizOAuthLogin,
};
