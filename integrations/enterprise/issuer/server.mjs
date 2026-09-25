import http from 'node:http';
import { readFileSync } from 'node:fs';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import Provider, { errors } from 'oidc-provider';

const config = JSON.parse(readFileSync('/config/issuer.json'));
const users = new Map(config.users.map(user => [user.id, user]));
const scopes = 'model:invoke mcp:connect workspace:read workspace:list document:read document:write action:propose operator:approve';
const provider = new Provider(config.issuer, {
  clients: config.clients, jwks: config.jwks, cookies: { keys: config.cookieKeys },
  claims: { openid: ['sub'] }, scopes: ['openid', ...scopes.split(' ')],
  pkce: { required: () => true },
  features: {
    devInteractions: { enabled: false }, clientCredentials: { enabled: true },
    resourceIndicators: {
      enabled: true, defaultResource: () => config.resource, useGrantedResource: () => true,
      getResourceServerInfo: (_ctx, resource) => {
        if (resource !== config.resource) throw new errors.InvalidTarget();
        return { scope: scopes, audience: config.resource, accessTokenTTL: 300,
          accessTokenFormat: 'jwt', jwt: { sign: { alg: 'RS256' } } };
      },
    },
  },
  interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
  findAccount: async (_ctx, id) => users.has(id)
    ? { accountId: id, claims: async () => ({ sub: id }) } : undefined,
  extraTokenClaims: async (_ctx, token) => ({ sub: token.accountId || token.clientId }),
});
const csrf = new Map(); const attempts = new Map(); const callback = provider.callback();
const server = http.createServer(async (req, res) => {
  try {
    if (req.url === '/health') { res.end('ready'); return; }
    if (!/^\/interaction\/[A-Za-z0-9_-]+$/.test(req.url || '')) { callback(req, res); return; }
    const details = await provider.interactionDetails(req, res);
    const { uid, prompt, params, session } = details;
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method === 'GET') {
      const nonce = randomBytes(32).toString('hex');
      if (csrf.size > 1024) csrf.clear();
      csrf.set(uid, { nonce, expires: Date.now() + 300000 });
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      const fields = prompt.name === 'login'
        ? '<label>Account <input name="username" autocomplete="username" required></label><label>Password <input name="password" type="password" autocomplete="current-password" required></label>'
        : '<p>Allow the registered Loom lab client to use your selected API permissions?</p>';
      res.end(`<form method="post"><input type="hidden" name="csrf" value="${nonce}">${fields}<button type="submit">Continue</button></form>`); return;
    }
    if (req.method !== 'POST') { res.writeHead(405).end(); return; }
    const expected = csrf.get(uid); csrf.delete(uid);
    let body = ''; for await (const part of req) { body += part; if (body.length > 4096) throw new Error('input limit'); }
    const form = new URLSearchParams(body);
    if (!expected || expected.expires < Date.now() || form.get('csrf') !== expected.nonce) throw new Error('invalid interaction');
    if (req.headers.origin && req.headers.origin !== config.issuer) throw new Error('invalid origin');
    if (prompt.name === 'login') {
      const username = form.get('username') || ''; const account = users.get(username);
      const now = Date.now(); const prior = attempts.get(username) || { count: 0, until: now + 60000 };
      if (prior.until < now) { prior.count = 0; prior.until = now + 60000; }
      if (attempts.size > 1024) throw new Error('login capacity');
      prior.count++; attempts.set(username, prior);
      if (prior.count > 5) throw new Error('login limited');
      const hash = scryptSync(form.get('password') || '', account?.salt || 'invalid-account', 32);
      if (!account || !timingSafeEqual(hash, Buffer.from(account.hash, 'hex'))) throw new Error('invalid login');
      await provider.interactionFinished(req, res, { login: { accountId: account.id, amr: ['pwd'], remember: false } }, { mergeWithLastSubmission: false });
    } else if (prompt.name === 'consent') {
      const grant = details.grantId ? await provider.Grant.find(details.grantId)
        : new provider.Grant({ accountId: session.accountId, clientId: params.client_id });
      if (prompt.details.missingOIDCScope) grant.addOIDCScope(prompt.details.missingOIDCScope.join(' '));
      for (const [resource, requested] of Object.entries(prompt.details.missingResourceScopes || {})) grant.addResourceScope(resource, requested.join(' '));
      await provider.interactionFinished(req, res, { consent: { grantId: await grant.save() } }, { mergeWithLastSubmission: true });
    } else { throw new Error('unsupported interaction'); }
  } catch {
    if (!res.headersSent) res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Interaction denied');
  }
});
server.requestTimeout = 10000; server.headersTimeout = 5000;
server.listen(8080, '0.0.0.0');
