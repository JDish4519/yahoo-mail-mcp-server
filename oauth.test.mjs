// OAuth hardening tests. Boots the real server on a random port with known
// credentials and drives the endpoints over HTTP.
import crypto from 'crypto';
import fs from 'fs';

const PORT = 3222;
const BASE = `http://localhost:${PORT}`;
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

// Run the real server in THIS process, so the tests can inspect and age the
// token store directly rather than only asserting on the source text.
process.env.TRANSPORT_MODE = 'sse';
process.env.PORT = String(PORT);
process.env.OAUTH_CLIENT_ID = CLIENT_ID;
process.env.OAUTH_CLIENT_SECRET = CLIENT_SECRET;

const src = fs.readFileSync(new URL('./server.js', import.meta.url), 'utf8')
    .replace(/\/\/ Start the server[\s\S]*$/, 'export { YahooMailMCPServer };\n');
fs.writeFileSync(new URL('./.oauth.testable.mjs', import.meta.url), src);
const { YahooMailMCPServer } = await import('./.oauth.testable.mjs');

const srv = new YahooMailMCPServer();
const origLog = console.error;
console.error = () => {};
await srv.runSSE();
for (let i = 0; i < 50; i++) {
    try { await fetch(`${BASE}/health`); break; } catch { await new Promise(r => setTimeout(r, 100)); }
}

let failures = 0;
const check = (name, cond, detail = '') => {
    console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : `  <- ${detail}`}`);
    if (!cond) failures++;
};

const authorize = (params) =>
    fetch(`${BASE}/oauth/authorize?${new URLSearchParams(params)}`, { redirect: 'manual' });

const token = (body) =>
    fetch(`${BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });

// Returns the HTTP status of an authenticated probe. 401 means the middleware
// rejected it; anything else (404 = no active session) means it got through.
const probeAuth = async (accessToken) => {
    const headers = { 'Content-Type': 'application/json' };
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    const r = await fetch(`${BASE}/mcp/message`, { method: 'POST', headers, body: '{}' });
    return r.status;
};

const pkce = () => {
    const verifier = crypto.randomBytes(32).toString('base64url');
    return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
};

const baseAuthParams = (over = {}) => ({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT,
    code_challenge: pkce().challenge, code_challenge_method: 'S256', ...over,
});

console.log('--- redirect_uri validation (the open redirect) ---');
for (const [name, uri] of [
    ['evil.com with claude.ai in query', 'https://evil.com/cb?x=claude.ai'],
    ['claude.ai as a subdomain of evil', 'https://claude.ai.evil.com/cb'],
    ['path-based lookalike',             'https://evil.com/claude.ai'],
    ['localhost substring on evil host', 'https://localhost.evil.com/cb'],
    ['cleartext http to claude.ai',      'http://claude.ai/cb'],
    ['not a url at all',                 'claude.ai'],
]) {
    const r = await authorize(baseAuthParams({ redirect_uri: uri }));
    check(name.padEnd(34) + ' rejected', r.status === 400, `HTTP ${r.status}`);
}
for (const [name, uri] of [
    ['claude.ai callback', REDIRECT],
    ['claude.com callback', 'https://claude.com/api/mcp/auth_callback'],
    ['localhost dev callback', 'http://localhost:5173/cb'],
]) {
    const r = await authorize(baseAuthParams({ redirect_uri: uri }));
    check(name.padEnd(34) + ' allowed', r.status === 302, `HTTP ${r.status}`);
}

console.log('\n--- PKCE is mandatory ---');
{
    const noChallenge = baseAuthParams();
    delete noChallenge.code_challenge;
    check('authorize without code_challenge rejected', (await authorize(noChallenge)).status === 400);
    check('plain method rejected',
        (await authorize(baseAuthParams({ code_challenge_method: 'plain' }))).status === 400);
}

console.log('\n--- authorization code exchange ---');
{
    const { verifier, challenge } = pkce();
    const r = await authorize(baseAuthParams({ code_challenge: challenge }));
    const code = new URL(r.headers.get('location')).searchParams.get('code');
    check('code is not guessable (>=32 chars, no client_id inside)',
        code.length >= 32 && !Buffer.from(code, 'base64url').toString().includes(CLIENT_ID));

    // Wrong verifier must fail.
    const bad = await token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT,
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: 'wrong-verifier' });
    check('wrong code_verifier rejected', bad.status === 400);

    // That failed attempt burned the code, so mint a fresh one.
    const { verifier: v2, challenge: c2 } = pkce();
    const r2 = await authorize(baseAuthParams({ code_challenge: c2 }));
    const code2 = new URL(r2.headers.get('location')).searchParams.get('code');

    const mismatch = await token({ grant_type: 'authorization_code', code: code2,
        redirect_uri: 'https://claude.com/other', client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET, code_verifier: v2 });
    check('mismatched redirect_uri rejected', mismatch.status === 400);

    const { verifier: v3, challenge: c3 } = pkce();
    const r3 = await authorize(baseAuthParams({ code_challenge: c3 }));
    const code3 = new URL(r3.headers.get('location')).searchParams.get('code');

    const ok = await token({ grant_type: 'authorization_code', code: code3, redirect_uri: REDIRECT,
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: v3 });
    const body = await ok.json();
    check('valid exchange succeeds', ok.status === 200 && !!body.access_token, JSON.stringify(body).slice(0, 80));
    check('returns a refresh_token', !!body.refresh_token);

    const replay = await token({ grant_type: 'authorization_code', code: code3, redirect_uri: REDIRECT,
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: v3 });
    check('code cannot be replayed', replay.status === 400);

    // The freshly issued token must actually work.
    const authed = await probeAuth(body.access_token);
    check('issued token passes authentication', authed !== 401, `HTTP ${authed}`);

    // Refresh rotation.
    const refreshed = await token({ grant_type: 'refresh_token', refresh_token: body.refresh_token,
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET });
    const rBody = await refreshed.json();
    check('refresh returns a new access token', refreshed.status === 200 && !!rBody.access_token);
    const reused = await token({ grant_type: 'refresh_token', refresh_token: body.refresh_token,
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET });
    check('old refresh token is rotated out', reused.status === 400);
}

console.log('\n--- credentials and tokens ---');
{
    const bad = await token({ grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: 'nope' });
    check('wrong client_secret rejected', bad.status === 401);
    check('unauthenticated request rejected', (await probeAuth(null)) === 401);
    check('garbage bearer rejected', (await probeAuth('nope')) === 401);
}

console.log('\n--- expiry is actually enforced (behavioural) ---');
{
    // Mint a real token over HTTP, prove it works, then age it into the past.
    const res = await token({ grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET });
    const { access_token, expires_in } = await res.json();

    const before = await probeAuth(access_token);
    check('fresh token accepted', before !== 401, `HTTP ${before}`);

    const entry = srv.validTokens.get(access_token);
    check('token stored with a future expiry', !!entry && entry.expiresAt > Date.now());
    check('stored TTL matches advertised expires_in',
        Math.abs((entry.expiresAt - Date.now()) - expires_in * 1000) < 5000,
        `expires_in=${expires_in}`);

    // Age it one second past its lifetime.
    entry.expiresAt = Date.now() - 1000;
    const after = await probeAuth(access_token);
    check('EXPIRED token now rejected', after === 401, `HTTP ${after}`);
    check('expired token evicted from the store', !srv.validTokens.has(access_token));

    // Expired auth codes must not be exchangeable.
    const { verifier, challenge } = pkce();
    const ar = await authorize(baseAuthParams({ code_challenge: challenge }));
    const code = new URL(ar.headers.get('location')).searchParams.get('code');
    srv.authCodes.get(code).expiresAt = Date.now() - 1000;
    const ex = await token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT,
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: verifier });
    check('EXPIRED authorization code rejected', ex.status === 400, `HTTP ${ex.status}`);

    // The sweep drops stale entries.
    srv.validTokens.set('stale', { client_id: CLIENT_ID, scope: 'mcp', expiresAt: Date.now() - 1 });
    srv.pruneExpiredOAuthState();
    check('sweep prunes expired entries', !srv.validTokens.has('stale'));
}

console.error = origLog;
fs.unlinkSync(new URL('./.oauth.testable.mjs', import.meta.url));
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
