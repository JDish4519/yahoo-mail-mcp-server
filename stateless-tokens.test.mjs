// Proves OAuth tokens survive a process restart when TOKEN_SIGNING_SECRET is
// set, that nothing changes when it is not, and that a signed token cannot be
// tampered with, confused for the other type, or reused after the secret
// that signed it is rotated out.
import crypto from 'crypto';
import fs from 'fs';

const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
const SIGNING_SECRET = crypto.randomBytes(32).toString('hex');

process.env.OAUTH_CLIENT_ID = CLIENT_ID;
process.env.OAUTH_CLIENT_SECRET = CLIENT_SECRET;
process.env.TRANSPORT_MODE = 'sse';

const src = fs.readFileSync(new URL('./server.js', import.meta.url), 'utf8')
    .replace(/\/\/ Start the server[\s\S]*$/, 'export { YahooMailMCPServer };\n');
fs.writeFileSync(new URL('./.stateless.testable.mjs', import.meta.url), src);
const { YahooMailMCPServer } = await import('./.stateless.testable.mjs');

let failures = 0;
const check = (name, cond, detail = '') => {
    console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : `  <- ${detail}`}`);
    if (!cond) failures++;
};

const origLog = console.error;
console.error = () => {};

// Boots a server on its own port. Two of these, sharing only process.env
// (exactly what Render preserves across a spin-down restart), stand in for
// "before" and "after" -- neither instance ever sees the other's in-memory
// Maps, which is the property a real restart has too.
const boot = async (port) => {
    process.env.PORT = String(port);
    const srv = new YahooMailMCPServer();
    await srv.runSSE();
    const base = `http://localhost:${port}`;
    for (let i = 0; i < 50; i++) {
        try { await fetch(`${base}/health`); break; } catch { await new Promise(r => setTimeout(r, 100)); }
    }
    return { srv, base };
};

const pkce = () => {
    const verifier = crypto.randomBytes(32).toString('base64url');
    return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
};
const baseAuthParams = (over = {}) => ({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT,
    code_challenge: pkce().challenge, code_challenge_method: 'S256', ...over,
});
const authorize = (base, params) =>
    fetch(`${base}/oauth/authorize?${new URLSearchParams(params)}`, { redirect: 'manual' });
const tokenReq = (base, body) =>
    fetch(`${base}/oauth/token`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
const probeAuth = async (base, accessToken) => {
    const headers = { 'Content-Type': 'application/json' };
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    const r = await fetch(`${base}/mcp/message`, { method: 'POST', headers, body: '{}' });
    return r.status;
};

console.log('--- memory mode: the problem this feature exists to fix ---');
{
    delete process.env.TOKEN_SIGNING_SECRET;
    const before = await boot(3441);
    const after = await boot(3442);

    const res = await tokenReq(before.base, {
        grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET
    });
    const { access_token } = await res.json();

    check('token works against the instance that issued it',
        (await probeAuth(before.base, access_token)) !== 401);
    check('same token rejected by a fresh instance (this is the bug being fixed)',
        (await probeAuth(after.base, access_token)) === 401);
    check('issuing instance stored it in memory', before.srv.validTokens.size === 1);
    check('fresh instance never saw it', after.srv.validTokens.size === 0);
}

console.log('\n--- stateless mode: an access token survives a restart ---');
{
    process.env.TOKEN_SIGNING_SECRET = SIGNING_SECRET;
    const before = await boot(3443);
    const after = await boot(3444);

    const res = await tokenReq(before.base, {
        grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET
    });
    const { access_token } = await res.json();
    check('token looks signed, not random', access_token.split('.').length === 2, access_token.slice(0, 40));

    check('token works against the issuing instance',
        (await probeAuth(before.base, access_token)) !== 401);
    check('SAME token works against a fresh instance (the fix)',
        (await probeAuth(after.base, access_token)) !== 401);
    check('issuing instance never stored it in memory', before.srv.validTokens.size === 0);
}

console.log('\n--- stateless mode: a refresh token survives a restart ---');
{
    const before = await boot(3445);
    const after = await boot(3446);

    const { verifier, challenge } = pkce();
    const ar = await authorize(before.base, baseAuthParams({ code_challenge: challenge }));
    const code = new URL(ar.headers.get('location')).searchParams.get('code');
    const ex = await tokenReq(before.base, {
        grant_type: 'authorization_code', code, redirect_uri: REDIRECT,
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: verifier
    });
    const { refresh_token } = await ex.json();
    check('refresh token issued and signed', refresh_token?.split('.').length === 2);

    // The "restart": redeem it against an instance that never saw the
    // authorization code or the original refresh token being minted.
    const refreshed = await tokenReq(after.base, {
        grant_type: 'refresh_token', refresh_token, client_id: CLIENT_ID, client_secret: CLIENT_SECRET
    });
    const rBody = await refreshed.json();
    check('refresh succeeds against a fresh instance',
        refreshed.status === 200 && !!rBody.access_token, JSON.stringify(rBody).slice(0, 100));
    check('the new access token also works against that instance',
        (await probeAuth(after.base, rBody.access_token)) !== 401);
}

console.log('\n--- stateless token integrity ---');
{
    process.env.TOKEN_SIGNING_SECRET = SIGNING_SECRET;
    const srv = new YahooMailMCPServer();

    const future = Date.now() + 60_000;
    const past = Date.now() - 1000;

    const good = srv.signStatelessToken({ typ: 'access', client_id: CLIENT_ID, scope: 'mcp', expiresAt: future });
    check('a freshly signed token verifies', srv.verifyStatelessToken(good, 'access') !== null);

    // Flip one character in the payload segment.
    const [payloadB64, sig] = good.split('.');
    const flip = (s) => `${s.slice(0, -1)}${s.slice(-1) === 'A' ? 'B' : 'A'}`;
    check('a tampered payload is rejected',
        srv.verifyStatelessToken(`${flip(payloadB64)}.${sig}`, 'access') === null);
    check('a tampered signature is rejected',
        srv.verifyStatelessToken(`${payloadB64}.${flip(sig)}`, 'access') === null);

    // Both token types are signed with the same secret; only the typ claim
    // tells them apart, so it has to be checked, not just the signature.
    const refreshTok = srv.signStatelessToken({ typ: 'refresh', client_id: CLIENT_ID, scope: 'mcp', expiresAt: future });
    check('an access token is rejected where a refresh token is required',
        srv.verifyStatelessToken(good, 'refresh') === null);
    check('a refresh token is rejected where an access token is required',
        srv.verifyStatelessToken(refreshTok, 'access') === null);

    const expired = srv.signStatelessToken({ typ: 'access', client_id: CLIENT_ID, scope: 'mcp', expiresAt: past });
    check('an expired stateless token is rejected', srv.verifyStatelessToken(expired, 'access') === null);

    // Simulates rotating TOKEN_SIGNING_SECRET: every previously issued token
    // stops verifying, all at once. That is the accepted trade-off for
    // needing no external store, not a bug.
    process.env.TOKEN_SIGNING_SECRET = crypto.randomBytes(32).toString('hex');
    check('a token signed under a rotated secret no longer verifies',
        srv.verifyStatelessToken(good, 'access') === null);
}

console.error = origLog;
fs.unlinkSync(new URL('./.stateless.testable.mjs', import.meta.url));
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
