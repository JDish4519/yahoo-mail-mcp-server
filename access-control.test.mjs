// Asserts the server cannot come up unauthenticated, and that the MCP endpoints
// are not reachable cross-origin or via a rebound hostname.
import fs from 'fs';
import http from 'node:http';
import { spawnSync } from 'child_process';

// fetch() silently drops a caller-supplied Host header (forbidden in undici), so
// anything testing Host has to go out over a raw request. Resolves as soon as the
// status line arrives and tears the socket down, so an SSE stream cannot hang us.
const rawRequest = ({ method, path, headers = {}, body }) => new Promise((resolve, reject) => {
    const req = http.request(
        { host: '127.0.0.1', port: PORT, method, path, headers },
        (res) => {
            resolve(res.statusCode);
            res.destroy();
            req.destroy();
        }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
});

const PORT = 3334;
const BASE = `http://localhost:${PORT}`;
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';

process.env.TRANSPORT_MODE = 'sse';
process.env.PORT = String(PORT);
process.env.OAUTH_CLIENT_ID = CLIENT_ID;
process.env.OAUTH_CLIENT_SECRET = CLIENT_SECRET;
process.env.YAHOO_EMAIL = 'someone@yahoo.com';
process.env.YAHOO_APP_PASSWORD = 'x'.repeat(16);

const src = fs.readFileSync(new URL('./server.js', import.meta.url), 'utf8')
    .replace(/\/\/ Start the server[\s\S]*$/, 'export { YahooMailMCPServer };\n');
fs.writeFileSync(new URL('./.access.testable.mjs', import.meta.url), src);
const { YahooMailMCPServer } = await import('./.access.testable.mjs');

let failures = 0;
const check = (name, cond, detail = '') => {
    console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : `  <- ${detail}`}`);
    if (!cond) failures++;
};

// --- startup refuses to run unauthenticated -------------------------------
// Separate process, because the guard calls process.exit(1).
console.log('--- SSE mode without OAuth credentials must not start ---');
for (const missing of ['OAUTH_CLIENT_ID', 'OAUTH_CLIENT_SECRET', 'both']) {
    const env = { ...process.env, TRANSPORT_MODE: 'sse', PORT: String(PORT + 10) };
    if (missing === 'both') {
        delete env.OAUTH_CLIENT_ID;
        delete env.OAUTH_CLIENT_SECRET;
    } else {
        delete env[missing];
    }

    const run = spawnSync(process.execPath, ['server.js'], {
        cwd: new URL('.', import.meta.url).pathname,
        env,
        encoding: 'utf8',
        timeout: 15000
    });

    check(`missing ${missing}`.padEnd(28) + '-> exit 1',
        run.status === 1, `exit=${run.status}`);
    check(`missing ${missing}`.padEnd(28) + '-> says why',
        /OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET are required/.test(run.stderr || ''),
        (run.stderr || '').slice(0, 120));
}

// stdio mode has no HTTP surface, so it must NOT be blocked by the guard.
{
    const env = { ...process.env, TRANSPORT_MODE: 'stdio' };
    delete env.OAUTH_CLIENT_ID;
    delete env.OAUTH_CLIENT_SECRET;
    const run = spawnSync(process.execPath, ['server.js'], {
        cwd: new URL('.', import.meta.url).pathname,
        env, encoding: 'utf8', timeout: 4000
    });
    // Killed by timeout means it stayed up, which is what we want.
    check('stdio mode still starts without OAuth creds',
        run.status !== 1, `exit=${run.status} stderr=${(run.stderr || '').slice(0, 80)}`);
}

// --- boot a configured instance -------------------------------------------
const srv = new YahooMailMCPServer();
const origLog = console.error;
console.error = () => {};
await srv.runSSE();
for (let i = 0; i < 50; i++) {
    try { await fetch(`${BASE}/health`); break; } catch { await new Promise(r => setTimeout(r, 100)); }
}

const token = await (async () => {
    const r = await fetch(`${BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            grant_type: 'client_credentials',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET
        })
    });
    return (await r.json()).access_token;
})();

const auth = { Authorization: `Bearer ${token}` };

// --- CORS ------------------------------------------------------------------
console.log('\n--- CORS must not reflect arbitrary origins ---');
const hostileOrigins = [
    'https://evil.com',
    'https://claude.ai.evil.com',
    'http://claude.ai',                 // scheme downgrade
    'https://evil.com/?x=https://claude.ai',
    'null',
];
for (const origin of hostileOrigins) {
    const r = await fetch(`${BASE}/health`, { headers: { Origin: origin } });
    const acao = r.headers.get('access-control-allow-origin');
    check(`no ACAO for ${origin}`.padEnd(52), acao === null, `got ${acao}`);
}

for (const origin of ['https://claude.ai', 'https://claude.com']) {
    const r = await fetch(`${BASE}/health`, { headers: { Origin: origin } });
    check(`ACAO present for ${origin}`.padEnd(52),
        r.headers.get('access-control-allow-origin') === origin,
        `got ${r.headers.get('access-control-allow-origin')}`);
}

{
    // Non-browser client, no Origin header: must still work.
    const r = await fetch(`${BASE}/health`);
    check('no Origin header -> still served'.padEnd(52), r.status === 200, `status ${r.status}`);
}

// --- Origin enforcement on /mcp -------------------------------------------
console.log('\n--- /mcp rejects disallowed Origin even with a valid token ---');
for (const origin of ['https://evil.com', 'https://claude.ai.evil.com']) {
    const r = await fetch(`${BASE}/mcp/message?sessionId=nope`, {
        method: 'POST',
        headers: { ...auth, 'Content-Type': 'application/json', Origin: origin },
        body: '{}'
    });
    check(`403 for Origin ${origin}`.padEnd(52), r.status === 403, `status ${r.status}`);
}

// --- DNS rebinding ---------------------------------------------------------
console.log('\n--- /mcp rejects unknown Host (DNS rebinding) ---');
const badHosts = ['evil.com', `attacker.test:${PORT}`, 'localhost.evil.com', `127.0.0.1.evil.com:${PORT}`];
for (const host of badHosts) {
    for (const [label, path, method] of [
        ['GET  /mcp/sse    ', '/mcp/sse', 'GET'],
        ['POST /mcp/message', '/mcp/message?sessionId=nope', 'POST'],
    ]) {
        const status = await rawRequest({
            method,
            path,
            headers: { ...auth, Host: host, 'Content-Type': 'application/json' },
            body: method === 'POST' ? '{}' : undefined
        });
        check(`${label} Host=${host}`.padEnd(56), status === 403, `status ${status}`);
    }
}

{
    // The legitimate Host must still be accepted (403 would break real clients).
    const status = await rawRequest({
        method: 'POST',
        path: '/mcp/message?sessionId=nope',
        headers: { ...auth, Host: `localhost:${PORT}`, 'Content-Type': 'application/json' },
        body: '{}'
    });
    check('allowed Host -> not 403'.padEnd(56), status !== 403, `status ${status}`);
}

// --- token endpoint throttling ---------------------------------------------
console.log('\n--- /oauth/token throttles credential guessing ---');
{
    // Wrong secret, repeatedly: what a brute-force attempt looks like.
    const guess = () => fetch(`${BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            grant_type: 'client_credentials',
            client_id: CLIENT_ID,
            client_secret: 'wrong-secret'
        })
    });

    const statuses = [];
    for (let i = 0; i < 30; i++) statuses.push((await guess()).status);

    const rejected = statuses.filter(s => s === 401).length;
    const throttled = statuses.filter(s => s === 429).length;

    check('bad credentials rejected'.padEnd(46), rejected > 0, `${rejected} x 401`);
    check('sustained guessing gets throttled'.padEnd(46), throttled > 0, `${throttled} x 429`);
    check('throttle kicks in after a usable allowance'.padEnd(46), rejected >= 15, `only ${rejected} allowed`);

    const limited = await guess();
    check('429 carries Retry-After'.padEnd(46), limited.headers.get('retry-after') !== null,
        `headers: ${[...limited.headers.keys()].join(',')}`);
}

// --- auth still enforced ---------------------------------------------------
console.log('\n--- unauthenticated MCP access still refused ---');
{
    const r = await fetch(`${BASE}/mcp/sse`);
    check('GET /mcp/sse without token -> 401'.padEnd(52), r.status === 401, `status ${r.status}`);
}

console.error = origLog;
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
