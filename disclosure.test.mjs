// Asserts the unauthenticated surface leaks nothing useful for recon.
import fs from 'fs';

const PORT = 3333;
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
fs.writeFileSync(new URL('./.disclosure.testable.mjs', import.meta.url), src);
const { YahooMailMCPServer } = await import('./.disclosure.testable.mjs');

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

// Things an attacker would use to pick an exploit or confirm a live target.
const FORBIDDEN = [
    ['node version',      /v?\d+\.\d+\.\d+/],
    ['platform',          /linux|darwin|win32/i],
    ['app version',       /"version"/],
    ['tool inventory',    /delete_emails|list_emails|move_emails/],
    ['credential status', /emailConfigured|passwordConfigured/],
    ['transport mode',    /transportMode/],
    ['internal paths',    /\/(app|Users|home)\//],
];

for (const path of ['/health', '/']) {
    console.log(`--- unauthenticated GET ${path} ---`);
    const res = await fetch(`${BASE}${path}`);
    const body = await res.text();
    check('returns 200', res.status === 200, `HTTP ${res.status}`);
    for (const [label, re] of FORBIDDEN) {
        check(`no ${label}`.padEnd(24), !re.test(body), body.slice(0, 90));
    }
    check('x-powered-by header absent', !res.headers.get('x-powered-by'),
        String(res.headers.get('x-powered-by')));
    console.log(`      body: ${body}`);
}

console.log('\n--- /health still usable as a health check ---');
{
    const res = await fetch(`${BASE}/health`);
    const body = await res.json();
    check('status is ok', body.status === 'ok');
    check('body is minimal (1 key)', Object.keys(body).length === 1, JSON.stringify(body));
}

console.log('\n--- /diagnostics requires auth ---');
{
    const anon = await fetch(`${BASE}/diagnostics`);
    check('unauthenticated -> 401', anon.status === 401, `HTTP ${anon.status}`);
    const anonBody = await anon.text();
    for (const [label, re] of FORBIDDEN) {
        check(`401 body leaks no ${label}`.padEnd(34), !re.test(anonBody), anonBody.slice(0, 80));
    }

    const tok = await (await fetch(`${BASE}/oauth/token`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET }),
    })).json();

    const authed = await fetch(`${BASE}/diagnostics`, { headers: { Authorization: `Bearer ${tok.access_token}` } });
    const d = await authed.json();
    check('authenticated -> 200', authed.status === 200, `HTTP ${authed.status}`);
    check('authenticated body still has the detail',
        !!d.environment?.nodeVersion && d.environment.emailConfigured === true);
}

console.log('\n--- error responses do not echo exception text ---');
{
    const src2 = fs.readFileSync(new URL('./server.js', import.meta.url), 'utf8');
    check('error middleware does not return err.message',
        !/error:\s*'Internal server error',\s*\n\s*message:\s*err\.message/.test(src2));
}

console.error = origLog;
fs.unlinkSync(new URL('./.disclosure.testable.mjs', import.meta.url));
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
