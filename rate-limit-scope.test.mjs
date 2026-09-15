// The token endpoint's rate limiter has to bucket by the REAL client, not by
// whatever address Render's proxy chain happens to present.
//
// With the old `trust proxy: 1`, req.ip resolved to Render's internal load
// balancer -- one constant for every caller on the internet. The per-IP window
// below then became a single global bucket, and because rateLimitToken runs
// before credential validation, anyone could spend all 20 attempts a minute
// with junk credentials and lock the real client out of renewing its token.
//
// Replays a real captured Render chain (client, Cloudflare edge, internal LB)
// rather than a synthetic one, so this tests the deployment's actual shape.
import fs from 'fs';

const PORT = 3229;
const BASE = `http://localhost:${PORT}`;
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';

process.env.TRANSPORT_MODE = 'sse';
process.env.PORT = String(PORT);
process.env.OAUTH_CLIENT_ID = CLIENT_ID;
process.env.OAUTH_CLIENT_SECRET = CLIENT_SECRET;

const src = fs.readFileSync(new URL('./server.js', import.meta.url), 'utf8')
    .replace(/\/\/ Start the server[\s\S]*$/, 'export { YahooMailMCPServer };\n');
fs.writeFileSync(new URL('./.ratelimit.testable.mjs', import.meta.url), src);
const { YahooMailMCPServer } = await import('./.ratelimit.testable.mjs');

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

// Cloudflare edge then Render's private LB, exactly as captured from a live
// Render deployment. Only the leftmost address differs between callers.
const CHAIN_TAIL = '104.23.197.250, 10.31.147.130';
const ATTACKER_IP = '203.0.113.9';
const VICTIM_IP = '24.210.72.128';

const tokenAs = (clientIp, body) =>
    fetch(`${BASE}/oauth/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Forwarded-For': `${clientIp}, ${CHAIN_TAIL}`
        },
        body: JSON.stringify(body)
    });

const goodCreds = { grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET };
const junkCreds = { grant_type: 'client_credentials', client_id: 'wrong', client_secret: 'wrong' };

console.log('--- one caller cannot exhaust another caller\'s budget ---');
{
    // Attacker spends the whole window with credentials that never validate.
    const attackerStatuses = [];
    for (let i = 0; i < 25; i++) {
        attackerStatuses.push((await tokenAs(ATTACKER_IP, junkCreds)).status);
    }

    check('attacker\'s own bogus requests are rejected',
        attackerStatuses.every((s) => s === 401 || s === 429),
        JSON.stringify(attackerStatuses.slice(0, 5)));

    check('attacker eventually throttles itself',
        attackerStatuses.includes(429),
        'never hit its own limit');

    // The legitimate client, at a different address, must be unaffected.
    const victim = await tokenAs(VICTIM_IP, goodCreds);
    const victimBody = await victim.json().catch(() => ({}));

    check('legitimate client at a DIFFERENT IP still gets a token',
        victim.status === 200, `HTTP ${victim.status} ${JSON.stringify(victimBody).slice(0, 80)}`);
    check('and that response really carries an access token',
        typeof victimBody.access_token === 'string' && victimBody.access_token.length > 0,
        JSON.stringify(victimBody).slice(0, 80));
}

console.log('\n--- the real client address is what gets bucketed ---');
{
    // Same real client, hammering: it must still be able to throttle itself,
    // or the limiter would be bucketing on something it does not control.
    const statuses = [];
    for (let i = 0; i < 25; i++) {
        statuses.push((await tokenAs('198.51.100.7', junkCreds)).status);
    }
    check('a single client can still be rate limited', statuses.includes(429),
        JSON.stringify(statuses.slice(-3)));

    // A caller cannot escape its own bucket by prepending addresses: everything
    // left of the first untrusted hop is never consulted.
    const spoofed = await fetch(`${BASE}/oauth/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Forwarded-For': `6.6.6.6, 198.51.100.7, ${CHAIN_TAIL}`
        },
        body: JSON.stringify(junkCreds)
    });
    check('prepending a fake hop does not buy a fresh bucket',
        spoofed.status === 429, `HTTP ${spoofed.status}`);
}

console.error = origLog;
fs.unlinkSync(new URL('./.ratelimit.testable.mjs', import.meta.url));
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
