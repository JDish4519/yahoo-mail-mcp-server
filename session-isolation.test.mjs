// Two clients must get two independent sessions, and a message must only ever
// reach the session it names.
import fs from 'fs';
import http from 'node:http';

const PORT = 3355;
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
fs.writeFileSync(new URL('./.session.testable.mjs', import.meta.url), src);
const { YahooMailMCPServer } = await import('./.session.testable.mjs');

const srv = new YahooMailMCPServer();
const origLog = console.error;
console.error = () => {};
await srv.runSSE();
for (let i = 0; i < 50; i++) {
    try { await fetch(`http://127.0.0.1:${PORT}/health`); break; } catch { await new Promise(r => setTimeout(r, 100)); }
}

let failures = 0;
const check = (name, cond, detail = '') => {
    console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : `  <- ${detail}`}`);
    if (!cond) failures++;
};

const token = await (async () => {
    const r = await fetch(`http://127.0.0.1:${PORT}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET })
    });
    return (await r.json()).access_token;
})();

// Opens an SSE stream and resolves with its sessionId plus a live buffer of
// everything the server pushes down it.
const openSession = () => new Promise((resolve, reject) => {
    const req = http.request({
        host: '127.0.0.1', port: PORT, path: '/mcp/sse', method: 'GET',
        headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' }
    }, (res) => {
        if (res.statusCode !== 200) return reject(new Error(`status ${res.statusCode}`));
        const state = { received: '', close: () => { res.destroy(); req.destroy(); } };
        res.on('data', (c) => {
            state.received += c;
            const m = state.received.match(/sessionId=([0-9a-f-]+)/);
            if (m && !state.sessionId) { state.sessionId = m[1]; resolve(state); }
        });
    });
    req.on('error', reject);
    req.end();
    setTimeout(() => reject(new Error('timed out opening session')), 5000);
});

const post = (sessionId, body) => fetch(
    `http://127.0.0.1:${PORT}/mcp/message${sessionId ? `?sessionId=${sessionId}` : ''}`,
    { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
);

console.log('--- two clients can connect at once ---');
const a = await openSession();
const b = await openSession().catch(e => ({ error: e.message }));

check('first session opens', !!a.sessionId, JSON.stringify(a).slice(0, 80));
check('second session opens', !!b.sessionId, b.error ?? 'no sessionId');
check('sessions get distinct ids', a.sessionId && b.sessionId && a.sessionId !== b.sessionId,
    `${a.sessionId} vs ${b.sessionId}`);

console.log('\n--- messages route only to the named session ---');
{
    const rpc = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} };
    a.received = ''; b.received = '';
    const res = await post(a.sessionId, rpc);
    check('accepted for a valid session', res.status === 202, `status ${res.status}`);

    await new Promise(r => setTimeout(r, 400));
    check('reply arrived on the addressed session', /list_emails/.test(a.received), a.received.slice(0, 60));
    check('nothing leaked to the other session', !/list_emails/.test(b.received), b.received.slice(0, 60));
}

console.log('\n--- unroutable messages are refused, not guessed ---');
{
    const rpc = { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} };
    a.received = ''; b.received = '';

    const noId = await post(null, rpc);
    check('missing sessionId -> 400', noId.status === 400, `status ${noId.status}`);

    const unknown = await post('11111111-2222-3333-4444-555555555555', rpc);
    check('unknown sessionId -> 404', unknown.status === 404, `status ${unknown.status}`);

    await new Promise(r => setTimeout(r, 400));
    check('no fallback delivery to session a', !/list_emails/.test(a.received), a.received.slice(0, 60));
    check('no fallback delivery to session b', !/list_emails/.test(b.received), b.received.slice(0, 60));
}

console.log('\n--- closing a session deregisters it ---');
{
    const closedId = b.sessionId;
    b.close();
    await new Promise(r => setTimeout(r, 500));

    const res = await post(closedId, { jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} });
    check('closed session no longer routable', res.status === 404, `status ${res.status}`);
    check('surviving session still routable',
        (await post(a.sessionId, { jsonrpc: '2.0', id: 4, method: 'tools/list', params: {} })).status === 202);
}

a.close();
console.error = origLog;
fs.unlinkSync(new URL('./.session.testable.mjs', import.meta.url));
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
