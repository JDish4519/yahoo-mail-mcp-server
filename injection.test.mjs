// Exercises the REAL searchEmails() from server.js against IMAP command injection.
// Loads server.js with its bootstrap lines swapped for an export, so nothing starts up.
import fs from 'fs';

const src = fs.readFileSync(new URL('./server.js', import.meta.url), 'utf8')
    .replace(/\/\/ Start the server[\s\S]*$/, 'export { YahooMailMCPServer };\n');
fs.writeFileSync(new URL('./.server.testable.mjs', import.meta.url), src);
const { YahooMailMCPServer } = await import('./.server.testable.mjs');

const server = new YahooMailMCPServer();

// Tripwire: if validation is bypassed, we find out that IMAP was reached.
let reachedImap = false;
server.createImapConnection = async () => {
    reachedImap = true;
    throw new Error('TRIPWIRE: opened an IMAP connection');
};

const textOf = r => r?.content?.[0]?.text ?? '';

const attacks = [
    ['CRLF -> injected LOGOUT',      'x"\r\nA1 LOGOUT'],
    ['CRLF -> injected EXPUNGE',     'x"\r\nA1 STORE 1:* +FLAGS (\\Deleted)\r\nA2 EXPUNGE'],
    ['bare LF',                      'x"\nA1 CAPABILITY'],
    ['bare CR',                      'x"\rA1 NOOP'],
    ['NUL byte',                     'x\u0000y'],
    ['injection via sender field',   null],
    ['non-string query (number)',    12345],
    ['overlong query',               'a'.repeat(300)],
];

let failures = 0;
console.log('--- attacks (all must be REJECTED before IMAP) ---');
for (const [name, payload] of attacks) {
    reachedImap = false;
    let res;
    if (name === 'injection via sender field') {
        res = await server.searchEmails('ok', { sender: 'a"\r\nA1 LOGOUT' });
    } else {
        res = await server.searchEmails(payload, {});
    }
    const out = textOf(res);
    const blocked = out.startsWith('Error:') && !reachedImap;
    console.log(`  ${blocked ? 'PASS' : 'FAIL'}  ${name.padEnd(28)} -> ${out.slice(0, 60)}`);
    if (!blocked) failures++;
}

console.log('\n--- legitimate queries (must pass validation, then hit tripwire) ---');
const legit = [
    ['plain text',        'invoice'],
    ['empty (date-only)', ''],
    ['email address',     'billing@example.com'],
    ['unicode subject',   'Rechnung fÜr Café ☕'],
    ['quotes/backslash',  'say "hi" c:\\path'],
    ['256 chars exactly', 'a'.repeat(256)],
];
for (const [name, q] of legit) {
    reachedImap = false;
    const out = textOf(await server.searchEmails(q, {}).catch(e => ({ content: [{ text: e.message }] })));
    const ok = reachedImap && out.includes('TRIPWIRE');
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(28)} -> ${ok ? 'passed validation' : out.slice(0, 60)}`);
    if (!ok) failures++;
}

fs.unlinkSync(new URL('./.server.testable.mjs', import.meta.url));
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
