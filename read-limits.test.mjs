// Covers message decoding (charset, RFC822.SIZE) and the read_email limits.
import fs from 'fs';
import { EventEmitter } from 'events';

const src = fs.readFileSync(new URL('./server.js', import.meta.url), 'utf8')
    .replace(/\/\/ Start the server[\s\S]*$/, 'export { YahooMailMCPServer };\n');
fs.writeFileSync(new URL('./.limits.testable.mjs', import.meta.url), src);
const { YahooMailMCPServer } = await import('./.limits.testable.mjs');

const srv = new YahooMailMCPServer();
let failures = 0;
const check = (name, cond, detail = '') => {
    console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : `  <- ${detail}`}`);
    if (!cond) failures++;
};
const textOf = r => r?.content?.[0]?.text ?? '';

// Records the options each fetch was called with, so we can assert on what the
// server actually asks the IMAP server for.
const makeImap = (messages, capture = {}) => {
    const build = (source, opts) => {
        capture.opts = opts;
        const f = new EventEmitter();
        setImmediate(() => {
            for (const m of messages) {
                const msg = new EventEmitter();
                f.emit('message', msg, m.seq ?? 1);
                const stream = new EventEmitter();
                msg.emit('body', stream, {});
                for (const chunk of m.chunks) stream.emit('data', chunk);
                msg.emit('attributes', {
                    uid: m.uid, size: m.size ?? 0, flags: [], struct: []
                });
                msg.emit('end');
            }
            f.emit('end');
        });
        return f;
    };
    return {
        openBox: (n, ro, cb) => setImmediate(() => cb(null, { messages: { total: messages.length } })),
        search: (c, cb) => setImmediate(() => cb(null, messages.map(m => m.uid))),
        seq: { fetch: build },
        fetch: build,
        end: () => {}
    };
};

console.log('--- RFC822.SIZE is actually requested ---');
{
    // The bug was not in reporting size, it was in never asking for it: node-imap
    // only emits RFC822.SIZE when the fetch options say size: true, so attrs.size
    // was undefined and every email reported 0 bytes.
    for (const [label, call] of [
        ['list_emails  ', c => srv.listEmails(5, 'INBOX', 0)],
        ['search_emails', c => srv.searchEmails('x', {})],
        ['read_email   ', c => srv.readEmail([7], 'INBOX')],
    ]) {
        const capture = {};
        srv.createImapConnection = async () => makeImap([{
            uid: 7,
            size: 4242,
            chunks: [Buffer.from('From: a@example.com\r\nSubject: Hi\r\n\r\nbody\r\n', 'utf8')]
        }], capture);
        await call().catch(() => {});
        check(`${label} requests size`, capture.opts?.size === true, JSON.stringify(capture.opts));
    }
}

console.log('\n--- reported size reaches the output ---');
{
    srv.createImapConnection = async () => makeImap([{
        uid: 7,
        size: 4242,
        chunks: [Buffer.from('From: a@example.com\r\nSubject: Hi\r\n\r\nbody\r\n', 'utf8')]
    }]);
    const out = textOf(await srv.listEmails(5, 'INBOX', 0));
    check('size is not hardcoded to 0', /"size": 4242/.test(out), out.slice(0, 120));
}

console.log('\n--- non-ASCII headers survive decoding ---');
{
    // chunk.toString('ascii') stripped the high bit off every byte, so these came
    // back as mojibake. The header is emitted as two chunks split mid-character,
    // which a per-chunk decode also gets wrong.
    const header = Buffer.from(
        'From: Café Müller <cafe@example.com>\r\nSubject: Rechnung für Januar — 12€\r\n\r\n',
        'utf8'
    );
    const split = Math.floor(header.length / 2);

    srv.createImapConnection = async () => makeImap([{
        uid: 7, size: header.length,
        chunks: [header.subarray(0, split), header.subarray(split)]
    }]);

    const out = textOf(await srv.listEmails(5, 'INBOX', 0));
    check('accented sender preserved', out.includes('Café Müller'), out.slice(0, 140));
    check('accented subject preserved', out.includes('Rechnung für Januar'), out.slice(0, 140));
    check('em dash and euro sign preserved', out.includes('— 12€'), out.slice(0, 140));
    check('no mojibake replacement chars', !out.includes('�'), out.slice(0, 140));
}

console.log('\n--- read_email batch cap ---');
{
    let opened = false;
    srv.createImapConnection = async () => { opened = true; throw new Error('TRIPWIRE'); };

    const over = textOf(await srv.readEmail(Array.from({ length: 21 }, (_, i) => i + 1), 'INBOX'));
    check('21 uids rejected before connecting',
        over.startsWith('Error:') && over.includes('20') && !opened, over.slice(0, 90));

    opened = false;
    await srv.readEmail(Array.from({ length: 20 }, (_, i) => i + 1), 'INBOX').catch(() => {});
    check('exactly 20 uids allowed through', opened);
}

console.log('\n--- read_email total byte ceiling ---');
{
    // 26 x 1MB across two messages: neither is enormous on its own, which is the
    // case a per-message limit would wave through.
    const oneMB = Buffer.alloc(1024 * 1024, 0x61);
    const header = Buffer.from('From: a@example.com\r\nSubject: Big\r\n\r\n', 'utf8');

    srv.createImapConnection = async () => makeImap([
        { uid: 1, seq: 1, size: 13e6, chunks: [header, ...Array(13).fill(oneMB)] },
        { uid: 2, seq: 2, size: 13e6, chunks: [header, ...Array(13).fill(oneMB)] }
    ]);

    const res = await srv.readEmail([1, 2], 'INBOX').then(
        r => ({ ok: true, text: textOf(r) }),
        e => ({ ok: false, text: e.message })
    );
    check('oversized read rejected', !res.ok && /25MB limit/.test(res.text), res.text.slice(0, 100));

    // A normal-sized read must still go through untouched.
    srv.createImapConnection = async () => makeImap([{
        uid: 1, size: 40,
        chunks: [Buffer.from('From: a@example.com\r\nSubject: Small\r\n\r\nhello there\r\n', 'utf8')]
    }]);
    const okRes = textOf(await srv.readEmail([1], 'INBOX'));
    check('normal read unaffected by the ceiling', okRes.includes('hello there'), okRes.slice(0, 100));
}

fs.unlinkSync(new URL('./.limits.testable.mjs', import.meta.url));
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
