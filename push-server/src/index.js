// 塩自給生活のお知らせサーバー
// ゲームが「この時刻にこの通知を出して」と予約し、1分ごとの定期実行で時刻が来たものを送る。
//
// POST /schedule     { subscription, items: [{ tag, at, title, body }] }  … その端末の予約をまるごと入れかえる
// POST /unsubscribe  { endpoint }                                         … その端末の予約をすべて消す

const MAX_ITEMS = 5;
const MAX_TEXT = 200;
const MAX_AHEAD = 7 * 24 * 3600_000;

export default {
  async fetch(req, env) {
    const cors = corsHeaders(req, env);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (req.method !== 'POST') return new Response('not found', { status: 404, headers: cors });

    let data;
    try { data = await req.json(); } catch { return json({ error: 'bad json' }, 400, cors); }
    const path = new URL(req.url).pathname;

    if (path === '/schedule') {
      const sub = data.subscription;
      if (!validSubscription(sub)) return json({ error: 'bad subscription' }, 400, cors);
      const now = Date.now();
      const items = (Array.isArray(data.items) ? data.items : []).slice(0, MAX_ITEMS).filter(i =>
        typeof i.tag === 'string' && i.tag.length <= 32 &&
        Number.isFinite(i.at) && i.at > now - 60_000 && i.at < now + MAX_AHEAD &&
        typeof i.title === 'string' && typeof i.body === 'string');
      const stmts = [env.DB.prepare('DELETE FROM pending WHERE endpoint = ?').bind(sub.endpoint)];
      for (const i of items) {
        stmts.push(env.DB.prepare('INSERT INTO pending (endpoint, tag, at, sub, title, body) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(sub.endpoint, i.tag, Math.round(i.at), JSON.stringify(sub), i.title.slice(0, MAX_TEXT), i.body.slice(0, MAX_TEXT)));
      }
      await env.DB.batch(stmts);
      return json({ ok: true, scheduled: items.length }, 200, cors);
    }

    if (path === '/unsubscribe') {
      if (typeof data.endpoint !== 'string') return json({ error: 'bad endpoint' }, 400, cors);
      await env.DB.prepare('DELETE FROM pending WHERE endpoint = ?').bind(data.endpoint).run();
      return json({ ok: true }, 200, cors);
    }

    return json({ error: 'not found' }, 404, cors);
  },

  async scheduled(_event, env) {
    const { results } = await env.DB.prepare('SELECT * FROM pending WHERE at <= ? ORDER BY at LIMIT 200').bind(Date.now()).all();
    for (const row of results) {
      let status = 0;
      try {
        const res = await sendPush(JSON.parse(row.sub), JSON.stringify({ title: row.title, body: row.body, tag: row.tag }), env);
        status = res.status;
      } catch (e) {
        console.log('push failed', row.tag, String(e));
      }
      if (status === 404 || status === 410) {
        // アプリが消された・通知がオフにされた端末は、予約ごと消す
        await env.DB.prepare('DELETE FROM pending WHERE endpoint = ?').bind(row.endpoint).run();
      } else {
        await env.DB.prepare('DELETE FROM pending WHERE endpoint = ? AND tag = ?').bind(row.endpoint, row.tag).run();
      }
    }
  },
};

function corsHeaders(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());
  return {
    'Access-Control-Allow-Origin': allowed.includes(origin) ? origin : allowed[0] || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
}
const json = (obj, status, headers) => new Response(JSON.stringify(obj), { status, headers: { ...headers, 'Content-Type': 'application/json' } });

function validSubscription(sub) {
  try {
    return sub && new URL(sub.endpoint).protocol === 'https:' &&
      b64d(sub.keys.p256dh).length === 65 && b64d(sub.keys.auth).length === 16;
  } catch { return false; }
}

// ---------- Web Push（RFC 8291 の暗号化 + RFC 8292 の VAPID 署名） ----------
const enc = new TextEncoder();
function b64d(s) {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
function b64e(bytes) {
  let bin = '';
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};
async function hkdf(salt, ikm, info, bytes) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8));
}

async function encryptPayload(sub, payload) {
  const uaPublic = b64d(sub.keys.p256dh);
  const auth = b64d(sub.keys.auth);
  const local = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', local.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, local.privateKey, 256));

  const ikm = await hkdf(auth, shared, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);

  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const plain = concat(enc.encode(payload), new Uint8Array([2]));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, plain));

  const header = new Uint8Array(16 + 4 + 1 + asPublic.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPublic.length;
  header.set(asPublic, 21);
  return concat(header, cipher);
}

async function vapidAuth(endpoint, env) {
  const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const header = b64e(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64e(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT,
  })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(`${header}.${claims}`));
  return `vapid t=${header}.${claims}.${b64e(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}

async function sendPush(sub, payload, env) {
  return fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': await vapidAuth(sub.endpoint, env),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '86400',
      'Urgency': 'normal',
    },
    body: await encryptPayload(sub, payload),
  });
}

export { encryptPayload, vapidAuth, b64d, b64e };
