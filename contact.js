/* Dkab SorX - İletişime Geçin mesajları (Vercel serverless + Upstash Redis)
 *
 * POST   /api/contact              -> giriş ekranından mesaj bırakır (herkese açık, hız sınırlı)
 * GET    /api/contact              -> mesajları listeler        (x-admin-key gerekir)
 * PATCH  /api/contact              -> okundu işaretler          (x-admin-key gerekir)  { id } veya { all:true }
 * DELETE /api/contact              -> mesajı siler              (x-admin-key gerekir)  { id }
 *
 * Gerekli ortam değişkenleri (Vercel > Settings > Environment Variables):
 *   KV_REST_API_URL, KV_REST_API_TOKEN   (Upstash Redis bağlanınca kendiliğinden eklenir)
 *   MESSAGES_ADMIN_KEY                   (sizin belirlediğiniz gizli anahtar)
 */
const crypto = require("crypto");

const HASH = "contact:msgs";
const MAX_MESSAGES = 1000;
const ROLES = ["Öğretmen", "Yönetici"];
const REASONS = [
  "Şifremi unuttum / şifre çalışmıyor",
  "Girişte teknik bir sorun yaşıyorum",
  "Yeni üyelik / kayıt almak istiyorum",
  "Diğer",
];

function cfg() {
  return {
    url: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || "",
    token: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || "",
    admin: process.env.MESSAGES_ADMIN_KEY || "",
  };
}

async function redis(c, cmd) {
  const r = await fetch(c.url, {
    method: "POST",
    headers: { Authorization: "Bearer " + c.token, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || "redis error");
  return j.result;
}

async function pipeline(c, cmds) {
  const r = await fetch(c.url.replace(/\/$/, "") + "/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + c.token, "Content-Type": "application/json" },
    body: JSON.stringify(cmds),
  });
  const j = await r.json();
  if (!r.ok || !Array.isArray(j)) throw new Error("redis pipeline error");
  return j.map((x) => {
    if (x.error) throw new Error(x.error);
    return x.result;
  });
}

/* Basit hız sınırı: aynı IP için pencere içinde en fazla `max` istek */
async function overLimit(c, name, ip, max, windowSec) {
  const key = "rl:" + name + ":" + ip;
  const [n, ttl] = await pipeline(c, [["INCR", key], ["TTL", key]]);
  if (n === 1 || ttl < 0) await redis(c, ["EXPIRE", key, windowSec]);
  return n > max;
}

function clientIp(req) {
  const xf = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return xf || (req.socket && req.socket.remoteAddress) || "unknown";
}

function sha(s) {
  return crypto.createHash("sha256").update(String(s)).digest();
}

function parseBody(req) {
  let b = req.body;
  if (typeof b === "string") {
    try { b = JSON.parse(b); } catch (e) { b = null; }
  }
  return b && typeof b === "object" ? b : {};
}

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const c = cfg();
  if (!c.url || !c.token) return send(res, 503, { error: "not_configured" });

  try {
    const ip = clientIp(req);

    /* ---- Herkese açık: mesaj bırak ---- */
    if (req.method === "POST") {
      if (await overLimit(c, "post", ip, 5, 600)) {
        return send(res, 429, { error: "Çok fazla deneme yaptınız. Lütfen biraz sonra tekrar deneyin." });
      }
      const b = parseBody(req);
      const name = String(b.name || "").trim().replace(/\s+/g, " ").slice(0, 80);
      const phone = String(b.phone || "").trim();
      const digits = phone.replace(/\D/g, "");
      if (!ROLES.includes(b.role)) return send(res, 400, { error: "Kimlik geçersiz." });
      if (!REASONS.includes(b.reason)) return send(res, 400, { error: "Giriş nedeni geçersiz." });
      if (phone.length > 20 || digits.length < 10 || digits.length > 15 || !/^[0-9+()\-\s.]+$/.test(phone)) {
        return send(res, 400, { error: "Geçerli bir telefon numarası girin." });
      }
      const count = await redis(c, ["HLEN", HASH]);
      if (count >= MAX_MESSAGES) return send(res, 429, { error: "Mesaj kutusu şu an dolu. Lütfen daha sonra tekrar deneyin." });
      const id = crypto.randomUUID();
      const msg = { id, ts: Date.now(), role: b.role, name, phone, reason: b.reason, read: false };
      await redis(c, ["HSET", HASH, id, JSON.stringify(msg)]);
      return send(res, 201, { ok: true });
    }

    /* ---- Yalnızca patron: listele / okundu / sil ---- */
    if (req.method === "GET" || req.method === "PATCH" || req.method === "DELETE") {
      if (!c.admin) return send(res, 503, { error: "not_configured" });
      if (await overLimit(c, "admin", ip, 30, 600)) {
        return send(res, 429, { error: "Çok fazla deneme. Lütfen biraz bekleyin." });
      }
      const given = sha(req.headers["x-admin-key"] || "");
      if (!crypto.timingSafeEqual(given, sha(c.admin))) return send(res, 401, { error: "unauthorized" });

      if (req.method === "GET") {
        const flat = (await redis(c, ["HGETALL", HASH])) || [];
        const messages = [];
        for (let i = 1; i < flat.length; i += 2) {
          try { messages.push(JSON.parse(flat[i])); } catch (e) { /* bozuk kaydı atla */ }
        }
        messages.sort((a, b) => b.ts - a.ts);
        return send(res, 200, { messages });
      }

      const b = parseBody(req);
      if (req.method === "PATCH") {
        if (b.all === true) {
          const flat = (await redis(c, ["HGETALL", HASH])) || [];
          const cmds = [];
          for (let i = 1; i < flat.length; i += 2) {
            try {
              const m = JSON.parse(flat[i]);
              if (!m.read) { m.read = true; cmds.push(["HSET", HASH, m.id, JSON.stringify(m)]); }
            } catch (e) { /* atla */ }
          }
          if (cmds.length) await pipeline(c, cmds);
          return send(res, 200, { ok: true });
        }
        const id = String(b.id || "");
        const raw = id ? await redis(c, ["HGET", HASH, id]) : null;
        if (!raw) return send(res, 404, { error: "Mesaj bulunamadı." });
        const m = JSON.parse(raw);
        m.read = b.read === false ? false : true;
        await redis(c, ["HSET", HASH, id, JSON.stringify(m)]);
        return send(res, 200, { ok: true });
      }

      /* DELETE */
      const id = String(b.id || "");
      if (!id) return send(res, 400, { error: "id gerekli." });
      await redis(c, ["HDEL", HASH, id]);
      return send(res, 200, { ok: true });
    }

    res.setHeader("Allow", "GET, POST, PATCH, DELETE");
    return send(res, 405, { error: "Method not allowed" });
  } catch (e) {
    return send(res, 500, { error: "Sunucu hatası." });
  }
};
