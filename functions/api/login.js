const encoder = new TextEncoder();

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000, // maximum autorisé par Cloudflare Workers
      hash: "SHA-256"
    },
    key,
    256
  );

  return Array.from(new Uint8Array(bits))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return Array.from(new Uint8Array(result))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function safeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return difference === 0;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) {
      throw new Error("Base de données indisponible.");
    }

    const origin = request.headers.get("Origin");
    const expectedOrigin = new URL(request.url).origin;

    if (!origin || origin !== expectedOrigin) {
      return json({
        success: false,
        message: "Requête non autorisée."
      }, 403);
    }

    const contentType = request.headers.get("Content-Type") || "";

    if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
      return json({
        success: false,
        message: "Format invalide."
      }, 415);
    }

    const rawBody = await request.text();

    if (encoder.encode(rawBody).length > 8192) {
      return json({
        success: false,
        message: "Requête trop volumineuse."
      }, 413);
    }

    let body;

    try {
      body = JSON.parse(rawBody);
    } catch {
      return json({
        success: false,
        message: "Données invalides."
      }, 400);
    }

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return json({
        success: false,
        message: "Données invalides."
      }, 400);
    }

    const publicId = String(body.publicId || "")
      .trim()
      .toUpperCase();

    const secretCode = String(body.secretCode || "");

    if (
      !/^KT-\d{6}$/.test(publicId) ||
      !secretCode ||
      secretCode.length > 128
    ) {
      return json({
        success: false,
        message: "Identifiant ou code secret invalide."
      }, 400);
    }

    // Rechercher le compte avec son identifiant unique
    const user = await env.DB.prepare(`
      SELECT id, first_name, last_name, public_id, password_hash
      FROM users
      WHERE public_id = ?
      LIMIT 1
    `).bind(publicId).first();

    if (!user || typeof user.password_hash !== "string") {
      return json({
        success: false,
        message: "Identifiant ou code secret incorrect."
      }, 401);
    }

    const parts = user.password_hash.split(":");

    if (parts.length !== 2) {
      throw new Error("Format du mot de passe invalide.");
    }

    const [saltHex, savedHash] = parts;

    if (
      !/^[a-f0-9]{32}$/i.test(saltHex) ||
      !/^[a-f0-9]{64}$/i.test(savedHash)
    ) {
      throw new Error("Hash du mot de passe invalide.");
    }

    const salt = new Uint8Array(
      saltHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
    );

    const submittedHash = await hashPassword(secretCode, salt);

    if (!safeCompare(submittedHash, savedHash.toLowerCase())) {
      return json({
        success: false,
        message: "Identifiant ou code secret incorrect."
      }, 401);
    }

    // Création de la session
    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));

    const token = Array.from(tokenBytes)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const tokenHash = await sha256(token);

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000
    ).toISOString();

    await env.DB.prepare(`
      INSERT INTO sessions (user_id, token_hash, expires_at)
      VALUES (?, ?, ?)
    `).bind(user.id, tokenHash, expiresAt).run();

    return json({
      success: true,
      message: "Connexion réussie.",
      user: {
        firstName: user.first_name,
        lastName: user.last_name,
        publicId: user.public_id
      }
    }, 200, {
      "Set-Cookie":
        `koto_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    });

  } catch (error) {
    console.error("Erreur connexion KotoStock:", error);

    return json({
      success: false,
      message: "Impossible de se connecter pour le moment."
    }, 500);
  }
}
