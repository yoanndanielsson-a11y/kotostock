
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
      iterations: 210000,
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

function normalize(value) {
  return value.trim().normalize("NFKC").toLowerCase();
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
    const origin = request.headers.get("Origin");
    const expectedOrigin = new URL(request.url).origin;

    if (!origin || origin !== expectedOrigin) {
      return json({ success: false, message: "Requête non autorisée." }, 403);
    }

    const contentType = request.headers.get("Content-Type") || "";

    if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
      return json({ success: false, message: "Format invalide." }, 415);
    }

    const rawBody = await request.text();

    if (encoder.encode(rawBody).length > 8192) {
      return json({ success: false, message: "Requête trop volumineuse." }, 413);
    }

    let body;

    try {
      body = JSON.parse(rawBody);
    } catch {
      return json({ success: false, message: "Données invalides." }, 400);
    }

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return json({ success: false, message: "Données invalides." }, 400);
    }

    const firstName = String(body.firstName || "").trim();
    const lastName = String(body.lastName || "").trim();
    const secretCode = String(body.secretCode || "");

    if (
      !firstName ||
      !lastName ||
      !secretCode ||
      firstName.length > 80 ||
      lastName.length > 80 ||
      secretCode.length > 128
    ) {
      return json({ success: false, message: "Identifiants invalides." }, 400);
    }

    const firstNameKey = normalize(firstName);
    const lastNameKey = normalize(lastName);

    const result = await env.DB.prepare(`
      SELECT id, first_name, last_name, password_hash
      FROM users
      WHERE first_name_key = ? AND last_name_key = ?
      ORDER BY id ASC
    `).bind(firstNameKey, lastNameKey).all();

    const users = result.results || [];
    let authenticatedUser = null;

    // Vérifier les comptes correspondants sans choisir arbitrairement
    // un compte lorsque plusieurs personnes partagent ces noms.
    for (const user of users) {
      if (typeof user.password_hash !== "string") continue;

      const parts = user.password_hash.split(":");

      if (parts.length !== 2) continue;

      const [saltHex, savedHash] = parts;

      if (
        !/^[a-f0-9]{32}$/i.test(saltHex) ||
        !/^[a-f0-9]{64}$/i.test(savedHash)
      ) {
        continue;
      }

      const salt = new Uint8Array(
        saltHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
      );

      const submittedHash = await hashPassword(secretCode, salt);

      if (safeCompare(submittedHash, savedHash.toLowerCase())) {
        authenticatedUser = user;
        break;
      }
    }

    if (!authenticatedUser) {
      return json({
        success: false,
        message: "Nom, prénom ou code secret incorrect."
      }, 401);
    }

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
    `).bind(authenticatedUser.id, tokenHash, expiresAt).run();

    return json({
      success: true,
      message: "Connexion réussie.",
      user: {
        firstName: authenticatedUser.first_name,
        lastName: authenticatedUser.last_name
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
