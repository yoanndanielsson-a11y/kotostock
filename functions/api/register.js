
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

    if (!firstName || !lastName || !secretCode) {
      return json({ success: false, message: "Tous les champs sont obligatoires." }, 400);
    }

    if (firstName.length > 80 || lastName.length > 80) {
      return json({ success: false, message: "Nom ou prénom trop long." }, 400);
    }

    if (secretCode.length < 12 || secretCode.length > 128) {
      return json({
        success: false,
        message: "Le code secret doit contenir entre 12 et 128 caractères."
      }, 400);
    }

    const firstNameKey = normalize(firstName);
    const lastNameKey = normalize(lastName);

    const existing = await env.DB.prepare(`
      SELECT id FROM users
      WHERE first_name_key = ? AND last_name_key = ?
      LIMIT 1
    `).bind(firstNameKey, lastNameKey).first();

    // Plusieurs comptes avec les mêmes nom et prénom sont autorisés.
    // L'identification se fera avec le code secret à la connexion.
    // On ne bloque donc pas la création sur cette seule correspondance.

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(secretCode, salt);

    const saltHex = Array.from(salt)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const storedHash = `${saltHex}:${passwordHash}`;

    const userResult = await env.DB.prepare(`
      INSERT INTO users (
        first_name,
        last_name,
        first_name_key,
        last_name_key,
        password_hash
      )
      VALUES (?, ?, ?, ?, ?)
    `).bind(
      firstName,
      lastName,
      firstNameKey,
      lastNameKey,
      storedHash
    ).run();

    const userId = userResult.meta.last_row_id;

    if (!userId) {
      throw new Error("Identifiant utilisateur indisponible.");
    }

    const shopResult = await env.DB.prepare(`
      INSERT INTO shops (user_id, name)
      VALUES (?, ?)
    `).bind(userId, `Boutique de ${firstName}`).run();

    const shopId = shopResult.meta.last_row_id;

    if (!shopId) {
      throw new Error("Identifiant boutique indisponible.");
    }

    const trialEnd = new Date(
      Date.now() + 3 * 24 * 60 * 60 * 1000
    ).toISOString();

    await env.DB.prepare(`
      INSERT INTO subscriptions (shop_id, plan, status, trial_ends_at)
      VALUES (?, 'trial', 'trial', ?)
    `).bind(shopId, trialEnd).run();

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
    `).bind(userId, tokenHash, expiresAt).run();

    return json({
      success: true,
      message: "Compte créé avec succès.",
      user: { firstName, lastName }
    }, 201, {
      "Set-Cookie":
        `koto_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    });

  } catch (error) {
    console.error("Erreur inscription KotoStock:", error);

    return json({
      success: false,
      message: "Impossible de créer le compte pour le moment."
    }, 500);
  }
}
