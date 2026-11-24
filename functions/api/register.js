
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

async function cleanupUser(env, userId) {
  if (!userId) return;

  // Supprimer les dépendances avant le compte utilisateur.
  await env.DB.prepare(`
    DELETE FROM sessions WHERE user_id = ?
  `).bind(userId).run();

  await env.DB.prepare(`
    DELETE FROM subscriptions
    WHERE shop_id IN (
      SELECT id FROM shops WHERE user_id = ?
    )
  `).bind(userId).run();

  await env.DB.prepare(`
    DELETE FROM shops WHERE user_id = ?
  `).bind(userId).run();

  await env.DB.prepare(`
    DELETE FROM users WHERE id = ?
  `).bind(userId).run();
}

export async function onRequestPost({ request, env }) {
  let userId = null;

  try {
    // 1. Vérifier l'origine.
    const origin = request.headers.get("Origin");
    const expectedOrigin = new URL(request.url).origin;

    if (!origin || origin !== expectedOrigin) {
      return json({
        success: false,
        message: "Requête non autorisée."
      }, 403);
    }

    // 2. Vérifier le format.
    const contentType = request.headers.get("Content-Type") || "";

    if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
      return json({
        success: false,
        message: "Format invalide."
      }, 415);
    }

    // 3. Limiter la taille de la requête.
    const contentLength = Number(
      request.headers.get("Content-Length") || 0
    );

    if (contentLength > 8192) {
      return json({
        success: false,
        message: "Requête trop volumineuse."
      }, 413);
    }

    const rawBody = await request.text();

    if (encoder.encode(rawBody).length > 8192) {
      return json({
        success: false,
        message: "Requête trop volumineuse."
      }, 413);
    }

    // 4. Lire les données.
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

    const firstName = String(body.firstName || "").trim();
    const lastName = String(body.lastName || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    // 5. Vérifier les champs.
    if (!firstName || !lastName || !email || !password) {
      return json({
        success: false,
        message: "Tous les champs sont obligatoires."
      }, 400);
    }

    if (firstName.length > 80 || lastName.length > 80) {
      return json({
        success: false,
        message: "Nom ou prénom trop long."
      }, 400);
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 254
    ) {
      return json({
        success: false,
        message: "Adresse e-mail invalide."
      }, 400);
    }

    if (password.length < 12 || password.length > 128) {
      return json({
        success: false,
        message: "Le mot de passe doit contenir entre 12 et 128 caractères."
      }, 400);
    }

    // 6. Vérifier si l'adresse existe déjà.
    const existing = await env.DB.prepare(`
      SELECT id FROM users WHERE email = ? LIMIT 1
    `).bind(email).first();

    if (existing) {
      return json({
        success: false,
        message: "Cette adresse e-mail est déjà utilisée."
      }, 409);
    }

    // 7. Hacher le mot de passe.
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(password, salt);

    const saltHex = Array.from(salt)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const storedHash = `${saltHex}:${passwordHash}`;

    // 8. Créer l'utilisateur.
    const userResult = await env.DB.prepare(`
      INSERT INTO users (
        first_name,
        last_name,
        email,
        password_hash
      )
      VALUES (?, ?, ?, ?)
    `).bind(
      firstName,
      lastName,
      email,
      storedHash
    ).run();

    userId = userResult.meta.last_row_id;

    if (!userId) {
      throw new Error("Identifiant utilisateur indisponible.");
    }

    // 9. Créer la boutique.
    const shopResult = await env.DB.prepare(`
      INSERT INTO shops (user_id, name)
      VALUES (?, ?)
    `).bind(
      userId,
      `Boutique de ${firstName}`
    ).run();

    const shopId = shopResult.meta.last_row_id;

    if (!shopId) {
      throw new Error("Identifiant boutique indisponible.");
    }

    // 10. Créer l'essai gratuit de trois jours.
    const trialEnd = new Date(
      Date.now() + 3 * 24 * 60 * 60 * 1000
    ).toISOString();

    await env.DB.prepare(`
      INSERT INTO subscriptions (
        shop_id,
        plan,
        status,
        trial_ends_at
      )
      VALUES (?, 'trial', 'trial', ?)
    `).bind(shopId, trialEnd).run();

    // 11. Créer la session.
    const tokenBytes = crypto.getRandomValues(
      new Uint8Array(32)
    );

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

    // 12. Répondre avec le cookie sécurisé.
    return json({
      success: true,
      message: "Compte créé avec succès.",
      user: {
        firstName,
        lastName,
        email
      }
    }, 201, {
      "Set-Cookie":
        `koto_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    });

  } catch (error) {
    // Nettoyer les données créées si l'inscription échoue.
    if (userId) {
      try {
        await cleanupUser(env, userId);
      } catch (cleanupError) {
        console.error(
          "Erreur de nettoyage après inscription:",
          cleanupError
        );
      }
    }

    // Gérer une inscription concurrente avec le même e-mail.
    if (
      error?.message?.includes("UNIQUE constraint failed: users.email")
    ) {
      return json({
        success: false,
        message: "Cette adresse e-mail est déjà utilisée."
      }, 409);
    }

    console.error("Erreur d'inscription KotoStock:", error);

    return json({
      success: false,
      message: "Impossible de créer le compte pour le moment."
    }, 500);
  }
}
