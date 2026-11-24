
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

// Comparaison sans arrêt au premier caractère différent.
function safeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

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
    // 1. Vérifier l'origine de la requête.
    const origin = request.headers.get("Origin");
    const expectedOrigin = new URL(request.url).origin;

    if (!origin || origin !== expectedOrigin) {
      return json({
        success: false,
        message: "Requête non autorisée."
      }, 403);
    }

    // 2. Vérifier le type de contenu.
    const contentType = request.headers.get("Content-Type") || "";

    if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
      return json({
        success: false,
        message: "Format invalide."
      }, 415);
    }

    // 3. Limiter la taille du corps de la requête.
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

    // 4. Lire et vérifier les données.
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

    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (
      !email ||
      !password ||
      email.length > 254 ||
      password.length > 128
    ) {
      return json({
        success: false,
        message: "Identifiants invalides."
      }, 400);
    }

    // 5. Rechercher le compte.
    const user = await env.DB.prepare(`
      SELECT id, first_name, last_name, email, password_hash
      FROM users
      WHERE email = ?
      LIMIT 1
    `)
      .bind(email)
      .first();

    if (!user || typeof user.password_hash !== "string") {
      return json({
        success: false,
        message: "Adresse e-mail ou mot de passe incorrect."
      }, 401);
    }

    // 6. Vérifier le format du mot de passe enregistré.
    const parts = user.password_hash.split(":");

    if (parts.length !== 2) {
      return json({
        success: false,
        message: "Identifiants invalides."
      }, 401);
    }

    const [saltHex, savedHash] = parts;

    if (
      !/^[a-f0-9]{32}$/i.test(saltHex) ||
      !/^[a-f0-9]{64}$/i.test(savedHash)
    ) {
      return json({
        success: false,
        message: "Identifiants invalides."
      }, 401);
    }

    const salt = new Uint8Array(
      saltHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
    );

    // 7. Vérifier le mot de passe.
    const submittedHash = await hashPassword(password, salt);

    if (!safeCompare(submittedHash, savedHash.toLowerCase())) {
      return json({
        success: false,
        message: "Adresse e-mail ou mot de passe incorrect."
      }, 401);
    }

    // 8. Générer un nouveau jeton de session.
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

    // 9. Enregistrer uniquement le hash du jeton.
    await env.DB.prepare(`
      INSERT INTO sessions (user_id, token_hash, expires_at)
      VALUES (?, ?, ?)
    `)
      .bind(user.id, tokenHash, expiresAt)
      .run();

    // 10. Créer le cookie sécurisé.
    return json({
      success: true,
      message: "Connexion réussie.",
      user: {
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email
      }
    }, 200, {
      "Set-Cookie":
        `koto_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    });

  } catch (error) {
    // Ne jamais exposer les détails internes au navigateur.
    console.error("Erreur de connexion KotoStock:", error);

    return json({
      success: false,
      message: "Impossible de se connecter pour le moment."
    }, 500);
  }
}
