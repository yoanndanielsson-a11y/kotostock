
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
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const contentType = request.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      return json({ success: false, message: "Format invalide." }, 415);
    }

    const body = await request.json();

    const firstName = String(body.firstName || "").trim();
    const lastName = String(body.lastName || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

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

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
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

    const existing = await env.DB
      .prepare("SELECT id FROM users WHERE email = ?")
      .bind(email)
      .first();

    if (existing) {
      return json({
        success: false,
        message: "Cette adresse e-mail est déjà utilisée."
      }, 409);
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(password, salt);
    const saltHex = Array.from(salt)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const storedHash = `${saltHex}:${passwordHash}`;

    const userResult = await env.DB
      .prepare(`
        INSERT INTO users (first_name, last_name, email, password_hash)
        VALUES (?, ?, ?, ?)
      `)
      .bind(firstName, lastName, email, storedHash)
      .run();

    const userId = userResult.meta.last_row_id;

    try {
      const shopResult = await env.DB
        .prepare("INSERT INTO shops (user_id, name) VALUES (?, ?)")
        .bind(userId, `Boutique de ${firstName}`)
        .run();

      const shopId = shopResult.meta.last_row_id;

      const trialEnd = new Date(
        Date.now() + 3 * 24 * 60 * 60 * 1000
      ).toISOString();

      await env.DB
        .prepare(`
          INSERT INTO subscriptions (shop_id, plan, status, trial_ends_at)
          VALUES (?, 'trial', 'trial', ?)
        `)
        .bind(shopId, trialEnd)
        .run();

      const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
      const token = Array.from(tokenBytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

      const tokenHash = await sha256(token);
      const expiresAt = new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
      ).toISOString();

      await env.DB
        .prepare(`
          INSERT INTO sessions (user_id, token_hash, expires_at)
          VALUES (?, ?, ?)
        `)
        .bind(userId, tokenHash, expiresAt)
        .run();

      return json({
        success: true,
        message: "Compte créé avec succès.",
        user: {
          firstName,
          lastName,
          email
        }
      }, 201, {
        "Set-Cookie": `koto_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
      });

    } catch (error) {
      await env.DB
        .prepare("DELETE FROM users WHERE id = ?")
        .bind(userId)
        .run();

      throw error;
    }

  } catch (error) {
    return json({
      success: false,
      message: "Impossible de créer le compte pour le moment."
    }, 500);
  }
}
