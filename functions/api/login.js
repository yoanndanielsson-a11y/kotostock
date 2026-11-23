
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

export async function onRequestPost({ request, env }) {
  try {
    const contentType = request.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      return json({ success: false, message: "Format invalide." }, 415);
    }

    const body = await request.json();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (!email || !password || email.length > 254 || password.length > 128) {
      return json({
        success: false,
        message: "Identifiants invalides."
      }, 400);
    }

    const user = await env.DB
      .prepare(`
        SELECT id, first_name, last_name, email, password_hash
        FROM users
        WHERE email = ?
      `)
      .bind(email)
      .first();

    if (!user || !user.password_hash.includes(":")) {
      return json({
        success: false,
        message: "Adresse e-mail ou mot de passe incorrect."
      }, 401);
    }

    const [saltHex, savedHash] = user.password_hash.split(":");

    if (!/^[a-f0-9]{32}$/i.test(saltHex) || !/^[a-f0-9]{64}$/i.test(savedHash)) {
      return json({
        success: false,
        message: "Identifiants invalides."
      }, 401);
    }

    const salt = new Uint8Array(
      saltHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
    );

    const submittedHash = await hashPassword(password, salt);

    if (submittedHash !== savedHash) {
      return json({
        success: false,
        message: "Adresse e-mail ou mot de passe incorrect."
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

    await env.DB
      .prepare(`
        INSERT INTO sessions (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
      `)
      .bind(user.id, tokenHash, expiresAt)
      .run();

    return json({
      success: true,
      message: "Connexion réussie.",
      user: {
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email
      }
    }, 200, {
      "Set-Cookie": `koto_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    });

  } catch (error) {
    return json({
      success: false,
      message: "Impossible de se connecter pour le moment."
    }, 500);
  }
}
