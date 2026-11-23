
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

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json();

    const token = String(body.token || "").trim();
    const password = String(body.password || "");

    if (!token || token.length !== 64) {
      return json({
        success: false,
        message: "Lien de récupération invalide."
      }, 400);
    }

    if (password.length < 12 || password.length > 128) {
      return json({
        success: false,
        message: "Le mot de passe doit contenir entre 12 et 128 caractères."
      }, 400);
    }

    const digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(token)
    );

    const tokenHash = Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const record = await env.DB.prepare(`
      SELECT id, user_id
      FROM account_email_tokens
      WHERE token_hash = ?
        AND purpose = 'reset_password'
        AND used_at IS NULL
        AND expires_at > CURRENT_TIMESTAMP
    `).bind(tokenHash).first();

    if (!record) {
      return json({
        success: false,
        message: "Lien invalide ou expiré."
      }, 400);
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));

    const saltHex = Array.from(salt)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const passwordHash = await hashPassword(password, salt);
    const storedHash = `${saltHex}:${passwordHash}`;

    await env.DB.batch([
      env.DB.prepare(`
        UPDATE account_email_tokens
        SET used_at = CURRENT_TIMESTAMP
        WHERE id = ? AND used_at IS NULL
      `).bind(record.id),

      env.DB.prepare(`
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
          AND EXISTS (
            SELECT 1
            FROM account_email_tokens
            WHERE id = ?
              AND used_at IS NOT NULL
          )
      `).bind(storedHash, record.user_id, record.id),

      env.DB.prepare(`
        DELETE FROM sessions
        WHERE user_id = ?
      `).bind(record.user_id)
    ]);

    return json({
      success: true,
      message: "Mot de passe modifié. Connectez-vous avec votre nouveau mot de passe."
    });

  } catch (error) {
    return json({
      success: false,
      message: "Une erreur est survenue."
    }, 500);
  }
}
