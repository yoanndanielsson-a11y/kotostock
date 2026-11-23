
export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const email = String(body.email || "").trim().toLowerCase();

    if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return Response.json({
        success: false,
        message: "Adresse e-mail invalide."
      }, { status: 400 });
    }

    const user = await context.env.DB.prepare(`
      SELECT id FROM users WHERE email = ?
    `).bind(email).first();

    // Même réponse, que le compte existe ou non.
    if (user) {
      const random = crypto.getRandomValues(new Uint8Array(32));
      const token = Array.from(random)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");

      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(token)
      );

      const tokenHash = Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");

      const expiresAt = new Date(Date.now() + 30 * 60 * 1000)
        .toISOString()
        .replace("T", " ")
        .replace("Z", "");

      await context.env.DB.prepare(`
        UPDATE account_email_tokens
        SET used_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
          AND purpose = 'reset_password'
          AND used_at IS NULL
      `).bind(user.id).run();

      await context.env.DB.prepare(`
        INSERT INTO account_email_tokens
          (user_id, token_hash, purpose, expires_at)
        VALUES (?, ?, 'reset_password', ?)
      `).bind(user.id, tokenHash, expiresAt).run();

      // L'envoi du lien sera branché après la configuration de Resend.
      // Ne jamais renvoyer le jeton dans la réponse publique.
    }

    return Response.json({
      success: true,
      message: "Si cette adresse correspond à un compte, un lien de récupération sera envoyé."
    });

  } catch (error) {
    return Response.json({
      success: false,
      message: "Une erreur est survenue."
    }, { status: 500 });
  }
}
