
export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const token = String(body.token || "").trim();

    if (!token || token.length < 32 || token.length > 200) {
      return Response.json({
        success: false,
        message: "Lien de vérification invalide."
      }, { status: 400 });
    }

    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(token)
    );

    const tokenHash = Array.from(new Uint8Array(digest))
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");

    const record = await context.env.DB.prepare(`
      SELECT id, user_id
      FROM account_email_tokens
      WHERE token_hash = ?
        AND purpose = 'verify_email'
        AND used_at IS NULL
        AND expires_at > CURRENT_TIMESTAMP
    `).bind(tokenHash).first();

    if (!record) {
      return Response.json({
        success: false,
        message: "Lien invalide ou expiré."
      }, { status: 400 });
    }

    await context.env.DB.batch([
      context.env.DB.prepare(`
        UPDATE users
        SET email_verified = 1
        WHERE id = ?
      `).bind(record.user_id),

      context.env.DB.prepare(`
        UPDATE account_email_tokens
        SET used_at = CURRENT_TIMESTAMP
        WHERE id = ? AND used_at IS NULL
      `).bind(record.id)
    ]);

    return Response.json({
      success: true,
      message: "Adresse e-mail vérifiée."
    });

  } catch (error) {
    return Response.json({
      success: false,
      message: "Une erreur est survenue."
    }, { status: 500 });
  }
}
