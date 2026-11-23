
const encoder = new TextEncoder();

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return Array.from(new Uint8Array(result))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function getAuthenticatedUser(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    /(?:^|;\s*)koto_session=([a-f0-9]{64})(?:;|$)/
  );

  if (!match) return null;

  const tokenHash = await sha256(match[1]);

  return await env.DB.prepare(`
    SELECT
      u.id AS user_id,
      u.first_name,
      u.last_name,
      u.email,
      s.id AS shop_id,
      s.name AS shop_name
    FROM sessions se
    JOIN users u ON u.id = se.user_id
    JOIN shops s ON s.user_id = u.id
    WHERE se.token_hash = ?
      AND se.expires_at > ?
    LIMIT 1
  `).bind(tokenHash, new Date().toISOString()).first();
}
