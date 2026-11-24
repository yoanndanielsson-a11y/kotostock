
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

function getSessionToken(request) {
  const cookieHeader = request.headers.get("Cookie") || "";

  if (cookieHeader.length > 8192) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  const sessionCookie = cookies.find(cookie =>
    cookie.trim().startsWith("koto_session=")
  );

  if (!sessionCookie) {
    return null;
  }

  const token = sessionCookie.trim().slice("koto_session=".length);

  return /^[a-f0-9]{64}$/.test(token) ? token : null;
}

export async function getAuthenticatedUser(request, env) {
  try {
    const token = getSessionToken(request);

    if (!token) {
      return null;
    }

    const tokenHash = await sha256(token);
    const now = new Date().toISOString();

    const user = await env.DB.prepare(`
      SELECT
        u.id AS user_id,
        u.first_name,
        u.last_name,
        u.email,
        s.id AS shop_id,
        s.name AS shop_name
      FROM sessions se
      INNER JOIN users u ON u.id = se.user_id
      INNER JOIN shops s ON s.user_id = u.id
      WHERE se.token_hash = ?
        AND se.expires_at > ?
      LIMIT 1
    `)
      .bind(tokenHash, now)
      .first();

    if (!user || !user.user_id || !user.shop_id) {
      return null;
    }

    return user;

  } catch (error) {
    console.error("Erreur d'authentification KotoStock:", error);
    return null;
  }
}
