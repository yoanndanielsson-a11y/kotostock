
const encoder = new TextEncoder();

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return Array.from(new Uint8Array(result))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

export async function onRequestGet({ request, env }) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(/(?:^|;\s*)koto_session=([a-f0-9]{64})(?:;|$)/);

    if (!match) {
      return json({
        success: false,
        message: "Vous devez vous connecter."
      }, 401);
    }

    const tokenHash = await sha256(match[1]);

    const account = await env.DB.prepare(`
      SELECT
        u.id,
        u.first_name,
        u.last_name,
        u.email,
        s.id AS shop_id,
        s.name AS shop_name,
        sub.status AS subscription_status,
        sub.trial_ends_at,
        sub.expires_at
      FROM sessions se
      JOIN users u ON u.id = se.user_id
      JOIN shops s ON s.user_id = u.id
      LEFT JOIN subscriptions sub ON sub.shop_id = s.id
      WHERE se.token_hash = ?
        AND se.expires_at > ?
      LIMIT 1
    `).bind(tokenHash, new Date().toISOString()).first();

    if (!account) {
      return json({
        success: false,
        message: "Session expirée. Veuillez vous reconnecter."
      }, 401);
    }

    return json({
      success: true,
      user: {
        firstName: account.first_name,
        lastName: account.last_name,
        email: account.email
      },
      shop: {
        id: account.shop_id,
        name: account.shop_name
      },
      subscription: {
        status: account.subscription_status,
        trialEndsAt: account.trial_ends_at,
        expiresAt: account.expires_at
      }
    });

  } catch (error) {
    return json({
      success: false,
      message: "Erreur lors de la vérification du compte."
    }, 500);
  }
}
