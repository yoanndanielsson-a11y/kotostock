const encoder = new TextEncoder();

async function sha256(value) {
  const result = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(result))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const part of cookies.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) throw new Error("Base de données indisponible.");

    const origin = request.headers.get("Origin");
    if (!origin || origin !== new URL(request.url).origin) {
      return json({ success: false, message: "Requête non autorisée." }, 403);
    }

    const token = getCookie(request, "koto_session");
    if (!token) {
      return json({ success: false, message: "Session expirée." }, 401);
    }

    const tokenHash = await sha256(token);
    const now = new Date().toISOString();

    const session = await env.DB.prepare(`
      SELECT s.user_id, sh.id AS shop_id
      FROM sessions s
      JOIN shops sh ON sh.user_id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?
      LIMIT 1
    `).bind(tokenHash, now).first();

    if (!session) {
      return json({ success: false, message: "Session expirée." }, 401);
    }

    // Les ventes d'abord (elles dépendent des produits)
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sales WHERE shop_id = ?").bind(session.shop_id),
      env.DB.prepare("DELETE FROM products WHERE shop_id = ?").bind(session.shop_id)
    ]);

    return json({ success: true, message: "Données réinitialisées." });

  } catch (error) {
    console.error("Erreur réinitialisation KotoStock:", error?.message || error);
    return json({ success: false, message: "Impossible de réinitialiser pour le moment." }, 500);
  }
}
