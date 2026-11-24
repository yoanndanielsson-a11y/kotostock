
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

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });
}

export async function onRequestPost({ request, env }) {
  const clearCookie =
    "koto_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

  try {
    // Vérifier l'origine de la requête.
    const origin = request.headers.get("Origin");
    const expectedOrigin = new URL(request.url).origin;

    if (!origin || origin !== expectedOrigin) {
      return json({
        success: false,
        message: "Requête non autorisée."
      }, 403, {
        "Set-Cookie": clearCookie
      });
    }

    const token = getSessionToken(request);

    // Supprimer la session correspondante.
    if (token) {
      const tokenHash = await sha256(token);

      await env.DB.prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
      `)
        .bind(tokenHash)
        .run();
    }

    return json({
      success: true,
      message: "Déconnexion réussie."
    }, 200, {
      "Set-Cookie": clearCookie
    });

  } catch (error) {
    console.error("Erreur de déconnexion KotoStock:", error);

    return json({
      success: false,
      message: "Impossible de terminer la session."
    }, 500, {
      "Set-Cookie": clearCookie
    });
  }
}
