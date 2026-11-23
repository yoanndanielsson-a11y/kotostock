
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

export async function onRequestPost({ request, env }) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(/(?:^|;\s*)koto_session=([a-f0-9]{64})(?:;|$)/);

    if (match) {
      const tokenHash = await sha256(match[1]);

      await env.DB
        .prepare("DELETE FROM sessions WHERE token_hash = ?")
        .bind(tokenHash)
        .run();
    }

    return Response.json({
      success: true,
      message: "Déconnexion réussie."
    }, {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Set-Cookie": "koto_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
      }
    });

  } catch (error) {
    return Response.json({
      success: false,
      message: "Impossible de terminer la session."
    }, { status: 500 });
  }
}
