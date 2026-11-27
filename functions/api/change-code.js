const encoder = new TextEncoder();

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  const result = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(result)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function safeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
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
    if (!token) return json({ success: false, message: "Session expirée." }, 401);

    const tokenHash = await sha256(token);
    const now = new Date().toISOString();

    const user = await env.DB.prepare(`
      SELECT u.id, u.password_hash
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?
      LIMIT 1
    `).bind(tokenHash, now).first();

    if (!user) return json({ success: false, message: "Session expirée." }, 401);

    let body;
    try {
      body = JSON.parse(await request.text());
    } catch {
      return json({ success: false, message: "Données invalides." }, 400);
    }

    const currentCode = String(body?.currentCode || "");
    const newCode = String(body?.newCode || "");

    if (!currentCode || newCode.length < 12 || newCode.length > 128) {
      return json({
        success: false,
        message: "Le nouveau code doit contenir entre 12 et 128 caractères."
      }, 400);
    }

    if (currentCode === newCode) {
      return json({
        success: false,
        message: "Le nouveau code doit être différent de l'ancien."
      }, 400);
    }

    // Vérifier l'ancien code
    const [saltHex, savedHash] = String(user.password_hash).split(":");
    if (!/^[a-f0-9]{32}$/i.test(saltHex || "") || !/^[a-f0-9]{64}$/i.test(savedHash || "")) {
      throw new Error("Hash du mot de passe invalide.");
    }

    const oldSalt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const submitted = await hashPassword(currentCode, oldSalt);

    if (!safeCompare(submitted, savedHash.toLowerCase())) {
      return json({ success: false, message: "Ancien code secret incorrect." }, 401);
    }

    // Enregistrer le nouveau code
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const newHash = await hashPassword(newCode, newSalt);
    const newSaltHex = Array.from(newSalt).map(b => b.toString(16).padStart(2, "0")).join("");

    await env.DB.batch([
      env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(`${newSaltHex}:${newHash}`, user.id),
      // Déconnecte les autres appareils, garde la session actuelle
      env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?")
        .bind(user.id, tokenHash)
    ]);

    return json({ success: true, message: "Code secret modifié." });

  } catch (error) {
    console.error("Erreur changement de code:", error?.message || error);
    return json({ success: false, message: "Impossible de modifier le code pour le moment." }, 500);
  }
}
