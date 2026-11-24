
import { getAuthenticatedUser } from "./_utils/auth.js";

const encoder = new TextEncoder();

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function checkOrigin(request) {
  const origin = request.headers.get("Origin");

  if (!origin) return false;

  try {
    return origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function readJson(request) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return { error: "Format invalide.", status: 415 };
  }

  const contentLength = Number(
    request.headers.get("Content-Length") || 0
  );

  if (contentLength > 8192) {
    return { error: "Requête trop volumineuse.", status: 413 };
  }

  const raw = await request.text();

  if (encoder.encode(raw).length > 8192) {
    return { error: "Requête trop volumineuse.", status: 413 };
  }

  let body;

  try {
    body = JSON.parse(raw);
  } catch {
    return { error: "Données invalides.", status: 400 };
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { error: "Données invalides.", status: 400 };
  }

  return { body };
}

function validNumber(value) {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0;
  }

  if (typeof value === "string") {
    return /^\d+$/.test(value.trim()) &&
      Number.isSafeInteger(Number(value)) &&
      Number(value) >= 0;
  }

  return false;
}

function subscriptionIsActive(subscription) {
  if (!subscription) return false;

  const now = Date.now();

  if (subscription.status === "trial") {
    const end = Date.parse(subscription.trial_ends_at || "");

    return Number.isFinite(end) && end > now;
  }

  if (subscription.status === "active") {
    const end = Date.parse(subscription.expires_at || "");

    return Number.isFinite(end) && end > now;
  }

  return false;
}

async function hasActiveSubscription(env, shopId) {
  const subscription = await env.DB.prepare(`
    SELECT status, trial_ends_at, expires_at
    FROM subscriptions
    WHERE shop_id = ?
    LIMIT 1
  `)
    .bind(shopId)
    .first();

  return subscriptionIsActive(subscription);
}

async function requireActiveSubscription(env, shopId) {
  const active = await hasActiveSubscription(env, shopId);

  if (!active) {
    return json({
      success: false,
      code: "SUBSCRIPTION_REQUIRED",
      message: "Votre essai gratuit est terminé. Un abonnement actif est nécessaire pour modifier vos produits."
    }, 403);
  }

  return null;
}

// GET : consulter les produits de sa boutique.
// La consultation reste possible après expiration.
export async function onRequestGet({ request, env }) {
  try {
    const user = await getAuthenticatedUser(request, env);

    if (!user) {
      return json({
        success: false,
        message: "Connexion requise."
      }, 401);
    }

    const products = await env.DB.prepare(`
      SELECT
        id,
        name,
        category,
        sale_price,
        quantity,
        created_at
      FROM products
      WHERE shop_id = ?
      ORDER BY id DESC
    `)
      .bind(user.shop_id)
      .all();

    return json({
      success: true,
      products: products.results || []
    });

  } catch (error) {
    console.error("Erreur de lecture des produits:", error);

    return json({
      success: false,
      message: "Erreur de chargement."
    }, 500);
  }
}

// POST : ajouter un produit.
export async function onRequestPost({ request, env }) {
  try {
    if (!checkOrigin(request)) {
      return json({
        success: false,
        message: "Requête non autorisée."
      }, 403);
    }

    const user = await getAuthenticatedUser(request, env);

    if (!user) {
      return json({
        success: false,
        message: "Connexion requise."
      }, 401);
    }

    const subscriptionError = await requireActiveSubscription(
      env,
      user.shop_id
    );

    if (subscriptionError) return subscriptionError;

    const parsed = await readJson(request);

    if (parsed.error) {
      return json({
        success: false,
        message: parsed.error
      }, parsed.status);
    }

    const body = parsed.body;

    const name = typeof body.name === "string"
      ? body.name.trim()
      : "";

    const category = typeof body.category === "string"
      ? body.category.trim()
      : "";

    if (!name || name.length > 120) {
      return json({
        success: false,
        message: "Nom de produit invalide."
      }, 400);
    }

    if (category.length > 80) {
      return json({
        success: false,
        message: "Catégorie trop longue."
      }, 400);
    }

    if (
      !validNumber(body.sale_price) ||
      !validNumber(body.quantity)
    ) {
      return json({
        success: false,
        message: "Prix ou quantité invalide."
      }, 400);
    }

    const result = await env.DB.prepare(`
      INSERT INTO products (
        shop_id,
        name,
        category,
        sale_price,
        quantity
      )
      VALUES (?, ?, ?, ?, ?)
    `)
      .bind(
        user.shop_id,
        name,
        category || null,
        Number(body.sale_price),
        Number(body.quantity)
      )
      .run();

    return json({
      success: true,
      message: "Produit ajouté.",
      productId: result.meta.last_row_id
    }, 201);

  } catch (error) {
    console.error("Erreur d'ajout de produit:", error);

    return json({
      success: false,
      message: "Erreur lors de l'ajout."
    }, 500);
  }
}

// PUT : modifier un produit de sa boutique.
export async function onRequestPut({ request, env }) {
  try {
    if (!checkOrigin(request)) {
      return json({
        success: false,
        message: "Requête non autorisée."
      }, 403);
    }

    const user = await getAuthenticatedUser(request, env);

    if (!user) {
      return json({
        success: false,
        message: "Connexion requise."
      }, 401);
    }

    const subscriptionError = await requireActiveSubscription(
      env,
      user.shop_id
    );

    if (subscriptionError) return subscriptionError;

    const parsed = await readJson(request);

    if (parsed.error) {
      return json({
        success: false,
        message: parsed.error
      }, parsed.status);
    }

    const body = parsed.body;
    const id = Number(body.id);

    const name = typeof body.name === "string"
      ? body.name.trim()
      : "";

    const category = typeof body.category === "string"
      ? body.category.trim()
      : "";

    if (
      !Number.isSafeInteger(id) ||
      id <= 0 ||
      !name ||
      name.length > 120 ||
      category.length > 80 ||
      !validNumber(body.sale_price) ||
      !validNumber(body.quantity)
    ) {
      return json({
        success: false,
        message: "Informations invalides."
      }, 400);
    }

    const result = await env.DB.prepare(`
      UPDATE products
      SET
        name = ?,
        category = ?,
        sale_price = ?,
        quantity = ?
      WHERE id = ? AND shop_id = ?
    `)
      .bind(
        name,
        category || null,
        Number(body.sale_price),
        Number(body.quantity),
        id,
        user.shop_id
      )
      .run();

    if (!result.meta.changes) {
      const existing = await env.DB.prepare(`
        SELECT id
        FROM products
        WHERE id = ? AND shop_id = ?
        LIMIT 1
      `)
        .bind(id, user.shop_id)
        .first();

      if (!existing) {
        return json({
          success: false,
          message: "Produit introuvable."
        }, 404);
      }
    }

    return json({
      success: true,
      message: "Produit modifié."
    });

  } catch (error) {
    console.error("Erreur de modification de produit:", error);

    return json({
      success: false,
      message: "Erreur lors de la modification."
    }, 500);
  }
}

// DELETE : supprimer un produit sans effacer son historique de ventes.
export async function onRequestDelete({ request, env }) {
  try {
    if (!checkOrigin(request)) {
      return json({
        success: false,
        message: "Requête non autorisée."
      }, 403);
    }

    const user = await getAuthenticatedUser(request, env);

    if (!user) {
      return json({
        success: false,
        message: "Connexion requise."
      }, 401);
    }

    const subscriptionError = await requireActiveSubscription(
      env,
      user.shop_id
    );

    if (subscriptionError) return subscriptionError;

    const parsed = await readJson(request);

    if (parsed.error) {
      return json({
        success: false,
        message: parsed.error
      }, parsed.status);
    }

    const id = Number(parsed.body.id);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return json({
        success: false,
        message: "Identifiant invalide."
      }, 400);
    }

    // La suppression est refusée si une vente référence le produit.
    const result = await env.DB.prepare(`
      DELETE FROM products
      WHERE id = ?
        AND shop_id = ?
        AND NOT EXISTS (
          SELECT 1
          FROM sales
          WHERE sales.product_id = products.id
        )
    `)
      .bind(id, user.shop_id)
      .run();

    if (!result.meta.changes) {
      const product = await env.DB.prepare(`
        SELECT id
        FROM products
        WHERE id = ? AND shop_id = ?
        LIMIT 1
      `)
        .bind(id, user.shop_id)
        .first();

      if (!product) {
        return json({
          success: false,
          message: "Produit introuvable."
        }, 404);
      }

      return json({
        success: false,
        message: "Ce produit possède déjà des ventes. Il ne peut pas être supprimé afin de préserver l'historique."
      }, 409);
    }

    return json({
      success: true,
      message: "Produit supprimé."
    });

  } catch (error) {
    console.error("Erreur de suppression de produit:", error);

    return json({
      success: false,
      message: "Erreur lors de la suppression."
    }, 500);
  }
}
