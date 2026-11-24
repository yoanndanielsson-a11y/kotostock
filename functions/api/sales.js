
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

// GET : consulter l'historique des ventes.
// L'historique reste accessible après expiration.
export async function onRequestGet({ request, env }) {
  try {
    const user = await getAuthenticatedUser(request, env);

    if (!user) {
      return json({
        success: false,
        message: "Connexion requise."
      }, 401);
    }

    const sales = await env.DB.prepare(`
      SELECT
        sales.id,
        sales.product_id,
        products.name AS product_name,
        sales.quantity,
        sales.unit_price,
        sales.total,
        sales.created_at
      FROM sales
      LEFT JOIN products
        ON products.id = sales.product_id
       AND products.shop_id = sales.shop_id
      WHERE sales.shop_id = ?
      ORDER BY sales.id DESC
      LIMIT 200
    `)
      .bind(user.shop_id)
      .all();

    return json({
      success: true,
      sales: sales.results || []
    });

  } catch (error) {
    console.error("Erreur de lecture des ventes:", error);

    return json({
      success: false,
      message: "Impossible de charger les ventes."
    }, 500);
  }
}

// POST : enregistrer une vente.
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

    // Vérifier l'abonnement avant toute nouvelle vente.
    const active = await hasActiveSubscription(env, user.shop_id);

    if (!active) {
      return json({
        success: false,
        code: "SUBSCRIPTION_REQUIRED",
        message: "Votre essai gratuit est terminé. Un abonnement actif est nécessaire pour enregistrer de nouvelles ventes."
      }, 403);
    }

    const parsed = await readJson(request);

    if (parsed.error) {
      return json({
        success: false,
        message: parsed.error
      }, parsed.status);
    }

    const body = parsed.body;

    const productId = Number(body.product_id);
    const quantity = Number(body.quantity);

    if (
      body.product_id === undefined ||
      body.product_id === null ||
      body.product_id === "" ||
      body.quantity === undefined ||
      body.quantity === null ||
      body.quantity === "" ||
      !Number.isSafeInteger(productId) ||
      productId <= 0 ||
      !Number.isSafeInteger(quantity) ||
      quantity <= 0
    ) {
      return json({
        success: false,
        message: "Produit ou quantité invalide."
      }, 400);
    }

    const product = await env.DB.prepare(`
      SELECT id, name, sale_price, quantity
      FROM products
      WHERE id = ? AND shop_id = ?
      LIMIT 1
    `)
      .bind(productId, user.shop_id)
      .first();

    if (!product) {
      return json({
        success: false,
        message: "Produit introuvable."
      }, 404);
    }

    const unitPrice = Number(product.sale_price);
    const availableStock = Number(product.quantity);

    if (
      !Number.isSafeInteger(unitPrice) ||
      unitPrice < 0 ||
      !Number.isSafeInteger(availableStock) ||
      availableStock < 0
    ) {
      return json({
        success: false,
        message: "Données du produit invalides."
      }, 500);
    }

    if (availableStock < quantity) {
      return json({
        success: false,
        message: "Stock insuffisant.",
        available: availableStock
      }, 409);
    }

    const total = unitPrice * quantity;

    if (!Number.isSafeInteger(total)) {
      return json({
        success: false,
        message: "Montant de vente invalide."
      }, 400);
    }

    // Vérification du stock, du prix et de l'abonnement
    // au moment de la modification du stock.
    const now = new Date().toISOString();

    const results = await env.DB.batch([
      env.DB.prepare(`
        UPDATE products
        SET quantity = quantity - ?
        WHERE id = ?
          AND shop_id = ?
          AND quantity >= ?
          AND sale_price = ?
          AND EXISTS (
            SELECT 1
            FROM subscriptions
            WHERE shop_id = ?
              AND (
                (status = 'trial' AND trial_ends_at > ?)
                OR
                (status = 'active' AND expires_at > ?)
              )
          )
      `).bind(
        quantity,
        productId,
        user.shop_id,
        quantity,
        unitPrice,
        user.shop_id,
        now,
        now
      ),

      env.DB.prepare(`
        INSERT INTO sales (
          shop_id,
          product_id,
          quantity,
          unit_price,
          total
        )
        SELECT ?, ?, ?, ?, ?
        WHERE changes() = 1
      `).bind(
        user.shop_id,
        productId,
        quantity,
        unitPrice,
        total
      )
    ]);

    if (
      results[0].meta.changes !== 1 ||
      results[1].meta.changes !== 1
    ) {
      return json({
        success: false,
        message: "Le stock, le prix ou l'abonnement a changé. Actualisez les données puis réessayez."
      }, 409);
    }

    return json({
      success: true,
      message: "Vente enregistrée avec succès.",
      sale: {
        productId,
        productName: product.name,
        quantity,
        unitPrice,
        total
      }
    }, 201);

  } catch (error) {
    console.error("Erreur d'enregistrement de vente:", error);

    return json({
      success: false,
      message: "Une erreur est survenue pendant la vente."
    }, 500);
  }
}
