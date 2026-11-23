
import { getAuthenticatedUser } from "./_utils/auth.js";

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

// Consulter l'historique des ventes
export async function onRequestGet({ request, env }) {
  try {
    const user = await getAuthenticatedUser(request, env);

    if (!user) {
      return json({ success: false, message: "Connexion requise." }, 401);
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
      WHERE sales.shop_id = ?
      ORDER BY sales.id DESC
      LIMIT 200
    `).bind(user.shop_id).all();

    return json({
      success: true,
      sales: sales.results
    });

  } catch (error) {
    return json({
      success: false,
      message: "Impossible de charger les ventes."
    }, 500);
  }
}

// Enregistrer une nouvelle vente
export async function onRequestPost({ request, env }) {
  try {
    const user = await getAuthenticatedUser(request, env);

    if (!user) {
      return json({ success: false, message: "Connexion requise." }, 401);
    }

    const body = await request.json();

    const productId = Number(body.product_id);
    const quantity = Number(body.quantity);

    if (
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

    // Le prix est récupéré directement depuis la base.
    // Le navigateur ne peut donc pas imposer son propre prix.
    const product = await env.DB.prepare(`
      SELECT id, name, sale_price, quantity
      FROM products
      WHERE id = ? AND shop_id = ?
    `).bind(productId, user.shop_id).first();

    if (!product) {
      return json({
        success: false,
        message: "Produit introuvable."
      }, 404);
    }

    if (product.quantity < quantity) {
      return json({
        success: false,
        message: "Stock insuffisant.",
        available: product.quantity
      }, 409);
    }

    const total = product.sale_price * quantity;

    if (!Number.isSafeInteger(total)) {
      return json({
        success: false,
        message: "Montant de vente invalide."
      }, 400);
    }

    // Les deux opérations sont exécutées dans un même batch D1.
    // La vente n'est insérée que si la diminution du stock réussit.
    const results = await env.DB.batch([
      env.DB.prepare(`
        UPDATE products
        SET quantity = quantity - ?
        WHERE id = ?
          AND shop_id = ?
          AND quantity >= ?
      `).bind(quantity, productId, user.shop_id, quantity),

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
        product.sale_price,
        total
      )
    ]);

    if (results[0].meta.changes !== 1 ||
        results[1].meta.changes !== 1) {
      return json({
        success: false,
        message: "Stock insuffisant ou vente non enregistrée."
      }, 409);
    }

    return json({
      success: true,
      message: "Vente enregistrée avec succès.",
      sale: {
        productId,
        productName: product.name,
        quantity,
        unitPrice: product.sale_price,
        total
      }
    }, 201);

  } catch (error) {
    return json({
      success: false,
      message: "Une erreur est survenue pendant la vente."
    }, 500);
  }
}
