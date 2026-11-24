
import { getAuthenticatedUser } from "./_utils/auth.js";

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

export async function onRequestGet({ request, env }) {
  try {
    const user = await getAuthenticatedUser(request, env);

    if (!user) {
      return json({
        success: false,
        message: "Connexion requise."
      }, 401);
    }

    // Récupération des statistiques du magasin
    const stats = await env.DB.prepare(`
      SELECT
        (SELECT COUNT(*)
         FROM products
         WHERE shop_id = ?) AS product_count,

        (SELECT COALESCE(SUM(quantity), 0)
         FROM products
         WHERE shop_id = ?) AS total_stock,

        (SELECT COUNT(*)
         FROM sales
         WHERE shop_id = ?) AS sales_count,

        (SELECT COALESCE(SUM(total), 0)
         FROM sales
         WHERE shop_id = ?) AS revenue,

        (SELECT COUNT(*)
         FROM products
         WHERE shop_id = ? AND quantity = 0) AS out_of_stock,

        (SELECT COUNT(*)
         FROM products
         WHERE shop_id = ? AND quantity BETWEEN 1 AND 5) AS low_stock
    `).bind(
      user.shop_id,
      user.shop_id,
      user.shop_id,
      user.shop_id,
      user.shop_id,
      user.shop_id
    ).first();

    if (!stats) {
      throw new Error("Statistiques indisponibles.");
    }

    // Récupération de l'abonnement
    const subscription = await env.DB.prepare(`
      SELECT
        plan,
        status,
        trial_ends_at,
        expires_at,
        CASE
          WHEN status = 'trial'
            AND julianday(trial_ends_at) > julianday('now')
            THEN 1

          WHEN status = 'active'
            AND julianday(expires_at) > julianday('now')
            THEN 1

          ELSE 0
        END AS is_active
      FROM subscriptions
      WHERE shop_id = ?
      LIMIT 1
    `).bind(user.shop_id).first();

    return json({
      success: true,

      shop: {
        id: user.shop_id,
        name: user.shop_name
      },

      statistics: {
        productCount: stats.product_count,
        totalStock: stats.total_stock,
        salesCount: stats.sales_count,
        revenue: stats.revenue,
        outOfStock: stats.out_of_stock,
        lowStock: stats.low_stock
      },

      subscription: subscription ? {
        plan: subscription.plan,
        status: subscription.status,
        active: subscription.is_active === 1,
        trialEndsAt: subscription.trial_ends_at,
        expiresAt: subscription.expires_at
      } : {
        plan: null,
        status: "unavailable",
        active: false,
        trialEndsAt: null,
        expiresAt: null
      }
    });

  } catch (error) {
    console.error("Dashboard error:", error);

    return json({
      success: false,
      message: "Impossible de charger les statistiques."
    }, 500);
  }
}
