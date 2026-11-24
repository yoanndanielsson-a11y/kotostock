
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
