
import { getAuthenticatedUser } from "./_utils/auth.js";

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

export async function onRequestGet({ request, env }) {
  try {
    const user = await getAuthenticatedUser(request, env);

    if (!user) {
      return json({ success: false, message: "Connexion requise." }, 401);
    }

    const products = await env.DB.prepare(`
      SELECT id, name, category, sale_price, quantity, created_at
      FROM products
      WHERE shop_id = ?
      ORDER BY id DESC
    `).bind(user.shop_id).all();

    return json({ success: true, products: products.results });

  } catch (error) {
    return json({ success: false, message: "Erreur de chargement." }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const user = await getAuthenticatedUser(request, env);
    if (!user) return json({ success: false, message: "Connexion requise." }, 401);

    const body = await request.json();
    const name = String(body.name || "").trim();
    const category = String(body.category || "").trim();
    const price = Number(body.sale_price);
    const quantity = Number(body.quantity);

    if (!name || name.length > 120) {
      return json({ success: false, message: "Nom de produit invalide." }, 400);
    }

    if (category.length > 80) {
      return json({ success: false, message: "Catégorie trop longue." }, 400);
    }

    if (!Number.isSafeInteger(price) || price < 0 ||
        !Number.isSafeInteger(quantity) || quantity < 0) {
      return json({ success: false, message: "Prix ou quantité invalide." }, 400);
    }

    const result = await env.DB.prepare(`
      INSERT INTO products (shop_id, name, category, sale_price, quantity)
      VALUES (?, ?, ?, ?, ?)
    `).bind(user.shop_id, name, category || null, price, quantity).run();

    return json({
      success: true,
      message: "Produit ajouté.",
      productId: result.meta.last_row_id
    }, 201);

  } catch (error) {
    return json({ success: false, message: "Erreur lors de l'ajout." }, 500);
  }
}

export async function onRequestPut({ request, env }) {
  try {
    const user = await getAuthenticatedUser(request, env);
    if (!user) return json({ success: false, message: "Connexion requise." }, 401);

    const body = await request.json();
    const id = Number(body.id);
    const name = String(body.name || "").trim();
    const category = String(body.category || "").trim();
    const price = Number(body.sale_price);
    const quantity = Number(body.quantity);

    if (!Number.isSafeInteger(id) || id <= 0 ||
        !name || name.length > 120 ||
        category.length > 80 ||
        !Number.isSafeInteger(price) || price < 0 ||
        !Number.isSafeInteger(quantity) || quantity < 0) {
      return json({ success: false, message: "Informations invalides." }, 400);
    }

    const result = await env.DB.prepare(`
      UPDATE products
      SET name = ?, category = ?, sale_price = ?, quantity = ?
      WHERE id = ? AND shop_id = ?
    `).bind(name, category || null, price, quantity, id, user.shop_id).run();

    if (!result.meta.changes) {
      return json({ success: false, message: "Produit introuvable." }, 404);
    }

    return json({ success: true, message: "Produit modifié." });

  } catch (error) {
    return json({ success: false, message: "Erreur lors de la modification." }, 500);
  }
}

export async function onRequestDelete({ request, env }) {
  try {
    const user = await getAuthenticatedUser(request, env);
    if (!user) return json({ success: false, message: "Connexion requise." }, 401);

    const body = await request.json();
    const id = Number(body.id);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return json({ success: false, message: "Identifiant invalide." }, 400);
    }

    const result = await env.DB.prepare(`
      DELETE FROM products
      WHERE id = ? AND shop_id = ?
    `).bind(id, user.shop_id).run();

    if (!result.meta.changes) {
      return json({ success: false, message: "Produit introuvable." }, 404);
    }

    return json({ success: true, message: "Produit supprimé." });

  } catch (error) {
    return json({ success: false, message: "Erreur lors de la suppression." }, 500);
  }
}
