
import { getAuthenticatedUser } from "./_utils/auth.js";

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store, private",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

export async function onRequestGet({ request, env }) {
  try {
    // 1. Vérifier l'identité de l'utilisateur.
    const account = await getAuthenticatedUser(request, env);

    if (!account) {
      return json({
        success: false,
        message: "Session expirée. Veuillez vous reconnecter."
      }, 401);
    }

    // 2. Récupérer l'abonnement de sa boutique.
    const subscription = await env.DB.prepare(`
      SELECT
        status,
        trial_ends_at,
        expires_at
      FROM subscriptions
      WHERE shop_id = ?
      LIMIT 1
    `)
      .bind(account.shop_id)
      .first();

    // 3. Retourner les informations nécessaires à l'application.
    return json({
      success: true,

      user: {
        firstName: account.first_name,
        lastName: account.last_name,
        email: account.email
      },

      shop: {
        id: account.shop_id,
        name: account.shop_name
      },

      subscription: {
        status: subscription?.status || null,
        trialEndsAt: subscription?.trial_ends_at || null,
        expiresAt: subscription?.expires_at || null
      }
    });

  } catch (error) {
    console.error("Erreur de vérification du compte KotoStock:", error);

    return json({
      success: false,
      message: "Erreur lors de la vérification du compte."
    }, 500);
  }
}
