
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
    const account = await getAuthenticatedUser(request, env);

    if (!account) {
      return json({
        success: false,
        message: "Session expirée. Veuillez vous reconnecter."
      }, 401);
    }

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
    `)
      .bind(account.shop_id)
      .first();

    return json({
      success: true,

      user: {
        firstName: account.first_name,
        lastName: account.last_name,
        publicId: account.public_id
      },

      shop: {
        id: account.shop_id,
        name: account.shop_name
      },

      subscription: {
        plan: subscription?.plan || null,
        status: subscription?.status || null,
        active: subscription?.is_active === 1,
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
