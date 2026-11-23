
export async function sendKotoStockEmail(env, { to, subject, html }) {
  const apiKey = env.RESEND_API_KEY;
  const from = env.EMAIL_FROM;

  if (!apiKey || !from) {
    return {
      success: false,
      message: "Service e-mail non configuré."
    };
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from,
        to: [to],
        subject,
        html
      })
    });

    const result = await response.json();

    if (!response.ok) {
      return {
        success: false,
        message: "Échec de l'envoi."
      };
    }

    return { success: true, id: result.id };
  } catch {
    return {
      success: false,
      message: "Erreur de connexion."
    };
  }
}
