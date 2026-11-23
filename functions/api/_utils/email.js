
export async function sendKotoStockEmail({ to, subject, html }) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM;

  if (!apiKey || !from) {
    console.error("Configuration e-mail manquante.");
    return {
      success: false,
      message: "Le service e-mail n'est pas encore configuré."
    };
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
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
      console.error("Erreur du service e-mail :", result);
      return {
        success: false,
        message: "Impossible d'envoyer l'e-mail."
      };
    }

    return {
      success: true,
      id: result.id
    };
  } catch (error) {
    console.error("Erreur e-mail :", error);
    return {
      success: false,
      message: "Erreur de connexion au service e-mail."
    };
  }
}
