export async function onRequest(context) {
  try {
    const result = await context.env.DB
      .prepare("SELECT 1 AS connected")
      .first();

    return Response.json({
      success: true,
      message: "KotoStock est connecté à sa base de données !",
      database: result
    });
  } catch (error) {
    return Response.json({
      success: false,
      message: "Erreur de connexion à la base de données."
    }, { status: 500 });
  }
}
