const jwt = require("jsonwebtoken");
const prisma = require("../config/prisma");

// Comprueba que el Access Token sea válido.
async function authenticateToken(req, res, next) {
  try {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Debes enviar un Access Token",
      });
    }

    // Extrae el token del encabezado.
    const token = authorization.split(" ")[1];

    // Verifica la firma y la expiración del JWT.
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Comprueba que el usuario todavía exista.
    const user = await prisma.user.findUnique({
      where: {
        id: decoded.id,
      },
    });

    if (!user) {
      return res.status(401).json({
        error: "Usuario no encontrado",
      });
    }

    // Comprueba que el token no haya sido invalidado por logout.
    if (decoded.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({
        error: "El Access Token ha sido revocado",
      });
    }

    // Guardamos la información del usuario para las rutas protegidas.
    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Access Token inválido o expirado",
    });
  }
}

module.exports = authenticateToken;
