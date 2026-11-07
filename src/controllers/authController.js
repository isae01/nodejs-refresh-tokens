const prisma = require("../config/prisma");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// Duración del Access Token: 15 minutos.
const ACCESS_TOKEN_TIME = "15m";

// Duración del Refresh Token: 7 días.
const REFRESH_TOKEN_DAYS = 7;

// Genera un Access Token JWT.
function generateAccessToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      tokenVersion: user.tokenVersion,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: ACCESS_TOKEN_TIME,
    },
  );
}

// Genera una cadena segura para el Refresh Token.
function generateRefreshToken() {
  return crypto.randomBytes(64).toString("hex");
}

// Calcula el hash del Refresh Token.
function hashRefreshToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Calcula la fecha de vencimiento del Refresh Token.
function getRefreshExpiration() {
  const expiration = new Date();

  expiration.setDate(expiration.getDate() + REFRESH_TOKEN_DAYS);

  return expiration;
}

// Registra un usuario nuevo.
async function register(req, res) {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Todos los campos son obligatorios",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "La contraseña debe tener al menos 8 caracteres",
      });
    }

    // Comprueba si el correo ya está registrado.
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(409).json({
        error: "El correo ya está registrado",
      });
    }

    // Protege la contraseña antes de guardarla.
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    return res.status(201).json({
      mensaje: "Usuario registrado correctamente",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Error en registro:", error);

    return res.status(500).json({
      error: "No se pudo registrar el usuario",
    });
  }
}

// Inicia sesión y genera los dos tokens.
async function login(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Correo y contraseña son obligatorios",
      });
    }

    // Busca al usuario por su correo.
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({
        error: "Credenciales incorrectas",
      });
    }

    // Compara la contraseña con el hash guardado.
    const passwordIsValid = await bcrypt.compare(password, user.password);

    if (!passwordIsValid) {
      return res.status(401).json({
        error: "Credenciales incorrectas",
      });
    }

    // Genera el Access Token.
    const accessToken = generateAccessToken(user);

    // Genera un Refresh Token seguro.
    const refreshToken = generateRefreshToken();

    // Guarda solamente el hash del Refresh Token.
    await prisma.refreshToken.create({
      data: {
        tokenHash: hashRefreshToken(refreshToken),
        userId: user.id,
        expiresAt: getRefreshExpiration(),
      },
    });

    return res.status(200).json({
      mensaje: "Inicio de sesión exitoso",
      accessToken,
      refreshToken,
      expiresIn: "15 minutos",
    });
  } catch (error) {
    console.error("Error en login:", error);

    return res.status(500).json({
      error: "No se pudo iniciar sesión",
    });
  }
}

// Renueva los tokens y revoca el Refresh Token anterior.
async function refresh(req, res) {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        error: "Debes enviar el Refresh Token",
      });
    }

    // Calcula el hash para buscarlo en la base de datos.
    const tokenHash = hashRefreshToken(refreshToken);

    const storedToken = await prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!storedToken) {
      return res.status(401).json({
        error: "Refresh Token inválido",
      });
    }

    // Comprueba si ya fue utilizado o revocado.
    if (storedToken.revokedAt) {
      return res.status(401).json({
        error: "El Refresh Token ya fue revocado",
      });
    }

    // Comprueba su fecha de vencimiento.
    if (storedToken.expiresAt <= new Date()) {
      return res.status(401).json({
        error: "El Refresh Token ha expirado",
      });
    }

    // Genera un nuevo par de tokens.
    const newAccessToken = generateAccessToken(storedToken.user);
    const newRefreshToken = generateRefreshToken();

    // La transacción evita que el mismo Refresh Token
    // pueda utilizarse exitosamente dos veces.
    const result = await prisma.$transaction(async (transaction) => {
      const revokedToken = await transaction.refreshToken.updateMany({
        where: {
          id: storedToken.id,
          revokedAt: null,
          expiresAt: {
            gt: new Date(),
          },
        },
        data: {
          revokedAt: new Date(),
        },
      });

      // Si otro proceso ya lo utilizó, no se genera otro token.
      if (revokedToken.count !== 1) {
        throw new Error("REFRESH_TOKEN_ALREADY_USED");
      }

      // Guarda el nuevo Refresh Token.
      const savedToken = await transaction.refreshToken.create({
        data: {
          tokenHash: hashRefreshToken(newRefreshToken),
          userId: storedToken.userId,
          expiresAt: getRefreshExpiration(),
        },
      });

      return savedToken;
    });

    return res.status(200).json({
      mensaje: "Tokens renovados correctamente",
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: "15 minutos",
    });
  } catch (error) {
    if (error.message === "REFRESH_TOKEN_ALREADY_USED") {
      return res.status(401).json({
        error: "El Refresh Token ya fue utilizado",
      });
    }

    console.error("Error al renovar tokens:", error);

    return res.status(500).json({
      error: "No se pudieron renovar los tokens",
    });
  }
}

// Cierra todas las sesiones activas del usuario.
async function logout(req, res) {
  try {
    const userId = req.user.id;

    await prisma.$transaction([
      // Revoca todos los Refresh Tokens activos.
      prisma.refreshToken.updateMany({
        where: {
          userId,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      }),

      // Cambia la versión para invalidar los Access Tokens anteriores.
      prisma.user.update({
        where: { id: userId },
        data: {
          tokenVersion: {
            increment: 1,
          },
        },
      }),
    ]);

    return res.status(200).json({
      mensaje: "Sesión cerrada y todos los tokens revocados",
    });
  } catch (error) {
    console.error("Error en logout:", error);

    return res.status(500).json({
      error: "No se pudo cerrar la sesión",
    });
  }
}

module.exports = {
  register,
  login,
  refresh,
  logout,
};
