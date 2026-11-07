const express = require("express");

const {
  register,
  login,
  refresh,
  logout,
} = require("../controllers/authController");

const authenticateToken = require("../middlewares/authMiddleware");

const router = express.Router();

// Registrar un usuario.
router.post("/register", register);

// Iniciar sesión y obtener los dos tokens.
router.post("/login", login);

// Renovar los tokens.
router.post("/refresh", refresh);

// Cerrar sesión y revocar todos los tokens.
router.post("/logout", authenticateToken, logout);

module.exports = router;
