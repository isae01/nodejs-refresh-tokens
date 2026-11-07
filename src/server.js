// Carga las variables del archivo .env.
require("dotenv").config();

const express = require("express");
const authRoutes = require("./routes/authRoutes");

const app = express();

const PORT = process.env.PORT || 3000;

// Permite recibir información en formato JSON.
app.use(express.json());

// Ruta para comprobar que el servidor funciona.
app.get("/", (req, res) => {
  res.json({
    mensaje: "API de autenticación con Refresh Tokens funcionando",
  });
});

// Todas las rutas de autenticación empiezan con /auth.
app.use("/auth", authRoutes);

// Inicia el servidor.
app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});
