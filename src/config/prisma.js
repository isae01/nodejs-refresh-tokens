const { PrismaClient } = require("@prisma/client");

// Crea la conexión con la base de datos.
const prisma = new PrismaClient();

module.exports = prisma;
