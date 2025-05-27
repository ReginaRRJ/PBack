// index.js (para SQL Server)
const express = require('express');
const cors = require('cors');
const sql = require('mssql');
const dotenv = require('dotenv');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const JWT_SECRET = process.env.JWT_SECRET || 'secreto_temporal';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const dbConfig = {
  user: process.env.DB_USER, 
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  options: {
    encrypt: false,
    trustServerCertificate: true,
  },
};

// Middleware para validar JWT
function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado' });

  const token = authHeader.split(' ')[1]; // "Bearer <token>"
  if (!token) return res.status(401).json({ error: 'Token mal formateado' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido o expirado' });
    req.usuario = decoded; // puedes usar info del token luego
    next();
  });
}

// 📘 Swagger Config
const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'API de Usuarios',
    version: '1.0.0',
    description: 'Documentación de API con Swagger',
  },
  servers: [{ url: 'http://localhost:4000' }],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
  },
  security: [{
    bearerAuth: [],
  }],
};

const swaggerOptions = {
  swaggerDefinition,
  apis: ['./index.js'], // 👈 Aquí se documentan directamente las rutas de este archivo
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * /usuarios:
 *   get:
 *     summary: Obtener todos los usuarios
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de usuarios
 */

// Obtener todos los usuarios
app.get('/usuarios', verificarToken, async (req, res) => {
  try {
    await sql.connect(dbConfig);
    const result = await sql.query('SELECT * FROM usuariosRegina');
    res.json(result.recordset);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});


/**
 * @swagger
 * /usuarios:
 *   post:
 *     summary: Crear un nuevo usuario
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [nombre, correo_electronico, contrasena]
 *             properties:
 *               nombre:
 *                 type: string
 *               correo_electronico:
 *                 type: string
 *               contrasena:
 *                 type: string
 *               descripcion:
 *                 type: string
 *     responses:
 *       201:
 *         description: Usuario creado correctamente
 */
// Crear usuarios
app.post('/usuarios', verificarToken, async (req, res) => {
  const { nombre, correo_electronico, contrasena, descripcion } = req.body;

  // Validación de campos
  if (!nombre || !correo_electronico || !contrasena) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  try {

    const hashedPassword = await bcrypt.hash(contrasena, 10);

    const pool = await sql.connect(dbConfig);
    await pool.request()
      .input('nombre', sql.VarChar, nombre)
      .input('correo', sql.VarChar, correo_electronico)
      .input('contrasena', sql.VarChar, hashedPassword)
      .input('descripcion', sql.VarChar, descripcion || '') // Valor por defecto
      .query(`
        INSERT INTO usuariosRegina (nombre, correo_electronico, contrasena, descripcion)
        VALUES (@nombre, @correo, @contrasena, @descripcion)
      `);

    res.status(201).json({ message: 'Usuario creado correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear el usuario' });
  }
});


/**
 * @swagger
 * /usuarios/{id}:
 *   put:
 *     summary: Editar un usuario existente
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               correo_electronico:
 *                 type: string
 *               contrasena:
 *                 type: string
 *               descripcion:
 *                 type: string
 *     responses:
 *       200:
 *         description: Usuario actualizado correctamente
 */
// Editar un usuario existente
app.put('/usuarios/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { nombre, correo_electronico, contrasena, descripcion } = req.body;
  try {
    await sql.connect(dbConfig);
    await sql.query(`
      UPDATE usuariosRegina
      SET nombre='${nombre}',
          correo_electronico='${correo_electronico}',
          contrasena='${contrasena}',
          descripcion='${descripcion}'
      WHERE id=${id}
    `);
    res.json({ message: 'Usuario actualizado correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar el usuario' });
  }
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Iniciar sesión
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [correo_electronico, contrasena]
 *             properties:
 *               correo_electronico:
 *                 type: string
 *               contrasena:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login exitoso
 *       401:
 *         description: Credenciales incorrectas
 */
// Ruta para login
app.post('/login', async (req, res) => {
  const { correo_electronico, contrasena } = req.body;

  if (!correo_electronico || !contrasena) {
    return res.status(400).json({ success: false, message: 'Faltan datos para login' });
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(correo_electronico)) {
    return res.status(400).json({ success: false, message: 'Correo inválido' });
  }

  try {
    await sql.connect(dbConfig);
    const result = await sql.query`
      SELECT * FROM usuariosRegina WHERE correo_electronico = ${correo_electronico}
    `;

    if (result.recordset.length === 0) {
      return res.status(401).json({ success: false, message: 'no existe usuario' });
    }
    
    const usuario = result.recordset[0];
    // Aquí metes los logs para debug
    console.log('Usuario desde DB:', usuario);
    console.log('Contraseña ingresada:', contrasena);

    //const isPasswordValid = await bcrypt.compare(contrasena, usuario.contrasena);


    const isPasswordValid = await bcrypt.compare(contrasena, usuario.contrasena);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos' });
    }
    console.log('Contraseña válida?', isPasswordValid);
    const token = jwt.sign(
      { id: usuario.id, correo_electronico: usuario.correo_electronico },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      success: true,
      message: 'Login exitoso',
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        correo_electronico: usuario.correo_electronico,
        descripcion: usuario.descripcion,
      },
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Error en el servidor' });
  }
});


/**
 * @swagger
 * /usuarios/{id}:
 *   delete:
 *     summary: Eliminar un usuario
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Usuario eliminado correctamente
 */
// Eliminar un usuario
app.delete('/usuarios/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  try {
    await sql.connect(dbConfig);
    await sql.query(`DELETE FROM usuariosRegina WHERE id = ${id}`);
    res.json({ message: 'Usuario eliminado correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al eliminar el usuario' });
  }
});

/*const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Servidor backend corriendo en puerto ${PORT}`);
  console.log(`Swagger disponible en http://localhost:${PORT}/api-docs`);
});*/

const PORT = process.env.PORT || 4000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Servidor backend corriendo en puerto ${PORT}`);
    console.log(`Swagger disponible en http://localhost:${PORT}/api-docs`);
  });
}

module.exports = app; // 👈 Esto es lo que necesitas para los tests
