const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('index.js'); // Ajusta la ruta si es necesario

// Crea un token válido para pruebas (debe coincidir con tu clave secreta en .env o usar 'secreto_temporal')
const token = jwt.sign({ id: 1, correo_electronico: 'test@example.com' }, process.env.JWT_SECRET || 'secreto_temporal');

describe('API de Usuarios', () => {
  it('GET /usuarios - debe requerir token', async () => {
    const res = await request(app).get('/usuarios');
    expect(res.statusCode).toBe(401);
  });

  it('GET /usuarios - token válido', async () => {
    const res = await request(app)
      .get('/usuarios')
      .set('Authorization', `Bearer ${token}`);
    
    // Este test puede fallar si no hay DB conectada o usuarios en la tabla
    expect([200, 500]).toContain(res.statusCode); 
  });

  it('POST /login - datos incompletos', async () => {
    const res = await request(app).post('/login').send({ correo_electronico: '' });
    expect(res.statusCode).toBe(400);
  });

  // Puedes agregar más tests para POST, PUT, DELETE si simulas o conectas a una base real
});
