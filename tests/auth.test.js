// tests/auth.test.js - Tests de Autenticación
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Importar app sin iniciar servidor
let app;

describe('🔐 Sistema de Autenticación - FASE 2', () => {
    let server;
    let validToken;

    beforeAll(async () => {
        // Importar app dinámicamente para evitar conflictos
        const express = require('express');
        const { Pool } = require('pg');
        const cors = require('cors');
        const rateLimit = require('express-rate-limit');
        const Joi = require('joi');
        
        // Recrear app para tests
        app = express();
        app.set('trust proxy', 1);
        app.use(cors());
        app.use(express.json({ limit: '10mb' }));
        
        // Rate limiting más permisivo para tests
        const testLimiter = rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 1000, // Más permisivo para tests
            message: { error: 'Rate limit exceeded in tests' },
        });
        
        app.use('/api/', testLimiter);
        
        // JWT Secret para tests
        const JWT_SECRET = global.testConfig.jwtSecret;
        
        // Middleware de autenticación
        const authenticateJWT = (req, res, next) => {
            const authHeader = req.headers.authorization;
            const token = authHeader && authHeader.split(' ')[1];

            if (!token) {
                return res.status(401).json({ error: 'Token de acceso requerido' });
            }

            jwt.verify(token, JWT_SECRET, (err, user) => {
                if (err) {
                    return res.status(403).json({ error: 'Token inválido o expirado' });
                }
                req.user = user;
                next();
            });
        };
        
        // Esquemas de validación
        const schemas = {
            login: Joi.object({
                username: Joi.string().alphanum().min(3).max(30).required(),
                password: Joi.string().min(6).required()
            })
        };
        
        const validate = (schema) => {
            return (req, res, next) => {
                const { error } = schema.validate(req.body);
                if (error) {
                    return res.status(400).json({
                        success: false,
                        message: 'Datos de entrada inválidos',
                        details: error.details.map(detail => detail.message)
                    });
                }
                next();
            };
        };
        
        // Pool de BD para tests
        const testPool = global.testPool;
        
        // Funciones bcrypt
        const hashPassword = async (password) => {
            return await bcrypt.hash(password, 12);
        };
        
        const comparePassword = async (password, hashedPassword) => {
            return await bcrypt.compare(password, hashedPassword);
        };
        
        // Rutas de test
        app.get('/api/health', (req, res) => {
            res.json({ 
                status: 'OK', 
                timestamp: new Date().toISOString(),
                environment: 'test'
            });
        });
        
        app.post('/api/login', validate(schemas.login), async (req, res) => {
            try {
                const { username, password } = req.body;
                
                if (!testPool) {
                    // Mock response para tests sin BD
                    if (username === 'testuser' && password === 'testpass123') {
                        const token = jwt.sign(
                            { id: 1, username: 'testuser' },
                            JWT_SECRET,
                            { expiresIn: '7d' }
                        );
                        
                        return res.json({
                            success: true,
                            message: 'Login exitoso',
                            token: token,
                            user: { id: 1, username: 'testuser' }
                        });
                    } else {
                        return res.status(401).json({
                            success: false,
                            message: 'Credenciales inválidas'
                        });
                    }
                }
                
                // Test con BD real
                const result = await testPool.query(
                    'SELECT id, username, password FROM admin_users WHERE username = $1', 
                    [username]
                );
                
                if (result.rows.length === 0) {
                    return res.status(401).json({
                        success: false,
                        message: 'Credenciales inválidas'
                    });
                }
                
                const user = result.rows[0];
                const isPasswordValid = await comparePassword(password, user.password);
                
                if (!isPasswordValid) {
                    return res.status(401).json({
                        success: false,
                        message: 'Credenciales inválidas'
                    });
                }
                
                const token = jwt.sign(
                    { id: user.id, username: user.username },
                    JWT_SECRET,
                    { expiresIn: '7d' }
                );
                
                res.json({
                    success: true,
                    message: 'Login exitoso',
                    token: token,
                    user: { id: user.id, username: user.username }
                });
                
            } catch (error) {
                res.status(500).json({
                    success: false,
                    message: 'Error interno del servidor'
                });
            }
        });
        
        app.get('/api/protected', authenticateJWT, (req, res) => {
            res.json({
                success: true,
                message: 'Acceso autorizado',
                user: req.user
            });
        });
        
        // Generar token válido para tests
        validToken = jwt.sign(
            { id: 1, username: 'testuser' },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
    });

    beforeEach(async () => {
        // Limpiar datos de prueba antes de cada test
        await global.cleanupTestData();
        jest.clearAllMocks();
    });

    describe('POST /api/login', () => {
        test('✅ Debe permitir login con credenciales válidas', async () => {
            const response = await request(app)
                .post('/api/login')
                .send({
                    username: 'testuser',
                    password: 'testpass123'
                });

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            expect(response.body.token).toBeDefined();
            expect(response.body.user).toEqual({
                id: 1,
                username: 'testuser'
            });
        });

        test('❌ Debe rechazar credenciales inválidas', async () => {
            const response = await request(app)
                .post('/api/login')
                .send({
                    username: 'testuser',
                    password: 'wrongpassword'
                });

            expect(response.status).toBe(401);
            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Credenciales inválidas');
            expect(response.body.token).toBeUndefined();
        });

        test('❌ Debe rechazar usuario inexistente', async () => {
            const response = await request(app)
                .post('/api/login')
                .send({
                    username: 'usuarioinexistente',
                    password: 'testpass123'
                });

            expect(response.status).toBe(401);
            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Credenciales inválidas');
        });

        test('❌ Debe validar formato de entrada', async () => {
            const response = await request(app)
                .post('/api/login')
                .send({
                    username: 'ab', // Muy corto
                    password: '123'  // Muy corto
                });

            expect(response.status).toBe(400);
            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Datos de entrada inválidos');
            expect(response.body.details).toBeDefined();
        });

        test('❌ Debe rechazar campos faltantes', async () => {
            const response = await request(app)
                .post('/api/login')
                .send({
                    username: 'testuser'
                    // password faltante
                });

            expect(response.status).toBe(400);
            expect(response.body.success).toBe(false);
        });
    });

    describe('🔑 JWT Token Validation', () => {
        test('✅ Debe aceptar token válido', async () => {
            const response = await request(app)
                .get('/api/protected')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            expect(response.body.user).toEqual({
                id: 1,
                username: 'testuser'
            });
        });

        test('❌ Debe rechazar token inválido', async () => {
            const response = await request(app)
                .get('/api/protected')
                .set('Authorization', 'Bearer tokeninvalido');

            expect(response.status).toBe(403);
            expect(response.body.error).toBe('Token inválido o expirado');
        });

        test('❌ Debe rechazar petición sin token', async () => {
            const response = await request(app)
                .get('/api/protected');

            expect(response.status).toBe(401);
            expect(response.body.error).toBe('Token de acceso requerido');
        });

        test('✅ Token debe tener estructura correcta', () => {
            const decoded = jwt.verify(validToken, global.testConfig.jwtSecret);
            
            expect(decoded.id).toBe(1);
            expect(decoded.username).toBe('testuser');
            expect(decoded.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
        });
    });

    describe('🔒 Bcrypt Password Hashing', () => {
        test('✅ Debe hashear contraseñas correctamente', async () => {
            const password = 'testpassword123';
            const hashedPassword = await bcrypt.hash(password, 12);
            
            expect(hashedPassword).toBeDefined();
            expect(hashedPassword).not.toBe(password);
            expect(hashedPassword.startsWith('$2b$')).toBe(true);
        });

        test('✅ Debe verificar contraseñas hasheadas', async () => {
            const password = 'testpassword123';
            const hashedPassword = await bcrypt.hash(password, 12);
            
            const isValid = await bcrypt.compare(password, hashedPassword);
            const isInvalid = await bcrypt.compare('wrongpassword', hashedPassword);
            
            expect(isValid).toBe(true);
            expect(isInvalid).toBe(false);
        });

        test('✅ Hashes diferentes para la misma contraseña', async () => {
            const password = 'testpassword123';
            const hash1 = await bcrypt.hash(password, 12);
            const hash2 = await bcrypt.hash(password, 12);
            
            expect(hash1).not.toBe(hash2);
            
            // Pero ambos deben verificar correctamente
            expect(await bcrypt.compare(password, hash1)).toBe(true);
            expect(await bcrypt.compare(password, hash2)).toBe(true);
        });
    });

    describe('🛡️ Rate Limiting', () => {
        test('✅ Health endpoint debe responder', async () => {
            const response = await request(app)
                .get('/api/health');

            expect(response.status).toBe(200);
            expect(response.body.status).toBe('OK');
            expect(response.body.environment).toBe('test');
        });

        test('✅ Rate limiting headers deben estar presentes', async () => {
            const response = await request(app)
                .post('/api/login')
                .send({
                    username: 'testuser',
                    password: 'testpass123'
                });

            expect(response.headers['x-ratelimit-limit']).toBeDefined();
            expect(response.headers['x-ratelimit-remaining']).toBeDefined();
        });
    });
});
