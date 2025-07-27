// server.js - VERSIÓN SEGURA CON MEJORAS CRÍTICAS
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt'); // NUEVO: Para hashear contraseñas
const jwt = require('jsonwebtoken'); // NUEVO: Para tokens JWT
const rateLimit = require('express-rate-limit'); // NUEVO: Para rate limiting
const helmet = require('helmet'); // NUEVO: Para seguridad HTTP
const validator = require('validator'); // NUEVO: Para validación de inputs

const app = express();
const PORT = process.env.PORT || 3000;

// CONFIGURACIÓN DE SEGURIDAD
const JWT_SECRET = process.env.JWT_SECRET || 'jireh_streaming_secret_key_2025!'; // Usar variable de entorno
const BCRYPT_ROUNDS = 12;
const SESSION_DURATION = '24h';

// MIDDLEWARE DE SEGURIDAD
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://ntfy.sh", "https://micuenta.me"],
        },
    },
}));

// Rate limiting
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requests por IP
    message: { error: 'Demasiadas peticiones, intenta más tarde' },
    standardHeaders: true,
    legacyHeaders: false,
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // máximo 5 intentos de login por IP
    message: { error: 'Demasiados intentos de login, intenta más tarde' },
    skipSuccessfulRequests: true,
});

app.use('/api', generalLimiter);
app.use('/api/login', loginLimiter);

// Middleware básico
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://streaming-manager-production.up.railway.app'] 
        : ['http://localhost:3000'],
    credentials: true
}));

app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf) => {
        try {
            JSON.parse(buf);
        } catch (e) {
            res.status(400).json({ error: 'JSON inválido' });
            return;
        }
    }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Configuración de PostgreSQL con SSL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Configuración de multer con validación
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { 
        fileSize: 5 * 1024 * 1024, // 5MB máximo
        files: 1
    },
    fileFilter: (req, file, cb) => {
        // Solo permitir imágenes
        const allowedTypes = /jpeg|jpg|png|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Solo se permiten archivos de imagen (JPEG, PNG, WebP)'));
        }
    }
});

// MIDDLEWARE DE AUTENTICACIÓN JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

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
}

// FUNCIONES DE VALIDACIÓN
function validateEmail(email) {
    return validator.isEmail(email) && email.length <= 254;
}

function validatePassword(password) {
    // Al menos 8 caracteres, una mayúscula, una minúscula, un número
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
}

function validateUsername(username) {
    return validator.isAlphanumeric(username) && 
           username.length >= 3 && 
           username.length <= 50;
}

function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    return validator.escape(input.trim());
}

// FUNCIONES DE HASH DE CONTRASEÑAS
async function hashPassword(password) {
    return await bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
}

// Función para calcular días restantes (timezone-safe)
function calcularDiasRestantes(fechaVencimiento) {
    if (!fechaVencimiento) return 0;

    const hoy = new Date();
    const hoyUTC = Date.UTC(hoy.getUTCFullYear(), hoy.getUTCMonth(), hoy.getUTCDate());

    const vencimiento = new Date(fechaVencimiento);
    const vencimientoUTC = Date.UTC(vencimiento.getUTCFullYear(), vencimiento.getUTCMonth(), vencimiento.getUTCDate());

    const diferenciaMilisegundos = vencimientoUTC - hoyUTC;
    const dias = Math.ceil(diferenciaMilisegundos / (1000 * 60 * 60 * 24));
    
    return Math.max(0, dias);
}

function calcularDiasRestantesPerfil(fechaVencimientoCliente) {
    return calcularDiasRestantes(fechaVencimientoCliente);
}

// Función para actualizar estado automáticamente
function actualizarEstado(diasRestantes) {
    if (diasRestantes > 5) return 'active';
    if (diasRestantes > 0) return 'inactive';
    return 'expired';
}

// Función para procesar perfiles y calcular días restantes individuales
function procesarPerfiles(profiles) {
    if (!profiles || !Array.isArray(profiles)) return [];
    
    return profiles.map(profile => {
        if (profile.estado === 'vendido' && profile.fechaVencimiento) {
            const diasRestantesCliente = calcularDiasRestantesPerfil(profile.fechaVencimiento);
            return {
                ...profile,
                diasRestantes: diasRestantesCliente
            };
        }
        return profile;
    });
}

// INICIALIZACIÓN SEGURA DE LA BASE DE DATOS
async function initDB() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Crear tabla de usuarios con contraseñas hasheadas
        await client.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email VARCHAR(254),
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                is_active BOOLEAN DEFAULT true
            )
        `);

        // Crear tabla de cuentas
        await client.query(`
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                client_name TEXT NOT NULL,
                client_phone TEXT DEFAULT '',
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                type TEXT NOT NULL,
                country TEXT NOT NULL DEFAULT 'PE',
                profiles JSONB NOT NULL DEFAULT '[]',
                days_remaining INTEGER NOT NULL DEFAULT 30,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                fecha_venta TIMESTAMP DEFAULT NOW(),
                fecha_vencimiento TIMESTAMP,
                fecha_inicio_proveedor TIMESTAMP,
                fecha_vencimiento_proveedor TIMESTAMP,
                voucher_imagen TEXT,
                numero_operacion TEXT,
                monto_pagado DECIMAL(10,2),
                estado_pago TEXT DEFAULT 'activo'
            )
        `);

        // Crear tabla de configuración de alarmas
        await client.query(`
            CREATE TABLE IF NOT EXISTS alarm_settings (
                id SERIAL PRIMARY KEY,
                provider_threshold_days INTEGER NOT NULL DEFAULT 5,
                client_threshold_days INTEGER NOT NULL DEFAULT 3,
                ntfy_topic TEXT,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Crear tabla de notificaciones enviadas
        await client.query(`
            CREATE TABLE IF NOT EXISTS sent_notifications (
                id SERIAL PRIMARY KEY,
                item_id TEXT NOT NULL,
                item_type TEXT NOT NULL,
                sent_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(item_id, item_type, DATE(sent_at))
            )
        `);

        // Crear tabla de logs de seguridad
        await client.query(`
            CREATE TABLE IF NOT EXISTS security_logs (
                id SERIAL PRIMARY KEY,
                event_type VARCHAR(50) NOT NULL,
                username VARCHAR(50),
                ip_address INET,
                user_agent TEXT,
                details JSONB,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Insertar configuración inicial de alarmas
        const alarmSettings = await client.query('SELECT * FROM alarm_settings');
        if (alarmSettings.rows.length === 0) {
            await client.query(
                'INSERT INTO alarm_settings (provider_threshold_days, client_threshold_days) VALUES (5, 3)'
            );
        }

        // Verificar si existe el usuario admin
        const existingAdmin = await client.query('SELECT * FROM admin_users WHERE username = $1', ['paolof']);
        
        if (existingAdmin.rows.length === 0) {
            // Crear usuario admin con contraseña hasheada
            const hashedPassword = await hashPassword('elpoderosodeizrael777xD!');
            await client.query(
                'INSERT INTO admin_users (username, password_hash, email) VALUES ($1, $2, $3)',
                ['paolof', hashedPassword, 'admin@jirehstreaming.com']
            );
            console.log('✅ Usuario admin creado con contraseña segura');
        } else {
            // Actualizar contraseña existente si no está hasheada
            const user = existingAdmin.rows[0];
            if (!user.password_hash || user.password_hash.length < 50) {
                const hashedPassword = await hashPassword('elpoderosodeizrael777xD!');
                await client.query(
                    'UPDATE admin_users SET password_hash = $1, updated_at = NOW() WHERE username = $2',
                    [hashedPassword, 'paolof']
                );
                console.log('✅ Contraseña admin actualizada a hash seguro');
            }
        }

        await client.query('COMMIT');
        console.log('✅ Base de datos inicializada correctamente con seguridad mejorada');
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error inicializando base de datos:', error);
        throw error;
    } finally {
        client.release();
    }
}

// FUNCIÓN DE LOGGING DE SEGURIDAD
async function logSecurityEvent(eventType, username, req, details = {}) {
    try {
        const ip = req.ip || req.connection.remoteAddress;
        const userAgent = req.get('User-Agent');
        
        await pool.query(
            'INSERT INTO security_logs (event_type, username, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)',
            [eventType, username, ip, userAgent, JSON.stringify(details)]
        );
    } catch (error) {
        console.error('Error logging security event:', error);
    }
}

// LÓGICA DE ENVÍO DE ALARMAS POR NTFY (MEJORADA)
async function checkAndSendAlarms() {
    console.log('⏰ Revisando alarmas para enviar notificaciones a ntfy...');

    try {
        const settingsRes = await pool.query('SELECT * FROM alarm_settings WHERE id = 1');
        const settings = settingsRes.rows[0];

        if (!settings || !settings.ntfy_topic) {
            console.log('⚠️ No se ha configurado un tema de ntfy para notificaciones.');
            return;
        }

        const accountsRes = await pool.query('SELECT * FROM accounts');

        for (const account of accountsRes.rows) {
            const providerDays = calcularDiasRestantes(account.fecha_vencimiento_proveedor);
            if (providerDays > 0 && providerDays <= settings.provider_threshold_days) {
                const notificationId = `provider-${account.id}`;
                const checkRes = await pool.query(
                    "SELECT 1 FROM sent_notifications WHERE item_id = $1 AND item_type = 'provider' AND sent_at > NOW() - INTERVAL '24 hours'", 
                    [notificationId]
                );
                
                if (checkRes.rows.length === 0) {
                    const message = `🚨 La cuenta de ${account.type} de "${account.client_name}" vence en ${providerDays} día(s).`;
                    
                    // Envío seguro con timeout
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 10000);
                    
                    try {
                        await fetch(`https://ntfy.sh/${settings.ntfy_topic}`, {
                            method: 'POST',
                            body: message,
                            headers: { 
                                'Title': 'Alarma de Proveedor', 
                                'Priority': 'high', 
                                'Tags': 'rotating_light' 
                            },
                            signal: controller.signal
                        });
                        
                        await pool.query(
                            "INSERT INTO sent_notifications (item_id, item_type, sent_at) VALUES ($1, 'provider', NOW()) ON CONFLICT (item_id, item_type, DATE(sent_at)) DO UPDATE SET sent_at = NOW()", 
                            [notificationId]
                        );
                        
                        console.log(`📲 Notificación de proveedor enviada para la cuenta ${account.id}`);
                    } catch (fetchError) {
                        console.error(`❌ Error enviando notificación para ${account.id}:`, fetchError.message);
                    } finally {
                        clearTimeout(timeoutId);
                    }
                }
            }

            // Procesar notificaciones de clientes
            const profiles = typeof account.profiles === 'string' ? JSON.parse(account.profiles) : account.profiles || [];
            for (const [index, profile] of profiles.entries()) {
                if (profile.estado === 'vendido') {
                    const clientDays = calcularDiasRestantesPerfil(profile.fechaVencimiento);
                    if (clientDays > 0 && clientDays <= settings.client_threshold_days) {
                        const notificationId = `client-${account.id}-${index}`;
                        const checkRes = await pool.query(
                            "SELECT 1 FROM sent_notifications WHERE item_id = $1 AND item_type = 'client' AND sent_at > NOW() - INTERVAL '24 hours'", 
                            [notificationId]
                        );

                        if (checkRes.rows.length === 0) {
                            const message = `🔔 El perfil "${profile.name}" del cliente ${profile.clienteNombre} (${account.type}) vence en ${clientDays} día(s).`;
                            
                            const controller = new AbortController();
                            const timeoutId = setTimeout(() => controller.abort(), 10000);
                            
                            try {
                                await fetch(`https://ntfy.sh/${settings.ntfy_topic}`, {
                                    method: 'POST',
                                    body: message,
                                    headers: { 
                                        'Title': 'Alarma de Cliente', 
                                        'Priority': 'default', 
                                        'Tags': 'bell' 
                                    },
                                    signal: controller.signal
                                });
                                
                                await pool.query(
                                    "INSERT INTO sent_notifications (item_id, item_type, sent_at) VALUES ($1, 'client', NOW()) ON CONFLICT (item_id, item_type, DATE(sent_at)) DO UPDATE SET sent_at = NOW()", 
                                    [notificationId]
                                );
                                
                                console.log(`📲 Notificación de cliente enviada para el perfil ${account.id}-${index}`);
                            } catch (fetchError) {
                                console.error(`❌ Error enviando notificación de cliente para ${account.id}-${index}:`, fetchError.message);
                            } finally {
                                clearTimeout(timeoutId);
                            }
                        }
                    }
                }
            }
        }
    } catch (error) {
        console.error('❌ Error durante la revisión de alarmas:', error);
    }
}

// RUTAS API SEGURAS

// Health check público
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '2.0.0'
    });
});

// Login seguro con JWT
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validar inputs
        if (!username || !password) {
            await logSecurityEvent('LOGIN_FAILED', username, req, { reason: 'Missing credentials' });
            return res.status(400).json({ success: false, message: 'Usuario y contraseña requeridos' });
        }

        if (!validateUsername(username)) {
            await logSecurityEvent('LOGIN_FAILED', username, req, { reason: 'Invalid username format' });
            return res.status(400).json({ success: false, message: 'Formato de usuario inválido' });
        }

        // Sanitizar input
        const cleanUsername = sanitizeInput(username);

        // Buscar usuario
        const result = await pool.query(
            'SELECT id, username, password_hash, failed_attempts, locked_until, is_active FROM admin_users WHERE username = $1',
            [cleanUsername]
        );

        if (result.rows.length === 0) {
            await logSecurityEvent('LOGIN_FAILED', cleanUsername, req, { reason: 'User not found' });
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const user = result.rows[0];

        // Verificar si está activo
        if (!user.is_active) {
            await logSecurityEvent('LOGIN_FAILED', cleanUsername, req, { reason: 'Account disabled' });
            return res.status(401).json({ success: false, message: 'Cuenta deshabilitada' });
        }

        // Verificar si está bloqueado
        if (user.locked_until && new Date() < new Date(user.locked_until)) {
            await logSecurityEvent('LOGIN_FAILED', cleanUsername, req, { reason: 'Account locked' });
            return res.status(423).json({ success: false, message: 'Cuenta temporalmente bloqueada' });
        }

        // Verificar contraseña
        const passwordValid = await verifyPassword(password, user.password_hash);

        if (!passwordValid) {
            // Incrementar intentos fallidos
            const newFailedAttempts = (user.failed_attempts || 0) + 1;
            let lockUntil = null;

            if (newFailedAttempts >= 5) {
                lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos
            }

            await pool.query(
                'UPDATE admin_users SET failed_attempts = $1, locked_until = $2 WHERE id = $3',
                [newFailedAttempts, lockUntil, user.id]
            );

            await logSecurityEvent('LOGIN_FAILED', cleanUsername, req, { 
                reason: 'Invalid password', 
                failed_attempts: newFailedAttempts 
            });

            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        // Login exitoso - resetear intentos fallidos
        await pool.query(
            'UPDATE admin_users SET failed_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1',
            [user.id]
        );

        // Generar JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username,
                iat: Math.floor(Date.now() / 1000)
            },
            JWT_SECRET,
            { expiresIn: SESSION_DURATION }
        );

        await logSecurityEvent('LOGIN_SUCCESS', cleanUsername, req);

        res.json({ 
            success: true, 
            message: 'Login exitoso',
            token: token,
            user: {
                id: user.id,
                username: user.username
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        await logSecurityEvent('LOGIN_ERROR', req.body.username, req, { error: error.message });
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Middleware de autenticación para rutas protegidas
app.use('/api/accounts', authenticateToken);
app.use('/api/stats', authenticateToken);
app.use('/api/alarms', authenticateToken);

// Obtener todas las cuentas (protegido)
app.get('/api/accounts', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM accounts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error obteniendo cuentas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Crear nueva cuenta (protegido)
app.post('/api/accounts', async (req, res) => {
    try {
        const { 
            id, client_name, client_phone, email, password, 
            type, country, profiles, fecha_inicio_proveedor 
        } = req.body;

        // Validaciones de seguridad
        if (!id || !client_name || !email || !password || !type) {
            return res.status(400).json({ error: 'Campos requeridos faltantes' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Email inválido' });
        }

        // Sanitizar inputs
        const cleanData = {
            id: sanitizeInput(id),
            client_name: sanitizeInput(client_name),
            client_phone: sanitizeInput(client_phone || ''),
            email: email.toLowerCase().trim(),
            password: sanitizeInput(password),
            type: sanitizeInput(type),
            country: sanitizeInput(country || 'PE')
        };

        // Verificar duplicados
        const existingAccount = await pool.query('SELECT id FROM accounts WHERE id = $1 OR email = $2', [cleanData.id, cleanData.email]);
        if (existingAccount.rows.length > 0) {
            return res.status(409).json({ error: 'Cuenta o email ya existe' });
        }

        const fechaInicio = fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : new Date();
        const fechaVencimientoProveedor = new Date(fechaInicio);
        fechaVencimientoProveedor.setDate(fechaVencimientoProveedor.getDate() + 30);
        
        const diasRestantesProveedor = calcularDiasRestantes(fechaVencimientoProveedor);
        const estadoProveedor = actualizarEstado(diasRestantesProveedor);

        const result = await pool.query(
            `INSERT INTO accounts (
                id, client_name, client_phone, email, password, type, country, profiles, 
                days_remaining, status, fecha_inicio_proveedor, fecha_vencimiento_proveedor, 
                estado_pago, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW()) 
            RETURNING *`,
            [
                cleanData.id, cleanData.client_name, cleanData.client_phone, cleanData.email,
                cleanData.password, cleanData.type, cleanData.country, JSON.stringify(profiles || []),
                diasRestantesProveedor, estadoProveedor, fechaInicio, fechaVencimientoProveedor, 'activo'
            ]
        );

        await logSecurityEvent('ACCOUNT_CREATED', req.user.username, req, { account_id: cleanData.id });

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Continuar con las demás rutas protegidas...
// [El resto de las rutas API seguirían el mismo patrón de seguridad]

// Ruta para proxy de micuenta.me con validación
app.post('/api/check-micuenta-me-code', authenticateToken, async (req, res) => {
    try {
        const { code, pdv } = req.body;

        // Validar inputs
        if (!code || !pdv) {
            return res.status(400).json({ error: 'Code y PDV son requeridos' });
        }

        // Sanitizar inputs
        const cleanCode = sanitizeInput(code);
        const cleanPdv = sanitizeInput(pdv);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000);

        try {
            const response = await fetch('https://micuenta.me/e/redeem', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'JIREH-Streaming-Manager/2.0.0'
                },
                body: JSON.stringify({ code: cleanCode, pdv: cleanPdv }),
                signal: controller.signal
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ 
                    message: 'Error desconocido del proxy de micuenta.me.' 
                }));
                return res.status(response.status).json(errorData);
            }

            const data = await response.json();
            
            await logSecurityEvent('MICUENTA_CHECK', req.user.username, req, { 
                code: cleanCode.substring(0, 4) + '***' 
            });

            res.json(data);

        } finally {
            clearTimeout(timeoutId);
        }

    } catch (error) {
        if (error.name === 'AbortError') {
            return res.status(408).json({ error: 'Timeout en la solicitud a micuenta.me' });
        }
        
        console.error('Error en proxy micuenta.me:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Servir archivos estáticos
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// Middleware de manejo de errores
app.use((error, req, res, next) => {
    console.error('Error no manejado:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'Archivo demasiado grande (máximo 5MB)' });
        }
        return res.status(400).json({ error: 'Error en la subida de archivo' });
    }
    
    res.status(500).json({ error: 'Error interno del servidor' });
});

// Catch-all para SPA
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Iniciar servidor con seguridad mejorada
async function startServer() {
    try {
        await initDB();
        
        const server = app.listen(PORT, () => {
            console.log(`🚀 JIREH Streaming Manager v2.0.0 (SEGURO) corriendo en puerto ${PORT}`);
            console.log(`🔒 Seguridad: JWT, bcrypt, rate limiting, helmet activados`);
            console.log(`🗄️ Base de datos: PostgreSQL con SSL`);
            console.log(`⏰ Sistema de alarmas ntfy: Activo`);
        });

        // Iniciar sistema de alarmas cada hora
        setInterval(checkAndSendAlarms, 3600000); 
        
        // Graceful shutdown
        process.on('SIGTERM', () => {
            console.log('🛑 Cerrando servidor gracefully...');
            server.close(() => {
                console.log('✅ Servidor cerrado');
                pool.end();
                process.exit(0);
            });
        });

    } catch (error) {
        console.error('❌ Error iniciando servidor:', error);
        process.exit(1);
    }
}

// Manejo de errores globales
process.on('unhandledRejection', (err) => {
    console.error('❌ Unhandled rejection:', err);
});

process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught exception:', err);
    process.exit(1);
});

startServer();
