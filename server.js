// server.js - Sistema completo con fechas automáticas, perfiles, vouchers, ALARMAS NTFY Y SEGURIDAD MEJORADA
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// ===============================================
// MIDDLEWARE DE SEGURIDAD MEJORADO
// ===============================================
app.use(helmet({
    contentSecurityPolicy: false, // Permitir inline scripts para el dashboard
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? 
        ['https://*.railway.app', 'https://*.up.railway.app'] : 
        true,
    credentials: true
}));

// Rate limiting mejorado
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requests por IP
    message: { error: 'Demasiadas solicitudes, intenta en 15 minutos' },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // máximo 5 intentos de login por IP
    message: { error: 'Demasiados intentos de login, intenta en 15 minutos' },
    skipSuccessfulRequests: true
});

app.use('/api/', limiter);
app.use('/api/login', authLimiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ===============================================
// CONFIGURACIÓN DE POSTGRESQL
// ===============================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// ===============================================
// CONFIGURACIÓN DE MULTER MEJORADA
// ===============================================
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { 
        fileSize: 5 * 1024 * 1024, // 5MB máximo
        files: 1
    },
    fileFilter: (req, file, cb) => {
        const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de archivo no permitido. Solo imágenes.'), false);
        }
    }
});

// ===============================================
// UTILIDADES Y FUNCIONES HELPER
// ===============================================
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

function actualizarEstado(diasRestantes) {
    if (diasRestantes > 5) return 'active';
    if (diasRestantes > 0) return 'inactive';
    return 'expired';
}

function procesarPerfiles(profiles) {
    if (!profiles || !Array.isArray(profiles)) return [];
    return profiles.map(profile => {
        if (profile.estado === 'vendido' && profile.fechaVencimiento) {
            const diasRestantesCliente = calcularDiasRestantesPerfil(profile.fechaVencimiento);
            return { ...profile, diasRestantes: diasRestantesCliente };
        }
        return profile;
    });
}

// Logger simple pero efectivo
const logger = {
    info: (msg, data = {}) => console.log(`ℹ️  ${new Date().toISOString()} - ${msg}`, data),
    warn: (msg, data = {}) => console.warn(`⚠️  ${new Date().toISOString()} - ${msg}`, data),
    error: (msg, error = {}) => console.error(`❌ ${new Date().toISOString()} - ${msg}`, error),
    success: (msg, data = {}) => console.log(`✅ ${new Date().toISOString()} - ${msg}`, data)
};

// ===============================================
// INICIALIZACIÓN DE BASE DE DATOS MEJORADA
// ===============================================
async function initDB() {
    try {
        logger.info('Inicializando base de datos...');
        
        // Crear tabla accounts
        await pool.query(`
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
        
        // Crear tabla alarm_settings
        await pool.query(`
            CREATE TABLE IF NOT EXISTS alarm_settings (
                id SERIAL PRIMARY KEY,
                provider_threshold_days INTEGER NOT NULL DEFAULT 5,
                client_threshold_days INTEGER NOT NULL DEFAULT 3,
                ntfy_topic TEXT
            )
        `);
        
        // Insertar configuración de alarmas por defecto
        const settings = await pool.query('SELECT * FROM alarm_settings');
        if (settings.rows.length === 0) {
            await pool.query('INSERT INTO alarm_settings (provider_threshold_days, client_threshold_days) VALUES (5, 3)');
        }
        
        // Verificar/agregar columna ntfy_topic si no existe
        const columns = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='alarm_settings' AND column_name='ntfy_topic'
        `);
        if (columns.rows.length === 0) {
            await pool.query("ALTER TABLE alarm_settings ADD COLUMN ntfy_topic TEXT");
        }
        
        // Crear tabla sent_notifications
        await pool.query(`
            CREATE TABLE IF NOT EXISTS sent_notifications (
                id SERIAL PRIMARY KEY,
                item_id TEXT NOT NULL,
                item_type TEXT NOT NULL,
                sent_at TIMESTAMP NOT NULL,
                UNIQUE(item_id, item_type)
            )
        `);
        
        // Crear tabla admin_users con seguridad mejorada
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        `);
        
        // Crear usuario admin con contraseña hasheada
        await createAdminUser();
        
        logger.success('Base de datos inicializada correctamente');
    } catch (error) {
        logger.error('Error inicializando base de datos:', error);
        throw error;
    }
}

// Crear usuario admin con contraseña hasheada
async function createAdminUser() {
    try {
        const username = process.env.ADMIN_USERNAME || 'paolof';
        const password = process.env.ADMIN_PASSWORD || 'elpoderosodeizrael777xD!';
        
        // Verificar si el usuario ya existe
        const existingUser = await pool.query('SELECT id FROM admin_users WHERE username = $1', [username]);
        
        if (existingUser.rows.length === 0) {
            // Crear nuevo usuario con contraseña hasheada
            const hashedPassword = await bcrypt.hash(password, 12);
            await pool.query(`
                INSERT INTO admin_users (username, password) 
                VALUES ($1, $2)
            `, [username, hashedPassword]);
            logger.success(`Usuario admin '${username}' creado con contraseña hasheada`);
        } else {
            logger.info(`Usuario admin '${username}' ya existe`);
        }
    } catch (error) {
        logger.error('Error creando usuario admin:', error);
    }
}

// ===============================================
// SISTEMA DE ALARMAS NTFY
// ===============================================
async function checkAndSendAlarms() {
    logger.info('Revisando alarmas para enviar notificaciones a ntfy...');

    try {
        const settingsRes = await pool.query('SELECT * FROM alarm_settings WHERE id = 1');
        const settings = settingsRes.rows[0];

        if (!settings || !settings.ntfy_topic) {
            logger.warn('No se ha configurado un tema de ntfy para notificaciones.');
            return;
        }

        const accountsRes = await pool.query('SELECT * FROM accounts');

        for (const account of accountsRes.rows) {
            // Verificar alarmas de proveedor
            const providerDays = calcularDiasRestantes(account.fecha_vencimiento_proveedor);
            if (providerDays > 0 && providerDays <= settings.provider_threshold_days) {
                const notificationId = `provider-${account.id}`;
                const checkRes = await pool.query(
                    "SELECT 1 FROM sent_notifications WHERE item_id = $1 AND sent_at > NOW() - INTERVAL '24 hours'", 
                    [notificationId]
                );
                
                if (checkRes.rows.length === 0) {
                    const message = `🚨 La cuenta de ${account.type} de "${account.client_name}" vence en ${providerDays} día(s).`;
                    await fetch(`https://ntfy.sh/${settings.ntfy_topic}`, {
                        method: 'POST',
                        body: message,
                        headers: { 
                            'Title': 'Alarma de Proveedor', 
                            'Priority': 'high', 
                            'Tags': 'rotating_light' 
                        }
                    });
                    await pool.query(
                        "INSERT INTO sent_notifications (item_id, item_type, sent_at) VALUES ($1, 'provider', NOW()) ON CONFLICT (item_id, item_type) DO UPDATE SET sent_at = NOW()", 
                        [notificationId]
                    );
                    logger.success(`Notificación de proveedor enviada para la cuenta ${account.id}`);
                }
            }

            // Verificar alarmas de clientes
            const profiles = typeof account.profiles === 'string' ? JSON.parse(account.profiles) : account.profiles || [];
            for (const [index, profile] of profiles.entries()) {
                if (profile.estado === 'vendido') {
                    const clientDays = calcularDiasRestantesPerfil(profile.fechaVencimiento);
                    if (clientDays > 0 && clientDays <= settings.client_threshold_days) {
                        const notificationId = `client-${account.id}-${index}`;
                        const checkRes = await pool.query(
                            "SELECT 1 FROM sent_notifications WHERE item_id = $1 AND sent_at > NOW() - INTERVAL '24 hours'", 
                            [notificationId]
                        );

                        if (checkRes.rows.length === 0) {
                           const message = `🔔 El perfil "${profile.name}" del cliente ${profile.clienteNombre} (${account.type}) vence en ${clientDays} día(s).`;
                           await fetch(`https://ntfy.sh/${settings.ntfy_topic}`, {
                                method: 'POST',
                                body: message,
                                headers: { 
                                    'Title': 'Alarma de Cliente', 
                                    'Priority': 'default', 
                                    'Tags': 'bell' 
                                }
                           });
                           await pool.query(
                                "INSERT INTO sent_notifications (item_id, item_type, sent_at) VALUES ($1, 'client', NOW()) ON CONFLICT (item_id, item_type) DO UPDATE SET sent_at = NOW()", 
                                [notificationId]
                            );
                           logger.success(`Notificación de cliente enviada para el perfil ${account.id}-${index}`);
                        }
                    }
                }
            }
        }
    } catch (error) {
        logger.error('Error durante la revisión de alarmas:', error);
    }
}

// ===============================================
// MIDDLEWARE DE VALIDACIÓN
// ===============================================
const validateAccount = [
    body('client_name').trim().isLength({ min: 2, max: 100 }).withMessage('Nombre debe tener entre 2 y 100 caracteres'),
    body('email').isEmail().normalizeEmail().withMessage('Email inválido'),
    body('password').isLength({ min: 6, max: 50 }).withMessage('Contraseña debe tener entre 6 y 50 caracteres'),
    body('client_phone').optional().isMobilePhone().withMessage('Teléfono inválido'),
    body('type').notEmpty().withMessage('Tipo de servicio requerido'),
    body('country').isLength({ min: 2, max: 2 }).withMessage('Código de país inválido')
];

const validateLogin = [
    body('username').trim().isLength({ min: 3, max: 50 }).withMessage('Usuario debe tener entre 3 y 50 caracteres'),
    body('password').isLength({ min: 6 }).withMessage('Contraseña debe tener al menos 6 caracteres')
];

// Middleware para manejar errores de validación
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Datos inválidos',
            errors: errors.array()
        });
    }
    next();
};

// ===============================================
// RUTAS API CON SEGURIDAD MEJORADA
// ===============================================
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '2.1.0'
    });
});

app.post('/api/login', validateLogin, handleValidationErrors, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Verificar si el usuario existe
        const result = await pool.query(
            'SELECT * FROM admin_users WHERE username = $1', 
            [username]
        );
        
        if (result.rows.length === 0) {
            logger.warn(`Intento de login fallido para usuario inexistente: ${username}`);
            return res.status(401).json({ 
                success: false, 
                message: 'Credenciales inválidas' 
            });
        }
        
        const user = result.rows[0];
        
        // Verificar si la cuenta está bloqueada
        if (user.locked_until && new Date() < new Date(user.locked_until)) {
            return res.status(423).json({ 
                success: false, 
                message: 'Cuenta temporalmente bloqueada por intentos fallidos' 
            });
        }
        
        // Verificar contraseña
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (isValidPassword) {
            // Login exitoso - resetear intentos fallidos y actualizar último login
            await pool.query(
                'UPDATE admin_users SET failed_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1', 
                [user.id]
            );
            
            logger.success(`Login exitoso para usuario: ${username}`);
            res.json({ success: true, message: 'Login exitoso' });
        } else {
            // Login fallido - incrementar intentos fallidos
            const failedAttempts = (user.failed_attempts || 0) + 1;
            let lockedUntil = null;
            
            // Bloquear después de 5 intentos fallidos por 15 minutos
            if (failedAttempts >= 5) {
                lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos
            }
            
            await pool.query(
                'UPDATE admin_users SET failed_attempts = $1, locked_until = $2 WHERE id = $3',
                [failedAttempts, lockedUntil, user.id]
            );
            
            logger.warn(`Login fallido para usuario: ${username} (${failedAttempts} intentos)`);
            res.status(401).json({ 
                success: false, 
                message: 'Credenciales inválidas' 
            });
        }
    } catch (error) {
        logger.error('Error en login:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error interno del servidor' 
        });
    }
});

app.get('/api/accounts', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM accounts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        logger.error('Error obteniendo cuentas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/alarms/settings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM alarm_settings WHERE id = 1');
        res.json(result.rows[0] || { provider_threshold_days: 5, client_threshold_days: 3, ntfy_topic: '' });
    } catch (error) {
        logger.error('Error obteniendo configuración de alarmas:', error);
        res.status(500).json({ error: 'Error obteniendo configuración de alarmas' });
    }
});

app.put('/api/alarms/settings', [
    body('provider_threshold_days').isInt({ min: 1, max: 30 }).withMessage('Umbral de proveedor debe ser entre 1 y 30 días'),
    body('client_threshold_days').isInt({ min: 1, max: 30 }).withMessage('Umbral de cliente debe ser entre 1 y 30 días'),
    body('ntfy_topic').optional().trim().isLength({ min: 3, max: 100 }).withMessage('Tema ntfy debe tener entre 3 y 100 caracteres')
], handleValidationErrors, async (req, res) => {
    try {
        const { provider_threshold_days, client_threshold_days, ntfy_topic } = req.body;
        const result = await pool.query(
            'UPDATE alarm_settings SET provider_threshold_days = $1, client_threshold_days = $2, ntfy_topic = $3 WHERE id = 1 RETURNING *',
            [provider_threshold_days, client_threshold_days, ntfy_topic]
        );
        
        logger.success('Configuración de alarmas actualizada');
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error actualizando configuración de alarmas:', error);
        res.status(500).json({ error: 'Error actualizando configuración de alarmas' });
    }
});

app.post('/api/alarms/test', async (req, res) => {
    logger.info('Disparando prueba de alarmas manualmente...');
    try {
        await checkAndSendAlarms();
        res.json({ success: true, message: 'Prueba de alarmas iniciada. Revisa tu celular en unos momentos.' });
    } catch (error) {
        logger.error('Error en la prueba manual de alarmas:', error);
        res.status(500).json({ success: false, message: 'Error al iniciar la prueba de alarmas.' });
    }
});

// RUTA API PARA CONSULTAR MICUENTA.ME con validación mejorada
app.post('/api/check-micuenta-me-code', [
    body('code').trim().notEmpty().withMessage('Código es requerido'),
    body('pdv').trim().notEmpty().withMessage('PDV es requerido')
], handleValidationErrors, async (req, res) => {
    try {
        const { code, pdv } = req.body;

        const response = await fetch('https://micuenta.me/e/redeem', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'JIREH-Streaming-Manager/2.1.0'
            },
            body: JSON.stringify({ code: code, pdv: pdv }),
            timeout: 10000 // 10 segundos de timeout
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ 
                message: 'Error desconocido del proxy de micuenta.me.' 
            }));
            logger.warn(`Error al consultar micuenta.me: ${response.status} - ${errorData.message}`);
            return res.status(response.status).json(errorData);
        }

        const data = await response.json();
        logger.success(`Código consultado exitosamente: ${code}`);
        res.json(data);

    } catch (error) {
        logger.error('Error en la ruta /api/check-micuenta-me-code:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error interno del servidor al procesar la solicitud externa a micuenta.me.' 
        });
    }
});

// ===============================================
// MIDDLEWARE DE MANEJO DE ERRORES GLOBAL
// ===============================================
const errorHandler = (err, req, res, next) => {
    logger.error('Error no manejado:', err);
    
    // Error de multer (archivo muy grande, etc.)
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ 
                error: 'Archivo demasiado grande. Máximo 5MB permitido.' 
            });
        }
        if (err.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).json({ 
                error: 'Demasiados archivos. Solo 1 archivo permitido.' 
            });
        }
        return res.status(400).json({ 
            error: 'Error en la subida de archivo: ' + err.message 
        });
    }
    
    // Error de validación de archivos
    if (err.message === 'Tipo de archivo no permitido. Solo imágenes.') {
        return res.status(400).json({ 
            error: 'Tipo de archivo no permitido. Solo se permiten imágenes (JPEG, PNG, GIF, WebP).' 
        });
    }
    
    // Error de JSON malformado
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ 
            error: 'JSON malformado en la solicitud.' 
        });
    }
    
    // Error de tamaño de payload
    if (err.type === 'entity.too.large') {
        return res.status(413).json({ 
            error: 'Payload demasiado grande.' 
        });
    }
    
    // Error de base de datos
    if (err.code && err.code.startsWith('23')) { // PostgreSQL constraint errors
        return res.status(409).json({ 
            error: 'Conflicto en la base de datos. Posible duplicado.' 
        });
    }
    
    // Error genérico
    res.status(500).json({ 
        error: 'Error interno del servidor',
        ...(process.env.NODE_ENV === 'development' && { 
            details: err.message,
            stack: err.stack 
        })
    });
};

app.use(errorHandler);

// ===============================================
// SERVIR ARCHIVOS ESTÁTICOS
// ===============================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// Manejar todas las rutas no encontradas
app.get('*', (req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===============================================
// INICIAR SERVIDOR
// ===============================================
async function startServer() {
    try {
        logger.info('Iniciando JIREH Streaming Manager v2.1.0...');
        
        // Verificar conexión a base de datos
        await pool.query('SELECT 1');
        logger.success('Conexión a PostgreSQL establecida');
        
        // Inicializar base de datos
        await initDB();
        
        // Iniciar servidor
        const server = app.listen(PORT, () => {
            logger.success(`Servidor corriendo en puerto ${PORT}`);
            logger.info(`Entorno: ${process.env.NODE_ENV || 'development'}`);
            logger.info('URL local: http://localhost:' + PORT);
        });
        
        // Configurar timeout del servidor
        server.timeout = 30000; // 30 segundos
        
        // Iniciar sistema de alarmas
        setInterval(checkAndSendAlarms, 3600000); // Cada hora
        logger.success('Sistema de revisión de alarmas por ntfy iniciado (cada hora)');
        
        // Ejecutar primera verificación de alarmas después de 1 minuto
        setTimeout(checkAndSendAlarms, 60000);
        
        // Graceful shutdown
        const gracefulShutdown = (signal) => {
            logger.info(`Señal ${signal} recibida. Cerrando servidor gracefully...`);
            server.close(async () => {
                logger.info('Servidor HTTP cerrado');
                try {
                    await pool.end();
                    logger.info('Conexiones de base de datos cerradas');
                    process.exit(0);
                } catch (error) {
                    logger.error('Error cerrando conexiones:', error);
                    process.exit(1);
                }
            });
        };
        
        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));
        
    } catch (error) {
        logger.error('Error crítico iniciando servidor:', error);
        process.exit(1);
    }
}

// ===============================================
// MANEJO DE ERRORES NO CAPTURADOS
// ===============================================
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
});

// ===============================================
// INICIAR APLICACIÓN
// ===============================================
startServer();

app.post('/api/accounts', validateAccount, handleValidationErrors, async (req, res) => {
    try {
        const { id, client_name, client_phone, email, password, type, country, profiles, fecha_inicio_proveedor } = req.body;
        
        const fechaInicio = fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : new Date();
        const fechaVencimientoProveedor = new Date(fechaInicio);
        fechaVencimientoProveedor.setDate(fechaVencimientoProveedor.getDate() + 30);
        
        const diasRestantesProveedor = calcularDiasRestantes(fechaVencimientoProveedor);
        const estadoProveedor = actualizarEstado(diasRestantesProveedor);
        
        const result = await pool.query(
            `INSERT INTO accounts (id, client_name, client_phone, email, password, type, country, profiles, days_remaining, status, fecha_inicio_proveedor, fecha_vencimiento_proveedor, estado_pago, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()) RETURNING *`,
            [id, client_name, client_phone || '', email, password, type, country, JSON.stringify(profiles), diasRestantesProveedor, estadoProveedor, fechaInicio, fechaVencimientoProveedor, 'activo']
        );
        
        logger.success(`Cuenta creada: ${id} para ${client_name}`);
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.put('/api/accounts/:id', validateAccount, handleValidationErrors, async (req, res) => {
    try {
        const { id } = req.params;
        const { client_name, client_phone, email, password, type, country, profiles, fecha_inicio_proveedor } = req.body;
        
        const fechaInicio = fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : new Date();
        const fechaVencimientoProveedor = new Date(fechaInicio);
        fechaVencimientoProveedor.setDate(fechaVencimientoProveedor.getDate() + 30);
        
        const diasRestantesProveedor = calcularDiasRestantes(fechaVencimientoProveedor);
        const estadoProveedor = actualizarEstado(diasRestantesProveedor);
        const profilesActualizados = procesarPerfiles(profiles);
        
        const result = await pool.query(
            `UPDATE accounts SET client_name = $1, client_phone = $2, email = $3, password = $4, type = $5, country = $6, profiles = $7, days_remaining = $8, status = $9, fecha_inicio_proveedor = $10, fecha_vencimiento_proveedor = $11
             WHERE id = $12 RETURNING *`,
            [client_name, client_phone || '', email, password, type, country, JSON.stringify(profilesActualizados), diasRestantesProveedor, estadoProveedor, fechaInicio, fechaVencimientoProveedor, id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        logger.success(`Cuenta actualizada: ${id}`);
        res.json(result.rows[0]);
    } catch (error) {
        logger.error('Error actualizando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.post('/api/accounts/:accountId/profile/:profileIndex/voucher', upload.single('voucher'), async (req, res) => {
    try {
        const { accountId, profileIndex } = req.params;
        const { numero_operacion, monto_pagado } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ error: 'No se subió ningún archivo' });
        }
        
        // Validar datos del voucher
        if (!numero_operacion || !monto_pagado) {
            return res.status(400).json({ error: 'Número de operación y monto son requeridos' });
        }
        
        const accountResult = await pool.query('SELECT * FROM accounts WHERE id = $1', [accountId]);
        if (accountResult.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        const account = accountResult.rows[0];
        const profiles = typeof account.profiles === 'string' ? JSON.parse(account.profiles) : account.profiles || [];
        const profileIdx = parseInt(profileIndex);
        
        if (profileIdx < 0 || profileIdx >= profiles.length) {
            return res.status(400).json({ error: 'Índice de perfil inválido' });
        }
        
        const profile = profiles[profileIdx];
        const voucherBase64 = req.file.buffer.toString('base64');
        
        // Actualizar perfil con voucher
        profile.voucherImagen = voucherBase64;
        profile.numeroOperacion = numero_operacion;
        profile.montoPagado = parseFloat(monto_pagado);
        profile.voucherSubido = true;
        profile.fechaVoucher = new Date().toISOString();
        
        if (profile.estado === 'vendido') {
            const fechaVencimientoActual = new Date(profile.fechaVencimiento);
            const nuevaFechaVencimiento = new Date(fechaVencimientoActual);
            nuevaFechaVencimiento.setDate(nuevaFechaVencimiento.getDate() + 30);
            
            profile.fechaVencimiento = nuevaFechaVencimiento.toISOString().split('T')[0];
            
            const fechaProximoPago = new Date(nuevaFechaVencimiento);
            fechaProximoPago.setDate(fechaProximoPago.getDate() - 1);
            profile.fechaProximoPago = fechaProximoPago.toISOString().split('T')[0];
            profile.fechaCorte = nuevaFechaVencimiento.toISOString().split('T')[0];
            profile.diasRestantes = calcularDiasRestantesPerfil(profile.fechaVencimiento);
            profile.estadoPago = 'pagado';
            profile.fechaUltimaRenovacion = new Date().toISOString().split('T')[0];
        } else {
            profile.estadoPago = 'confirmado';
        }
        
        await pool.query('UPDATE accounts SET profiles = $1 WHERE id = $2', [JSON.stringify(profiles), accountId]);
        
        logger.success(`Voucher procesado para cuenta ${accountId}, perfil ${profileIndex}`);
        res.json({ success: true, message: 'Voucher procesado', profile: profile });
    } catch (error) {
        logger.error('Error procesando voucher:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.delete('/api/accounts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM accounts WHERE id = $1 RETURNING *', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        logger.success(`Cuenta eliminada: ${id}`);
        res.json({ message: 'Cuenta eliminada exitosamente' });
    } catch (error) {
        logger.error('Error eliminando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const totalResult = await pool.query('SELECT COUNT(*) FROM accounts');
        const accountsResult = await pool.query('SELECT fecha_vencimiento_proveedor, profiles FROM accounts');
        
        let activeCount = 0, expiringCount = 0, totalProfiles = 0, soldProfiles = 0;
        const today = new Date();
        
        accountsResult.rows.forEach(row => {
            const profiles = typeof row.profiles === 'string' ? JSON.parse(row.profiles) : row.profiles || [];
            totalProfiles += profiles.length;
            soldProfiles += profiles.filter(p => p.estado === 'vendido').length;
            
            if (row.fecha_vencimiento_proveedor) {
                const vencimiento = new Date(row.fecha_vencimiento_proveedor);
                const diffDays = Math.ceil((vencimiento - today) / (1000 * 60 * 60 * 24));
                if (diffDays > 5) activeCount++;
                else if (diffDays > 0) expiringCount++;
            }
        });
        
        res.json({
            total: parseInt(totalResult.rows[0].count),
            active: activeCount,
            profiles: totalProfiles,
            expiring: expiringCount,
            sold_profiles: soldProfiles
        });
    } catch (error) {
        logger.error('Error obteniendo estadísticas:', error);
