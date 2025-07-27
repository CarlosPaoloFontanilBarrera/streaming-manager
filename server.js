// server.js - JIREH Streaming Manager con Seguridad Mejorada
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult, param } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// Variables de entorno para seguridad
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'paolof';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'elpoderosodeizrael777xD!';

// Middleware de seguridad
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://ntfy.sh", "https://micuenta.me"]
        }
    }
}));

// Rate limiting
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas solicitudes desde esta IP, intenta nuevamente en 15 minutos.' }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Demasiados intentos de login, intenta nuevamente en 15 minutos.' }
});

app.use(generalLimiter);

// CORS configurado
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://streaming-manager-production.up.railway.app']
        : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Configuración de multer para subida de archivos
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { 
        fileSize: 5 * 1024 * 1024,
        files: 1
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de archivo no permitido. Solo se permiten imágenes.'));
        }
    }
});

// Store para sesiones simples (en memoria)
const activeSessions = new Map();

// Función para logging de seguridad
function logSecurityEvent(event, ip, details = '') {
    console.log(`🔒 [SECURITY] ${new Date().toISOString()} - ${event} - IP: ${ip} - ${details}`);
}

// Middleware de autenticación simple
function authenticateSession(req, res, next) {
    const sessionId = req.headers['x-session-id'];
    
    if (!sessionId || !activeSessions.has(sessionId)) {
        logSecurityEvent('UNAUTHORIZED_ACCESS_ATTEMPT', req.ip, 'No session or invalid session');
        return res.status(401).json({ error: 'Sesión requerida o inválida' });
    }

    const session = activeSessions.get(sessionId);
    if (session.expiresAt < Date.now()) {
        activeSessions.delete(sessionId);
        logSecurityEvent('SESSION_EXPIRED', req.ip, sessionId);
        return res.status(401).json({ error: 'Sesión expirada' });
    }

    req.user = session.user;
    next();
}

// Validadores de entrada
const validateAccountData = [
    body('id').notEmpty().trim().isLength({ min: 1, max: 100 }).escape(),
    body('client_name').notEmpty().trim().isLength({ min: 1, max: 200 }).escape(),
    body('client_phone').optional().trim().isLength({ max: 20 }).escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6, max: 100 }),
    body('type').notEmpty().trim().isIn(['Netflix', 'Disney+', 'HBO Max', 'Amazon Prime', 'Spotify', 'YouTube Premium']),
    body('country').optional().isLength({ max: 5 }).trim().escape()
];

const validateLoginData = [
    body('username').notEmpty().trim().isLength({ min: 1, max: 50 }).escape(),
    body('password').notEmpty().isLength({ min: 1, max: 100 })
];

// Función para calcular días restantes
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

// Crear tabla si no existe
async function initDB() {
    try {
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
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS alarm_settings (
                id SERIAL PRIMARY KEY,
                provider_threshold_days INTEGER NOT NULL DEFAULT 5,
                client_threshold_days INTEGER NOT NULL DEFAULT 3,
                ntfy_topic TEXT
            )
        `);

        const settings = await pool.query('SELECT * FROM alarm_settings');
        if (settings.rows.length === 0) {
            await pool.query('INSERT INTO alarm_settings (provider_threshold_days, client_threshold_days) VALUES (5, 3)');
        } else {
            const columns = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='alarm_settings' AND column_name='ntfy_topic'");
            if (columns.rows.length === 0) {
                await pool.query("ALTER TABLE alarm_settings ADD COLUMN ntfy_topic TEXT");
            }
        }
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS sent_notifications (
                id SERIAL PRIMARY KEY, 
                item_id TEXT NOT NULL, 
                item_type TEXT NOT NULL, 
                sent_at TIMESTAMP NOT NULL, 
                UNIQUE(item_id, item_type)
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY, 
                username TEXT UNIQUE NOT NULL, 
                password_hash TEXT NOT NULL, 
                created_at TIMESTAMP DEFAULT NOW(),
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        `);
        
        // Crear usuario admin con contraseña hasheada
        const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, BCRYPT_ROUNDS);
        await pool.query(
            `INSERT INTO admin_users (username, password_hash) 
             VALUES ($1, $2) 
             ON CONFLICT (username) DO UPDATE SET password_hash = $2`,
            [ADMIN_USERNAME, hashedPassword]
        );
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS security_logs (
                id SERIAL PRIMARY KEY,
                event_type TEXT NOT NULL,
                ip_address INET,
                user_agent TEXT,
                details JSONB,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        
        console.log('✅ Base de datos inicializada correctamente con mejoras de seguridad');
    } catch (error) {
        console.error('❌ Error inicializando base de datos:', error);
    }
}

// Lógica de envío de alarmas por NTFY
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
                const checkRes = await pool.query("SELECT 1 FROM sent_notifications WHERE item_id = $1 AND sent_at > NOW() - INTERVAL '24 hours'", [notificationId]);
                
                if (checkRes.rows.length === 0) {
                    const message = `🚨 La cuenta de ${account.type} de "${account.client_name}" vence en ${providerDays} día(s).`;
                    await fetch(`https://ntfy.sh/${settings.ntfy_topic}`, {
                        method: 'POST',
                        body: message,
                        headers: { 'Title': 'Alarma de Proveedor', 'Priority': 'high', 'Tags': 'rotating_light' }
                    });
                    await pool.query("INSERT INTO sent_notifications (item_id, item_type, sent_at) VALUES ($1, 'provider', NOW()) ON CONFLICT (item_id, item_type) DO UPDATE SET sent_at = NOW()", [notificationId]);
                    console.log(`📲 Notificación de proveedor enviada para la cuenta ${account.id}`);
                }
            }

            const profiles = typeof account.profiles === 'string' ? JSON.parse(account.profiles) : account.profiles || [];
            for (const [index, profile] of profiles.entries()) {
                if (profile.estado === 'vendido') {
                    const clientDays = calcularDiasRestantesPerfil(profile.fechaVencimiento);
                    if (clientDays > 0 && clientDays <= settings.client_threshold_days) {
                        const notificationId = `client-${account.id}-${index}`;
                        const checkRes = await pool.query("SELECT 1 FROM sent_notifications WHERE item_id = $1 AND sent_at > NOW() - INTERVAL '24 hours'", [notificationId]);

                        if (checkRes.rows.length === 0) {
                           const message = `🔔 El perfil "${profile.name}" del cliente ${profile.clienteNombre} (${account.type}) vence en ${clientDays} día(s).`;
                           await fetch(`https://ntfy.sh/${settings.ntfy_topic}`, {
                                method: 'POST',
                                body: message,
                                headers: { 'Title': 'Alarma de Cliente', 'Priority': 'default', 'Tags': 'bell' }
                           });
                           await pool.query("INSERT INTO sent_notifications (item_id, item_type, sent_at) VALUES ($1, 'client', NOW()) ON CONFLICT (item_id, item_type) DO UPDATE SET sent_at = NOW()", [notificationId]);
                           console.log(`📲 Notificación de cliente enviada para el perfil ${account.id}-${index}`);
                        }
                    }
                }
            }
        }
    } catch (error) {
        console.error('❌ Error durante la revisión de alarmas:', error);
    }
}

// RUTAS API

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Login con seguridad mejorada
app.post('/api/login', authLimiter, validateLoginData, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logSecurityEvent('VALIDATION_ERROR', req.ip, 'Login validation failed');
            return res.status(400).json({ success: false, message: 'Datos de entrada inválidos' });
        }

        const { username, password } = req.body;
        
        const result = await pool.query(
            'SELECT id, username, password_hash, failed_attempts, locked_until FROM admin_users WHERE username = $1', 
            [username]
        );
        
        if (result.rows.length === 0) {
            logSecurityEvent('LOGIN_FAILED', req.ip, `Usuario inexistente: ${username}`);
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const user = result.rows[0];
        
        // Verificar si la cuenta está bloqueada
        if (user.locked_until && new Date() < new Date(user.locked_until)) {
            logSecurityEvent('LOGIN_BLOCKED', req.ip, `Usuario bloqueado: ${username}`);
            return res.status(423).json({ success: false, message: 'Cuenta temporalmente bloqueada por intentos fallidos' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!isValidPassword) {
            const newFailedAttempts = (user.failed_attempts || 0) + 1;
            let lockedUntil = null;
            
            if (newFailedAttempts >= 5) {
                lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
            }
            
            await pool.query(
                'UPDATE admin_users SET failed_attempts = $1, locked_until = $2 WHERE id = $3',
                [newFailedAttempts, lockedUntil, user.id]
            );
            
            logSecurityEvent('LOGIN_FAILED', req.ip, `Contraseña incorrecta para: ${username}, intentos: ${newFailedAttempts}`);
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        // Login exitoso
        await pool.query(
            'UPDATE admin_users SET failed_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1',
            [user.id]
        );

        // Crear sesión simple
        const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const expiresAt = Date.now() + (24 * 60 * 60 * 1000);
        
        activeSessions.set(sessionId, {
            user: { id: user.id, username: user.username },
            expiresAt: expiresAt
        });

        logSecurityEvent('LOGIN_SUCCESS', req.ip, `Usuario: ${username}`);
        
        res.json({ 
            success: true, 
            message: 'Login exitoso',
            sessionId: sessionId,
            expiresIn: '24h'
        });
    } catch (error) {
        console.error('Error en login:', error);
        logSecurityEvent('LOGIN_ERROR', req.ip, error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// Rutas protegidas
app.use('/api/accounts', authenticateSession);
app.use('/api/stats', authenticateSession);
app.use('/api/alarms', authenticateSession);
app.use('/api/check-micuenta-me-code', authenticateSession);

// Obtener cuentas
app.get('/api/accounts', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM accounts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error obteniendo cuentas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Crear cuenta
app.post('/api/accounts', validateAccountData, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Datos de entrada inválidos', details: errors.array() });
        }

        const { id, client_name, client_phone, email, password, type, country, profiles, fecha_inicio_proveedor } = req.body;
        
        const existingAccount = await pool.query('SELECT id FROM accounts WHERE id = $1', [id]);
        if (existingAccount.rows.length > 0) {
            return res.status(409).json({ error: 'Ya existe una cuenta con este ID' });
        }

        const fechaInicio = fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : new Date();
        const fechaVencimientoProveedor = new Date(fechaInicio);
        fechaVencimientoProveedor.setDate(fechaVencimientoProveedor.getDate() + 30);
        const diasRestantesProveedor = calcularDiasRestantes(fechaVencimientoProveedor);
        const estadoProveedor = actualizarEstado(diasRestantesProveedor);
        
        const result = await pool.query(
            `INSERT INTO accounts (id, client_name, client_phone, email, password, type, country, profiles, days_remaining, status, fecha_inicio_proveedor, fecha_vencimiento_proveedor, estado_pago, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW()) RETURNING *`,
            [id, client_name, client_phone || '', email, password, type, country, JSON.stringify(profiles), diasRestantesProveedor, estadoProveedor, fechaInicio, fechaVencimientoProveedor, 'activo']
        );
        
        logSecurityEvent('ACCOUNT_CREATED', req.ip, `Cuenta creada: ${id} por usuario: ${req.user.username}`);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Actualizar cuenta
app.put('/api/accounts/:id', param('id').notEmpty().trim().escape(), validateAccountData, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Datos de entrada inválidos', details: errors.array() });
        }

        const { id } = req.params;
        const { client_name, client_phone, email, password, type, country, profiles, fecha_inicio_proveedor } = req.body;
        
        const fechaInicio = fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : new Date();
        const fechaVencimientoProveedor = new Date(fechaInicio);
        fechaVencimientoProveedor.setDate(fechaVencimientoProveedor.getDate() + 30);
        const diasRestantesProveedor = calcularDiasRestantes(fechaVencimientoProveedor);
        const estadoProveedor = actualizarEstado(diasRestantesProveedor);
        const profilesActualizados = procesarPerfiles(profiles);
        
        const result = await pool.query(
            `UPDATE accounts SET client_name = $1, client_phone = $2, email = $3, password = $4, type = $5, country = $6, profiles = $7, days_remaining = $8, status = $9, fecha_inicio_proveedor = $10, fecha_vencimiento_proveedor = $11, updated_at = NOW()
             WHERE id = $12 RETURNING *`,
            [client_name, client_phone || '', email, password, type, country, JSON.stringify(profilesActualizados), diasRestantesProveedor, estadoProveedor, fechaInicio, fechaVencimientoProveedor, id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        logSecurityEvent('ACCOUNT_UPDATED', req.ip, `Cuenta actualizada: ${id} por usuario: ${req.user.username}`);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error actualizando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Subir voucher
app.post('/api/accounts/:accountId/profile/:profileIndex/voucher', 
    param('accountId').notEmpty().trim().escape(),
    param('profileIndex').isInt({ min: 0 }),
    upload.single('voucher'), 
    async (req, res) => {
    try {
        const { accountId, profileIndex } = req.params;
        const { numero_operacion, monto_pagado } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ error: 'No se subió ningún archivo' });
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
        
        await pool.query('UPDATE accounts SET profiles = $1, updated_at = NOW() WHERE id = $2', [JSON.stringify(profiles), accountId]);
        
        logSecurityEvent('VOUCHER_UPLOADED', req.ip, `Voucher subido para cuenta: ${accountId}, perfil: ${profileIndex} por usuario: ${req.user.username}`);
        res.json({ success: true, message: 'Voucher procesado', profile: profile });
    } catch (error) {
        console.error('Error procesando voucher:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Eliminar cuenta
app.delete('/api/accounts/:id', param('id').notEmpty().trim().escape(), async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM accounts WHERE id = $1 RETURNING *', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        logSecurityEvent('ACCOUNT_DELETED', req.ip, `Cuenta eliminada: ${id} por usuario: ${req.user.username}`);
        res.json({ message: 'Cuenta eliminada exitosamente' });
    } catch (error) {
        console.error('Error eliminando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Estadísticas
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
        console.error('Error obteniendo estadísticas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Configuración de alarmas
app.get('/api/alarms/settings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM alarm_settings WHERE id = 1');
        res.json(result.rows[0] || { provider_threshold_days: 5, client_threshold_days: 3, ntfy_topic: '' });
    } catch (error) {
        console.error('Error obteniendo configuración de alarmas:', error);
        res.status(500).json({ error: 'Error obteniendo configuración de alarmas' });
    }
});

app.put('/api/alarms/settings', [
    body('provider_threshold_days').isInt({ min: 1, max: 30 }),
    body('client_threshold_days').isInt({ min: 1, max: 30 }),
    body('ntfy_topic').optional().trim().isLength({ max: 100 }).escape()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Datos de entrada inválidos', details: errors.array() });
        }

        const { provider_threshold_days, client_threshold_days, ntfy_topic } = req.body;
        const result = await pool.query(
            'UPDATE alarm_settings SET provider_threshold_days = $1, client_threshold_days = $2, ntfy_topic = $3 WHERE id = 1 RETURNING *',
            [provider_threshold_days, client_threshold_days, ntfy_topic]
        );
        
        logSecurityEvent('ALARM_SETTINGS_UPDATED', req.ip, `Por usuario: ${req.user.username}`);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error actualizando configuración de alarmas:', error);
        res.status(500).json({ error: 'Error actualizando configuración de alarmas' });
    }
});

// Prueba de alarmas
app.post('/api/alarms/test', async (req, res) => {
    console.log('⚡️ Disparando prueba de alarmas manualmente...');
    try {
        await checkAndSendAlarms();
        logSecurityEvent('ALARM_TEST_TRIGGERED', req.ip, `Por usuario: ${req.user.username}`);
        res.json({ success: true, message: 'Prueba de alarmas iniciada. Revisa tu celular en unos momentos.' });
    } catch (error) {
        console.error('❌ Error en la prueba manual de alarmas:', error);
        res.status(500).json({ success: false, message: 'Error al iniciar la prueba de alarmas.' });
    }
});

// Consulta a micuenta.me
app.post('/api/check-micuenta-me-code', [
    body('code').notEmpty().trim().isLength({ min: 1, max: 50 }).escape(),
    body('pdv').optional().trim().isLength({ max: 50 }).escape()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Datos de entrada inválidos', details: errors.array() });
        }

        const { code, pdv } = req.body;

        const response = await fetch('https://micuenta.me/e/redeem', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'JIREH-Streaming-Manager/2.1.0'
            },
            body: JSON.stringify({ code: code, pdv: pdv }),
            timeout: 10000
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: 'Error desconocido del proxy de micuenta.me.' }));
            console.error('Error al consultar micuenta.me:', response.status, errorData.message);
            return res.status(response.status).json(errorData);
        }

        const data = await response.json();
        
        logSecurityEvent('MICUENTA_QUERY', req.ip, `Código consultado por usuario: ${req.user.username}`);
        res.json(data);

    } catch (error) {
        console.error('Error en la ruta /api/check-micuenta-me-code:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor al procesar la solicitud externa a micuenta.me.' });
    }
});

// Middleware para manejo de errores
app.use((error, req, res, next) => {
    console.error('Error no manejado:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'Archivo demasiado grande. Máximo 5MB.' });
        }
        return res.status(400).json({ error: 'Error en la subida del archivo.' });
    }
    
    res.status(500).json({ error: 'Error interno del servidor' });
});

// Servir archivos estáticos
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Función para logging de eventos de seguridad en base de datos
async function logSecurityEventToDB(eventType, ipAddress, userAgent, details) {
    try {
        await pool.query(
            'INSERT INTO security_logs (event_type, ip_address, user_agent, details) VALUES ($1, $2, $3, $4)',
            [eventType, ipAddress, userAgent, JSON.stringify(details)]
        );
    } catch (error) {
        console.error('Error guardando log de seguridad:', error);
    }
}

// Iniciar servidor
async function startServer() {
    try {
        await initDB();
        
        // Configurar logging mejorado
        app.use((req, res, next) => {
            req.startTime = Date.now();
            next();
        });

        app.use((req, res, next) => {
            res.on('finish', () => {
                const duration = Date.now() - req.startTime;
                console.log(`${req.method} ${req.path} - ${res.statusCode} - ${duration}ms - IP: ${req.ip}`);
                
                // Log eventos sospechosos
                if (res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 429) {
                    logSecurityEventToDB(
                        'SUSPICIOUS_REQUEST',
                        req.ip,
                        req.get('User-Agent'),
                        { method: req.method, path: req.path, statusCode: res.statusCode }
                    );
                }
            });
            next();
        });

        app.listen(PORT, () => {
            console.log(`🚀 JIREH Streaming Manager SEGURO corriendo en puerto ${PORT}`);
            console.log(`🔒 Seguridad mejorada: Rate Limiting, Bcrypt, Helmet, Validación activados`);
            
            // Iniciar sistema de alarmas
            setInterval(checkAndSendAlarms, 3600000);
            console.log('⏰ Sistema de revisión de alarmas por ntfy iniciado.');
            
            // Log del inicio del servidor
            logSecurityEventToDB('SERVER_STARTED', '127.0.0.1', 'System', { port: PORT });
        });
    } catch (error) {
        console.error('❌ Error iniciando servidor:', error);
    }
}

// Manejo mejorado de errores del proceso
process.on('unhandledRejection', (err) => {
    console.error('Unhandled rejection:', err);
    logSecurityEventToDB('UNHANDLED_REJECTION', '127.0.0.1', 'System', { error: err.message });
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
    logSecurityEventToDB('UNCAUGHT_EXCEPTION', '127.0.0.1', 'System', { error: err.message });
    process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM recibido, cerrando servidor...');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT recibido, cerrando servidor...');
    await pool.end();
    process.exit(0);
});

startServer();
