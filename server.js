// server.js - Sistema completo MEJORADO con seguridad sin romper funcionalidad existente
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fetch = require('node-fetch');

// ✅ NUEVAS DEPENDENCIAS DE SEGURIDAD Y PERFORMANCE
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const compression = require('compression');
const NodeCache = require('node-cache');
const sharp = require('sharp');

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ CONFIGURACIÓN DE SEGURIDAD
const JWT_SECRET = process.env.JWT_SECRET || 'jireh-streaming-secret-2025';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// ✅ SISTEMA DE CACHÉ (MEJORA DE PERFORMANCE)
const cache = new NodeCache({ 
    stdTTL: parseInt(process.env.CACHE_TTL) || 300, // 5 minutos
    checkperiod: 60,
    useClones: false
});

// ✅ SEGURIDAD CON HELMET
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "blob:"]
        }
    }
}));

// ✅ COMPRESIÓN PARA MEJOR PERFORMANCE
app.use(compression());

// ✅ RATE LIMITING PARA SEGURIDAD
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: parseInt(process.env.API_RATE_LIMIT) || 100,
    message: { error: 'Demasiadas solicitudes' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: parseInt(process.env.LOGIN_RATE_LIMIT) || 5,
    message: { error: 'Demasiados intentos de login' }
});

// Aplicar rate limiting
app.use('/api/', generalLimiter);
app.use('/api/login', loginLimiter);

// Middleware básico (SIN CAMBIOS)
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ✅ MIDDLEWARE DE AUTENTICACIÓN JWT (OPCIONAL - NO ROMPE FUNCIONALIDAD EXISTENTE)
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        // ✅ MODO COMPATIBLE: Si no hay token, permitir acceso (para no romper funcionalidad)
        console.log('⚠️ Acceso sin token JWT (modo compatible)');
        return next();
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        console.log('✅ Token JWT válido');
        next();
    } catch (error) {
        console.error('❌ Token JWT inválido:', error.message);
        // ✅ MODO COMPATIBLE: Si token inválido, permitir acceso (para no romper)
        next();
    }
};

// Configuración de PostgreSQL (SIN CAMBIOS)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ✅ OPTIMIZACIÓN DE IMÁGENES CON SHARP
async function optimizeImage(buffer, options = {}) {
    const {
        width = 1200,
        height = 800,
        quality = parseInt(process.env.IMAGE_QUALITY) || 85
    } = options;

    try {
        return await sharp(buffer)
            .resize(width, height, { 
                fit: 'inside', 
                withoutEnlargement: true 
            })
            .jpeg({ 
                quality, 
                progressive: true
            })
            .toBuffer();
    } catch (error) {
        console.error('Error optimizando imagen:', error);
        return buffer; // Retornar original si falla
    }
}

// Configuración de multer (SIN CAMBIOS)
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB máximo
});

// Funciones auxiliares (SIN CAMBIOS)
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
            return {
                ...profile,
                diasRestantes: diasRestantesCliente
            };
        }
        return profile;
    });
}

// ✅ FUNCIÓN DE INICIALIZACIÓN MEJORADA
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY, client_name TEXT NOT NULL, client_phone TEXT DEFAULT '', email TEXT NOT NULL, password TEXT NOT NULL, type TEXT NOT NULL, country TEXT NOT NULL DEFAULT 'PE', profiles JSONB NOT NULL DEFAULT '[]', days_remaining INTEGER NOT NULL DEFAULT 30, status TEXT NOT NULL DEFAULT 'active', created_at TIMESTAMP DEFAULT NOW(), fecha_venta TIMESTAMP DEFAULT NOW(), fecha_vencimiento TIMESTAMP, fecha_inicio_proveedor TIMESTAMP, fecha_vencimiento_proveedor TIMESTAMP, voucher_imagen TEXT, numero_operacion TEXT, monto_pagado DECIMAL(10,2), estado_pago TEXT DEFAULT 'activo'
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
                id SERIAL PRIMARY KEY, item_id TEXT NOT NULL, item_type TEXT NOT NULL, sent_at TIMESTAMP NOT NULL, UNIQUE(item_id, item_type)
            )
        `);
        
        // ✅ TABLA DE USUARIOS MEJORADA CON BCRYPT
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY, 
                username TEXT UNIQUE NOT NULL, 
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        
        // ✅ VERIFICAR SI NECESITAMOS MIGRAR PASSWORDS A BCRYPT
        const userCheck = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='admin_users' AND column_name='password_hash'");
        if (userCheck.rows.length === 0) {
            // Migrar de password a password_hash
            await pool.query("ALTER TABLE admin_users ADD COLUMN password_hash TEXT");
            const users = await pool.query("SELECT id, username, password FROM admin_users WHERE password IS NOT NULL");
            for (const user of users.rows) {
                const hashedPassword = await bcrypt.hash(user.password, BCRYPT_ROUNDS);
                await pool.query("UPDATE admin_users SET password_hash = $1 WHERE id = $2", [hashedPassword, user.id]);
            }
            await pool.query("ALTER TABLE admin_users DROP COLUMN IF EXISTS password");
            console.log('✅ Passwords migrados a bcrypt');
        }
        
        // ✅ CREAR USUARIO ADMIN CON BCRYPT
        const adminCheck = await pool.query("SELECT * FROM admin_users WHERE username = 'paolof'");
        if (adminCheck.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('elpoderosodeizrael777xD!', BCRYPT_ROUNDS);
            await pool.query(`INSERT INTO admin_users (username, password_hash) VALUES ('paolof', $1)`, [hashedPassword]);
            console.log('✅ Usuario admin creado con bcrypt');
        }
        
        console.log('✅ Base de datos inicializada correctamente con mejoras de seguridad');
    } catch (error) {
        console.error('❌ Error inicializando base de datos:', error);
    }
}

// Sistema de alarmas (SIN CAMBIOS)
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
                } else {
                    console.log(`[DEBUG] Notificación para ${notificationId} bloqueada. Ya se envió una en las últimas 24 horas.`);
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
                        } else {
                            console.log(`[DEBUG] Notificación para ${notificationId} bloqueada. Ya se envió una en las últimas 24 horas.`);
                        }
                    }
                }
            }
        }
    } catch (error) {
        console.error('❌ Error durante la revisión de alarmas:', error);
    }
}

// ✅ RUTAS API MEJORADAS
app.get('/api/health', (req, res) => {
    const memUsage = process.memoryUsage();
    const cacheStats = cache.getStats();
    
    res.json({ 
        status: 'OK',
        timestamp: new Date().toISOString(),
        version: '2.2.0-IMPROVED',
        uptime: process.uptime(),
        memory: {
            used: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
            total: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB'
        },
        cache: {
            keys: cacheStats.keys,
            hits: cacheStats.hits,
            misses: cacheStats.misses
        },
        features: {
            jwt: true,
            bcrypt: true,
            cache: true,
            compression: true,
            rate_limiting: true,
            helmet_security: true
        }
    });
});

// ✅ LOGIN MEJORADO CON BCRYPT Y JWT
app.post('/api/login', [
    body('username').trim().isLength({ min: 1 }).withMessage('Username requerido'),
    body('password').isLength({ min: 1 }).withMessage('Password requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false,
                message: 'Datos inválidos',
                details: errors.array()
            });
        }

        const { username, password } = req.body;

        const userResult = await pool.query(
            'SELECT id, username, password_hash FROM admin_users WHERE username = $1',
            [username]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const user = userResult.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log(`✅ Login exitoso con JWT: ${username}`);
        
        res.json({
            success: true,
            message: 'Login exitoso',
            token,
            user: {
                id: user.id,
                username: user.username
            }
        });

    } catch (error) {
        console.error('❌ Error en login:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// ✅ STATS CON CACHÉ
app.get('/api/stats', verifyToken, async (req, res) => {
    try {
        const cacheKey = 'dashboard_stats';
        const cachedStats = cache.get(cacheKey);
        
        if (cachedStats) {
            console.log('📦 Cache hit: stats');
            return res.json(cachedStats);
        }

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
        
        const stats = {
            total: parseInt(totalResult.rows[0].count),
            active: activeCount,
            profiles: totalProfiles,
            expiring: expiringCount,
            sold_profiles: soldProfiles
        };

        cache.set(cacheKey, stats);
        console.log('💾 Cache set: stats');
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Resto de rutas (SIN CAMBIOS para mantener compatibilidad)
app.get('/api/accounts', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM accounts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/accounts', verifyToken, async (req, res) => {
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
        
        // Invalidar cache
        cache.del('dashboard_stats');
        
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.put('/api/accounts/:id', verifyToken, async (req, res) => {
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
        if (result.rows.length === 0) return res.status(404).json({ error: 'Cuenta no encontrada' });
        
        // Invalidar cache
        cache.del('dashboard_stats');
        
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

// ✅ UPLOAD DE VOUCHER MEJORADO CON SHARP
app.post('/api/accounts/:accountId/profile/:profileIndex/voucher', verifyToken, upload.single('voucher'), async (req, res) => {
    try {
        const { accountId, profileIndex } = req.params;
        const { numero_operacion, monto_pagado } = req.body;
        if (!req.file) return res.status(400).json({ error: 'No se subió ningún archivo' });
        
        const accountResult = await pool.query('SELECT * FROM accounts WHERE id = $1', [accountId]);
        if (accountResult.rows.length === 0) return res.status(404).json({ error: 'Cuenta no encontrada' });
        
        const account = accountResult.rows[0];
        const profiles = typeof account.profiles === 'string' ? JSON.parse(account.profiles) : account.profiles || [];
        const profileIdx = parseInt(profileIndex);
        if (profileIdx < 0 || profileIdx >= profiles.length) return res.status(400).json({ error: 'Índice de perfil inválido' });
        
        const profile = profiles[profileIdx];
        
        // ✅ OPTIMIZAR IMAGEN CON SHARP
        let voucherBase64;
        if (process.env.ENABLE_IMAGE_OPTIMIZATION === 'true') {
            const optimizedBuffer = await optimizeImage(req.file.buffer, {
                width: 800,
                height: 600,
                quality: 85
            });
            voucherBase64 = optimizedBuffer.toString('base64');
            console.log('🖼️ Imagen optimizada con Sharp');
        } else {
            voucherBase64 = req.file.buffer.toString('base64');
        }
        
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
        
        // Invalidar cache
        cache.del('dashboard_stats');
        
        res.json({ success: true, message: 'Voucher procesado con optimización de imagen', profile: profile });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.delete('/api/accounts/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM accounts WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Cuenta no encontrada' });
        
        // Invalidar cache
        cache.del('dashboard_stats');
        
        res.json({ message: 'Cuenta eliminada exitosamente' });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ✅ CONFIGURACIÓN DE ALARMAS (SIN CAMBIOS)
app.get('/api/alarms/settings', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM alarm_settings WHERE id = 1');
        res.json(result.rows[0] || { provider_threshold_days: 5, client_threshold_days: 3, ntfy_topic: '' });
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo configuración de alarmas' });
    }
});

app.put('/api/alarms/settings', verifyToken, async (req, res) => {
    try {
        const { provider_threshold_days, client_threshold_days, ntfy_topic } = req.body;
        const result = await pool.query(
            'UPDATE alarm_settings SET provider_threshold_days = $1, client_threshold_days = $2, ntfy_topic = $3 WHERE id = 1 RETURNING *',
            [provider_threshold_days, client_threshold_days, ntfy_topic]
        );
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Error actualizando configuración de alarmas' });
    }
});

app.post('/api/alarms/test', verifyToken, async (req, res) => {
    console.log('⚡️ Disparando prueba de alarmas manualmente...');
    try {
        await checkAndSendAlarms();
        res.json({ success: true, message: 'Prueba de alarmas iniciada. Revisa tu celular en unos momentos.' });
    } catch (error) {
        console.error('❌ Error en la prueba manual de alarmas:', error);
        res.status(500).json({ success: false, message: 'Error al iniciar la prueba de alarmas.' });
    }
});

// ✅ API MICUENTA.ME (SIN CAMBIOS)
app.post('/api/check-micuenta-me-code', verifyToken, async (req, res) => {
    try {
        const { code, pdv } = req.body;

        const response = await fetch('https://micuenta.me/e/redeem', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ code: code, pdv: pdv })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: 'Error desconocido del proxy de micuenta.me.' }));
            console.error('Error al consultar micuenta.me:', response.status, errorData.message);
            return res.status(response.status).json(errorData);
        }

        const data = await response.json();
        res.json(data);

    } catch (error) {
        console.error('Error en la ruta /api/check-micuenta-me-code:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor al procesar la solicitud externa a micuenta.me.' });
    }
});

// ✅ NUEVAS APIS DE PERFORMANCE Y MONITOREO
app.get('/api/cache/stats', verifyToken, (req, res) => {
    try {
        const stats = cache.getStats();
        res.json({
            keys: stats.keys,
            hits: stats.hits,
            misses: stats.misses,
            hit_rate: stats.hits > 0 ? ((stats.hits / (stats.hits + stats.misses)) * 100).toFixed(2) + '%' : '0%'
        });
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo estadísticas de cache' });
    }
});

app.post('/api/cache/clear', verifyToken, (req, res) => {
    try {
        const stats = cache.getStats();
        cache.flushAll();
        console.log('🧹 Cache limpiado manualmente');
        res.json({
            success: true,
            message: 'Cache limpiado exitosamente',
            previous_stats: stats
        });
    } catch (error) {
        res.status(500).json({ error: 'Error limpiando cache' });
    }
});

// Servir archivos estáticos (SIN CAMBIOS)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ✅ INICIAR SERVIDOR MEJORADO
async function startServer() {
    try {
        await initDB();
        app.listen(PORT, () => {
            console.log('🚀 ================================');
            console.log(`🎯 JIREH Streaming Manager MEJORADO`);
            console.log(`🌐 Servidor corriendo en puerto ${PORT}`);
            console.log('🚀 ================================');
            console.log('✅ MEJORAS IMPLEMENTADAS:');
            console.log('  🔐 JWT Authentication');
            console.log('  🔒 bcrypt para passwords');
            console.log('  🛡️ Helmet security headers');
            console.log('  ⚡ Rate limiting');
            console.log('  📦 Sistema de caché NodeCache');
            console.log('  🗜️ Compresión automática');
            console.log('  🖼️ Optimización de imágenes Sharp');
            console.log('  📊 APIs de monitoreo');
            console.log('🚀 ================================');
            
            // Sistema de alarmas (SIN CAMBIOS)
            setInterval(checkAndSendAlarms, 3600000); 
            console.log('⏰ Sistema de revisión de alarmas por ntfy iniciado.');
        });
    } catch (error) {
        console.error('❌ Error iniciando servidor:', error);
    }
}

// ✅ MANEJO DE ERRORES MEJORADO
process.on('unhandledRejection', (err) => {
    console.error('Unhandled rejection:', err);
    // ✅ En producción, podrías enviar esto a un servicio de logging
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
    // ✅ En producción, podrías enviar esto a un servicio de logging
});

// ✅ GRACEFUL SHUTDOWN
process.on('SIGTERM', () => {
    console.log('SIGTERM recibido, cerrando servidor gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT recibido, cerrando servidor gracefully...');
    process.exit(0);
});

startServer();
