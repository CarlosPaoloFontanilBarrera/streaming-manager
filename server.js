// server.js - SISTEMA CORREGIDO COMPLETAMENTE
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fetch = require('node-fetch');

// DEPENDENCIAS DE SEGURIDAD
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// CONFIGURACIÓN DE SEGURIDAD
const JWT_SECRET = process.env.JWT_SECRET || 'jireh_streaming_secret_2025_ultra_secure!';
const BCRYPT_ROUNDS = 12;

// ✅ CORREGIDO: Trust proxy configurado correctamente para Railway
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1); // Solo confiar en el primer proxy
} else {
    app.set('trust proxy', false); // Desarrollo local
}

// Helmet para headers de seguridad
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "blob:"],
            connectSrc: ["'self'", "https://ntfy.sh"]
        }
    }
}));

// ✅ CORREGIDO: Rate limiting mejorado
const createRateLimiter = (windowMs, max, message) => rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    // Skip en desarrollo local
    skip: (req) => {
        if (process.env.NODE_ENV !== 'production') {
            return req.ip === '127.0.0.1' || req.ip === '::1';
        }
        return false;
    }
});

const loginLimiter = createRateLimiter(
    15 * 60 * 1000, // 15 minutos
    5, // 5 intentos
    'Demasiados intentos de login. Intenta en 15 minutos.'
);

const apiLimiter = createRateLimiter(
    1 * 60 * 1000, // 1 minuto
    100, // 100 requests
    'Demasiadas solicitudes. Intenta más tarde.'
);

// Middleware básico
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Aplicar rate limiting
app.use('/api/login', loginLimiter);
app.use('/api/', apiLimiter);

// Configuración de PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Configuración de multer
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB máximo
});

// ✅ MIDDLEWARE DE AUTENTICACIÓN JWT MEJORADO
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(401).json({ error: 'Token requerido' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expirado' });
        }
        return res.status(403).json({ error: 'Token inválido' });
    }
}

// ✅ VALIDADORES CORREGIDOS
const loginValidators = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 30 })
        .withMessage('Usuario debe tener 3-30 caracteres'),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Password debe tener mínimo 6 caracteres')
];

const accountValidators = [
    body('client_name')
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Nombre debe tener 2-100 caracteres'),
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Email inválido'),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Password debe tener mínimo 6 caracteres'),
    body('type')
        .notEmpty()
        .withMessage('Tipo de servicio requerido'),
    body('country')
        .isIn(['PE', 'US', 'GB', 'ES'])
        .withMessage('País inválido')
];

// Funciones de utilidad
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

// Inicialización de base de datos
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
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        
        await pool.query(`
            INSERT INTO admin_users (username, password) 
            VALUES ('paolof', 'elpoderosodeizrael777xD!') 
            ON CONFLICT (username) DO NOTHING
        `);
        
        console.log('✅ Base de datos inicializada correctamente');
    } catch (error) {
        console.error('❌ Error inicializando base de datos:', error);
        throw error;
    }
}

// Sistema de alarmas
async function checkAndSendAlarms() {
    console.log('⏰ Revisando alarmas...');

    try {
        const settingsRes = await pool.query('SELECT * FROM alarm_settings WHERE id = 1');
        const settings = settingsRes.rows[0];

        if (!settings?.ntfy_topic) {
            console.log('⚠️ No hay tema de ntfy configurado');
            return;
        }

        const accountsRes = await pool.query('SELECT * FROM accounts');

        for (const account of accountsRes.rows) {
            // Alarmas de proveedor
            const providerDays = calcularDiasRestantes(account.fecha_vencimiento_proveedor);
            if (providerDays > 0 && providerDays <= settings.provider_threshold_days) {
                const notificationId = `provider-${account.id}`;
                const checkRes = await pool.query(
                    "SELECT 1 FROM sent_notifications WHERE item_id = $1 AND sent_at > NOW() - INTERVAL '24 hours'", 
                    [notificationId]
                );
                
                if (checkRes.rows.length === 0) {
                    const message = `🚨 La cuenta de ${account.type} de "${account.client_name}" vence en ${providerDays} día(s).`;
                    
                    try {
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
                        
                        console.log(`📲 Notificación de proveedor enviada para ${account.id}`);
                    } catch (notifyError) {
                        console.error(`❌ Error enviando notificación: ${notifyError.message}`);
                    }
                }
            }

            // Alarmas de cliente
            const profiles = typeof account.profiles === 'string' ? JSON.parse(account.profiles) : account.profiles || [];
            for (const [index, profile] of profiles.entries()) {
                if (profile.estado === 'vendido' && profile.fechaVencimiento) {
                    const clientDays = calcularDiasRestantesPerfil(profile.fechaVencimiento);
                    if (clientDays > 0 && clientDays <= settings.client_threshold_days) {
                        const notificationId = `client-${account.id}-${index}`;
                        const checkRes = await pool.query(
                            "SELECT 1 FROM sent_notifications WHERE item_id = $1 AND sent_at > NOW() - INTERVAL '24 hours'", 
                            [notificationId]
                        );

                        if (checkRes.rows.length === 0) {
                            const message = `🔔 El perfil "${profile.name}" del cliente ${profile.clienteNombre} (${account.type}) vence en ${clientDays} día(s).`;
                            
                            try {
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
                                
                                console.log(`📲 Notificación de cliente enviada para ${account.id}-${index}`);
                            } catch (notifyError) {
                                console.error(`❌ Error enviando notificación: ${notifyError.message}`);
                            }
                        }
                    }
                }
            }
        }
    } catch (error) {
        console.error('❌ Error en sistema de alarmas:', error);
    }
}

// ✅ RUTAS API CORREGIDAS

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ✅ LOGIN MEJORADO
app.post('/api/login', loginValidators, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                message: 'Datos inválidos',
                errors: errors.array()
            });
        }

        const { username, password } = req.body;

        const result = await pool.query(
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
        let isValidPassword = false;
        
        // Verificar password (soporte para migración gradual)
        if (user.password.startsWith('$2b$')) {
            isValidPassword = await bcrypt.compare(password, user.password);
        } else {
            isValidPassword = password === user.password;
            
            // Migrar a bcrypt si es válido
            if (isValidPassword) {
                const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
                await pool.query(
                    'UPDATE admin_users SET password = $1 WHERE id = $2',
                    [hashedPassword, user.id]
                );
                console.log(`✅ Password migrado a bcrypt para: ${username}`);
            }
        }
        
        if (!isValidPassword) {
            return res.status(401).json({ 
                success: false, 
                message: 'Credenciales inválidas' 
            });
        }

        // Generar JWT
        const token = jwt.sign(
            { userId: user.id, username: user.username }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        console.log(`✅ Login exitoso: ${username} desde ${req.ip}`);

        res.json({ 
            success: true, 
            message: 'Login exitoso',
            token,
            user: { id: user.id, username: user.username }
        });

    } catch (error) {
        console.error('❌ Error en login:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error interno del servidor' 
        });
    }
});

// Cuentas - GET
app.get('/api/accounts', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM accounts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('❌ Error obteniendo cuentas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Cuentas - POST
app.post('/api/accounts', accountValidators, verifyToken, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Datos inválidos',
                details: errors.array()
            });
        }

        const { 
            id, client_name, client_phone, email, password, 
            type, country, profiles, fecha_inicio_proveedor 
        } = req.body;
        
        const fechaInicio = fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : new Date();
        const fechaVencimientoProveedor = new Date(fechaInicio);
        fechaVencimientoProveedor.setDate(fechaVencimientoProveedor.getDate() + 30);
        
        const diasRestantesProveedor = calcularDiasRestantes(fechaVencimientoProveedor);
        const estadoProveedor = actualizarEstado(diasRestantesProveedor);
        
        const result = await pool.query(
            `INSERT INTO accounts (
                id, client_name, client_phone, email, password, type, country, 
                profiles, days_remaining, status, fecha_inicio_proveedor, 
                fecha_vencimiento_proveedor, estado_pago, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()) 
            RETURNING *`,
            [
                id, client_name, client_phone || '', email, password, type, country, 
                JSON.stringify(profiles || []), diasRestantesProveedor, estadoProveedor, 
                fechaInicio, fechaVencimientoProveedor, 'activo'
            ]
        );
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('❌ Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

// Cuentas - PUT
app.put('/api/accounts/:id', accountValidators, verifyToken, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Datos inválidos',
                details: errors.array()
            });
        }

        const { id } = req.params;
        const { 
            client_name, client_phone, email, password, 
            type, country, profiles, fecha_inicio_proveedor 
        } = req.body;
        
        const fechaInicio = fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : new Date();
        const fechaVencimientoProveedor = new Date(fechaInicio);
        fechaVencimientoProveedor.setDate(fechaVencimientoProveedor.getDate() + 30);
        
        const diasRestantesProveedor = calcularDiasRestantes(fechaVencimientoProveedor);
        const estadoProveedor = actualizarEstado(diasRestantesProveedor);
        const profilesActualizados = procesarPerfiles(profiles);
        
        const result = await pool.query(
            `UPDATE accounts SET 
                client_name = $1, client_phone = $2, email = $3, password = $4, 
                type = $5, country = $6, profiles = $7, days_remaining = $8, 
                status = $9, fecha_inicio_proveedor = $10, fecha_vencimiento_proveedor = $11
             WHERE id = $12 RETURNING *`,
            [
                client_name, client_phone || '', email, password, type, country, 
                JSON.stringify(profilesActualizados), diasRestantesProveedor, estadoProveedor, 
                fechaInicio, fechaVencimientoProveedor, id
            ]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('❌ Error actualizando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

// Cuentas - DELETE
app.delete('/api/accounts/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM accounts WHERE id = $1 RETURNING *', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        res.json({ message: 'Cuenta eliminada exitosamente' });
    } catch (error) {
        console.error('❌ Error eliminando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Estadísticas
app.get('/api/stats', verifyToken, async (req, res) => {
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
        console.error('❌ Error obteniendo estadísticas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Configuración de alarmas
app.get('/api/alarms/settings', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM alarm_settings WHERE id = 1');
        res.json(result.rows[0] || { 
            provider_threshold_days: 5, 
            client_threshold_days: 3, 
            ntfy_topic: '' 
        });
    } catch (error) {
        console.error('❌ Error obteniendo configuración de alarmas:', error);
        res.status(500).json({ error: 'Error obteniendo configuración de alarmas' });
    }
});

app.put('/api/alarms/settings', verifyToken, async (req, res) => {
    try {
        const { provider_threshold_days, client_threshold_days, ntfy_topic } = req.body;
        const result = await pool.query(
            `UPDATE alarm_settings SET 
                provider_threshold_days = $1, 
                client_threshold_days = $2, 
                ntfy_topic = $3 
             WHERE id = 1 RETURNING *`,
            [provider_threshold_days, client_threshold_days, ntfy_topic]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('❌ Error actualizando configuración de alarmas:', error);
        res.status(500).json({ error: 'Error actualizando configuración de alarmas' });
    }
});

// Test de alarmas
app.post('/api/alarms/test', verifyToken, async (req, res) => {
    console.log('⚡️ Ejecutando test de alarmas...');
    try {
        await checkAndSendAlarms();
        res.json({ 
            success: true, 
            message: 'Test de alarmas ejecutado. Revisa las notificaciones.' 
        });
    } catch (error) {
        console.error('❌ Error en test de alarmas:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al ejecutar test de alarmas.' 
        });
    }
});

// Vouchers
app.post('/api/accounts/:accountId/profile/:profileIndex/voucher', verifyToken, upload.single('voucher'), async (req, res) => {
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
            profile.diasRestantes = calcularDiasRestantesPerfil(profile.fechaVencimiento);
            profile.estadoPago = 'pagado';
            profile.fechaUltimaRenovacion = new Date().toISOString().split('T')[0];
        } else {
            profile.estadoPago = 'confirmado';
        }
        
        await pool.query('UPDATE accounts SET profiles = $1 WHERE id = $2', [JSON.stringify(profiles), accountId]);
        
        res.json({ success: true, message: 'Voucher procesado', profile: profile });
    } catch (error) {
        console.error('❌ Error procesando voucher:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

// Micuenta.me checker
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
            const errorData = await response.json().catch(() => ({ 
                message: 'Error desconocido del proxy de micuenta.me.' 
            }));
            console.error('Error al consultar micuenta.me:', response.status, errorData.message);
            return res.status(response.status).json(errorData);
        }

        const data = await response.json();
        res.json(data);

    } catch (error) {
        console.error('Error en micuenta.me checker:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error interno del servidor al procesar la solicitud externa a micuenta.me.' 
        });
    }
});

// ✅ RUTAS ESTÁTICAS
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ✅ INICIAR SERVIDOR
async function startServer() {
    try {
        await initDB();
        
        app.listen(PORT, () => {
            console.log(`🚀 JIREH Streaming Manager corriendo en puerto ${PORT}`);
            console.log(`🔒 Seguridad JWT habilitada`);
            console.log(`🛡️ Rate limiting configurado CORRECTAMENTE`);
            console.log(`🌐 Entorno: ${process.env.NODE_ENV || 'development'}`);
            
            // Iniciar sistema de alarmas
            setInterval(checkAndSendAlarms, 3600000); // Cada hora
            console.log('⏰ Sistema de alarmas ntfy iniciado');
        });
    } catch (error) {
        console.error('❌ Error iniciando servidor:', error);
        process.exit(1);
    }
}

// ✅ MANEJO DE ERRORES MEJORADO
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM recibido, cerrando servidor...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT recibido, cerrando servidor...');
    process.exit(0);
});

startServer();
