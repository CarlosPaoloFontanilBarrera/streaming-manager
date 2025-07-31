// server.js - Sistema completo con JWT, fechas automáticas, perfiles, vouchers Y ALARMAS NTFY + AUTO-CREACIÓN DE TABLAS
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// CONFIGURACIÓN JWT
const JWT_SECRET = process.env.JWT_SECRET || 'jireh-streaming-secret-key-ultra-segura-2024';
const JWT_EXPIRES_IN = '7d';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// MIDDLEWARE DE AUTENTICACIÓN JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log('❌ Token inválido:', err.message);
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }
        req.user = user;
        next();
    });
};

// Configuración de PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Configuración de multer para subida de archivos
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB máximo
});

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
            const columns = await pool.query(`
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='alarm_settings' AND column_name='ntfy_topic'
            `);
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
        
        console.log('✅ Tablas principales inicializadas correctamente');
        
    } catch (error) {
        console.error('❌ Error inicializando base de datos:', error);
    }
}

// LÓGICA DE ENVÍO DE ALARMAS POR NTFY
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

// ===============================================
// RUTAS API CON JWT
// ===============================================

// Ruta de salud (sin autenticación)
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// RUTA DE LOGIN CON JWT Y AUTO-CREACIÓN DE USUARIO
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('🔐 Intento de login para:', username);
        
        // PRIMERO: Asegurar que la tabla admin_users existe correctamente
        try {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS admin_users (
                    id SERIAL PRIMARY KEY, 
                    username TEXT UNIQUE NOT NULL, 
                    password TEXT NOT NULL, 
                    created_at TIMESTAMP DEFAULT NOW()
                )
            `);
            
            // Verificar si el usuario existe, si no, crearlo
            const userCheck = await pool.query('SELECT COUNT(*) FROM admin_users WHERE username = $1', ['paolof']);
            if (parseInt(userCheck.rows[0].count) === 0) {
                await pool.query(
                    'INSERT INTO admin_users (username, password) VALUES ($1, $2)',
                    ['paolof', 'elpoderosodeizrael777xD!']
                );
                console.log('👤 Usuario paolof creado automáticamente');
            }
        } catch (tableError) {
            console.error('❌ Error creando tabla/usuario:', tableError);
        }
        
        // SEGUNDO: Realizar el login
        const result = await pool.query('SELECT id, username, password FROM admin_users WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            console.log('❌ Usuario no encontrado:', username);
            return res.status(401).json({ success: false, message: 'Usuario no encontrado' });
        }
        
        const user = result.rows[0];
        if (user.password !== password) {
            console.log('❌ Contraseña incorrecta para:', username);
            return res.status(401).json({ success: false, message: 'Contraseña incorrecta' });
        }
        
        // TERCERO: Generar token JWT
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username,
                exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 días
            },
            JWT_SECRET
        );
        
        console.log('✅ Login exitoso para:', username);
        
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
        console.error('❌ Error en login:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// RUTAS PROTEGIDAS CON JWT
app.get('/api/accounts', authenticateJWT, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM accounts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error obteniendo cuentas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/accounts', authenticateJWT, async (req, res) => {
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
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.put('/api/accounts/:id', authenticateJWT, async (req, res) => {
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
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error actualizando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.post('/api/accounts/:accountId/profile/:profileIndex/voucher', authenticateJWT, upload.single('voucher'), async (req, res) => {
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
        
        await pool.query('UPDATE accounts SET profiles = $1 WHERE id = $2', [JSON.stringify(profiles), accountId]);
        res.json({ success: true, message: 'Voucher procesado', profile: profile });
    } catch (error) {
        console.error('Error procesando voucher:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.delete('/api/accounts/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM accounts WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Cuenta no encontrada' });
        res.json({ message: 'Cuenta eliminada exitosamente' });
    } catch (error) {
        console.error('Error eliminando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/stats', authenticateJWT, async (req, res) => {
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

app.get('/api/alarms/settings', authenticateJWT, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM alarm_settings WHERE id = 1');
        res.json(result.rows[0] || { provider_threshold_days: 5, client_threshold_days: 3, ntfy_topic: '' });
    } catch (error) {
        console.error('Error obteniendo configuración de alarmas:', error);
        res.status(500).json({ error: 'Error obteniendo configuración de alarmas' });
    }
});

app.put('/api/alarms/settings', authenticateJWT, async (req, res) => {
    try {
        const { provider_threshold_days, client_threshold_days, ntfy_topic } = req.body;
        const result = await pool.query(
            'UPDATE alarm_settings SET provider_threshold_days = $1, client_threshold_days = $2, ntfy_topic = $3 WHERE id = 1 RETURNING *',
            [provider_threshold_days, client_threshold_days, ntfy_topic]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error actualizando configuración de alarmas:', error);
        res.status(500).json({ error: 'Error actualizando configuración de alarmas' });
    }
});

app.post('/api/alarms/test', authenticateJWT, async (req, res) => {
    console.log('⚡️ Disparando prueba de alarmas manualmente...');
    try {
        await checkAndSendAlarms();
        res.json({ success: true, message: 'Prueba de alarmas iniciada. Revisa tu celular en unos momentos.' });
    } catch (error) {
        console.error('❌ Error en la prueba manual de alarmas:', error);
        res.status(500).json({ success: false, message: 'Error al iniciar la prueba de alarmas.' });
    }
});

app.post('/api/check-micuenta-me-code', authenticateJWT, async (req, res) => {
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

// Servir archivos estáticos
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// FUNCIÓN DE INICIO CON AUTO-CREACIÓN DE TABLAS Y USUARIO ADMIN
async function startServer() {
    try {
        console.log('🔧 Iniciando JIREH Streaming Manager...');
        
        // PASO 1: Crear tabla admin_users automáticamente
        console.log('📝 Creando tabla admin_users...');
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY, 
                username TEXT UNIQUE NOT NULL, 
                password TEXT NOT NULL, 
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        console.log('✅ Tabla admin_users creada/verificada');
        
        // PASO 2: Crear usuario admin automáticamente
        try {
            const userExists = await pool.query('SELECT COUNT(*) FROM admin_users WHERE username = $1', ['paolof']);
            if (parseInt(userExists.rows[0].count) === 0) {
                await pool.query(
                    'INSERT INTO admin_users (username, password) VALUES ($1, $2)',
                    ['paolof', 'elpoderosodeizrael777xD!']
                );
                console.log('👤 Usuario administrador paolof creado automáticamente');
            } else {
                console.log('👤 Usuario administrador paolof ya existe');
            }
        } catch (userError) {
            console.log('⚠️ Error con usuario admin:', userError.message);
        }
        
        // PASO 3: Ejecutar la inicialización normal de otras tablas
        await initDB();
        
        // PASO 4: Iniciar el servidor
        app.listen(PORT, () => {
            console.log(`🚀 JIREH Streaming Manager corriendo en puerto ${PORT}`);
            console.log(`🔐 Sistema JWT activado con clave: ${JWT_SECRET.substring(0, 10)}...`);
            console.log(`✅ Base de datos PostgreSQL lista en Railway`);
            console.log(`👤 Usuario admin: paolof`);
            
            // Iniciar sistema de alarmas
            setInterval(checkAndSendAlarms, 3600000); 
            console.log('⏰ Sistema de revisión de alarmas por ntfy iniciado.');
        });
        
    } catch (error) {
        console.error('❌ Error crítico iniciando servidor:', error);
        
        // MODO RESPALDO: Intentar iniciar sin verificaciones si falla
        try {
            app.listen(PORT, () => {
                console.log(`🚀 Servidor iniciado en modo básico en puerto ${PORT}`);
                console.log('⚠️ Algunas funciones pueden no estar disponibles');
            });
        } catch (fallbackError) {
            console.error('❌ Error crítico total:', fallbackError);
            process.exit(1);
        }
    }
}

// Manejo de errores
process.on('unhandledRejection', (err) => console.error('Unhandled rejection:', err));
process.on('uncaughtException', (err) => console.error('Uncaught exception:', err));

// INICIAR EL SERVIDOR
startServer();
