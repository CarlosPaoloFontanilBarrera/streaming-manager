// server.js - Sistema completo con notificaciones push automáticas vía ntfy.sh
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const axios = require('axios'); // Nueva librería para enviar notificaciones

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

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

// --- NUEVO: CONFIGURACIÓN DE NOTIFICACIONES ---
const NOTIFICACION_CONFIG = {
    // IMPORTANTE: Reemplaza esto con el nombre de tu tema secreto de ntfy.sh
    topic: 'jireh-alertas-manager-2025', 
    providerAlarmDays: 3,
    clientAlarmDays: 2
};

// Función para calcular días restantes
function calcularDiasRestantes(fechaVencimiento) {
    if (!fechaVencimiento) return 0;
    const hoy = new Date();
    const vencimiento = new Date(fechaVencimiento);
    const diferencia = vencimiento.getTime() - hoy.getTime();
    const dias = Math.ceil(diferencia / (1000 * 3600 * 24));
    return Math.max(0, dias); // No permitir números negativos
}

// Función para actualizar estado automáticamente
function actualizarEstado(diasRestantes) {
    if (diasRestantes > 5) return 'active';
    if (diasRestantes > 0) return 'inactive';
    return 'expired';
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
        
        const columnCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'accounts' AND column_name IN (
                'fecha_venta', 'fecha_vencimiento', 'fecha_inicio_proveedor', 
                'fecha_vencimiento_proveedor', 'voucher_imagen', 'numero_operacion', 
                'monto_pagado', 'estado_pago'
            )
        `);
        
        const existingColumns = columnCheck.rows.map(row => row.column_name);
        
        const columnsToAdd = [
            'fecha_venta TIMESTAMP DEFAULT NOW()',
            'fecha_vencimiento TIMESTAMP',
            'fecha_inicio_proveedor TIMESTAMP',
            'fecha_vencimiento_proveedor TIMESTAMP',
            'voucher_imagen TEXT',
            'numero_operacion TEXT',
            'monto_pagado DECIMAL(10,2)',
            'estado_pago TEXT DEFAULT \'activo\''
        ];
        
        for (const column of columnsToAdd) {
            const columnName = column.split(' ')[0];
            if (!existingColumns.includes(columnName)) {
                try {
                    await pool.query(`ALTER TABLE accounts ADD COLUMN ${column}`);
                    console.log(`✅ Columna ${columnName} agregada`);
                } catch (error) {
                    // Ignora el error si la columna ya existe
                }
            }
        }
        
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
    }
}


// --- NUEVO: FUNCIÓN DE ENVÍO DE NOTIFICACIONES PUSH ---
async function enviarNotificacionPush(titulo, mensaje) {
    try {
        await axios.post(`https://ntfy.sh/${NOTIFICACION_CONFIG.topic}`, mensaje, {
            headers: {
                'Title': titulo,
                'Priority': 'high', // 'high' o 'urgent' para que suene
                'Tags': 'bell' // Emoji de campana
            }
        });
        console.log(`✅ Notificación push enviada: "${titulo}"`);
    } catch (error) {
        console.error('❌ Error enviando notificación push:', error.message);
    }
}

// --- NUEVO: MOTOR DE ALARMAS EN EL BACKEND ---
function iniciarMotorDeAlarmas() {
    console.log(`🚨 Motor de alarmas con ntfy.sh iniciado. Verificando cada 1 minuto.`);
    
    setInterval(async () => {
        console.log(`⏰ Ejecutando verificación de alarmas: ${new Date().toLocaleString('es-PE')}`);
        
        try {
            const result = await pool.query('SELECT * FROM accounts');
            const accounts = result.rows;
            const today = new Date();

            if (accounts.length === 0) return;

            for (const account of accounts) {
                const diasRestantes = calcularDiasRestantes(account.fecha_vencimiento_proveedor);

                // Alarma para cuentas del proveedor
                if (diasRestantes > 0 && diasRestantes <= NOTIFICACION_CONFIG.providerAlarmDays) {
                    const titulo = `⚠️ Alerta Proveedor: ${account.client_name}`;
                    const mensaje = `El servicio ${account.type} vence en ${diasRestantes} día(s). ¡Renovar urgente!`;
                    await enviarNotificacionPush(titulo, mensaje);
                }

                // Alarma para perfiles de clientes
                const perfiles = typeof account.profiles === 'string' ? JSON.parse(account.profiles) : account.profiles;
                for (const profile of perfiles) {
                    if (profile.estado === 'vendido' && profile.fechaVencimiento) {
                        const vencimientoPerfil = new Date(profile.fechaVencimiento);
                        const diasRestantesPerfil = Math.ceil((vencimientoPerfil - today) / (1000 * 60 * 60 * 24));

                        if (diasRestantesPerfil > 0 && diasRestantesPerfil <= NOTIFICACION_CONFIG.clientAlarmDays) {
                            const titulo = `💰 Alerta Cobro: ${profile.clienteNombre}`;
                            const mensaje = `El perfil ${profile.name} (${account.type}) vence en ${diasRestantesPerfil} día(s). ¡Contactar para renovar!`;
                            await enviarNotificacionPush(titulo, mensaje);
                        }
                    }
                }
            }
        } catch (dbError) {
            console.error('❌ Error de base de datos en el motor de alarmas:', dbError);
        }
    }, 60000); // Se ejecuta cada 60 segundos
}


// RUTAS API
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await pool.query('SELECT * FROM admin_users WHERE username = $1 AND password = $2', [username, password]);
        if (result.rows.length > 0) {
            res.json({ success: true, message: 'Login exitoso' });
        } else {
            res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

app.get('/api/accounts', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM accounts ORDER BY created_at DESC');
        const accounts = result.rows.map(account => ({
            ...account,
            days_remaining: calcularDiasRestantes(account.fecha_vencimiento_proveedor),
            status: actualizarEstado(calcularDiasRestantes(account.fecha_vencimiento_proveedor))
        }));
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/accounts', async (req, res) => {
    try {
        const { id, client_name, client_phone, email, password, type, country, profiles, fecha_inicio_proveedor, fecha_vencimiento_proveedor } = req.body;
        const days_remaining = calcularDiasRestantes(fecha_vencimiento_proveedor);
        const status = actualizarEstado(days_remaining);
        const result = await pool.query(
            `INSERT INTO accounts (id, client_name, client_phone, email, password, type, country, profiles, days_remaining, status, fecha_inicio_proveedor, fecha_vencimiento_proveedor)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
            [id, client_name, client_phone, email, password, type, country, JSON.stringify(profiles), days_remaining, status, fecha_inicio_proveedor, fecha_vencimiento_proveedor]
        );
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.put('/api/accounts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { client_name, client_phone, email, password, type, country, profiles, fecha_inicio_proveedor, fecha_vencimiento_proveedor } = req.body;
        const days_remaining = calcularDiasRestantes(fecha_vencimiento_proveedor);
        const status = actualizarEstado(days_remaining);
        const result = await pool.query(
            `UPDATE accounts SET client_name = $1, client_phone = $2, email = $3, password = $4, type = $5, country = $6, profiles = $7, days_remaining = $8, status = $9, fecha_inicio_proveedor = $10, fecha_vencimiento_proveedor = $11
             WHERE id = $12 RETURNING *`,
            [client_name, client_phone, email, password, type, country, JSON.stringify(profiles), days_remaining, status, fecha_inicio_proveedor, fecha_vencimiento_proveedor, id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

app.delete('/api/accounts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('DELETE FROM accounts WHERE id = $1', [id]);
        res.json({ message: 'Cuenta eliminada exitosamente' });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const result = await pool.query('SELECT fecha_vencimiento_proveedor, profiles FROM accounts');
        let total = result.rows.length;
        let active = 0;
        let expiring = 0;
        let totalProfiles = 0;
        result.rows.forEach(row => {
            const days = calcularDiasRestantes(row.fecha_vencimiento_proveedor);
            if (days > 5) active++;
            else if (days > 0) expiring++;
            const profiles = typeof row.profiles === 'string' ? JSON.parse(row.profiles) : row.profiles;
            totalProfiles += profiles.length;
        });
        res.json({ total, active, profiles: totalProfiles, expiring });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});


// Servir archivos estáticos
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Iniciar servidor
async function startServer() {
    try {
        await initDB();
        app.listen(PORT, () => {
            console.log(`🚀 JIREH Streaming Manager corriendo en puerto ${PORT}`);
            iniciarMotorDeAlarmas(); // Iniciar el motor de alarmas
        });
    } catch (error) {
        console.error('❌ Error iniciando servidor:', error);
    }
}

startServer();
