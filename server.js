// server.js - Sistema completo con fechas automáticas y vouchers
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const multer = require('multer');

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

// Función para calcular días restantes
function calcularDiasRestantes(fechaVencimiento) {
    const hoy = new Date();
    const vencimiento = new Date(fechaVencimiento);
    const diferencia = vencimiento.getTime() - hoy.getTime();
    const dias = Math.ceil(diferencia / (1000 * 3600 * 24));
    return Math.max(0, dias); // No permitir números negativos
}

// Función para actualizar estado automáticamente
function actualizarEstado(diasRestantes) {
    if (diasRestantes > 5) return 'activo';
    if (diasRestantes > 0) return 'por_vencer';
    return 'vencido';
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
                voucher_imagen TEXT,
                numero_operacion TEXT,
                monto_pagado DECIMAL(10,2),
                estado_pago TEXT DEFAULT 'activo'
            )
        `);
        
        // Verificar si las columnas nuevas existen, si no, agregarlas
        const columnCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'accounts' AND column_name IN ('fecha_venta', 'fecha_vencimiento', 'voucher_imagen', 'numero_operacion', 'monto_pagado', 'estado_pago')
        `);
        
        if (columnCheck.rows.length < 6) {
            await pool.query(`
                ALTER TABLE accounts 
                ADD COLUMN IF NOT EXISTS fecha_venta TIMESTAMP DEFAULT NOW(),
                ADD COLUMN IF NOT EXISTS fecha_vencimiento TIMESTAMP,
                ADD COLUMN IF NOT EXISTS voucher_imagen TEXT,
                ADD COLUMN IF NOT EXISTS numero_operacion TEXT,
                ADD COLUMN IF NOT EXISTS monto_pagado DECIMAL(10,2),
                ADD COLUMN IF NOT EXISTS estado_pago TEXT DEFAULT 'activo'
            `);
            
            // Actualizar registros existentes
            await pool.query(`
                UPDATE accounts 
                SET 
                    fecha_venta = COALESCE(fecha_venta, created_at),
                    fecha_vencimiento = COALESCE(fecha_vencimiento, created_at + INTERVAL '30 days'),
                    estado_pago = COALESCE(estado_pago, 'activo')
                WHERE fecha_vencimiento IS NULL
            `);
        }
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        
        // Insertar usuario admin por defecto
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

// RUTAS API
// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        database: 'Connected' 
    });
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const result = await pool.query(
            'SELECT * FROM admin_users WHERE username = $1 AND password = $2',
            [username, password]
        );
        
        if (result.rows.length > 0) {
            res.json({ 
                success: true, 
                message: 'Login exitoso',
                user: result.rows[0].username
            });
        } else {
            res.status(401).json({ 
                success: false, 
                message: 'Credenciales inválidas' 
            });
        }
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error interno del servidor' 
        });
    }
});

// Obtener todas las cuentas con cálculo automático
app.get('/api/accounts', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT *, 
                   CASE 
                       WHEN fecha_vencimiento > NOW() THEN EXTRACT(days FROM fecha_vencimiento - NOW())::INTEGER
                       ELSE 0
                   END as dias_calculados
            FROM accounts 
            ORDER BY created_at DESC
        `);
        
        // Actualizar días y estado para cada cuenta
        const accounts = result.rows.map(account => {
            const diasRestantes = calcularDiasRestantes(account.fecha_vencimiento);
            const estado = actualizarEstado(diasRestantes);
            
            return {
                ...account,
                days_remaining: diasRestantes,
                status: estado,
                dias_restantes: diasRestantes
            };
        });
        
        res.json(accounts);
    } catch (error) {
        console.error('Error obteniendo cuentas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Crear nueva cuenta con fechas automáticas
app.post('/api/accounts', async (req, res) => {
    try {
        const { 
            id, client_name, client_phone, email, password, 
            type, country, profiles, days_remaining, status 
        } = req.body;
        
        const fechaVenta = new Date();
        const fechaVencimiento = new Date(fechaVenta);
        fechaVencimiento.setDate(fechaVencimiento.getDate() + 30);
        
        const result = await pool.query(
            `INSERT INTO accounts (
                id, client_name, client_phone, email, password, type, country, 
                profiles, days_remaining, status, fecha_venta, fecha_vencimiento, estado_pago
            )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING *`,
            [
                id, client_name, client_phone || '', email, password, type, country, 
                JSON.stringify(profiles), 30, 'active', fechaVenta, fechaVencimiento, 'activo'
            ]
        );
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Actualizar cuenta
app.put('/api/accounts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { 
            client_name, client_phone, email, password, 
            type, country, profiles, days_remaining, status 
        } = req.body;
        
        const result = await pool.query(
            `UPDATE accounts SET 
                client_name = $1, client_phone = $2, email = $3, password = $4, 
                type = $5, country = $6, profiles = $7, days_remaining = $8, status = $9
             WHERE id = $10 RETURNING *`,
            [client_name, client_phone || '', email, password, type, country, JSON.stringify(profiles), days_remaining, status, id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error actualizando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Subir voucher y renovar cuenta
app.post('/api/accounts/:id/voucher', upload.single('voucher'), async (req, res) => {
    try {
        const { id } = req.params;
        const { numero_operacion, monto_pagado } = req.body;
        const voucherImagen = req.file ? req.file.buffer.toString('base64') : null;
        
        // Obtener cuenta actual
        const accountResult = await pool.query('SELECT * FROM accounts WHERE id = $1', [id]);
        if (accountResult.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        const account = accountResult.rows[0];
        
        // Calcular nueva fecha de vencimiento (desde la fecha actual o desde vencimiento si aún es válida)
        const fechaActual = new Date();
        const fechaVencimientoActual = new Date(account.fecha_vencimiento);
        
        let nuevaFechaVencimiento;
        if (fechaVencimientoActual > fechaActual) {
            // Si aún no ha vencido, extender desde la fecha de vencimiento actual
            nuevaFechaVencimiento = new Date(fechaVencimientoActual);
            nuevaFechaVencimiento.setDate(nuevaFechaVencimiento.getDate() + 30);
        } else {
            // Si ya venció, extender desde hoy
            nuevaFechaVencimiento = new Date(fechaActual);
            nuevaFechaVencimiento.setDate(nuevaFechaVencimiento.getDate() + 30);
        }
        
        // Actualizar cuenta con voucher y nueva fecha
        const result = await pool.query(
            `UPDATE accounts SET 
                voucher_imagen = $1, 
                numero_operacion = $2, 
                monto_pagado = $3,
                fecha_vencimiento = $4,
                estado_pago = 'activo',
                status = 'active',
                days_remaining = 30
             WHERE id = $5 RETURNING *`,
            [voucherImagen, numero_operacion, parseFloat(monto_pagado), nuevaFechaVencimiento, id]
        );
        
        res.json({
            success: true,
            message: 'Voucher subido y cuenta renovada exitosamente',
            account: result.rows[0],
            nueva_fecha_vencimiento: nuevaFechaVencimiento.toLocaleDateString('es-PE')
        });
        
    } catch (error) {
        console.error('Error subiendo voucher:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Obtener voucher de una cuenta
app.get('/api/accounts/:id/voucher', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            'SELECT voucher_imagen, numero_operacion, monto_pagado FROM accounts WHERE id = $1',
            [id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        const voucher = result.rows[0];
        if (!voucher.voucher_imagen) {
            return res.status(404).json({ error: 'No hay voucher para esta cuenta' });
        }
        
        res.json(voucher);
    } catch (error) {
        console.error('Error obteniendo voucher:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Eliminar cuenta
app.delete('/api/accounts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM accounts WHERE id = $1 RETURNING *', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        res.json({ message: 'Cuenta eliminada exitosamente' });
    } catch (error) {
        console.error('Error eliminando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Estadísticas con cálculo automático
app.get('/api/stats', async (req, res) => {
    try {
        const totalResult = await pool.query('SELECT COUNT(*) FROM accounts');
        
        // Calcular estados en tiempo real
        const accountsResult = await pool.query(`
            SELECT 
                CASE 
                    WHEN fecha_vencimiento > NOW() + INTERVAL '5 days' THEN 'active'
                    WHEN fecha_vencimiento > NOW() THEN 'por_vencer'
                    ELSE 'vencido'
                END as estado_calculado,
                profiles
            FROM accounts
        `);
        
        let activeCount = 0;
        let expiringCount = 0;
        let totalProfiles = 0;
        
        accountsResult.rows.forEach(row => {
            const profiles = typeof row.profiles === 'string' ? JSON.parse(row.profiles) : row.profiles;
            totalProfiles += profiles.length;
            
            if (row.estado_calculado === 'active') activeCount++;
            if (row.estado_calculado === 'por_vencer') expiringCount++;
        });
        
        res.json({
            total: parseInt(totalResult.rows[0].count),
            active: activeCount,
            profiles: totalProfiles,
            expiring: expiringCount
        });
    } catch (error) {
        console.error('Error obteniendo estadísticas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Servir archivos estáticos
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Catch all - servir index.html para SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Iniciar servidor
async function startServer() {
    try {
        await initDB();
        app.listen(PORT, () => {
            console.log(`🚀 JIREH Streaming Manager corriendo en puerto ${PORT}`);
            console.log(`🌐 URL: http://localhost:${PORT}`);
            console.log(`📅 Sistema de fechas automáticas: ACTIVO`);
            console.log(`💳 Sistema de vouchers: ACTIVO`);
        });
    } catch (error) {
        console.error('❌ Error iniciando servidor:', error);
    }
}

// Manejo de errores
process.on('unhandledRejection', (err) => {
    console.error('Unhandled rejection:', err);
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
});

startServer();
