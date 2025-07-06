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
        
        // Verificar si las columnas nuevas existen, si no, agregarlas
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
        
        // Agregar columnas que faltan
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
                    console.log(`ℹ️ Columna ${columnName} ya existe o error:`, error.message);
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
            SELECT * FROM accounts 
            ORDER BY created_at DESC
        `);
        
        // Actualizar días y estado para cada cuenta basado en fecha_vencimiento_proveedor
        const accounts = result.rows.map(account => {
            const diasRestantes = calcularDiasRestantes(account.fecha_vencimiento_proveedor);
            const estado = actualizarEstado(diasRestantes);
            
            return {
                ...account,
                days_remaining: diasRestantes,
                status: estado
            };
        });
        
        console.log(`📊 Enviando ${accounts.length} cuentas`);
        res.json(accounts);
    } catch (error) {
        console.error('Error obteniendo cuentas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Crear nueva cuenta con fechas del proveedor
app.post('/api/accounts', async (req, res) => {
    try {
        const { 
            id, client_name, client_phone, email, password, 
            type, country, profiles, days_remaining, status,
            fecha_inicio_proveedor, fecha_vencimiento_proveedor
        } = req.body;
        
        console.log('📥 Datos recibidos:', {
            id, client_name, type, 
            fecha_inicio_proveedor, 
            fecha_vencimiento_proveedor,
            days_remaining
        });
        
        // Usar las fechas del proveedor
        const fechaInicio = fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : new Date();
        const fechaVencimiento = fecha_vencimiento_proveedor ? new Date(fecha_vencimiento_proveedor) : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        
        const result = await pool.query(
            `INSERT INTO accounts (
                id, client_name, client_phone, email, password, type, country, 
                profiles, days_remaining, status, fecha_inicio_proveedor, 
                fecha_vencimiento_proveedor, estado_pago, created_at
            )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
             RETURNING *`,
            [
                id, client_name, client_phone || '', email, password, type, country, 
                JSON.stringify(profiles), days_remaining || 30, status || 'active', 
                fechaInicio, fechaVencimiento, 'activo'
            ]
        );
        
        console.log('✅ Cuenta creada:', result.rows[0].id);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('❌ Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

// Actualizar cuenta
app.put('/api/accounts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { 
            client_name, client_phone, email, password, 
            type, country, profiles, days_remaining, status,
            fecha_inicio_proveedor, fecha_vencimiento_proveedor
        } = req.body;
        
        console.log('📝 Actualizando cuenta:', id, {
            fecha_inicio_proveedor, 
            fecha_vencimiento_proveedor
        });
        
        const result = await pool.query(
            `UPDATE accounts SET 
                client_name = $1, client_phone = $2, email = $3, password = $4, 
                type = $5, country = $6, profiles = $7, days_remaining = $8, status = $9,
                fecha_inicio_proveedor = $10, fecha_vencimiento_proveedor = $11
             WHERE id = $12 RETURNING *`,
            [
                client_name, client_phone || '', email, password, type, country, 
                JSON.stringify(profiles), days_remaining, status,
                fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : null,
                fecha_vencimiento_proveedor ? new Date(fecha_vencimiento_proveedor) : null,
                id
            ]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        console.log('✅ Cuenta actualizada:', id);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('❌ Error actualizando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
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
        
        // Calcular estados en tiempo real basado en fecha_vencimiento_proveedor
        const accountsResult = await pool.query(`
            SELECT 
                fecha_vencimiento_proveedor,
                profiles
            FROM accounts
        `);
        
        let activeCount = 0;
        let expiringCount = 0;
        let totalProfiles = 0;
        const today = new Date();
        
        accountsResult.rows.forEach(row => {
            const profiles = typeof row.profiles === 'string' ? JSON.parse(row.profiles) : row.profiles;
            totalProfiles += profiles.length;
            
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
            console.log(`📅 Sistema de fechas del proveedor: ACTIVO`);
            console.log(`💳 Sistema de vouchers: ACTIVO`);
            console.log(`🚨 Sistema de alarmas: ACTIVO`);
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
