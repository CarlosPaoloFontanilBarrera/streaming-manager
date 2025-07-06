// server.js - Sistema completo con fechas automáticas de perfiles y vouchers
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

// Función para calcular días restantes del proveedor
function calcularDiasRestantes(fechaVencimiento) {
    if (!fechaVencimiento) return 0;
    const hoy = new Date();
    const vencimiento = new Date(fechaVencimiento);
    const diferencia = vencimiento.getTime() - hoy.getTime();
    const dias = Math.ceil(diferencia / (1000 * 3600 * 24));
    return Math.max(0, dias);
}

// Función para calcular días restantes de un perfil específico
function calcularDiasRestantesPerfil(fechaVencimientoCliente) {
    if (!fechaVencimientoCliente) return 0;
    const hoy = new Date();
    const vencimiento = new Date(fechaVencimientoCliente);
    const diferencia = vencimiento.getTime() - hoy.getTime();
    const dias = Math.ceil(diferencia / (1000 * 3600 * 24));
    return Math.max(0, dias);
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
        // Si el perfil está vendido, calcular sus días restantes individuales
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

// Obtener todas las cuentas con cálculo automático de días restantes
app.get('/api/accounts', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT * FROM accounts 
            ORDER BY created_at DESC
        `);
        
        // Actualizar días y estado para cada cuenta
        const accounts = result.rows.map(account => {
            // Días restantes del proveedor (para la cuenta)
            const diasRestantesProveedor = calcularDiasRestantes(account.fecha_vencimiento_proveedor);
            const estadoProveedor = actualizarEstado(diasRestantesProveedor);
            
            // Procesar perfiles con sus propios días restantes
            const profiles = typeof account.profiles === 'string' 
                ? JSON.parse(account.profiles) 
                : account.profiles || [];
            
            const profilesActualizados = procesarPerfiles(profiles);
            
            return {
                ...account,
                days_remaining: diasRestantesProveedor, // Días del proveedor
                status: estadoProveedor, // Estado del proveedor
                profiles: profilesActualizados // Perfiles con días individuales
            };
        });
        
        console.log(`📊 Enviando ${accounts.length} cuentas con fechas actualizadas`);
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
            fecha_inicio_proveedor
        } = req.body;
        
        console.log('📥 Creando nueva cuenta:', {
            id, client_name, type, fecha_inicio_proveedor
        });
        
        // Calcular fecha de vencimiento del proveedor (30 días después del inicio)
        const fechaInicio = fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : new Date();
        const fechaVencimientoProveedor = new Date(fechaInicio);
        fechaVencimientoProveedor.setDate(fechaVencimientoProveedor.getDate() + 30);
        
        // Calcular días restantes del proveedor
        const diasRestantesProveedor = calcularDiasRestantes(fechaVencimientoProveedor);
        const estadoProveedor = actualizarEstado(diasRestantesProveedor);
        
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
                JSON.stringify(profiles), diasRestantesProveedor, estadoProveedor, 
                fechaInicio, fechaVencimientoProveedor, 'activo'
            ]
        );
        
        console.log('✅ Cuenta creada con días del proveedor:', result.rows[0].id);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('❌ Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

// Actualizar cuenta con perfiles y fechas
app.put('/api/accounts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { 
            client_name, client_phone, email, password, 
            type, country, profiles, days_remaining, status,
            fecha_inicio_proveedor, fecha_vencimiento_proveedor
        } = req.body;
        
        console.log('📝 Actualizando cuenta:', id);
        
        // Procesar perfiles para asegurar que tengan fechas correctas
        const profilesActualizados = procesarPerfiles(profiles);
        
        const result = await pool.query(
            `UPDATE accounts SET 
                client_name = $1, client_phone = $2, email = $3, password = $4, 
                type = $5, country = $6, profiles = $7, days_remaining = $8, status = $9,
                fecha_inicio_proveedor = $10, fecha_vencimiento_proveedor = $11
             WHERE id = $12 RETURNING *`,
            [
                client_name, client_phone || '', email, password, type, country, 
                JSON.stringify(profilesActualizados), days_remaining, status,
                fecha_inicio_proveedor ? new Date(fecha_inicio_proveedor) : null,
                fecha_vencimiento_proveedor ? new Date(fecha_vencimiento_proveedor) : null,
                id
            ]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        console.log('✅ Cuenta actualizada con fechas de perfiles:', id);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('❌ Error actualizando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor: ' + error.message });
    }
});

// Subir voucher para perfil específico
app.post('/api/accounts/:accountId/profile/:profileIndex/voucher', upload.single('voucher'), async (req, res) => {
    try {
        const { accountId, profileIndex } = req.params;
        const { numero_operacion, monto_pagado } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ error: 'No se subió ningún archivo' });
        }
        
        // Obtener la cuenta
        const accountResult = await pool.query('SELECT * FROM accounts WHERE id = $1', [accountId]);
        if (accountResult.rows.length === 0) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        
        const account = accountResult.rows[0];
        const profiles = typeof account.profiles === 'string' 
            ? JSON.parse(account.profiles) 
            : account.profiles || [];
        
        const profileIdx = parseInt(profileIndex);
        if (profileIdx < 0 || profileIdx >= profiles.length) {
            return res.status(400).json({ error: 'Índice de perfil inválido' });
        }
        
        const profile = profiles[profileIdx];
        
        // Convertir imagen a base64
        const voucherBase64 = req.file.buffer.toString('base64');
        
        // Actualizar perfil con voucher
        profile.voucherImagen = voucherBase64;
        profile.numeroOperacion = numero_operacion;
        profile.montoPagado = parseFloat(monto_pagado);
        profile.voucherSubido = true;
        profile.fechaVoucher = new Date().toISOString();
        
        // Si el perfil está vendido, es una renovación
        if (profile.estado === 'vendido') {
            const fechaVencimientoActual = new Date(profile.fechaVencimiento);
            const nuevaFechaVencimiento = new Date(fechaVencimientoActual);
            nuevaFechaVencimiento.setDate(nuevaFechaVencimiento.getDate() + 30);
            
            // Actualizar fechas del cliente
            profile.fechaVencimiento = nuevaFechaVencimiento.toISOString().split('T')[0];
            
            const fechaProximoPago = new Date(nuevaFechaVencimiento);
            fechaProximoPago.setDate(fechaProximoPago.getDate() - 1);
            profile.fechaProximoPago = fechaProximoPago.toISOString().split('T')[0];
            
            profile.fechaCorte = nuevaFechaVencimiento.toISOString().split('T')[0];
            profile.diasRestantes = calcularDiasRestantesPerfil(profile.fechaVencimiento);
            profile.estadoPago = 'pagado';
            profile.fechaUltimaRenovacion = new Date().toISOString().split('T')[0];
            
            console.log(`🔄 Perfil renovado: ${profile.name} - ${profile.diasRestantes} días más`);
        } else {
            // Perfil disponible, solo confirmar voucher
            profile.estadoPago = 'confirmado';
            console.log(`💳 Voucher confirmado para perfil disponible: ${profile.name}`);
        }
        
        // Guardar en base de datos
        await pool.query(
            'UPDATE accounts SET profiles = $1 WHERE id = $2',
            [JSON.stringify(profiles), accountId]
        );
        
        res.json({ 
            success: true, 
            message: profile.estado === 'vendido' ? 'Perfil renovado exitosamente' : 'Voucher confirmado',
            profile: profile
        });
        
    } catch (error) {
        console.error('❌ Error subiendo voucher:', error);
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
        
        // Calcular estados en tiempo real
        const accountsResult = await pool.query(`
            SELECT 
                fecha_vencimiento_proveedor,
                profiles
            FROM accounts
        `);
        
        let activeCount = 0;
        let expiringCount = 0;
        let totalProfiles = 0;
        let soldProfiles = 0;
        const today = new Date();
        
        accountsResult.rows.forEach(row => {
            const profiles = typeof row.profiles === 'string' ? JSON.parse(row.profiles) : row.profiles || [];
            totalProfiles += profiles.length;
            
            // Contar perfiles vendidos
            soldProfiles += profiles.filter(p => p.estado === 'vendido').length;
            
            // Estado de la cuenta del proveedor
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
            console.log(`📅 Sistema de fechas de perfiles: ACTIVO`);
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
