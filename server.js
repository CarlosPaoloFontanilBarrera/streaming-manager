// ===============================================
// 🚀 JIREH STREAMING MANAGER v2.2.0 - PERFORMANCE EDITION
// Sistema profesional de gestión multi-plataforma con optimizaciones avanzadas
// ===============================================

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const multer = require('multer');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

// 🚀 DEPENDENCIAS DE PERFORMANCE
const compression = require('compression');
const NodeCache = require('node-cache');
const sharp = require('sharp');
const ExcelJS = require('exceljs');
const moment = require('moment');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;

// ===============================================
// 🔐 CONFIGURACIÓN DE SEGURIDAD
// ===============================================

const JWT_SECRET = process.env.JWT_SECRET || 'jireh-streaming-secret-2024';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// 🚀 Cache optimizado con TTL inteligente
const cache = new NodeCache({ 
    stdTTL: parseInt(process.env.CACHE_TTL) || 300, // 5 minutos default
    checkperiod: 60, // Verificar cada minuto
    useClones: false, // Mejor performance
    deleteOnExpire: true,
    maxKeys: 1000 // Límite de memoria
});

// 🚀 Compresión avanzada
app.use(compression({
    level: parseInt(process.env.COMPRESSION_LEVEL) || 6,
    threshold: 1024, // Solo comprimir archivos > 1KB
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

// Configuración de seguridad con Helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: ["'self'", "https://ntfy.sh"]
        }
    }
}));

// Rate limiting configurado para Railway
const createRateLimit = (windowMs, max, message) => rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    trustProxy: true // Importante para Railway
});

const generalLimiter = createRateLimit(15 * 60 * 1000, parseInt(process.env.API_RATE_LIMIT) || 100, 'Demasiadas solicitudes');
const loginLimiter = createRateLimit(15 * 60 * 1000, parseInt(process.env.LOGIN_RATE_LIMIT) || 5, 'Demasiados intentos de login');
const uploadLimiter = createRateLimit(60 * 1000, parseInt(process.env.UPLOAD_RATE_LIMIT) || 10, 'Demasiadas subidas de archivos');

app.use('/api/', generalLimiter);
app.use('/api/login', loginLimiter);

// Middlewares básicos
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ===============================================
// 🚀 CONFIGURACIÓN DE POSTGRESQL OPTIMIZADA
// ===============================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    // Optimizaciones de conexión
    max: parseInt(process.env.POOL_MAX_CONNECTIONS) || 20,
    idleTimeoutMillis: parseInt(process.env.POOL_IDLE_TIMEOUT) || 30000,
    connectionTimeoutMillis: parseInt(process.env.POOL_CONNECTION_TIMEOUT) || 2000,
    allowExitOnIdle: true
});

// ===============================================
// 🚀 SISTEMA DE CACHE INTELIGENTE
// ===============================================

function getCacheKey(prefix, ...args) {
    return `${prefix}:${args.join(':')}`;
}

function setCacheWithTTL(key, data, ttl = 300) {
    cache.set(key, data, ttl);
}

function getCachedData(key) {
    return cache.get(key);
}

// Middleware de cache para APIs
function cacheMiddleware(ttl = 300) {
    return (req, res, next) => {
        if (req.method !== 'GET') return next();
        
        const cacheKey = getCacheKey('api', req.originalUrl, req.user?.userId || 'anonymous');
        const cachedData = getCachedData(cacheKey);
        
        if (cachedData) {
            console.log(`📦 Cache hit: ${cacheKey}`);
            return res.json(cachedData);
        }
        
        // Interceptar res.json para cachear
        const originalJson = res.json;
        res.json = function(data) {
            setCacheWithTTL(cacheKey, data, ttl);
            console.log(`💾 Cache set: ${cacheKey}`);
            return originalJson.call(this, data);
        };
        
        next();
    };
}

// 🚀 OPTIMIZACIÓN DE IMÁGENES CON SHARP
async function optimizeImage(buffer, options = {}) {
    const {
        width = 1200,
        height = 800,
        quality = parseInt(process.env.IMAGE_QUALITY) || 75,
        format = 'jpeg'
    } = options;

    try {
        return await sharp(buffer)
            .resize(width, height, { 
                fit: 'inside', 
                withoutEnlargement: true 
            })
            .jpeg({ 
                quality, 
                progressive: true,
                mozjpeg: true // Mejor compresión
            })
            .toBuffer();
    } catch (error) {
        console.error('Error optimizando imagen:', error);
        return buffer; // Retornar original si falla
    }
}

// ===============================================
// 🔐 MIDDLEWARE DE AUTENTICACIÓN
// ===============================================

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('❌ Token inválido:', error.message);
        return res.status(403).json({ error: 'Token inválido o expirado' });
    }
};

// ===============================================
// 🗄️ INICIALIZACIÓN DE BASE DE DATOS
// ===============================================

async function initDB() {
    try {
        console.log('🔧 Inicializando base de datos...');
        
        // ===============================================
        // 🔄 MIGRACIÓN INTELIGENTE DE TABLA admin_users
        // ===============================================
        
        // Verificar si la tabla existe y su estructura
        const tableExists = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'admin_users'
        `);
        
        if (tableExists.rows.length === 0) {
            // Tabla no existe - crear nueva con estructura correcta
            console.log('📝 Creando nueva tabla admin_users...');
            await pool.query(`
                CREATE TABLE admin_users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
        } else {
            // Verificar si tiene la columna password_hash
            const hasPasswordHash = tableExists.rows.some(row => row.column_name === 'password_hash');
            const hasPassword = tableExists.rows.some(row => row.column_name === 'password');
            
            if (!hasPasswordHash && hasPassword) {
                console.log('🔄 Migrando tabla admin_users de password a password_hash...');
                
                // Agregar nueva columna password_hash
                await pool.query(`ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255)`);
                
                // Migrar passwords existentes (solo si no están ya hasheados)
                const existingUsers = await pool.query('SELECT id, username, password FROM admin_users WHERE password_hash IS NULL');
                
                for (const user of existingUsers.rows) {
                    // Verificar si ya está hasheado (bcrypt hash empieza con $2b$)
                    if (!user.password.startsWith('$2b

// ===============================================
// 🔍 FUNCIONES AUXILIARES
// ===============================================

function procesarPerfiles(profiles) {
    if (!profiles || profiles.length === 0) {
        return { perfiles: 'Sin perfiles configurados', vendidos: 0, disponibles: 0 };
    }
    
    const vendidos = profiles.filter(p => p.estado === 'vendido').length;
    const disponibles = profiles.length - vendidos;
    
    return {
        perfiles: profiles.map(p => `${p.perfil}: ${p.estado === 'vendido' ? '❌ Vendido' : '✅ Disponible'}`).join('<br>'),
        vendidos,
        disponibles
    };
}

function calcularDiasRestantes(fechaVencimiento) {
    if (!fechaVencimiento) return 0;
    
    const hoy = new Date();
    const vencimiento = new Date(fechaVencimiento);
    const diffTime = vencimiento - hoy;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    return Math.max(0, diffDays);
}

// Configuración de multer para archivos
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Solo se permiten archivos de imagen (JPEG, PNG)'), false);
        }
    }
});

// ===============================================
// 🔐 RUTAS DE AUTENTICACIÓN
// ===============================================

app.post('/api/login', [
    body('username').trim().isLength({ min: 1 }).withMessage('Username requerido'),
    body('password').isLength({ min: 1 }).withMessage('Password requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Datos inválidos',
                details: errors.array()
            });
        }

        const { username, password } = req.body;

        const userResult = await pool.query(
            'SELECT id, username, password_hash FROM admin_users WHERE username = $1',
            [username]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const user = userResult.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log(`✅ Login exitoso: ${username}`);
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username
            }
        });

    } catch (error) {
        console.error('❌ Error en login:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ===============================================
// 📊 APIS DE DATOS OPTIMIZADAS
// ===============================================

// 🚀 Cuentas con cache y paginación
app.get('/api/accounts', verifyToken, cacheMiddleware(120), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;
        const search = req.query.search;

        let query = 'SELECT * FROM accounts';
        let countQuery = 'SELECT COUNT(*) FROM accounts';
        let params = [];

        if (search) {
            query += ` WHERE to_tsvector('spanish', client_name || ' ' || email || ' ' || type) @@ plainto_tsquery('spanish', $1)`;
            countQuery += ` WHERE to_tsvector('spanish', client_name || ' ' || email || ' ' || type) @@ plainto_tsquery('spanish', $1)`;
            params.push(search);
        }

        query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
        params.push(limit, offset);

        const [accountsResult, countResult] = await Promise.all([
            pool.query(query, params),
            pool.query(countQuery, search ? [search] : [])
        ]);

        const total = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(total / limit);

        res.json({
            accounts: accountsResult.rows,
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });
    } catch (error) {
        console.error('❌ Error obteniendo cuentas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// 🚀 Estadísticas con cache inteligente
app.get('/api/stats', verifyToken, cacheMiddleware(60), async (req, res) => {
    try {
        // Usar queries optimizadas en paralelo
        const [totalResult, accountsResult] = await Promise.all([
            pool.query('SELECT COUNT(*) FROM accounts'),
            pool.query('SELECT fecha_vencimiento_proveedor, profiles FROM accounts')
        ]);
        
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

// ===============================================
// 🚀 NUEVAS APIS DE PERFORMANCE
// ===============================================

// 🚀 API de Analytics con cache inteligente
app.get('/api/analytics', verifyToken, cacheMiddleware(600), async (req, res) => {
    try {
        if (process.env.ENABLE_ANALYTICS !== 'true') {
            return res.status(403).json({ error: 'Analytics deshabilitado' });
        }

        const { period = '30d' } = req.query;
        
        let dateFilter = '';
        switch(period) {
            case '7d':
                dateFilter = "WHERE created_at >= NOW() - INTERVAL '7 days'";
                break;
            case '30d':
                dateFilter = "WHERE created_at >= NOW() - INTERVAL '30 days'";
                break;
            case '90d':
                dateFilter = "WHERE created_at >= NOW() - INTERVAL '90 days'";
                break;
            default:
                dateFilter = "WHERE created_at >= NOW() - INTERVAL '30 days'";
        }

        const [
            accountsOverTime,
            serviceTypes,
            countryStats
        ] = await Promise.all([
            pool.query(`
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as accounts_created,
                    AVG(days_remaining) as avg_days_remaining
                FROM accounts 
                ${dateFilter}
                GROUP BY DATE(created_at)
                ORDER BY date DESC
                LIMIT 30
            `),
            pool.query(`
                SELECT 
                    type,
                    COUNT(*) as count,
                    AVG(days_remaining) as avg_days
                FROM accounts 
                GROUP BY type
                ORDER BY count DESC
            `),
            pool.query(`
                SELECT 
                    country,
                    COUNT(*) as count
                FROM accounts 
                GROUP BY country
                ORDER BY count DESC
            `)
        ]);

        res.json({
            period,
            accounts_over_time: accountsOverTime.rows,
            service_types: serviceTypes.rows,
            country_stats: countryStats.rows,
            generated_at: new Date().toISOString()
        });

    } catch (error) {
        console.error('❌ Error en analytics:', error);
        res.status(500).json({ error: 'Error generando analytics' });
    }
});

// 🚀 API de exportación a Excel
app.get('/api/export/excel', verifyToken, async (req, res) => {
    try {
        if (process.env.ENABLE_EXCEL_EXPORT !== 'true') {
            return res.status(403).json({ error: 'Exportación Excel deshabilitada' });
        }

        console.log('📊 Generando reporte Excel...');
        
        const accounts = await pool.query(`
            SELECT 
                id, client_name, client_phone, email, type, country,
                status, days_remaining, created_at,
                fecha_inicio_proveedor, fecha_vencimiento_proveedor
            FROM accounts 
            ORDER BY created_at DESC
        `);

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Cuentas JIREH Streaming');

        // Configurar columnas
        worksheet.columns = [
            { header: 'ID', key: 'id', width: 15 },
            { header: 'Cliente', key: 'client_name', width: 25 },
            { header: 'Teléfono', key: 'client_phone', width: 15 },
            { header: 'Email', key: 'email', width: 30 },
            { header: 'Tipo Servicio', key: 'type', width: 25 },
            { header: 'País', key: 'country', width: 10 },
            { header: 'Estado', key: 'status', width: 12 },
            { header: 'Días Restantes', key: 'days_remaining', width: 15 },
            { header: 'Fecha Creación', key: 'created_at', width: 20 },
            { header: 'Inicio Proveedor', key: 'fecha_inicio_proveedor', width: 20 },
            { header: 'Vencimiento Proveedor', key: 'fecha_vencimiento_proveedor', width: 20 }
        ];

        // Estilo del header
        worksheet.getRow(1).font = { bold: true };
        worksheet.getRow(1).fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFE50914' }
        };

        // Agregar datos
        accounts.rows.forEach(account => {
            worksheet.addRow({
                ...account,
                created_at: moment(account.created_at).format('YYYY-MM-DD HH:mm'),
                fecha_inicio_proveedor: account.fecha_inicio_proveedor ? moment(account.fecha_inicio_proveedor).format('YYYY-MM-DD') : '',
                fecha_vencimiento_proveedor: account.fecha_vencimiento_proveedor ? moment(account.fecha_vencimiento_proveedor).format('YYYY-MM-DD') : ''
            });
        });

        // Configurar respuesta
        const filename = `jireh-streaming-${moment().format('YYYY-MM-DD-HHmm')}.xlsx`;
        
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

        await workbook.xlsx.write(res);
        res.end();

        console.log(`✅ Reporte Excel generado: ${filename}`);

    } catch (error) {
        console.error('❌ Error generando Excel:', error);
        res.status(500).json({ error: 'Error generando reporte Excel' });
    }
});

// 🚀 API de limpieza de cache
app.post('/api/cache/clear', verifyToken, (req, res) => {
    try {
        if (process.env.ENABLE_CACHE_API !== 'true') {
            return res.status(403).json({ error: 'API de cache deshabilitada' });
        }

        const stats = cache.getStats();
        cache.flushAll();
        
        console.log('🧹 Cache limpiado manualmente');
        
        res.json({
            success: true,
            message: 'Cache limpiado exitosamente',
            previous_stats: stats,
            cleared_at: new Date().toISOString()
        });
    } catch (error) {
        console.error('❌ Error limpiando cache:', error);
        res.status(500).json({ error: 'Error limpiando cache' });
    }
});

// ===============================================
// 📝 GESTIÓN DE CUENTAS
// ===============================================

app.post('/api/accounts', verifyToken, uploadLimiter, upload.single('voucher'), [
    body('client_name').trim().isLength({ min: 1 }).withMessage('Nombre del cliente requerido'),
    body('email').optional().isEmail().withMessage('Email inválido'),
    body('type').trim().isLength({ min: 1 }).withMessage('Tipo de servicio requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Datos inválidos',
                details: errors.array()
            });
        }

        const {
            client_name, client_phone, email, type, country = 'PE',
            email_proveedor, password_proveedor, fecha_inicio_proveedor,
            fecha_vencimiento_proveedor, profiles, comunicados
        } = req.body;

        let voucherBase64 = null;
        
        if (req.file) {
            console.log(`📤 Procesando voucher: ${req.file.originalname} (${req.file.size} bytes)`);
            
            if (process.env.ENABLE_IMAGE_OPTIMIZATION === 'true') {
                console.log('🖼️ Optimizando imagen con Sharp...');
                const optimizedBuffer = await optimizeImage(req.file.buffer, {
                    width: 800,
                    height: 600,
                    quality: 75
                });
                
                voucherBase64 = optimizedBuffer.toString('base64');
                const compressionRatio = ((req.file.size - optimizedBuffer.length) / req.file.size * 100).toFixed(1);
                console.log(`✅ Imagen optimizada: ${req.file.size} → ${optimizedBuffer.length} bytes (${compressionRatio}% reducción)`);
            } else {
                voucherBase64 = req.file.buffer.toString('base64');
            }
        }

        const days_remaining = calcularDiasRestantes(fecha_vencimiento_proveedor);
        
        const parsedProfiles = profiles ? JSON.parse(profiles) : [];

        const result = await pool.query(`
            INSERT INTO accounts (
                client_name, client_phone, email, type, country,
                email_proveedor, password_proveedor, fecha_inicio_proveedor,
                fecha_vencimiento_proveedor, days_remaining, profiles,
                comunicados, voucher_base64
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id
        `, [
            client_name, client_phone, email, type, country,
            email_proveedor, password_proveedor, fecha_inicio_proveedor,
            fecha_vencimiento_proveedor, days_remaining, JSON.stringify(parsedProfiles),
            comunicados, voucherBase64
        ]);

        // Invalidar cache relacionado
        cache.del(getCacheKey('api', '/api/accounts', req.user?.userId || 'anonymous'));
        cache.del(getCacheKey('api', '/api/stats', req.user?.userId || 'anonymous'));

        console.log(`✅ Nueva cuenta creada: ID ${result.rows[0].id} - ${client_name}`);
        
        res.status(201).json({
            success: true,
            message: 'Cuenta creada exitosamente',
            id: result.rows[0].id
        });

    } catch (error) {
        console.error('❌ Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.put('/api/accounts/:id', verifyToken, upload.single('voucher'), async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = { ...req.body };

        if (req.file) {
            if (process.env.ENABLE_IMAGE_OPTIMIZATION === 'true') {
                const optimizedBuffer = await optimizeImage(req.file.buffer, {
                    width: 800,
                    height: 600,
                    quality: 75
                });
                updateData.voucher_base64 = optimizedBuffer.toString('base64');
            } else {
                updateData.voucher_base64 = req.file.buffer.toString('base64');
            }
        }

        if (updateData.fecha_vencimiento_proveedor) {
            updateData.days_remaining = calcularDiasRestantes(updateData.fecha_vencimiento_proveedor);
        }

        if (updateData.profiles) {
            updateData.profiles = JSON.stringify(JSON.parse(updateData.profiles));
        }

        const fields = Object.keys(updateData).map((key, index) => `${key} = $${index + 1}`).join(', ');
        const values = Object.values(updateData);
        values.push(id);

        await pool.query(`UPDATE accounts SET ${fields}, updated_at = CURRENT_TIMESTAMP WHERE id = $${values.length}`, values);

        // Invalidar cache relacionado
        cache.del(getCacheKey('api', '/api/accounts', req.user?.userId || 'anonymous'));
        cache.del(getCacheKey('api', '/api/stats', req.user?.userId || 'anonymous'));

        console.log(`✅ Cuenta actualizada: ID ${id}`);
        res.json({ success: true, message: 'Cuenta actualizada exitosamente' });

    } catch (error) {
        console.error('❌ Error actualizando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.delete('/api/accounts/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        await pool.query('DELETE FROM accounts WHERE id = $1', [id]);

        // Invalidar cache relacionado
        cache.del(getCacheKey('api', '/api/accounts', req.user?.userId || 'anonymous'));
        cache.del(getCacheKey('api', '/api/stats', req.user?.userId || 'anonymous'));

        console.log(`✅ Cuenta eliminada: ID ${id}`);
        res.json({ success: true, message: 'Cuenta eliminada exitosamente' });

    } catch (error) {
        console.error('❌ Error eliminando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ===============================================
// 🔔 SISTEMA DE NOTIFICACIONES NTFY
// ===============================================

async function sendNtfyNotification(topic, title, message, tags = [], priority = 3) {
    try {
        const response = await fetch(`https://ntfy.sh/${topic}`, {
            method: 'POST',
            headers: {
                'Title': title,
                'Tags': tags.join(','),
                'Priority': priority.toString()
            },
            body: message
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        console.log(`✅ Notificación enviada a ${topic}: ${title}`);
        return true;
    } catch (error) {
        console.error(`❌ Error enviando notificación a ${topic}:`, error);
        return false;
    }
}

async function checkAndSendAlarms() {
    try {
        const accounts = await pool.query(`
            SELECT id, client_name, type, days_remaining, fecha_vencimiento_proveedor 
            FROM accounts 
            WHERE fecha_vencimiento_proveedor IS NOT NULL
        `);

        const today = new Date();
        let alertCount = 0;

        for (const account of accounts.rows) {
            const vencimiento = new Date(account.fecha_vencimiento_proveedor);
            const diffDays = Math.ceil((vencimiento - today) / (1000 * 60 * 60 * 24));

            // Verificar si ya se envió notificación hoy
            const notificationCheck = await pool.query(`
                SELECT COUNT(*) FROM sent_notifications 
                WHERE account_id = $1 AND notification_type = $2 AND DATE(sent_at) = CURRENT_DATE
            `, [account.id, 'expiry_warning']);

            const alreadySent = parseInt(notificationCheck.rows[0].count) > 0;

            if ((diffDays <= 5 && diffDays > 0) && !alreadySent) {
                const message = `⚠️ CUENTA POR VENCER
Cliente: ${account.client_name}
Servicio: ${account.type}
Días restantes: ${diffDays}
Vence: ${vencimiento.toLocaleDateString('es-PE')}`;

                const success = await sendNtfyNotification(
                    'jireh-streaming-alerts',
                    `🚨 Cuenta por vencer (${diffDays} días)`,
                    message,
                    ['warning', 'alarm_clock'],
                    4
                );

                if (success) {
                    await pool.query(`
                        INSERT INTO sent_notifications (account_id, notification_type) 
                        VALUES ($1, $2)
                    `, [account.id, 'expiry_warning']);
                    alertCount++;
                }
            }
        }

        if (alertCount > 0) {
            console.log(`⏰ ${alertCount} alertas de vencimiento enviadas`);
        }

    } catch (error) {
        console.error('❌ Error en sistema de alarmas:', error);
    }
}

// ===============================================
// 🚀 HEALTH CHECK AVANZADO
// ===============================================

app.get('/api/health', (req, res) => {
    const memUsage = process.memoryUsage();
    const cacheStats = cache.getStats();
    
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '2.2.0',
        environment: process.env.NODE_ENV || 'development',
        uptime: process.uptime(),
        memory: {
            used: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
            total: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB'
        },
        cache: {
            keys: cacheStats.keys,
            hits: cacheStats.hits,
            misses: cacheStats.misses,
            hit_rate: cacheStats.hits > 0 ? ((cacheStats.hits / (cacheStats.hits + cacheStats.misses)) * 100).toFixed(2) + '%' : '0%'
        },
        features: {
            analytics: process.env.ENABLE_ANALYTICS === 'true',
            excel_export: process.env.ENABLE_EXCEL_EXPORT === 'true',
            image_optimization: process.env.ENABLE_IMAGE_OPTIMIZATION === 'true',
            cache_api: process.env.ENABLE_CACHE_API === 'true',
            cron_jobs: process.env.ENABLE_CRON_JOBS === 'true'
        }
    });
});

// ===============================================
// 🎨 RUTAS ESTÁTICAS
// ===============================================

app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.get('/dashboard', (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

// ===============================================
// 🚀 INICIALIZACIÓN DEL SERVIDOR
// ===============================================

async function startServer() {
    try {
        await initDB();
        
        app.listen(PORT, () => {
            console.log('🚀 ================================');
            console.log(`🎯 JIREH Streaming Manager v2.2.0`);
            console.log(`🌐 Servidor corriendo en puerto ${PORT}`);
            console.log('🚀 ================================');
            
            // Configurar sistema de alarmas
            console.log('⏰ Sistema de alarmas ntfy iniciado');
            
            if (process.env.ENABLE_CRON_JOBS === 'true') {
                // Ejecutar alarmas cada hora
                cron.schedule('0 * * * *', () => {
                    console.log('⏰ Ejecutando alarmas programadas...');
                    checkAndSendAlarms();
                });

                // Limpiar cache cada 6 horas
                cron.schedule('0 */6 * * *', () => {
                    const stats = cache.getStats();
                    console.log(`🧹 Limpieza automática de cache - Keys: ${stats.keys}, Hits: ${stats.hits}, Misses: ${stats.misses}`);
                    cache.flushAll();
                });

                // Optimizar base de datos cada domingo a las 3 AM
                cron.schedule('0 3 * * 0', async () => {
                    try {
                        console.log('🔧 Optimizando base de datos...');
                        await pool.query('VACUUM ANALYZE');
                        console.log('✅ Base de datos optimizada');
                    } catch (error) {
                        console.error('❌ Error optimizando base de datos:', error);
                    }
                });

                console.log('⏰ Tareas programadas iniciadas');
            }

            console.log('📦 Cache NodeCache inicializado (TTL: 300s)');
            console.log('🗜️ Compresión gzip habilitada');
            console.log('🖼️ Optimización de imágenes Sharp habilitada');
            console.log('📊 Analytics y Excel habilitados');
            console.log('📈 Versión: 2.2.0 - PERFORMANCE EDITION');
            console.log('🔐 Seguridad: JWT + bcrypt + Helmet + Rate Limiting');
            console.log('⚡ Performance: Cache + Compression + Sharp + Indices');
            console.log('🚀 ================================');
        });

    } catch (error) {
        console.error('❌ Error iniciando servidor:', error);
        process.exit(1);
    }
}

// ===============================================
// 🔚 GRACEFUL SHUTDOWN OPTIMIZADO
// ===============================================

async function gracefulShutdown(signal) {
    console.log(`${signal} recibido, cerrando servidor gracefully...`);
    
    try {
        // Cerrar pool de base de datos
        await pool.end();
        console.log('✅ Pool de PostgreSQL cerrado');
        
        // Mostrar estadísticas finales de cache
        const stats = cache.getStats();
        console.log(`📊 Estadísticas finales de cache - Keys: ${stats.keys}, Hits: ${stats.hits}, Misses: ${stats.misses}`);
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Error durante shutdown:', error);
        process.exit(1);
    }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ===============================================
// 🚀 INICIAR SERVIDOR
// ===============================================

startServer();)) {
                        console.log(`🔒 Hasheando password para usuario: ${user.username}`);
                        const hashedPassword = await bcrypt.hash(user.password, BCRYPT_ROUNDS);
                        await pool.query('UPDATE admin_users SET password_hash = $1 WHERE id = $2', [hashedPassword, user.id]);
                    } else {
                        // Ya está hasheado, solo copiar
                        await pool.query('UPDATE admin_users SET password_hash = $1 WHERE id = $2', [user.password, user.id]);
                    }
                }
                
                // Eliminar columna password antigua después de migrar
                console.log('🗑️ Eliminando columna password antigua...');
                await pool.query(`ALTER TABLE admin_users DROP COLUMN IF EXISTS password`);
                
                console.log('✅ Migración de admin_users completada');
            } else if (!hasPasswordHash) {
                // No tiene ni password ni password_hash - agregar password_hash
                await pool.query(`ALTER TABLE admin_users ADD COLUMN password_hash VARCHAR(255) NOT NULL DEFAULT ''`);
            }
        }

        // ===============================================
        // 📊 CREAR/VERIFICAR OTRAS TABLAS
        // ===============================================

        // Crear tabla principal de cuentas
        await pool.query(`
            CREATE TABLE IF NOT EXISTS accounts (
                id SERIAL PRIMARY KEY,
                client_name VARCHAR(255) NOT NULL,
                client_phone VARCHAR(20),
                email VARCHAR(255),
                type VARCHAR(100) NOT NULL,
                country VARCHAR(3) DEFAULT 'PE',
                email_proveedor VARCHAR(255),
                password_proveedor VARCHAR(255),
                fecha_inicio_proveedor DATE,
                fecha_vencimiento_proveedor DATE,
                days_remaining INTEGER DEFAULT 0,
                profiles TEXT,
                comunicados TEXT,
                voucher_base64 TEXT,
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Crear tabla de notificaciones enviadas
        await pool.query(`
            CREATE TABLE IF NOT EXISTS sent_notifications (
                id SERIAL PRIMARY KEY,
                account_id INTEGER REFERENCES accounts(id),
                notification_type VARCHAR(50),
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // ===============================================
        // 🚀 CREAR ÍNDICES PARA PERFORMANCE
        // ===============================================
        console.log('📈 Creando índices de performance...');
        
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_type ON accounts(type)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_created_at ON accounts(created_at DESC)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_expiry ON accounts(fecha_vencimiento_proveedor)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_client_search ON accounts USING gin(to_tsvector('spanish', client_name || ' ' || email))`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_notifications_sent_at ON sent_notifications(sent_at DESC)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_username ON admin_users(username)`);

        // ===============================================
        // 👤 VERIFICAR/CREAR USUARIO ADMIN
        // ===============================================
        
        // Verificar si existe usuario admin
        const adminCheck = await pool.query('SELECT COUNT(*) FROM admin_users WHERE username = $1', ['admin']);
        
        if (adminCheck.rows[0].count === '0') {
            console.log('👤 Creando usuario admin por defecto...');
            const defaultPassword = 'admin123';
            const hashedPassword = await bcrypt.hash(defaultPassword, BCRYPT_ROUNDS);
            
            await pool.query(
                'INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)',
                ['admin', hashedPassword]
            );
            
            console.log('✅ Usuario admin creado - Usuario: admin, Password: admin123');
        } else {
            console.log('👤 Usuario admin ya existe');
        }

        console.log('✅ Base de datos inicializada correctamente');
        console.log('📦 Índices de performance creados');
        
    } catch (error) {
        console.error('❌ Error inicializando base de datos:', error);
        throw error; // Re-throw para que el servidor no continue si hay error crítico
    }
}

// ===============================================
// 🔍 FUNCIONES AUXILIARES
// ===============================================

function procesarPerfiles(profiles) {
    if (!profiles || profiles.length === 0) {
        return { perfiles: 'Sin perfiles configurados', vendidos: 0, disponibles: 0 };
    }
    
    const vendidos = profiles.filter(p => p.estado === 'vendido').length;
    const disponibles = profiles.length - vendidos;
    
    return {
        perfiles: profiles.map(p => `${p.perfil}: ${p.estado === 'vendido' ? '❌ Vendido' : '✅ Disponible'}`).join('<br>'),
        vendidos,
        disponibles
    };
}

function calcularDiasRestantes(fechaVencimiento) {
    if (!fechaVencimiento) return 0;
    
    const hoy = new Date();
    const vencimiento = new Date(fechaVencimiento);
    const diffTime = vencimiento - hoy;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    return Math.max(0, diffDays);
}

// Configuración de multer para archivos
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Solo se permiten archivos de imagen (JPEG, PNG)'), false);
        }
    }
});

// ===============================================
// 🔐 RUTAS DE AUTENTICACIÓN
// ===============================================

app.post('/api/login', [
    body('username').trim().isLength({ min: 1 }).withMessage('Username requerido'),
    body('password').isLength({ min: 1 }).withMessage('Password requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Datos inválidos',
                details: errors.array()
            });
        }

        const { username, password } = req.body;

        const userResult = await pool.query(
            'SELECT id, username, password_hash FROM admin_users WHERE username = $1',
            [username]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const user = userResult.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log(`✅ Login exitoso: ${username}`);
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username
            }
        });

    } catch (error) {
        console.error('❌ Error en login:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ===============================================
// 📊 APIS DE DATOS OPTIMIZADAS
// ===============================================

// 🚀 Cuentas con cache y paginación
app.get('/api/accounts', verifyToken, cacheMiddleware(120), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;
        const search = req.query.search;

        let query = 'SELECT * FROM accounts';
        let countQuery = 'SELECT COUNT(*) FROM accounts';
        let params = [];

        if (search) {
            query += ` WHERE to_tsvector('spanish', client_name || ' ' || email || ' ' || type) @@ plainto_tsquery('spanish', $1)`;
            countQuery += ` WHERE to_tsvector('spanish', client_name || ' ' || email || ' ' || type) @@ plainto_tsquery('spanish', $1)`;
            params.push(search);
        }

        query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
        params.push(limit, offset);

        const [accountsResult, countResult] = await Promise.all([
            pool.query(query, params),
            pool.query(countQuery, search ? [search] : [])
        ]);

        const total = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(total / limit);

        res.json({
            accounts: accountsResult.rows,
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });
    } catch (error) {
        console.error('❌ Error obteniendo cuentas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// 🚀 Estadísticas con cache inteligente
app.get('/api/stats', verifyToken, cacheMiddleware(60), async (req, res) => {
    try {
        // Usar queries optimizadas en paralelo
        const [totalResult, accountsResult] = await Promise.all([
            pool.query('SELECT COUNT(*) FROM accounts'),
            pool.query('SELECT fecha_vencimiento_proveedor, profiles FROM accounts')
        ]);
        
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

// ===============================================
// 🚀 NUEVAS APIS DE PERFORMANCE
// ===============================================

// 🚀 API de Analytics con cache inteligente
app.get('/api/analytics', verifyToken, cacheMiddleware(600), async (req, res) => {
    try {
        if (process.env.ENABLE_ANALYTICS !== 'true') {
            return res.status(403).json({ error: 'Analytics deshabilitado' });
        }

        const { period = '30d' } = req.query;
        
        let dateFilter = '';
        switch(period) {
            case '7d':
                dateFilter = "WHERE created_at >= NOW() - INTERVAL '7 days'";
                break;
            case '30d':
                dateFilter = "WHERE created_at >= NOW() - INTERVAL '30 days'";
                break;
            case '90d':
                dateFilter = "WHERE created_at >= NOW() - INTERVAL '90 days'";
                break;
            default:
                dateFilter = "WHERE created_at >= NOW() - INTERVAL '30 days'";
        }

        const [
            accountsOverTime,
            serviceTypes,
            countryStats
        ] = await Promise.all([
            pool.query(`
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as accounts_created,
                    AVG(days_remaining) as avg_days_remaining
                FROM accounts 
                ${dateFilter}
                GROUP BY DATE(created_at)
                ORDER BY date DESC
                LIMIT 30
            `),
            pool.query(`
                SELECT 
                    type,
                    COUNT(*) as count,
                    AVG(days_remaining) as avg_days
                FROM accounts 
                GROUP BY type
                ORDER BY count DESC
            `),
            pool.query(`
                SELECT 
                    country,
                    COUNT(*) as count
                FROM accounts 
                GROUP BY country
                ORDER BY count DESC
            `)
        ]);

        res.json({
            period,
            accounts_over_time: accountsOverTime.rows,
            service_types: serviceTypes.rows,
            country_stats: countryStats.rows,
            generated_at: new Date().toISOString()
        });

    } catch (error) {
        console.error('❌ Error en analytics:', error);
        res.status(500).json({ error: 'Error generando analytics' });
    }
});

// 🚀 API de exportación a Excel
app.get('/api/export/excel', verifyToken, async (req, res) => {
    try {
        if (process.env.ENABLE_EXCEL_EXPORT !== 'true') {
            return res.status(403).json({ error: 'Exportación Excel deshabilitada' });
        }

        console.log('📊 Generando reporte Excel...');
        
        const accounts = await pool.query(`
            SELECT 
                id, client_name, client_phone, email, type, country,
                status, days_remaining, created_at,
                fecha_inicio_proveedor, fecha_vencimiento_proveedor
            FROM accounts 
            ORDER BY created_at DESC
        `);

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Cuentas JIREH Streaming');

        // Configurar columnas
        worksheet.columns = [
            { header: 'ID', key: 'id', width: 15 },
            { header: 'Cliente', key: 'client_name', width: 25 },
            { header: 'Teléfono', key: 'client_phone', width: 15 },
            { header: 'Email', key: 'email', width: 30 },
            { header: 'Tipo Servicio', key: 'type', width: 25 },
            { header: 'País', key: 'country', width: 10 },
            { header: 'Estado', key: 'status', width: 12 },
            { header: 'Días Restantes', key: 'days_remaining', width: 15 },
            { header: 'Fecha Creación', key: 'created_at', width: 20 },
            { header: 'Inicio Proveedor', key: 'fecha_inicio_proveedor', width: 20 },
            { header: 'Vencimiento Proveedor', key: 'fecha_vencimiento_proveedor', width: 20 }
        ];

        // Estilo del header
        worksheet.getRow(1).font = { bold: true };
        worksheet.getRow(1).fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFE50914' }
        };

        // Agregar datos
        accounts.rows.forEach(account => {
            worksheet.addRow({
                ...account,
                created_at: moment(account.created_at).format('YYYY-MM-DD HH:mm'),
                fecha_inicio_proveedor: account.fecha_inicio_proveedor ? moment(account.fecha_inicio_proveedor).format('YYYY-MM-DD') : '',
                fecha_vencimiento_proveedor: account.fecha_vencimiento_proveedor ? moment(account.fecha_vencimiento_proveedor).format('YYYY-MM-DD') : ''
            });
        });

        // Configurar respuesta
        const filename = `jireh-streaming-${moment().format('YYYY-MM-DD-HHmm')}.xlsx`;
        
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

        await workbook.xlsx.write(res);
        res.end();

        console.log(`✅ Reporte Excel generado: ${filename}`);

    } catch (error) {
        console.error('❌ Error generando Excel:', error);
        res.status(500).json({ error: 'Error generando reporte Excel' });
    }
});

// 🚀 API de limpieza de cache
app.post('/api/cache/clear', verifyToken, (req, res) => {
    try {
        if (process.env.ENABLE_CACHE_API !== 'true') {
            return res.status(403).json({ error: 'API de cache deshabilitada' });
        }

        const stats = cache.getStats();
        cache.flushAll();
        
        console.log('🧹 Cache limpiado manualmente');
        
        res.json({
            success: true,
            message: 'Cache limpiado exitosamente',
            previous_stats: stats,
            cleared_at: new Date().toISOString()
        });
    } catch (error) {
        console.error('❌ Error limpiando cache:', error);
        res.status(500).json({ error: 'Error limpiando cache' });
    }
});

// ===============================================
// 📝 GESTIÓN DE CUENTAS
// ===============================================

app.post('/api/accounts', verifyToken, uploadLimiter, upload.single('voucher'), [
    body('client_name').trim().isLength({ min: 1 }).withMessage('Nombre del cliente requerido'),
    body('email').optional().isEmail().withMessage('Email inválido'),
    body('type').trim().isLength({ min: 1 }).withMessage('Tipo de servicio requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Datos inválidos',
                details: errors.array()
            });
        }

        const {
            client_name, client_phone, email, type, country = 'PE',
            email_proveedor, password_proveedor, fecha_inicio_proveedor,
            fecha_vencimiento_proveedor, profiles, comunicados
        } = req.body;

        let voucherBase64 = null;
        
        if (req.file) {
            console.log(`📤 Procesando voucher: ${req.file.originalname} (${req.file.size} bytes)`);
            
            if (process.env.ENABLE_IMAGE_OPTIMIZATION === 'true') {
                console.log('🖼️ Optimizando imagen con Sharp...');
                const optimizedBuffer = await optimizeImage(req.file.buffer, {
                    width: 800,
                    height: 600,
                    quality: 75
                });
                
                voucherBase64 = optimizedBuffer.toString('base64');
                const compressionRatio = ((req.file.size - optimizedBuffer.length) / req.file.size * 100).toFixed(1);
                console.log(`✅ Imagen optimizada: ${req.file.size} → ${optimizedBuffer.length} bytes (${compressionRatio}% reducción)`);
            } else {
                voucherBase64 = req.file.buffer.toString('base64');
            }
        }

        const days_remaining = calcularDiasRestantes(fecha_vencimiento_proveedor);
        
        const parsedProfiles = profiles ? JSON.parse(profiles) : [];

        const result = await pool.query(`
            INSERT INTO accounts (
                client_name, client_phone, email, type, country,
                email_proveedor, password_proveedor, fecha_inicio_proveedor,
                fecha_vencimiento_proveedor, days_remaining, profiles,
                comunicados, voucher_base64
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id
        `, [
            client_name, client_phone, email, type, country,
            email_proveedor, password_proveedor, fecha_inicio_proveedor,
            fecha_vencimiento_proveedor, days_remaining, JSON.stringify(parsedProfiles),
            comunicados, voucherBase64
        ]);

        // Invalidar cache relacionado
        cache.del(getCacheKey('api', '/api/accounts', req.user?.userId || 'anonymous'));
        cache.del(getCacheKey('api', '/api/stats', req.user?.userId || 'anonymous'));

        console.log(`✅ Nueva cuenta creada: ID ${result.rows[0].id} - ${client_name}`);
        
        res.status(201).json({
            success: true,
            message: 'Cuenta creada exitosamente',
            id: result.rows[0].id
        });

    } catch (error) {
        console.error('❌ Error creando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.put('/api/accounts/:id', verifyToken, upload.single('voucher'), async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = { ...req.body };

        if (req.file) {
            if (process.env.ENABLE_IMAGE_OPTIMIZATION === 'true') {
                const optimizedBuffer = await optimizeImage(req.file.buffer, {
                    width: 800,
                    height: 600,
                    quality: 75
                });
                updateData.voucher_base64 = optimizedBuffer.toString('base64');
            } else {
                updateData.voucher_base64 = req.file.buffer.toString('base64');
            }
        }

        if (updateData.fecha_vencimiento_proveedor) {
            updateData.days_remaining = calcularDiasRestantes(updateData.fecha_vencimiento_proveedor);
        }

        if (updateData.profiles) {
            updateData.profiles = JSON.stringify(JSON.parse(updateData.profiles));
        }

        const fields = Object.keys(updateData).map((key, index) => `${key} = $${index + 1}`).join(', ');
        const values = Object.values(updateData);
        values.push(id);

        await pool.query(`UPDATE accounts SET ${fields}, updated_at = CURRENT_TIMESTAMP WHERE id = $${values.length}`, values);

        // Invalidar cache relacionado
        cache.del(getCacheKey('api', '/api/accounts', req.user?.userId || 'anonymous'));
        cache.del(getCacheKey('api', '/api/stats', req.user?.userId || 'anonymous'));

        console.log(`✅ Cuenta actualizada: ID ${id}`);
        res.json({ success: true, message: 'Cuenta actualizada exitosamente' });

    } catch (error) {
        console.error('❌ Error actualizando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.delete('/api/accounts/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        await pool.query('DELETE FROM accounts WHERE id = $1', [id]);

        // Invalidar cache relacionado
        cache.del(getCacheKey('api', '/api/accounts', req.user?.userId || 'anonymous'));
        cache.del(getCacheKey('api', '/api/stats', req.user?.userId || 'anonymous'));

        console.log(`✅ Cuenta eliminada: ID ${id}`);
        res.json({ success: true, message: 'Cuenta eliminada exitosamente' });

    } catch (error) {
        console.error('❌ Error eliminando cuenta:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ===============================================
// 🔔 SISTEMA DE NOTIFICACIONES NTFY
// ===============================================

async function sendNtfyNotification(topic, title, message, tags = [], priority = 3) {
    try {
        const response = await fetch(`https://ntfy.sh/${topic}`, {
            method: 'POST',
            headers: {
                'Title': title,
                'Tags': tags.join(','),
                'Priority': priority.toString()
            },
            body: message
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        console.log(`✅ Notificación enviada a ${topic}: ${title}`);
        return true;
    } catch (error) {
        console.error(`❌ Error enviando notificación a ${topic}:`, error);
        return false;
    }
}

async function checkAndSendAlarms() {
    try {
        const accounts = await pool.query(`
            SELECT id, client_name, type, days_remaining, fecha_vencimiento_proveedor 
            FROM accounts 
            WHERE fecha_vencimiento_proveedor IS NOT NULL
        `);

        const today = new Date();
        let alertCount = 0;

        for (const account of accounts.rows) {
            const vencimiento = new Date(account.fecha_vencimiento_proveedor);
            const diffDays = Math.ceil((vencimiento - today) / (1000 * 60 * 60 * 24));

            // Verificar si ya se envió notificación hoy
            const notificationCheck = await pool.query(`
                SELECT COUNT(*) FROM sent_notifications 
                WHERE account_id = $1 AND notification_type = $2 AND DATE(sent_at) = CURRENT_DATE
            `, [account.id, 'expiry_warning']);

            const alreadySent = parseInt(notificationCheck.rows[0].count) > 0;

            if ((diffDays <= 5 && diffDays > 0) && !alreadySent) {
                const message = `⚠️ CUENTA POR VENCER
Cliente: ${account.client_name}
Servicio: ${account.type}
Días restantes: ${diffDays}
Vence: ${vencimiento.toLocaleDateString('es-PE')}`;

                const success = await sendNtfyNotification(
                    'jireh-streaming-alerts',
                    `🚨 Cuenta por vencer (${diffDays} días)`,
                    message,
                    ['warning', 'alarm_clock'],
                    4
                );

                if (success) {
                    await pool.query(`
                        INSERT INTO sent_notifications (account_id, notification_type) 
                        VALUES ($1, $2)
                    `, [account.id, 'expiry_warning']);
                    alertCount++;
                }
            }
        }

        if (alertCount > 0) {
            console.log(`⏰ ${alertCount} alertas de vencimiento enviadas`);
        }

    } catch (error) {
        console.error('❌ Error en sistema de alarmas:', error);
    }
}

// ===============================================
// 🚀 HEALTH CHECK AVANZADO
// ===============================================

app.get('/api/health', (req, res) => {
    const memUsage = process.memoryUsage();
    const cacheStats = cache.getStats();
    
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '2.2.0',
        environment: process.env.NODE_ENV || 'development',
        uptime: process.uptime(),
        memory: {
            used: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
            total: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB'
        },
        cache: {
            keys: cacheStats.keys,
            hits: cacheStats.hits,
            misses: cacheStats.misses,
            hit_rate: cacheStats.hits > 0 ? ((cacheStats.hits / (cacheStats.hits + cacheStats.misses)) * 100).toFixed(2) + '%' : '0%'
        },
        features: {
            analytics: process.env.ENABLE_ANALYTICS === 'true',
            excel_export: process.env.ENABLE_EXCEL_EXPORT === 'true',
            image_optimization: process.env.ENABLE_IMAGE_OPTIMIZATION === 'true',
            cache_api: process.env.ENABLE_CACHE_API === 'true',
            cron_jobs: process.env.ENABLE_CRON_JOBS === 'true'
        }
    });
});

// ===============================================
// 🎨 RUTAS ESTÁTICAS
// ===============================================

app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.get('/dashboard', (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

// ===============================================
// 🚀 INICIALIZACIÓN DEL SERVIDOR
// ===============================================

async function startServer() {
    try {
        await initDB();
        
        app.listen(PORT, () => {
            console.log('🚀 ================================');
            console.log(`🎯 JIREH Streaming Manager v2.2.0`);
            console.log(`🌐 Servidor corriendo en puerto ${PORT}`);
            console.log('🚀 ================================');
            
            // Configurar sistema de alarmas
            console.log('⏰ Sistema de alarmas ntfy iniciado');
            
            if (process.env.ENABLE_CRON_JOBS === 'true') {
                // Ejecutar alarmas cada hora
                cron.schedule('0 * * * *', () => {
                    console.log('⏰ Ejecutando alarmas programadas...');
                    checkAndSendAlarms();
                });

                // Limpiar cache cada 6 horas
                cron.schedule('0 */6 * * *', () => {
                    const stats = cache.getStats();
                    console.log(`🧹 Limpieza automática de cache - Keys: ${stats.keys}, Hits: ${stats.hits}, Misses: ${stats.misses}`);
                    cache.flushAll();
                });

                // Optimizar base de datos cada domingo a las 3 AM
                cron.schedule('0 3 * * 0', async () => {
                    try {
                        console.log('🔧 Optimizando base de datos...');
                        await pool.query('VACUUM ANALYZE');
                        console.log('✅ Base de datos optimizada');
                    } catch (error) {
                        console.error('❌ Error optimizando base de datos:', error);
                    }
                });

                console.log('⏰ Tareas programadas iniciadas');
            }

            console.log('📦 Cache NodeCache inicializado (TTL: 300s)');
            console.log('🗜️ Compresión gzip habilitada');
            console.log('🖼️ Optimización de imágenes Sharp habilitada');
            console.log('📊 Analytics y Excel habilitados');
            console.log('📈 Versión: 2.2.0 - PERFORMANCE EDITION');
            console.log('🔐 Seguridad: JWT + bcrypt + Helmet + Rate Limiting');
            console.log('⚡ Performance: Cache + Compression + Sharp + Indices');
            console.log('🚀 ================================');
        });

    } catch (error) {
        console.error('❌ Error iniciando servidor:', error);
        process.exit(1);
    }
}

// ===============================================
// 🔚 GRACEFUL SHUTDOWN OPTIMIZADO
// ===============================================

async function gracefulShutdown(signal) {
    console.log(`${signal} recibido, cerrando servidor gracefully...`);
    
    try {
        // Cerrar pool de base de datos
        await pool.end();
        console.log('✅ Pool de PostgreSQL cerrado');
        
        // Mostrar estadísticas finales de cache
        const stats = cache.getStats();
        console.log(`📊 Estadísticas finales de cache - Keys: ${stats.keys}, Hits: ${stats.hits}, Misses: ${stats.misses}`);
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Error durante shutdown:', error);
        process.exit(1);
    }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ===============================================
// 🚀 INICIAR SERVIDOR
// ===============================================

startServer();
