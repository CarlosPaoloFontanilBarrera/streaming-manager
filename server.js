// ===============================================
// 🚀 PATCHES PARA TU SERVER.JS ACTUAL
// ===============================================
// APLICAR ESTOS CAMBIOS LÍNEA POR LÍNEA A TU ARCHIVO

// ✅ PASO 1: AGREGAR IMPORTS DE PERFORMANCE
// BUSCAR la línea: const { body, validationResult } = require('express-validator');
// AGREGAR DESPUÉS de esa línea:

// 🚀 DEPENDENCIAS DE PERFORMANCE - AGREGAR ESTAS LÍNEAS
const compression = require('compression');
const NodeCache = require('node-cache');
const sharp = require('sharp');
const ExcelJS = require('exceljs');
const moment = require('moment');
const cron = require('node-cron');

// ===============================================
// ✅ PASO 2: CONFIGURAR CACHE
// BUSCAR la línea: const BCRYPT_ROUNDS = 12;
// AGREGAR DESPUÉS:

// 🚀 Cache optimizado con TTL inteligente - AGREGAR
const cache = new NodeCache({ 
    stdTTL: parseInt(process.env.CACHE_TTL) || 300, // 5 minutos default
    checkperiod: 60, // Verificar cada minuto
    useClones: false, // Mejor performance
    deleteOnExpire: true,
    maxKeys: 1000 // Límite de memoria
});

// ===============================================
// ✅ PASO 3: AGREGAR COMPRESIÓN
// BUSCAR la línea: app.use(helmet({
// AGREGAR ANTES de esa línea:

// 🚀 Compresión avanzada - AGREGAR ANTES DE HELMET
app.use(compression({
    level: 6, // Balance entre velocidad y compresión
    threshold: 1024, // Solo comprimir archivos > 1KB
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

// ===============================================
// ✅ PASO 4: OPTIMIZAR POSTGRESQL
// BUSCAR la línea: const pool = new Pool({
// REEMPLAZAR ESE BLOQUE CON:

// 🚀 Configuración de PostgreSQL optimizada - REEMPLAZAR
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    // Optimizaciones de conexión
    max: 20, // Máximo 20 conexiones
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    allowExitOnIdle: true
});

// ===============================================
// ✅ PASO 5: AGREGAR FUNCIONES DE CACHE
// BUSCAR la línea: function procesarPerfiles(profiles) {
// AGREGAR ANTES de esa función:

// 🚀 Sistema de cache inteligente - AGREGAR
function getCacheKey(prefix, ...args) {
    return `${prefix}:${args.join(':')}`;
}

function setCacheWithTTL(key, data, ttl = 300) {
    cache.set(key, data, ttl);
}

function getCachedData(key) {
    return cache.get(key);
}

// Middleware de cache para APIs - AGREGAR
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

// 🚀 OPTIMIZACIÓN DE IMÁGENES CON SHARP - AGREGAR
async function optimizeImage(buffer, options = {}) {
    const {
        width = 1200,
        height = 800,
        quality = 85,
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
// ✅ PASO 6: MEJORAR INITDB CON ÍNDICES
// BUSCAR la línea: console.log('✅ Base de datos inicializada correctamente');
// AGREGAR ANTES de esa línea:

        // 🚀 CREAR ÍNDICES PARA PERFORMANCE - AGREGAR
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_type ON accounts(type)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_created_at ON accounts(created_at DESC)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_expiry ON accounts(fecha_vencimiento_proveedor)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_accounts_client_search ON accounts USING gin(to_tsvector('spanish', client_name || ' ' || email))`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_notifications_sent_at ON sent_notifications(sent_at DESC)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_username ON admin_users(username)`);

// ===============================================
// ✅ PASO 7: AGREGAR CACHE A API ROUTES
// BUSCAR la línea: app.get('/api/accounts', verifyToken, async (req, res) => {
// REEMPLAZAR CON:

// 🚀 Cuentas con cache y paginación - REEMPLAZAR
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

// ===============================================
// ✅ PASO 8: AGREGAR CACHE A STATS
// BUSCAR la línea: app.get('/api/stats', verifyToken, async (req, res) => {
// REEMPLAZAR CON:

// 🚀 Estadísticas con cache inteligente - REEMPLAZAR
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
// ✅ PASO 9: OPTIMIZAR VOUCHERS CON SHARP
// BUSCAR la línea: const voucherBase64 = req.file.buffer.toString('base64');
// REEMPLAZAR ESE BLOQUE CON:

        // 🚀 OPTIMIZAR IMAGEN CON SHARP - REEMPLAZAR
        console.log(`📤 Procesando voucher: ${req.file.originalname} (${req.file.size} bytes)`);
        
        // Optimizar imagen antes de guardar
        console.log('🖼️ Optimizando imagen con Sharp...');
        const optimizedBuffer = await optimizeImage(req.file.buffer, {
            width: 800,
            height: 600,
            quality: 75
        });
        
        const voucherBase64 = optimizedBuffer.toString('base64');
        const compressionRatio = ((req.file.size - optimizedBuffer.length) / req.file.size * 100).toFixed(1);
        console.log(`✅ Imagen optimizada: ${req.file.size} → ${optimizedBuffer.length} bytes (${compressionRatio}% reducción)`);

// ===============================================
// ✅ PASO 10: AGREGAR INVALIDACIÓN DE CACHE
// EN LAS RUTAS POST, PUT, DELETE agregar después de la operación exitosa:

        // Invalidar cache relacionado - AGREGAR en POST/PUT/DELETE
        cache.del(getCacheKey('api', '/api/accounts', req.user?.userId || 'anonymous'));
        cache.del(getCacheKey('api', '/api/stats', req.user?.userId || 'anonymous'));

// ===============================================
// ✅ PASO 11: NUEVAS APIS DE PERFORMANCE
// AGREGAR ANTES de las rutas estáticas:

// 🚀 API de Analytics con cache inteligente - AGREGAR
app.get('/api/analytics', verifyToken, cacheMiddleware(600), async (req, res) => {
    try {
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

// 🚀 API de exportación a Excel - AGREGAR
app.get('/api/export/excel', verifyToken, async (req, res) => {
    try {
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

// 🚀 API de limpieza de cache - AGREGAR
app.post('/api/cache/clear', verifyToken, (req, res) => {
    try {
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
// ✅ PASO 12: MEJORAR HEALTH CHECK
// BUSCAR la línea: app.get('/api/health', (req, res) => {
// REEMPLAZAR CON:

// 🚀 Health check con información del sistema - REEMPLAZAR
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
            misses: cacheStats.misses
        }
    });
});

// ===============================================
// ✅ PASO 13: AGREGAR TAREAS PROGRAMADAS
// BUSCAR la línea: console.log('⏰ Sistema de alarmas ntfy iniciado');
// AGREGAR DESPUÉS:

            // 🚀 TAREAS PROGRAMADAS - AGREGAR
            
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

            console.log('📦 Cache NodeCache inicializado (TTL: 300s)');
            console.log('🗜️ Compresión gzip habilitada');
            console.log('🖼️ Optimización de imágenes Sharp habilitada');
            console.log('📊 Analytics y Excel habilitados');
            console.log('⏰ Tareas programadas iniciadas');
            console.log('📈 Versión: 2.2.0 - PERFORMANCE EDITION');

// ===============================================
// ✅ PASO 14: MEJORAR GRACEFUL SHUTDOWN
// BUSCAR la línea: process.on('SIGTERM', () => {
// REEMPLAZAR TODO EL BLOQUE DE SHUTDOWN CON:

// 🚀 Graceful shutdown optimizado - REEMPLAZAR
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
