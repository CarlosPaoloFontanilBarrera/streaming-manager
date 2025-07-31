// tests/setup.js - Configuración global para Jest
const { Pool } = require('pg');

// Variables globales para tests
global.testConfig = {
    jwtSecret: 'test-jwt-secret-key',
    testUser: {
        username: 'testuser',
        password: 'testpass123'
    },
    testAccount: {
        id: '123456',
        client_name: 'Test Cliente',
        client_phone: '+51987654321',
        email: 'test@ejemplo.com',
        password: 'testAccountPass123',
        type: 'Netflix Completa',
        country: 'PE',
        profiles: [
            {
                name: 'Perfil 1',
                pin: '1234',
                estado: 'disponible'
            }
        ],
        fecha_inicio_proveedor: '2025-01-01'
    }
};

// Pool de base de datos para tests
let testPool;

beforeAll(async () => {
    // Configurar variables de entorno para tests
    process.env.JWT_SECRET = global.testConfig.jwtSecret;
    process.env.NODE_ENV = 'test';
    
    // Usar base de datos de prueba si está disponible
    const testDatabaseUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;
    
    if (testDatabaseUrl) {
        testPool = new Pool({
            connectionString: testDatabaseUrl,
            ssl: false
        });
        
        global.testPool = testPool;
        
        try {
            // Verificar conexión
            await testPool.query('SELECT NOW()');
            console.log('✅ Conexión de prueba a BD establecida');
        } catch (error) {
            console.warn('⚠️ No se pudo conectar a BD de prueba:', error.message);
        }
    }
}, 30000);

afterAll(async () => {
    // Limpiar conexiones
    if (testPool) {
        await testPool.end();
    }
}, 10000);

// Función helper para limpiar tablas de prueba
global.cleanupTestData = async () => {
    if (!testPool) return;
    
    try {
        await testPool.query('DELETE FROM accounts WHERE id LIKE $1', ['test%']);
        await testPool.query('DELETE FROM admin_users WHERE username LIKE $1', ['test%']);
        await testPool.query('DELETE FROM sent_notifications WHERE item_id LIKE $1', ['test%']);
    } catch (error) {
        console.warn('⚠️ Error limpiando datos de prueba:', error.message);
    }
};

// Mock para fetch (ntfy calls)
global.fetch = jest.fn(() =>
    Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ success: true }),
    })
);

// Configuración de timeouts
jest.setTimeout(30000);
