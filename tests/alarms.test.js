// tests/alarms.test.js - Tests del Sistema de Alarmas
const request = require('supertest');
const jwt = require('jsonwebtoken');

describe('🚨 Sistema de Alarmas NTFY - FASE 2', () => {
    let app;
    let validToken;

    beforeAll(async () => {
        const express = require('express');
        app = express();
        app.use(express.json());
        
        const JWT_SECRET = global.testConfig.jwtSecret;
        
        // Middleware de autenticación
        const authenticateJWT = (req, res, next) => {
            const authHeader = req.headers.authorization;
            const token = authHeader && authHeader.split(' ')[1];

            if (!token) {
                return res.status(401).json({ error: 'Token de acceso requerido' });
            }

            jwt.verify(token, JWT_SECRET, (err, user) => {
                if (err) {
                    return res.status(403).json({ error: 'Token inválido o expirado' });
                }
                req.user = user;
                next();
            });
        };
        
        // Mock de configuraciones de alarmas
        let alarmSettings = {
            id: 1,
            provider_threshold_days: 5,
            client_threshold_days: 3,
            ntfy_topic: 'test-topic-jireh'
        };
        
        // Mock de notificaciones enviadas
        let sentNotifications = [];
        
        // Mock de cuentas para alarmas
        let mockAccounts = [];
        
        // Rutas de alarmas
        app.get('/api/alarms/settings', authenticateJWT, (req, res) => {
            res.json(alarmSettings);
        });
        
        app.put('/api/alarms/settings', authenticateJWT, (req, res) => {
            alarmSettings = {
                ...alarmSettings,
                ...req.body
            };
            res.json(alarmSettings);
        });
        
        app.post('/api/alarms/test', authenticateJWT, async (req, res) => {
            try {
                // Simular revisión de alarmas
                let alertsSent = 0;
                
                for (const account of mockAccounts) {
                    // Simular cálculo de días restantes
                    const providerDays = account.days_remaining || 0;
                    
                    if (providerDays > 0 && providerDays <= alarmSettings.provider_threshold_days) {
                        const notificationId = `provider-${account.id}`;
                        
                        // Verificar si ya se envió en las últimas 24h
                        const recentNotification = sentNotifications.find(n => 
                            n.item_id === notificationId && 
                            (Date.now() - new Date(n.sent_at).getTime()) < 24 * 60 * 60 * 1000
                        );
                        
                        if (!recentNotification) {
                            // Simular envío de notificación
                            if (global.fetch) {
                                await global.fetch(`https://ntfy.sh/${alarmSettings.ntfy_topic}`, {
                                    method: 'POST',
                                    body: `🚨 La cuenta de ${account.type} de "${account.client_name}" vence en ${providerDays} día(s).`,
                                    headers: { 'Title': 'Alarma de Proveedor', 'Priority': 'high', 'Tags': 'rotating_light' }
                                });
                            }
                            
                            sentNotifications.push({
                                item_id: notificationId,
                                item_type: 'provider',
                                sent_at: new Date().toISOString()
                            });
                            
                            alertsSent++;
                        }
                    }
                    
                    // Revisar perfiles de clientes
                    if (account.profiles) {
                        for (const [index, profile] of account.profiles.entries()) {
                            if (profile.estado === 'vendido' && profile.days_remaining) {
                                const clientDays = profile.days_remaining;
                                
                                if (clientDays > 0 && clientDays <= alarmSettings.client_threshold_days) {
                                    const notificationId = `client-${account.id}-${index}`;
                                    
                                    const recentNotification = sentNotifications.find(n => 
                                        n.item_id === notificationId && 
                                        (Date.now() - new Date(n.sent_at).getTime()) < 24 * 60 * 60 * 1000
                                    );
                                    
                                    if (!recentNotification) {
                                        if (global.fetch) {
                                            await global.fetch(`https://ntfy.sh/${alarmSettings.ntfy_topic}`, {
                                                method: 'POST',
                                                body: `🔔 El perfil "${profile.name}" del cliente ${profile.clienteNombre} (${account.type}) vence en ${clientDays} día(s).`,
                                                headers: { 'Title': 'Alarma de Cliente', 'Priority': 'default', 'Tags': 'bell' }
                                            });
                                        }
                                        
                                        sentNotifications.push({
                                            item_id: notificationId,
                                            item_type: 'client',
                                            sent_at: new Date().toISOString()
                                        });
                                        
                                        alertsSent++;
                                    }
                                }
                            }
                        }
                    }
                }
                
                res.json({ 
                    success: true, 
                    message: `Prueba completada. ${alertsSent} notificaciones enviadas.`
                });
                
            } catch (error) {
                res.status(500).json({ 
                    success: false, 
                    message: 'Error al iniciar la prueba de alarmas.' 
                });
            }
        });
        
        // Endpoints de test para manipular datos
        app.post('/api/test/accounts', (req, res) => {
            mockAccounts = req.body;
            res.json({ message: 'Test accounts set' });
        });
        
        app.post('/api/test/reset-notifications', (req, res) => {
            sentNotifications = [];
            res.json({ message: 'Notifications reset' });
        });
        
        app.get('/api/test/notifications', (req, res) => {
            res.json(sentNotifications);
        });
        
        // Generar token válido
        validToken = jwt.sign(
            { id: 1, username: 'testuser' },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
    });

    beforeEach(async () => {
        // Reset notificaciones antes de cada test
        await request(app).post('/api/test/reset-notifications');
        jest.clearAllMocks();
    });

    describe('GET /api/alarms/settings', () => {
        test('✅ Debe retornar configuración de alarmas', async () => {
            const response = await request(app)
                .get('/api/alarms/settings')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(200);
            expect(response.body.provider_threshold_days).toBe(5);
            expect(response.body.client_threshold_days).toBe(3);
            expect(response.body.ntfy_topic).toBe('test-topic-jireh');
        });

        test('❌ Debe rechazar acceso sin autenticación', async () => {
            const response = await request(app)
                .get('/api/alarms/settings');

            expect(response.status).toBe(401);
        });
    });

    describe('PUT /api/alarms/settings', () => {
        test('✅ Debe actualizar configuración correctamente', async () => {
            const newSettings = {
                provider_threshold_days: 7,
                client_threshold_days: 2,
                ntfy_topic: 'new-topic-test'
            };

            const response = await request(app)
                .put('/api/alarms/settings')
                .set('Authorization', `Bearer ${validToken}`)
                .send(newSettings);

            expect(response.status).toBe(200);
            expect(response.body.provider_threshold_days).toBe(7);
            expect(response.body.client_threshold_days).toBe(2);
            expect(response.body.ntfy_topic).toBe('new-topic-test');
        });

        test('✅ Configuración debe persistir', async () => {
            // Actualizar configuración
            await request(app)
                .put('/api/alarms/settings')
                .set('Authorization', `Bearer ${validToken}`)
                .send({
                    provider_threshold_days: 10,
                    client_threshold_days: 1,
                    ntfy_topic: 'persistent-topic'
                });

            // Verificar que persiste
            const getResponse = await request(app)
                .get('/api/alarms/settings')
                .set('Authorization', `Bearer ${validToken}`);

            expect(getResponse.body.provider_threshold_days).toBe(10);
            expect(getResponse.body.client_threshold_days).toBe(1);
            expect(getResponse.body.ntfy_topic).toBe('persistent-topic');
        });
    });

    describe('POST /api/alarms/test', () => {
        test('✅ Debe ejecutar prueba de alarmas sin cuentas', async () => {
            // Sin cuentas configuradas
            await request(app)
                .post('/api/test/accounts')
                .send([]);

            const response = await request(app)
                .post('/api/alarms/test')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            expect(response.body.message).toContain('0 notificaciones enviadas');
        });

        test('✅ Debe enviar alarmas para cuentas próximas a vencer', async () => {
            // Configurar cuentas de prueba
            const testAccounts = [
                {
                    id: '123456',
                    client_name: 'Cliente Urgente',
                    type: 'Netflix Completa',
                    days_remaining: 3, // Menor al threshold (5)
                    profiles: []
                },
                {
                    id: '789012',
                    client_name: 'Cliente Seguro',
                    type: 'Disney+ Completa',
                    days_remaining: 15, // Mayor al threshold
                    profiles: []
                }
            ];

            await request(app)
                .post('/api/test/accounts')
                .send(testAccounts);

            const response = await request(app)
                .post('/api/alarms/test')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            expect(response.body.message).toContain('1 notificaciones enviadas');

            // Verificar que se llamó a fetch
            expect(global.fetch).toHaveBeenCalledWith(
                'https://ntfy.sh/test-topic-jireh',
                expect.objectContaining({
                    method: 'POST',
                    body: expect.stringContaining('Cliente Urgente'),
                    headers: expect.objectContaining({
                        'Title': 'Alarma de Proveedor',
                        'Priority': 'high'
                    })
                })
            );
        });

        test('✅ Debe enviar alarmas para perfiles de clientes', async () => {
            const testAccounts = [
                {
                    id: '111111',
                    client_name: 'Proveedor Test',
                    type: 'Netflix Completa',
                    days_remaining: 20, // Cuenta del proveedor OK
                    profiles: [
                        {
                            name: 'Perfil Cliente 1',
                            estado: 'vendido',
                            clienteNombre: 'Juan Pérez',
                            days_remaining: 2 // Cliente próximo a vencer
                        },
                        {
                            name: 'Perfil Cliente 2',
                            estado: 'vendido',
                            clienteNombre: 'María García',
                            days_remaining: 10 // Cliente seguro
                        }
                    ]
                }
            ];

            await request(app)
                .post('/api/test/accounts')
                .send(testAccounts);

            const response = await request(app)
                .post('/api/alarms/test')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            expect(response.body.message).toContain('1 notificaciones enviadas');

            // Verificar llamada para cliente
            expect(global.fetch).toHaveBeenCalledWith(
                'https://ntfy.sh/test-topic-jireh',
                expect.objectContaining({
                    method: 'POST',
                    body: expect.stringContaining('Juan Pérez'),
                    headers: expect.objectContaining({
                        'Title': 'Alarma de Cliente',
                        'Priority': 'default'
                    })
                })
            );
        });

        test('✅ No debe enviar notificaciones duplicadas', async () => {
            const testAccounts = [
                {
                    id: '555555',
                    client_name: 'Cliente Duplicado',
                    type: 'Amazon Prime',
                    days_remaining: 2,
                    profiles: []
                }
            ];

            await request(app)
                .post('/api/test/accounts')
                .send(testAccounts);

            // Primera ejecución
            const response1 = await request(app)
                .post('/api/alarms/test')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response1.body.message).toContain('1 notificaciones enviadas');

            // Segunda ejecución inmediata
            const response2 = await request(app)
                .post('/api/alarms/test')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response2.body.message).toContain('0 notificaciones enviadas');

            // Verificar que fetch solo se llamó una vez
            expect(global.fetch).toHaveBeenCalledTimes(1);
        });

        test('✅ Debe respetar configuración de thresholds', async () => {
            // Cambiar configuración
            await request(app)
                .put('/api/alarms/settings')
                .set('Authorization', `Bearer ${validToken}`)
                .send({
                    provider_threshold_days: 2, // Más restrictivo
                    client_threshold_days: 1,
                    ntfy_topic: 'test-topic-jireh'
                });

            const testAccounts = [
                {
                    id: '666666',
                    client_name: 'Límite Justo',
                    type: 'Max Completa',
                    days_remaining: 3, // Ahora está fuera del threshold (2)
                    profiles: []
                }
            ];

            await request(app)
                .post('/api/test/accounts')
                .send(testAccounts);

            const response = await request(app)
                .post('/api/alarms/test')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.body.message).toContain('0 notificaciones enviadas');
            expect(global.fetch).not.toHaveBeenCalled();
        });
    });

    describe('🔄 Integración Completa de Alarmas', () => {
        test('✅ Flujo completo de gestión de alarmas', async () => {
            // 1. Obtener configuración inicial
            const initialSettings = await request(app)
                .get('/api/alarms/settings')
                .set('Authorization', `Bearer ${validToken}`);

            expect(initialSettings.status).toBe(200);

            // 2. Actualizar configuración
            const newConfig = {
                provider_threshold_days: 4,
                client_threshold_days: 2,
                ntfy_topic: 'test-integration-flow'
            };

            const updateResponse = await request(app)
                .put('/api/alarms/settings')
                .set('Authorization', `Bearer ${validToken}`)
                .send(newConfig);

            expect(updateResponse.status).toBe(200);

            // 3. Configurar datos de prueba
            const integrationAccounts = [
                {
                    id: '777777',
                    client_name: 'Integración Test',
                    type: 'Netflix Completa',
                    days_remaining: 3, // Dentro del threshold (4)
                    profiles: [
                        {
                            name: 'Perfil Integración',
                            estado: 'vendido',
                            clienteNombre: 'Cliente Integración',
                            days_remaining: 1 // Dentro del threshold (2)
                        }
                    ]
                }
            ];

            await request(app)
                .post('/api/test/accounts')
                .send(integrationAccounts);

            // 4. Ejecutar prueba de alarmas
            const testResponse = await request(app)
                .post('/api/alarms/test')
                .set('Authorization', `Bearer ${validToken}`);

            expect(testResponse.status).toBe(200);
            expect(testResponse.body.success).toBe(true);
            expect(testResponse.body.message).toContain('2 notificaciones enviadas');

            // 5. Verificar notificaciones enviadas
            const notificationsResponse = await request(app)
                .get('/api/test/notifications');

            expect(notificationsResponse.body).toHaveLength(2);
            expect(notificationsResponse.body.find(n => n.item_type === 'provider')).toBeDefined();
            expect(notificationsResponse.body.find(n => n.item_type === 'client')).toBeDefined();

            // 6. Verificar llamadas a NTFY
            expect(global.fetch).toHaveBeenCalledTimes(2);
        });
    });
});
