import request from 'supertest';
import app from './server.js';
import oidcApp from './oidc-provider.js';
import { describe, test, expect, beforeAll, afterAll } from 'vitest';

const CLIENT_ID = 'my-random-client-id';
const CLIENT_SECRET = 'my-random-and-very-long-client-secret';
const REDIRECT_URI = 'http://localhost:3000/callback';

describe('OAuth2 E2E Tests', () => {
    let expressServer;
    let oidcServer;

    beforeAll(() => {
        expressServer = app.listen(3002);
        oidcServer = oidcApp.listen(3001);
    });

    afterAll(() => {
        expressServer.close();
        oidcServer.close();
    });

    describe('Authorization Code Flow', () => {
        let authorizationCode;
        let accessToken;
        let refreshToken;

        test('Should initiate authorization and receive code', async () => {
            const res = await request(oidcApp)
                .get('/oidc/auth')
                .query({
                    client_id: CLIENT_ID,
                    redirect_uri: REDIRECT_URI,
                    response_type: 'code',
                    scope: 'openid profile',
                });

            expect(res.status).toBe(303);
            const locationHeader = res.header.location;
            expect(locationHeader).toContain('/interaction/');

            // Simulate user interaction (login and consent)
            const interactionUrl = new URL(locationHeader, `http://localhost:3001`);
            const uid = interactionUrl.pathname.split('/').pop();

            await request(oidcApp)
                .post(`/interaction/${uid}/login`)
                .send('login=anyuser&password=anypass')
                .expect(303);

            // const consentRes = await request(oidcApp)
            //     .post(`/interaction/${uid}/confirm`)
            //     .expect(303);

            // const callbackUrl = new URL(consentRes.header.location, `http://localhost:3001`);
            // authorizationCode = callbackUrl.searchParams.get('code');
            // expect(authorizationCode).toBeTruthy();
        });

        test('Should exchange code for tokens', async () => {
            const res = await request(app)
                .post('/exchange')
                .send({ code: authorizationCode })
                .set('Content-Type', 'application/json');

            expect(res.status).toBe(200);
            expect(res.body).toHaveProperty('access_token');
            expect(res.body).toHaveProperty('refresh_token');
            expect(res.body).toHaveProperty('id_token');

            accessToken = res.body.access_token;
            refreshToken = res.body.refresh_token;
        });

        test('Should access protected resource with access token', async () => {
            const res = await request(app)
                .get('/api/private')
                .set('Authorization', `Bearer ${accessToken}`);

            expect(res.status).toBe(200);
            expect(res.body).toHaveProperty('message', 'This is private data!');
        });

        test('Should access protected resource with access token (JWKS verification)', async () => {
            const res = await request(app)
                .get('/api/privateJWKS')
                .set('Authorization', `Bearer ${accessToken}`);

            expect(res.status).toBe(200);
            expect(res.body).toHaveProperty('message', 'This is private data!');
        });
    });

    describe('Refresh Token Flow', () => {
        let newAccessToken;

        test('Should refresh access token', async () => {
            const res = await request(app)
                .post('/refresh')
                .send({ refresh_token: refreshToken })
                .set('Content-Type', 'application/json');

            expect(res.status).toBe(200);
            expect(res.body).toHaveProperty('access_token');
            expect(res.body).toHaveProperty('refresh_token');

            newAccessToken = res.body.access_token;
        });

        test('Should access protected resource with new access token', async () => {
            const res = await request(app)
                .get('/api/private')
                .set('Authorization', `Bearer ${newAccessToken}`);

            expect(res.status).toBe(200);
            expect(res.body).toHaveProperty('message', 'This is private data!');
        });
    });

    describe('Token Introspection', () => {
        test('Should introspect a valid token', async () => {
            const res = await request(oidcApp)
                .post('/oidc/token/introspection')
                .send(`token=${accessToken}&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}`)
                .set('Content-Type', 'application/x-www-form-urlencoded');

            expect(res.status).toBe(200);
            expect(res.body).toHaveProperty('active', true);
        });

        test('Should introspect an invalid token', async () => {
            const res = await request(oidcApp)
                .post('/oidc/token/introspection')
                .send(`token=invalid_token&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}`)
                .set('Content-Type', 'application/x-www-form-urlencoded');

            expect(res.status).toBe(200);
            expect(res.body).toHaveProperty('active', false);
        });
    });

    describe('Error Scenarios', () => {
        test('Should return 401 for invalid token', async () => {
            const res = await request(app)
                .get('/api/private')
                .set('Authorization', 'Bearer invalid_token');

            expect(res.status).toBe(401);
        });

        test('Should return 401 for missing token', async () => {
            const res = await request(app)
                .get('/api/private');

            expect(res.status).toBe(401);
        });

        test('Should fail to refresh with invalid refresh token', async () => {
            const res = await request(app)
                .post('/refresh')
                .send({ refresh_token: 'invalid_refresh_token' })
                .set('Content-Type', 'application/json');

            expect(res.status).toBe(400);
        });
    });
});
