import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import axios from 'axios';
import { spawn } from 'child_process';
import { JSDOM } from 'jsdom';
import { wrapper } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';
import { URLSearchParams } from 'url';
import path from 'path';

describe('SAML 2.0 POST Authentication Flow', () => {
    let idpServer, spServer, client;
    const IDP_BASE_URL = 'http://localhost:4002';
    const SP_BASE_URL = 'http://localhost:4001';

    // Helper to wait for servers to be ready
    const waitForServer = (serverProcess, url) => {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                serverProcess.kill();
                reject(new Error(`Server at ${url} failed to start in time.`));
            }, 20000);

            serverProcess.stdout.on('data', (data) => {
                console.log(`Server logs: ${data}`);
                if (data.toString().includes('listening on port')) {
                    clearTimeout(timeout);
                    resolve();
                }
            });

            serverProcess.stderr.on('data', (data) => {
                console.error(`Server Error: ${data}`);
            });
        });
    };

    beforeAll(async () => {
        const jar = new CookieJar();
        client = wrapper(axios.create({ jar, withCredentials: true }));

        const spPath = path.resolve(__dirname, 'sp.js');
        const idpPath = path.resolve(__dirname, 'idp.js');

        spServer = spawn('node', [spPath]);
        idpServer = spawn('node', [idpPath]);

        await Promise.all([
            waitForServer(spServer, SP_BASE_URL),
            waitForServer(idpServer, IDP_BASE_URL)
        ]);

    }, 30000);

    afterAll(() => {
        idpServer?.kill();
        spServer?.kill();
    });

    it('should complete full SAML authentication flow successfully', async () => {
        // Step 1: Initiate login from SP to get the SAMLRequest
        const loginPostResponse = await client.get(`${SP_BASE_URL}/login-post`);
        const loginPostDom = new JSDOM(loginPostResponse.data);
        const samlRequest = loginPostDom.window.document.querySelector('input[name="SAMLRequest"]').value;
        expect(samlRequest).toBeTruthy();

        // Step 2: The browser would auto-submit, but we simulate it by getting the IdP login page
        const idpSsoResponse = await client.post(`${IDP_BASE_URL}/sso`, new URLSearchParams({ SAMLRequest: samlRequest }));
        const idpLoginDom = new JSDOM(idpSsoResponse.data);
        const hiddenSamlRequest = idpLoginDom.window.document.querySelector('input[name="SAMLRequest"]').value;
        expect(hiddenSamlRequest).toBe(samlRequest);

        // Step 3: Submit credentials to IdP to get the SAMLResponse
        const idpLoginResponse = await client.post(`${IDP_BASE_URL}/login`, new URLSearchParams({
            email: 'test@example.com',
            password: 'password',
            SAMLRequest: hiddenSamlRequest
        }));
        const idpResponseDom = new JSDOM(idpLoginResponse.data);
        const samlResponse = idpResponseDom.window.document.querySelector('input[name="SAMLResponse"]').value;
        expect(samlResponse).toBeTruthy();

        // Step 4: The browser would auto-submit the SAMLResponse to the SP's ACS URL. We simulate this.
        // We need to follow the redirect manually to get the final destination.
        const assertResponse = await client.post(`${SP_BASE_URL}/assert`, new URLSearchParams({ SAMLResponse: samlResponse }), {
            maxRedirects: 0, // Stop axios from following redirects automatically
            validateStatus: status => status === 302 || status === 200, // Expect a redirect
        });

        // The cookie jar now holds the session cookie.
        expect(assertResponse.status).toBe(302);
        expect(assertResponse.headers.location).toBe('http://localhost:5173/profile');

        // Step 5: Verify that the user is logged in by accessing a protected route
        const meResponse = await client.get(`${SP_BASE_URL}/me`);
        expect(meResponse.status).toBe(200);
        expect(meResponse.data).toEqual({ email: 'test@example.com' });

        // Step 6: Log out
        const logoutResponse = await client.post(`${SP_BASE_URL}/logout`);
        expect(logoutResponse.status).toBe(200);

        // Step 7: Verify user is logged out
        const meAfterLogoutResponse = await client.get(`${SP_BASE_URL}/me`, {
            validateStatus: status => status === 401,
        });
        expect(meAfterLogoutResponse.status).toBe(401);

    }, 20000);
});
