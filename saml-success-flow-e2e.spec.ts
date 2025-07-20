import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import axios, { AxiosInstance } from 'axios';
import { spawn, ChildProcess } from 'child_process';
import { JSDOM } from 'jsdom';
import { wrapper } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';

describe('SAML 2.0 Successful Authentication Flow', () => {
    let idpServer: ChildProcess;
    let spServer: ChildProcess;
    let client: AxiosInstance;

    const IDP_BASE_URL = 'http://localhost:4002';
    const SP_BASE_URL = 'http://localhost:4001';
    const TEST_USER = {
        username: 'john@example.com',
        password: 'password123'
    };

    beforeAll(async () => {
        console.log('🚀 Starting SAML servers...');

        // Create axios client with cookie support
        const jar = new CookieJar();
        client = wrapper(axios.create({ jar }));

        // Start IdP server first
        idpServer = spawn('node', ['saml_2/backend/saml-identity-provider.js'], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        // Monitor IdP logs for debugging
        idpServer.stderr?.on('data', (data) => {
            console.log('IdP Error:', data.toString());
        });

        // Wait for IdP
        console.log('⏳ Waiting for IdP server...');
        for (let i = 0; i < 30; i++) {
            try {
                await axios.get(`${IDP_BASE_URL}/idp/metadata`, { timeout: 2000 });
                console.log('✅ IdP server is ready');
                break;
            } catch (error) {
                if (i === 29) throw new Error('IdP server failed to start');
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }

        // Start SP server
        spServer = spawn('node', ['saml_2/backend/server.js'], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        // Monitor SP logs for debugging
        spServer.stderr?.on('data', (data) => {
            console.log('SP Error:', data.toString());
        });

        // Wait for SP
        console.log('⏳ Waiting for SP server...');
        for (let i = 0; i < 30; i++) {
            try {
                await axios.get(`${SP_BASE_URL}/`, { timeout: 2000 });
                console.log('✅ SP server is ready');
                break;
            } catch (error) {
                if (i === 29) throw new Error('SP server failed to start');
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
    }, 60000);

    afterAll(() => {
        idpServer?.kill();
        spServer?.kill();
    });

    it('should complete full SAML authentication flow successfully', async () => {
        try {
            // Step 1: SP initiates SAML SSO
            console.log('🚀 Step 1: Initiating SAML SSO...');
            const ssoResponse = await client.get(`${SP_BASE_URL}/sp/sso/initiate`, {
                params: { app: 'app3', returnUrl: 'http://localhost:4003' },
                maxRedirects: 0,
                validateStatus: status => status === 302
            });

            expect(ssoResponse.status).toBe(302);
            const idpLoginUrl = ssoResponse.headers.location;
            console.log('IdP Login URL:', idpLoginUrl);

            const loginUrl = new URL(idpLoginUrl);
            const relayState = loginUrl.searchParams.get('RelayState');
            console.log('RelayState:', relayState);

            // Step 2: Get login form from IdP (with cookies)
            console.log('🔐 Step 2: Getting login form from IdP...');
            const loginFormResponse = await client.get(idpLoginUrl);

            expect(loginFormResponse.status).toBe(200);
            console.log('Login form received, length:', loginFormResponse.data.length);

            // Extract requestId from form
            const dom = new JSDOM(loginFormResponse.data);
            const requestIdInput = dom.window.document.querySelector('input[name="requestId"]') as HTMLInputElement;
            const requestId = requestIdInput?.value;

            console.log('RequestId extracted:', requestId);
            expect(requestId).toBeTruthy();

            // Step 3: Submit credentials with proper form data
            console.log('🔑 Step 3: Submitting credentials to IdP...');

            const formData = new URLSearchParams({
                username: TEST_USER.username,
                password: TEST_USER.password,
                requestId: requestId!,
                relayState: relayState || ''
            });

            console.log('Form data:', formData.toString());

            const authResponse = await client.post(`${IDP_BASE_URL}/idp/authenticate`,
                formData.toString(),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                }
            );

            console.log('Auth response status:', authResponse.status);
            console.log('Auth response length:', authResponse.data.length);

            expect(authResponse.status).toBe(200);
            expect(authResponse.data).toContain('SAMLResponse');

            // Step 4: Extract SAMLResponse
            const responseDom = new JSDOM(authResponse.data);
            const samlResponseInput = responseDom.window.document.querySelector('input[name="SAMLResponse"]') as HTMLInputElement;
            const finalRelayStateInput = responseDom.window.document.querySelector('input[name="RelayState"]') as HTMLInputElement;

            const samlResponse = samlResponseInput?.value;
            const finalRelayState = finalRelayStateInput?.value;

            console.log('SAMLResponse extracted:', !!samlResponse);
            console.log('Final RelayState:', finalRelayState);

            expect(samlResponse).toBeTruthy();

            // Step 5: Submit to SP ACS
            console.log('📨 Step 4: Posting SAMLResponse to SP ACS...');

            const acsData = new URLSearchParams({
                SAMLResponse: samlResponse!,
                RelayState: finalRelayState || ''
            });

            const acsResponse = await client.post(`${SP_BASE_URL}/sp/acs`,
                acsData.toString(),
                {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    maxRedirects: 0,
                    validateStatus: status => status === 302
                }
            );

            expect(acsResponse.status).toBe(302);
            console.log('ACS redirect location:', acsResponse.headers.location);

            // Step 6: Verify session
            console.log('🔍 Step 5: Verifying SAML session...');
            const sessionResponse = await client.get(`${SP_BASE_URL}/sp/session/status`);

            expect(sessionResponse.status).toBe(200);
            expect(sessionResponse.data.authenticated).toBe(true);

            console.log('Session data:', JSON.stringify(sessionResponse.data, null, 2));

            // Step 7: Access protected resource
            console.log('🛡️ Step 6: Accessing protected resource...');
            const protectedResponse = await client.get(`${SP_BASE_URL}/api/protected/app3`);

            expect(protectedResponse.status).toBe(200);
            expect(protectedResponse.data.message).toContain('Hello');
            expect(protectedResponse.data.appId).toBe('app3');

            console.log('🎉 SAML authentication flow completed successfully!');
            console.log('Protected data:', JSON.stringify(protectedResponse.data, null, 2));

        } catch (error) {
            console.error('❌ Test failed with error:', error.stack);
            if (axios.isAxiosError(error)) {
                console.error('Response status:', error.response?.status);
                console.error('Response data:', error.response?.data);
                console.error('Request URL:', error.config?.url);
                console.error('Request method:', error.config?.method);
            }
            throw error;
        }
    }, 60000);
});
