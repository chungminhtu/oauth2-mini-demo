import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import axios from 'axios';
import { spawn, ChildProcess } from 'child_process';
import { JSDOM } from 'jsdom';
import { wrapper } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';

describe('SAML 2.0 Authentication Flow', () => {
    let idpServer: ChildProcess;
    let spServer: ChildProcess;
    let client: any;

    const IDP_BASE_URL = 'http://localhost:4002';
    const SP_BASE_URL = 'http://localhost:4001';
    const TEST_USER = {
        email: 'john@example.com',
        password: 'password123'
    };

    beforeAll(async () => {
        const jar = new CookieJar();
        client = wrapper(axios.create({ jar }));

        idpServer = spawn('node', ['saml_2/backend/saml-identity-provider.js'], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        for (let i = 0; i < 30; i++) {
            try {
                await axios.get(`${IDP_BASE_URL}/idp/metadata`, { timeout: 2000 });
                break;
            } catch (error) {
                if (i === 29) throw new Error('IdP server failed to start');
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }

        spServer = spawn('node', ['saml_2/backend/server.js'], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        for (let i = 0; i < 30; i++) {
            try {
                await axios.get(`${SP_BASE_URL}/`, { timeout: 2000 });
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

    it('should complete full SAML HTTP-POST authentication flow successfully', async () => {
        const ssoResponse = await client.get(`${SP_BASE_URL}/sp/sso/initiate`, {
            params: { app: 'app3', returnUrl: 'http://localhost:4003' }
        });

        expect(ssoResponse.status).toBe(200);

        const ssoDom = new JSDOM(ssoResponse.data);
        const samlRequestInput = ssoDom.window.document.querySelector('input[name="SAMLRequest"]') as HTMLInputElement;
        const relayStateInput = ssoDom.window.document.querySelector('input[name="RelayState"]') as HTMLInputElement;

        const samlRequest = samlRequestInput?.value;
        const relayState = relayStateInput?.value;

        expect(samlRequest).toBeTruthy();

        const idpSsoData = new URLSearchParams({
            SAMLRequest: samlRequest!,
            RelayState: relayState || ''
        });

        const loginFormResponse = await client.post(`${IDP_BASE_URL}/idp/sso`, idpSsoData.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        expect(loginFormResponse.status).toBe(200);

        const loginDom = new JSDOM(loginFormResponse.data);
        const hiddenSamlRequestInput = loginDom.window.document.querySelector('input[name="SAMLRequest"]') as HTMLInputElement;
        const hiddenRelayStateInput = loginDom.window.document.querySelector('input[name="RelayState"]') as HTMLInputElement;

        const hiddenSamlRequest = hiddenSamlRequestInput?.value;
        const hiddenRelayState = hiddenRelayStateInput?.value;

        expect(hiddenSamlRequest).toBeTruthy();

        const formData = new URLSearchParams({
            email: TEST_USER.email,
            password: TEST_USER.password,
            SAMLRequest: hiddenSamlRequest!,
            RelayState: hiddenRelayState || ''
        });

        const authResponse = await client.post(`${IDP_BASE_URL}/idp/login`,
            formData.toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
            }
        );

        expect(authResponse.status).toBe(200);
        expect(authResponse.data).toContain('SAMLResponse');

        const responseDom = new JSDOM(authResponse.data);
        const samlResponseInput = responseDom.window.document.querySelector('input[name="SAMLResponse"]') as HTMLInputElement;
        const finalRelayStateInput = responseDom.window.document.querySelector('input[name="RelayState"]') as HTMLInputElement;

        const samlResponse = samlResponseInput?.value;
        const finalRelayState = finalRelayStateInput?.value;

        expect(samlResponse).toBeTruthy();

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

        const sessionResponse = await client.get(`${SP_BASE_URL}/sp/session/status`);

        expect(sessionResponse.status).toBe(200);
        expect(sessionResponse.data.authenticated).toBe(true);

        const protectedResponse = await client.get(`${SP_BASE_URL}/api/protected/app3`);

        expect(protectedResponse.status).toBe(200);
        expect(protectedResponse.data.message).toContain('Hello');
        expect(protectedResponse.data.appId).toBe('app3');

        const logoutResponse = await client.get(`${SP_BASE_URL}/sp/logout`);
        expect(logoutResponse.status).toBe(200);

        const postLogoutSession = await client.get(`${SP_BASE_URL}/sp/session/status`);
        expect(postLogoutSession.data.authenticated).toBe(false);
    }, 60000);

    it('should complete full SAML HTTP-POST authentication flow for app4', async () => {
        const ssoResponse = await client.get(`${SP_BASE_URL}/sp/sso/initiate`, {
            params: { app: 'app4', returnUrl: 'http://localhost:4004' }
        });

        expect(ssoResponse.status).toBe(200);

        const ssoDom = new JSDOM(ssoResponse.data);
        const samlRequestInput = ssoDom.window.document.querySelector('input[name="SAMLRequest"]') as HTMLInputElement;
        const relayStateInput = ssoDom.window.document.querySelector('input[name="RelayState"]') as HTMLInputElement;

        const samlRequest = samlRequestInput?.value;
        const relayState = relayStateInput?.value;

        expect(samlRequest).toBeTruthy();

        const idpSsoData = new URLSearchParams({
            SAMLRequest: samlRequest!,
            RelayState: relayState || ''
        });

        const loginFormResponse = await client.post(`${IDP_BASE_URL}/idp/sso`, idpSsoData.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        expect(loginFormResponse.status).toBe(200);

        const loginDom = new JSDOM(loginFormResponse.data);
        const hiddenSamlRequestInput = loginDom.window.document.querySelector('input[name="SAMLRequest"]') as HTMLInputElement;
        const hiddenRelayStateInput = loginDom.window.document.querySelector('input[name="RelayState"]') as HTMLInputElement;

        const hiddenSamlRequest = hiddenSamlRequestInput?.value;
        const hiddenRelayState = hiddenRelayStateInput?.value;

        expect(hiddenSamlRequest).toBeTruthy();

        const formData = new URLSearchParams({
            email: TEST_USER.email,
            password: TEST_USER.password,
            SAMLRequest: hiddenSamlRequest!,
            RelayState: hiddenRelayState || ''
        });

        const authResponse = await client.post(`${IDP_BASE_URL}/idp/login`,
            formData.toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
            }
        );

        expect(authResponse.status).toBe(200);
        expect(authResponse.data).toContain('SAMLResponse');

        const responseDom = new JSDOM(authResponse.data);
        const samlResponseInput = responseDom.window.document.querySelector('input[name="SAMLResponse"]') as HTMLInputElement;
        const finalRelayStateInput = responseDom.window.document.querySelector('input[name="RelayState"]') as HTMLInputElement;

        const samlResponse = samlResponseInput?.value;
        const finalRelayState = finalRelayStateInput?.value;

        expect(samlResponse).toBeTruthy();

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

        const sessionResponse = await client.get(`${SP_BASE_URL}/sp/session/status`);

        expect(sessionResponse.status).toBe(200);
        expect(sessionResponse.data.authenticated).toBe(true);

        const protectedResponse = await client.get(`${SP_BASE_URL}/api/protected/app4`);

        expect(protectedResponse.status).toBe(200);
        expect(protectedResponse.data.message).toContain('Hello');
        expect(protectedResponse.data.appId).toBe('app4');

        const logoutResponse = await client.get(`${SP_BASE_URL}/sp/logout`);
        expect(logoutResponse.status).toBe(200);

        const postLogoutSession = await client.get(`${SP_BASE_URL}/sp/session/status`);
        expect(postLogoutSession.data.authenticated).toBe(false);
    }, 60000);
});
