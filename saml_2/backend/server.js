import express from 'express';
import session from 'express-session';
import urlencoded from 'body-parser';
import json from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import { DOMParser } from '@xmldom/xmldom';
import cors from 'cors';

const app = express();
const PORT = 4001;
const IDP_SSO_URL = 'http://localhost:4002/idp/sso';
const SP_ENTITY_ID = 'http://localhost:4001/sp/metadata';
const SP_ACS_URL = 'http://localhost:4001/sp/acs';

// App configuration for universal redirect
const UNIVERSAL_APP_CONFIG = {
    'app3': {
        url: 'http://localhost:4003',
        name: 'Analytics Dashboard'
    },
    'app4': {
        url: 'http://localhost:4004',
        name: 'Admin Portal'
    }
};

app.use(cors({
    origin: ['http://localhost:4003', 'http://localhost:4004'],
    credentials: true
}));

app.use(urlencoded({ extended: true }));
app.use(json());
app.use(session({
    secret: 'sp-secret-key-for-saml',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// ========== POST METHOD (Original) ==========

// SSO Initiation endpoint using POST method
app.get('/sp/sso/initiate', (req, res) => {
    const { app: appName, returnUrl, method = 'post' } = req.query;
    console.log(`🚀 Initiating SAML login for app: ${appName} using ${method.toUpperCase()} method`);
    console.log(`🔗 Return URL: ${returnUrl}`);

    const id = '_' + uuidv4();
    const issueInstant = new Date().toISOString();

    // Store the relay state in session
    req.session.relayState = {
        app: appName,
        returnUrl: returnUrl,
        timestamp: new Date().toISOString(),
        requestId: id,
        method: method
    };

    const authnRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="${id}"
        Version="2.0"
        IssueInstant="${issueInstant}"
        Destination="${IDP_SSO_URL}"
        AssertionConsumerServiceURL="${SP_ACS_URL}"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
        <saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>
    </samlp:AuthnRequest>`;

    const samlRequest = Buffer.from(authnRequest).toString('base64');

    // Create RelayState
    const relayStateData = {
        app: appName,
        returnUrl: returnUrl,
        method: method
    };

    if (method === 'redirect') {
        // ========== REDIRECT METHOD ==========
        const relayStateParam = encodeURIComponent(JSON.stringify(relayStateData));
        const redirectUrl = `${IDP_SSO_URL}?SAMLRequest=${encodeURIComponent(samlRequest)}&RelayState=${relayStateParam}`;

        console.log('🌐 Using HTTP-Redirect binding');
        console.log(`🔗 Redirecting to: ${redirectUrl}`);

        return res.redirect(redirectUrl);
    } else {
        // ========== POST METHOD (Default) ==========
        const relayStateParam = JSON.stringify(relayStateData);

        console.log('📋 Using HTTP-POST binding');
        console.log('🔗 Creating RelayState:', relayStateData);

        const html = `<html>
            <body onload="document.forms[0].submit()">
                <form method="POST" action="${IDP_SSO_URL}">
                    <input type="hidden" name="SAMLRequest" value="${samlRequest}" />
                    <input type="hidden" name="RelayState" value="${relayStateParam}" />
                </form>
                <p>🔄 Redirecting to Identity Provider using POST method...</p>
            </body>
        </html>`;

        return res.send(html);
    }
});

// ========== SEPARATE ENDPOINTS FOR EASY TESTING ==========

// POST method endpoint
app.get('/sp/sso/initiate-post', (req, res) => {
    const { app: appName, returnUrl } = req.query;
    const redirectUrl = `/sp/sso/initiate?app=${appName}&returnUrl=${returnUrl}&method=post`;
    res.redirect(redirectUrl);
});

// Redirect method endpoint  
app.get('/sp/sso/initiate-redirect', (req, res) => {
    const { app: appName, returnUrl } = req.query;
    const redirectUrl = `/sp/sso/initiate?app=${appName}&returnUrl=${returnUrl}&method=redirect`;
    res.redirect(redirectUrl);
});

// ========== ACS ENDPOINTS - Handle both methods ==========

// ACS POST endpoint (original)
app.post('/sp/acs', (req, res) => {
    console.log('📥 Received POST /sp/acs request (HTTP-POST binding)');
    handleACSRequest(req, res, req.body.SAMLResponse, req.body.RelayState, 'POST');
});

// ACS GET endpoint (for redirect binding)
app.get('/sp/acs', (req, res) => {
    console.log('📥 Received GET /sp/acs request (HTTP-Redirect binding)');
    handleACSRequest(req, res, req.query.SAMLResponse, req.query.RelayState, 'GET');
});

// Unified ACS handler function
function handleACSRequest(req, res, samlResponse, relayState, method) {
    console.log(`📋 Processing ${method} request`);
    console.log('📋 SAMLResponse present:', !!samlResponse);
    console.log('📋 RelayState:', relayState);

    if (!samlResponse) {
        console.error('❌ Missing SAMLResponse');
        return res.status(400).json({
            error: 'Missing SAMLResponse'
        });
    }

    try {
        const decodedResponse = Buffer.from(samlResponse, 'base64').toString('utf8');
        console.log('🔍 Parsing SAML Response...');

        const doc = new DOMParser().parseFromString(decodedResponse, 'text/xml');
        const nameId = doc.getElementsByTagName('saml:NameID')[0]?.textContent;

        if (!nameId) {
            console.error('❌ No NameID found in SAML response');
            return res.status(401).send("Authentication failed - no NameID");
        }

        console.log('✅ SAML Response parsed successfully');
        console.log('📋 NameID:', nameId);

        // Extract attributes if present
        const attributes = {};
        const attributeStatements = doc.getElementsByTagName('saml:AttributeStatement');
        if (attributeStatements.length > 0) {
            const attributeNodes = doc.getElementsByTagName('saml:Attribute');
            for (let i = 0; i < attributeNodes.length; i++) {
                const attr = attributeNodes[i];
                const name = attr.getAttribute('Name');
                const valueNode = attr.getElementsByTagName('saml:AttributeValue')[0];
                if (valueNode) {
                    attributes[name] = valueNode.textContent;
                }
            }
        }

        // Set session data
        req.session.loggedIn = true;
        req.session.user = {
            email: nameId,
            nameId: nameId
        };
        req.session.attributes = attributes;
        req.session.samlAssertion = {
            subject: nameId,
            attributes: attributes,
            timestamp: new Date().toISOString(),
            validUntil: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
            method: method // Track which method was used
        };

        console.log('✅ User session created for:', nameId);

        // Universal redirect logic
        let redirectUrl = null;

        // Parse RelayState (handle URL encoding for GET requests)
        if (relayState) {
            try {
                let relayData;
                if (method === 'GET') {
                    relayData = JSON.parse(decodeURIComponent(relayState));
                } else {
                    relayData = JSON.parse(relayState);
                }

                console.log('📋 Parsed RelayState:', relayData);

                // Use returnUrl if provided
                if (relayData.returnUrl) {
                    redirectUrl = relayData.returnUrl;
                    console.log(`🎯 Using specific returnUrl: ${redirectUrl}`);
                }
                // Map app to configured URL
                else if (relayData.app && UNIVERSAL_APP_CONFIG[relayData.app]) {
                    redirectUrl = UNIVERSAL_APP_CONFIG[relayData.app].url;
                    console.log(`🎯 Mapped app '${relayData.app}' to: ${redirectUrl}`);
                }

            } catch (parseError) {
                console.log('⚠️ RelayState parse error:', parseError.message);
            }
        }

        // Try session-stored RelayState as backup
        if (!redirectUrl && req.session.relayState) {
            console.log('🔄 Trying session-stored RelayState:', req.session.relayState);
            const sessionRelay = req.session.relayState;

            if (sessionRelay.returnUrl) {
                redirectUrl = sessionRelay.returnUrl;
                console.log(`🎯 Using returnUrl from session: ${redirectUrl}`);
            } else if (sessionRelay.app && UNIVERSAL_APP_CONFIG[sessionRelay.app]) {
                redirectUrl = UNIVERSAL_APP_CONFIG[sessionRelay.app].url;
                console.log(`🎯 Mapped session app '${sessionRelay.app}' to: ${redirectUrl}`);
            }
        }

        // Fallback to default
        if (!redirectUrl) {
            redirectUrl = UNIVERSAL_APP_CONFIG['app3'].url;
            console.log(`🔄 Using default redirect: ${redirectUrl}`);
        }

        console.log(`🚀 Final redirect (via ${method}): ${redirectUrl}`);
        return res.redirect(redirectUrl);

    } catch (error) {
        console.error('❌ Error processing SAML response:', error);
        return res.status(500).json({
            error: 'Failed to process SAML response',
            details: error.message
        });
    }
}

// ========== OTHER ENDPOINTS ==========

// Session status endpoint
app.get('/sp/session/status', (req, res) => {
    console.log('📋 Session status check');
    console.log('Session logged in:', req.session.loggedIn);

    if (req.session.loggedIn && req.session.user) {
        // Check if session is still valid
        if (req.session.samlAssertion?.validUntil) {
            const validUntil = new Date(req.session.samlAssertion.validUntil);
            if (validUntil <= new Date()) {
                req.session.destroy();
                return res.json({ authenticated: false, reason: 'Session expired' });
            }
        }

        res.json({
            authenticated: true,
            authMethod: 'saml',
            user: req.session.user,
            assertion: req.session.samlAssertion
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Logout endpoint
app.get('/sp/logout', (req, res) => {
    console.log('🚪 User logout requested');
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Could not log out' });
        }
        res.json({ message: 'Logged out successfully' });
    });
});

// Protected endpoints
app.get('/api/protected/app3', (req, res) => {
    console.log('🔒 Protected endpoint /api/protected/app3 accessed');

    if (!req.session.loggedIn || !req.session.user) {
        const returnUrl = encodeURIComponent('http://localhost:4003');
        const loginUrl = `/sp/sso/initiate?app=app3&returnUrl=${returnUrl}`;
        return res.status(401).json({
            error: 'Authentication required',
            loginUrl: loginUrl
        });
    }

    // Check session validity
    if (req.session.samlAssertion?.validUntil) {
        const validUntil = new Date(req.session.samlAssertion.validUntil);
        if (validUntil <= new Date()) {
            req.session.destroy();
            const returnUrl = encodeURIComponent('http://localhost:4003');
            const loginUrl = `/sp/sso/initiate?app=app3&returnUrl=${returnUrl}`;
            return res.status(401).json({
                error: 'Session expired',
                loginUrl: loginUrl
            });
        }
    }

    const name = req.session.user.email || 'Anonymous';
    res.json({
        message: `Hello ${name}! This is protected data for App 3!`,
        timestamp: new Date().toISOString(),
        user: req.session.user,
        appId: 'app3',
        attributes: req.session.attributes,
        samlMethod: req.session.samlAssertion?.method || 'unknown'
    });
});

app.get('/api/protected/app4', (req, res) => {
    console.log('🔒 Protected endpoint /api/protected/app4 accessed');

    if (!req.session.loggedIn || !req.session.user) {
        const returnUrl = encodeURIComponent('http://localhost:4004');
        const loginUrl = `/sp/sso/initiate?app=app4&returnUrl=${returnUrl}`;
        return res.status(401).json({
            error: 'Authentication required',
            loginUrl: loginUrl
        });
    }

    // Check session validity
    if (req.session.samlAssertion?.validUntil) {
        const validUntil = new Date(req.session.samlAssertion.validUntil);
        if (validUntil <= new Date()) {
            req.session.destroy();
            const returnUrl = encodeURIComponent('http://localhost:4004');
            const loginUrl = `/sp/sso/initiate?app=app4&returnUrl=${returnUrl}`;
            return res.status(401).json({
                error: 'Session expired',
                loginUrl: loginUrl
            });
        }
    }

    const name = req.session.user.email || 'Anonymous';
    res.json({
        message: `Hello ${name}! This is protected data for App 4!`,
        timestamp: new Date().toISOString(),
        user: req.session.user,
        appId: 'app4',
        attributes: req.session.attributes,
        samlMethod: req.session.samlAssertion?.method || 'unknown'
    });
});

// Single Logout initiation endpoint
app.get('/sp/slo/initiate', (req, res) => {
    console.log('🚪 Initiating SAML Single Logout...');

    if (!req.session.loggedIn || !req.session.user) {
        return res.json({ message: 'No active session to logout' });
    }

    const logoutRequestId = '_' + uuidv4();
    const issueInstant = new Date().toISOString();
    const nameId = req.session.user.email || req.session.samlAssertion?.subject;

    const logoutRequest = `<?xml version="1.0" encoding="UTF-8"?>
    <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                         xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                         ID="${logoutRequestId}"
                         Version="2.0"
                         IssueInstant="${issueInstant}"
                         Destination="http://localhost:4002/idp/slo">
        <saml:Issuer>http://localhost:4001/sp/metadata</saml:Issuer>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>
    </samlp:LogoutRequest>`;

    const samlRequest = Buffer.from(logoutRequest).toString('base64');
    const relayState = JSON.stringify({ action: 'slo', timestamp: Date.now() });

    // Create auto-submit form to IdP
    const html = `<html>
        <body onload="document.forms[0].submit()">
            <form method="GET" action="http://localhost:4002/idp/slo">
                <input type="hidden" name="SAMLRequest" value="${samlRequest}" />
                <input type="hidden" name="RelayState" value="${relayState}" />
            </form>
            <p>🔄 Initiating Single Logout...</p>
        </body>
    </html>`;

    res.send(html);
});

// Single Logout Response handler
app.post('/sp/slo', (req, res) => {
    console.log('📥 Received SAML Logout Response...');

    const { SAMLResponse, RelayState } = req.body;

    if (!SAMLResponse) {
        return res.status(400).json({ error: 'Missing SAMLResponse' });
    }

    try {
        // Decode and parse the logout response
        const logoutResponse = Buffer.from(SAMLResponse, 'base64').toString('utf8');
        console.log('🔍 Parsing logout response...');

        // Check if logout was successful (simple check for Success status)
        if (logoutResponse.includes('urn:oasis:names:tc:SAML:2.0:status:Success')) {
            console.log('✅ Logout successful according to IdP');

            // Clear the session
            req.session.destroy(err => {
                if (err) {
                    console.error('Error destroying session:', err);
                }
            });

            // Redirect to a logout success page
            res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Logout Successful</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .success { background: #d4edda; color: #155724; padding: 20px; border-radius: 5px; margin: 20px auto; max-width: 500px; }
                    </style>
                </head>
                <body>
                    <div class="success">
                        <h2>🎉 Logout Successful</h2>
                        <p>You have been successfully logged out from all applications.</p>
                        <div style="margin-top: 20px;">
                            <a href="http://localhost:4003" style="margin: 0 10px; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 3px;">Go to App 3</a>
                            <a href="http://localhost:4004" style="margin: 0 10px; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 3px;">Go to App 4</a>
                        </div>
                    </div>
                </body>
                </html>
            `);

        } else {
            console.log('❌ Logout failed according to IdP');
            res.status(500).json({ error: 'Logout failed' });
        }

    } catch (error) {
        console.error('❌ Error processing logout response:', error);
        res.status(500).json({ error: 'Failed to process logout response' });
    }
});

// SP metadata endpoint - support both bindings
app.get('/sp/metadata', (req, res) => {
    const metadata = `<?xml version="1.0" encoding="UTF-8"?>
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                         entityID="${SP_ENTITY_ID}">
        <md:SPSSODescriptor AuthnRequestsSigned="false" 
                            WantAssertionsSigned="false" 
                            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <!-- Support both POST and Redirect for flexibility -->
            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
                                         Location="${SP_ACS_URL}" 
                                         index="0" 
                                         isDefault="true"/>
            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" 
                                         Location="${SP_ACS_URL}" 
                                         index="1"/>
            <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                    Location="http://localhost:4001/sp/slo"/>
            <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                    Location="http://localhost:4001/sp/slo"/>
        </md:SPSSODescriptor>
    </md:EntityDescriptor>`;

    res.header('Content-Type', 'text/xml').send(metadata);
});

// Dynamic app registration (no IdP changes needed!)
app.post('/sp/register-app', (req, res) => {
    const { appId, url, name } = req.body;

    if (!appId || !url) {
        return res.status(400).json({ error: 'appId and url are required' });
    }

    UNIVERSAL_APP_CONFIG[appId] = {
        url: url,
        name: name || `App ${appId}`
    };

    console.log(`✅ Registered new app: ${appId} -> ${url}`);

    res.json({
        message: 'App registered successfully',
        appId: appId,
        config: UNIVERSAL_APP_CONFIG[appId],
        loginUrls: {
            post: `/sp/sso/initiate-post?app=${appId}`,
            redirect: `/sp/sso/initiate-redirect?app=${appId}`
        }
    });
});

// List registered apps
app.get('/sp/apps', (req, res) => {
    res.json({
        registeredApps: UNIVERSAL_APP_CONFIG,
        totalApps: Object.keys(UNIVERSAL_APP_CONFIG).length,
        availableMethods: ['post', 'redirect']
    });
});

// Health check with testing endpoints
app.get('/', (req, res) => {
    res.json({
        service: 'SAML Service Provider',
        status: 'running',
        supportedMethods: ['HTTP-POST', 'HTTP-Redirect'],
        endpoints: {
            metadata: '/sp/metadata',
            sso_initiate: '/sp/sso/initiate',
            sso_initiate_post: '/sp/sso/initiate-post',
            sso_initiate_redirect: '/sp/sso/initiate-redirect',
            acs: '/sp/acs',
            session_status: '/sp/session/status',
            logout: '/sp/logout',
            slo_initiate: '/sp/slo/initiate',
            protected_app3: '/api/protected/app3',
            protected_app4: '/api/protected/app4',
            register_app: '/sp/register-app',
            list_apps: '/sp/apps'
        },
        testUrls: {
            app3_post: `http://localhost:4001/sp/sso/initiate-post?app=app3`,
            app3_redirect: `http://localhost:4001/sp/sso/initiate-redirect?app=app3`,
            app4_post: `http://localhost:4001/sp/sso/initiate-post?app=app4`,
            app4_redirect: `http://localhost:4001/sp/sso/initiate-redirect?app=app4`
        }
    });
});

app.listen(PORT, () => {
    console.log('🔐 SAML Service Provider running on http://localhost:4001');
    console.log('📋 Available endpoints:');
    console.log('   - GET  /sp/metadata (SP metadata)');
    console.log('   - GET  /sp/sso/initiate (Initiate SAML login - supports both methods)');
    console.log('   - GET  /sp/sso/initiate-post (Force POST method)');
    console.log('   - GET  /sp/sso/initiate-redirect (Force Redirect method)');
    console.log('   - POST /sp/acs (Assertion Consumer Service - POST)');
    console.log('   - GET  /sp/acs (Assertion Consumer Service - Redirect)');
    console.log('   - GET  /sp/session/status (Check auth status)');
    console.log('   - GET  /sp/logout (Logout)');
    console.log('   - GET  /sp/slo/initiate (Single Logout)');
    console.log('   - GET  /api/protected/app3 (Protected endpoint for App 3)');
    console.log('   - GET  /api/protected/app4 (Protected endpoint for App 4)');
    console.log('   - POST /sp/register-app (Register new app)');
    console.log('   - GET  /sp/apps (List registered apps)');
    console.log('');
    console.log('🧪 Test URLs:');
    console.log('   - App3 POST: http://localhost:4001/sp/sso/initiate-post?app=app3');
    console.log('   - App3 Redirect: http://localhost:4001/sp/sso/initiate-redirect?app=app3');
    console.log('   - App4 POST: http://localhost:4001/sp/sso/initiate-post?app=app4');
    console.log('   - App4 Redirect: http://localhost:4001/sp/sso/initiate-redirect?app=app4');
});
