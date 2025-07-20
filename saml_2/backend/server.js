import express from 'express';
import cookieSession from 'cookie-session';
import { setSchemaValidator, IdentityProvider, ServiceProvider } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import urlencoded from 'body-parser';
import json from 'body-parser';
import { randomUUID } from 'crypto';
import { addMinutes } from 'date-fns';
import cors from 'cors';
import axios from 'axios';

const app = express();

app.use(urlencoded({ extended: true }));
app.use(json());
app.use(cors({
    origin: ['http://localhost:4003', 'http://localhost:4004'],
    credentials: true
}));

app.use(cookieSession({
    name: 'sp_session',
    keys: ['sp-secret-key'],
    maxAge: 24 * 60 * 60 * 1000
}));

// Set the validator
setSchemaValidator(validator);

// ATTRIBUTE MAPPING
const INVERSE_ATTRIBUTE_MAP = {
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'email',
    'urn:oid:2.5.4.3': 'cn',
    'urn:oid:2.5.4.4': 'sn',
    'urn:oid:2.5.4.42': 'givenName',
    'urn:oid:2.16.840.1.113730.3.1.241': 'displayName',
    'urn:oid:0.9.2342.19200300.100.1.1': 'uid',
    'urn:oid:0.9.2342.19200300.100.1.3': 'mail',
    'urn:oid:2.5.4.20': 'telephoneNumber',
    'urn:oid:2.5.4.12': 'title'
};

const generateRequestID = () => {
    return '_' + randomUUID();
};

const URI_IDP_METADATA = 'http://localhost:4002/idp/metadata';

// Initialize SP and IdP
let sp, idp;

async function initializeSAML() {
    try {
        console.log('📡 Fetching IdP metadata...');
        const response = await axios.get(URI_IDP_METADATA);
        console.log('✅ Successfully fetched IdP metadata');

        // Create IdP from metadata
        idp = IdentityProvider({
            metadata: response.data,
            wantAuthnRequestsSigned: false
        });

        // Create SP configuration
        sp = ServiceProvider({
            entityID: 'http://localhost:4001/sp/metadata',
            authnRequestsSigned: false,
            wantAssertionsSigned: false,
            wantMessageSigned: false,
            wantLogoutResponseSigned: false,
            wantLogoutRequestSigned: false,
            assertionConsumerService: [{
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                Location: 'http://localhost:4001/sp/acs',
            }],
            nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
            loginRequestTemplate: {
                context: `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}">
                  <saml:Issuer>{Issuer}</saml:Issuer>
                  <samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="true"/>
                </samlp:AuthnRequest>`
            }
        });

        console.log('✅ SAML SP and IdP initialized successfully');
        return true;
    } catch (error) {
        console.error('❌ Failed to initialize SAML:', error.message);
        return false;
    }
}

// SSO Initiation endpoint
app.get('/sp/sso/initiate', async (req, res) => {
    const { app: appId, returnUrl } = req.query;

    if (!sp) {
        console.error('❌ SP not initialized');
        return res.status(500).json({ error: 'Service Provider not initialized' });
    }

    try {
        console.log(`🚀 Initiating SAML SSO for app: ${appId}`);
        console.log(`📋 Return URL: ${returnUrl}`);

        // Create login request with template callback
        const templateCallback = createTemplateCallback();
        const { id, context } = sp.createLoginRequest(
            idpInstance,
            'redirect',
            templateCallback
        );

        req.session.samlRequestId = id;
        req.session.appId = appId;
        req.session.returnUrl = returnUrl;
        req.session.timestamp = Date.now();

        console.log('✅ SAML AuthnRequest created');
        console.log('📋 Request ID:', id);
        console.log('🔗 Redirecting to:', context);

        res.redirect(context);
    } catch (error) {
        console.error('❌ Error creating SAML AuthnRequest:', error);
        res.status(500).json({
            error: 'Failed to initiate SSO',
            details: error.message
        });
    }
});

// Fix the template callback function for SP (around line 50-80)
const createTemplateCallback = () => template => {
    const id = generateRequestID();
    const now = new Date();

    const tagValues = {
        ID: id,
        Destination: 'http://localhost:4002/idp/sso',
        Issuer: 'http://localhost:4001/sp/metadata',
        IssueInstant: now.toISOString(),
        AssertionConsumerServiceURL: 'http://localhost:4001/sp/acs',
        ProtocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    };

    // For SP, we need to return the template string directly
    return template.replace(/{(\w+)}/g, (match, key) => tagValues[key] || match);
};

// SP configuration - update the loginRequestTemplate
const spConfig = {
    entityID: 'http://localhost:4001/sp/metadata',
    authnRequestsSigned: false,
    wantAssertionsSigned: false,
    wantMessageSigned: false,
    wantLogoutResponseSigned: false,
    wantLogoutRequestSigned: false,
    assertionConsumerService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'http://localhost:4001/sp/acs',
    }],
    nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
    // Add the login request template
    loginRequestTemplate: {
        context: `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="{ProtocolBinding}" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}">
            <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{Issuer}</saml:Issuer>
        </samlp:AuthnRequest>`
    }
};

// ACS endpoint
app.post('/sp/acs', async (req, res) => {
    if (!sp || !idp) {
        return res.status(500).json({ error: 'SAML not initialized' });
    }

    console.log('📥 Received /sp/acs post request...');
    console.log('📋 Request body keys:', Object.keys(req.body));

    const relayState = req.body.RelayState;
    console.log('📋 Relay state:', relayState);

    if (!req.body.SAMLResponse) {
        console.error('❌ Invalid or missing SAMLResponse');
        return res.status(400).json({
            error: 'Invalid SAMLResponse received',
            receivedKeys: Object.keys(req.body)
        });
    }

    try {
        console.log('🔍 Parsing SAML Response...');
        const { extract } = await sp.parseLoginResponse(idp, 'post', req);
        console.log('✅ SAML Response parsed successfully');
        console.log('📋 Extract keys:', Object.keys(extract));
        console.log('📋 NameID:', extract.nameID);

        req.session.loggedIn = true;

        // Process attributes
        const attributes = {};
        if (extract.attributes) {
            for (const key in extract.attributes) {
                const mappedKey = INVERSE_ATTRIBUTE_MAP[key] || key;
                const value = Array.isArray(extract.attributes[key])
                    ? extract.attributes[key][0]
                    : extract.attributes[key];
                attributes[mappedKey] = value;
            }
        }

        // Store session data
        req.session.attributes = attributes;
        req.session.samlAssertion = {
            subject: extract.nameID,
            attributes: attributes,
            sessionIndex: extract.sessionIndex || generateRequestID(),
            issuer: extract.issuer,
            timestamp: new Date().toISOString(),
            validUntil: addMinutes(new Date(), 30).toISOString()
        };

        console.log('✅ SAML attributes processed:', JSON.stringify(attributes, null, 2));

        // Handle RelayState for redirect
        let returnUrl = 'http://localhost:4004'; // default
        if (relayState) {
            try {
                const relayData = JSON.parse(relayState);
                console.log('📋 Parsed RelayState:', relayData);
                if (relayData.returnUrl) {
                    returnUrl = relayData.returnUrl;
                } else if (relayData.app === 'app3') {
                    returnUrl = 'http://localhost:4003';
                } else if (relayData.app === 'app4') {
                    returnUrl = 'http://localhost:4004';
                }
            } catch (e) {
                console.log('⚠️ Could not parse RelayState as JSON, using default return URL');
            }
        }

        console.log(`🔗 Redirecting to: ${returnUrl}`);
        return res.redirect(returnUrl);

    } catch (error) {
        console.error('❌ Error parsing SAML login response:', error);
        return res.status(500).json({
            error: 'Failed to process SAML response',
            details: error.message
        });
    }
});

// SP metadata endpoint
app.get('/sp/metadata', (req, res) => {
    if (!sp) {
        return res.status(500).json({ error: 'SP not initialized' });
    }

    try {
        const metadata = sp.getMetadata();
        res.header('Content-Type', 'text/xml').send(metadata);
    } catch (error) {
        console.error('❌ Error generating SP metadata:', error);
        res.status(500).json({ error: 'Failed to generate metadata' });
    }
});

// Session status endpoint
app.get('/sp/session/status', (req, res) => {
    console.log('📋 Session status check');
    console.log('Session logged in:', req.session.loggedIn);

    if (req.session.loggedIn && req.session.samlAssertion) {
        // Check if session is still valid
        const validUntil = new Date(req.session.samlAssertion.validUntil);
        const isValid = validUntil > new Date();

        if (!isValid) {
            req.session = null;
            return res.json({ authenticated: false, reason: 'Session expired' });
        }

        res.json({
            authenticated: true,
            authMethod: 'saml',
            assertion: req.session.samlAssertion,
            expiresAt: req.session.samlAssertion.validUntil
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Logout endpoint
app.get('/sp/logout', (req, res) => {
    console.log('🚪 User logout requested');
    req.session = null;
    res.json({ message: 'Logged out successfully' });
});

// Protected endpoints
app.get('/api/protected/app3', (req, res) => {
    console.log('🔒 Protected endpoint /api/protected/app3 accessed');

    if (!req.session.loggedIn) {
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
            req.session = null;
            const returnUrl = encodeURIComponent('http://localhost:4003');
            const loginUrl = `/sp/sso/initiate?app=app3&returnUrl=${returnUrl}`;
            return res.status(401).json({
                error: 'Session expired',
                loginUrl: loginUrl
            });
        }
    }

    const name = req.session.attributes?.givenName || req.session.attributes?.cn || 'Anonymous';
    const responseData = {
        message: `Hello ${name}! This is protected data for App 3!`,
        timestamp: new Date().toISOString(),
        samlUser: req.session.samlAssertion,
        appId: 'app3',
        attributes: req.session.attributes,
        sessionId: generateRequestID()
    };

    console.log('✅ Returning protected data for App 3');
    res.json(responseData);
});

app.get('/api/protected/app4', (req, res) => {
    console.log('🔒 Protected endpoint /api/protected/app4 accessed');

    if (!req.session.loggedIn) {
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
            req.session = null;
            const returnUrl = encodeURIComponent('http://localhost:4004');
            const loginUrl = `/sp/sso/initiate?app=app4&returnUrl=${returnUrl}`;
            return res.status(401).json({
                error: 'Session expired',
                loginUrl: loginUrl
            });
        }
    }

    const name = req.session.attributes?.givenName || req.session.attributes?.cn || 'Anonymous';
    const responseData = {
        message: `Hello ${name}! This is protected data for App 4!`,
        timestamp: new Date().toISOString(),
        samlUser: req.session.samlAssertion,
        appId: 'app4',
        attributes: req.session.attributes,
        sessionId: generateRequestID()
    };

    console.log('✅ Returning protected data for App 4');
    res.json(responseData);
});

// Root endpoint for health check
app.get('/', (req, res) => {
    res.json({
        service: 'SAML Service Provider',
        status: 'running',
        version: '2.0.0',
        timestamp: new Date().toISOString(),
        endpoints: {
            metadata: '/sp/metadata',
            sso_initiate: '/sp/sso/initiate',
            acs: '/sp/acs',
            session_status: '/sp/session/status',
            logout: '/sp/logout',
            protected_app3: '/api/protected/app3',
            protected_app4: '/api/protected/app4'
        },
        idpMetadataUrl: URI_IDP_METADATA
    });
});

// Start server after SAML initialization
async function startServer() {
    const initialized = await initializeSAML();

    if (!initialized) {
        console.error('❌ Failed to initialize SAML. Make sure IdP is running on http://localhost:4002');
        process.exit(1);
    }

    app.listen(4001, () => {
        console.log('🔐 SAML Service Provider v2.0 running on http://localhost:4001');
        console.log('📋 Available endpoints:');
        console.log('   - GET  / (Health check & service info)');
        console.log('   - GET  /sp/metadata (SP metadata)');
        console.log('   - GET  /sp/sso/initiate (Initiate SAML login)');
        console.log('   - POST /sp/acs (Assertion Consumer Service)');
        console.log('   - GET  /sp/session/status (Check auth status)');
        console.log('   - GET  /sp/logout (Logout)');
        console.log('   - GET  /api/protected/app3 (Protected endpoint for App 3)');
        console.log('   - GET  /api/protected/app4 (Protected endpoint for App 4)');
        console.log('🔗 Identity Provider: ' + URI_IDP_METADATA);
    });
}

startServer().catch(error => {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
});
