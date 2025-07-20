import express from 'express';
import session from 'express-session';
import { ServiceProvider, IdentityProvider, setSchemaValidator } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import axios from 'axios';
import cors from 'cors';

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:4003', 'http://localhost:4004'],
    credentials: true
}));

app.use(session({
    secret: 'sp-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

setSchemaValidator(validator);

let sp, idp;

// Initialize SAML
async function initializeSAML() {
    try {
        // Fetch IdP metadata
        const response = await axios.get('http://localhost:4002/idp/metadata');

        // Create IdP from metadata
        idp = IdentityProvider({ metadata: response.data });

        // Create SP
        sp = ServiceProvider({
            entityID: 'http://localhost:4001/sp/metadata',
            assertionConsumerService: [{
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                Location: 'http://localhost:4001/sp/acs'
            }]
        });

        console.log('✅ SAML initialized successfully');
        return true;
    } catch (error) {
        console.error('❌ SAML initialization failed:', error.message);
        return false;
    }
}

// Health check
app.get('/', (req, res) => {
    res.json({
        service: 'SAML Service Provider',
        status: 'running',
        version: '2.0.0',
        endpoints: {
            metadata: '/sp/metadata',
            sso_initiate: '/sp/sso/initiate',
            acs: '/sp/acs',
            session_status: '/sp/session/status',
            logout: '/sp/logout',
            protected_app3: '/api/protected/app3',
            protected_app4: '/api/protected/app4'
        }
    });
});

// SP Metadata
app.get('/sp/metadata', (req, res) => {
    if (!sp) {
        return res.status(500).json({ error: 'SP not initialized' });
    }

    const metadata = sp.getMetadata();
    res.set('Content-Type', 'text/xml');
    res.send(metadata);
});

// SSO Initiate
app.get('/sp/sso/initiate', (req, res) => {
    const { app: appId, returnUrl } = req.query;

    if (!sp || !idp) {
        return res.status(500).json({ error: 'SAML not initialized' });
    }

    try {
        const { context } = sp.createLoginRequest(idp, 'redirect');

        // Store app info in session
        req.session.appId = appId;
        req.session.returnUrl = returnUrl;

        console.log(`🚀 SSO initiated for app: ${appId}`);
        console.log(`🔗 Redirecting to: ${context}`);

        res.redirect(context);
    } catch (error) {
        console.error('❌ SSO initiation failed:', error);
        res.status(500).json({
            error: 'Failed to initiate SSO',
            details: error.message
        });
    }
});

// Assertion Consumer Service
app.post('/sp/acs', async (req, res) => {
    if (!sp || !idp) {
        return res.status(500).json({ error: 'SAML not initialized' });
    }

    try {
        const { extract } = await sp.parseLoginResponse(idp, 'post', req);

        // Extract user info
        const user = {
            nameID: extract.nameID,
            attributes: extract.attributes || {},
            sessionIndex: extract.sessionIndex
        };

        // Store in session
        req.session.user = user;
        req.session.authenticated = true;

        console.log('✅ User authenticated:', user.nameID);
        console.log('📋 Attributes:', user.attributes);

        // Redirect to return URL or default
        const returnUrl = req.session.returnUrl || 'http://localhost:4004';
        req.session.returnUrl = null; // Clear it

        res.redirect(returnUrl);

    } catch (error) {
        console.error('❌ ACS processing failed:', error);
        res.status(500).json({
            error: 'Failed to process SAML response',
            details: error.message
        });
    }
});

// Session Status
app.get('/sp/session/status', (req, res) => {
    if (req.session.authenticated && req.session.user) {
        res.json({
            authenticated: true,
            user: req.session.user,
            authMethod: 'saml'
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Logout
app.get('/sp/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out successfully' });
});

// Protected endpoint for App 3
app.get('/api/protected/app3', (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).json({
            error: 'Authentication required',
            loginUrl: '/sp/sso/initiate?app=app3&returnUrl=' + encodeURIComponent('http://localhost:4003')
        });
    }

    const name = req.session.user.attributes?.givenName ||
        req.session.user.attributes?.cn ||
        req.session.user.nameID || 'User';

    res.json({
        message: `Hello ${name}! This is protected data for App 3!`,
        timestamp: new Date().toISOString(),
        user: req.session.user,
        appId: 'app3'
    });
});

// Protected endpoint for App 4
app.get('/api/protected/app4', (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).json({
            error: 'Authentication required',
            loginUrl: '/sp/sso/initiate?app=app4&returnUrl=' + encodeURIComponent('http://localhost:4004')
        });
    }

    const name = req.session.user.attributes?.givenName ||
        req.session.user.attributes?.cn ||
        req.session.user.nameID || 'User';

    res.json({
        message: `Hello ${name}! This is protected data for App 4!`,
        timestamp: new Date().toISOString(),
        user: req.session.user,
        appId: 'app4'
    });
});

// Start server
async function startServer() {
    const initialized = await initializeSAML();

    if (!initialized) {
        console.error('❌ Failed to initialize SAML');
        process.exit(1);
    }

    app.listen(4001, () => {
        console.log('🔐 SAML Service Provider running on http://localhost:4001');
        console.log('📋 Endpoints available:');
        console.log('   - GET  /sp/sso/initiate');
        console.log('   - POST /sp/acs');
        console.log('   - GET  /sp/metadata');
        console.log('   - GET  /sp/session/status');
        console.log('   - GET  /sp/logout');
        console.log('   - GET  /api/protected/app3');
        console.log('   - GET  /api/protected/app4');
    });
}

startServer();
