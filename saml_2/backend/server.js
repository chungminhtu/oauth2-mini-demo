import express from 'express';
import cors from 'cors';
import session from 'express-session';
import { ServiceProvider, IdentityProvider } from 'samlify';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: ['http://localhost:3002', 'http://localhost:3003'],
    credentials: true
}));

app.use(session({
    name: 'saml_session',
    secret: 'saml-service-provider-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 8 * 60 * 60 * 1000 // 8 hours
    }
}));

// SAML Service Provider Configuration
const sp = ServiceProvider({
    entityID: 'http://localhost:4003/saml/metadata',
    authnRequestsSigned: false,
    wantAssertionsSigned: false,
    wantMessageSigned: false,
    wantLogoutResponseSigned: false,
    wantLogoutRequestSigned: false,
    assertionConsumerService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'http://localhost:4003/saml/acs'
    }],
    singleLogoutService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        Location: 'http://localhost:4003/saml/sls'
    }]
});

// SAML Identity Provider Configuration
const idp = IdentityProvider({
    entityID: 'http://localhost:4001/saml/metadata',
    wantAuthnRequestsSigned: false,
    singleSignOnService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        Location: 'http://localhost:4001/saml/sso'
    }],
    singleLogoutService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        Location: 'http://localhost:4001/saml/slo'
    }]
});

// SP Metadata endpoint
app.get('/saml/metadata', (req, res) => {
    res.header('Content-Type', 'text/xml').send(sp.getMetadata());
});

// Initiate SAML SSO - FIXED VERSION
app.get('/saml/sso/initiate', (req, res) => {
    const { app: appName, returnUrl } = req.query;

    console.log('🚀 Initiating SAML SSO for:', appName);
    req.session.appContext = { appName, returnUrl };

    try {
        const { id, context } = sp.createLoginRequest(idp, 'redirect');
        req.session.samlRequestId = id;

        console.log('📝 SAML Request ID:', id);
        console.log('🔗 Context type:', typeof context);

        // FIX: Handle context properly - it should be a URL with SAMLRequest
        let samlRequest;
        if (typeof context === 'string' && context.includes('SAMLRequest=')) {
            // Extract SAMLRequest from URL
            const urlObj = new URL(context);
            samlRequest = urlObj.searchParams.get('SAMLRequest');
        } else {
            // Context is the SAMLRequest directly
            samlRequest = context;
        }

        const relayState = JSON.stringify({ appName, returnUrl });
        const ssoUrl = `http://localhost:4001/saml/sso?SAMLRequest=${encodeURIComponent(samlRequest)}&RelayState=${encodeURIComponent(relayState)}`;

        console.log('🔄 Redirecting to:', ssoUrl);
        res.redirect(ssoUrl);
    } catch (error) {
        console.error('❌ Error creating SAML login request:', error);
        res.status(500).json({ error: 'Failed to initiate SAML SSO', details: error.message });
    }
});

// SAML Assertion Consumer Service (ACS) - FIXED VERSION
app.post('/saml/acs', (req, res) => {
    const { SAMLResponse, RelayState } = req.body;

    try {
        let relayState = {};
        try {
            relayState = JSON.parse(decodeURIComponent(RelayState || '{}'));
        } catch (e) {
            console.warn('Could not parse RelayState:', RelayState);
            relayState = { appName: 'app3', returnUrl: 'http://localhost:3002' };
        }

        console.log('📨 Received SAML Response, RelayState:', relayState);

        // Parse and validate SAML response
        const { extract } = sp.parseLoginResponse(idp, 'post', { body: req.body });

        console.log('✅ SAML Response validated successfully');
        console.log('👤 SAML Subject (nameID):', extract.nameID);
        console.log('📋 SAML Attributes:', extract.attributes);
        console.log('🔑 Session Index:', extract.sessionIndex);

        // Store SAML assertion in session
        req.session.samlAssertion = {
            subject: extract.nameID,
            attributes: extract.attributes,
            sessionIndex: extract.sessionIndex,
            issuer: extract.issuer,
            audience: extract.audience,
            notBefore: extract.conditions?.notBefore,
            notOnOrAfter: extract.conditions?.notOnOrAfter,
            authnStatement: extract.authnStatement
        };

        req.session.authenticated = true;
        req.session.authMethod = 'saml';

        console.log('💾 Stored SAML assertion in session');

        // Redirect back to the original app
        const returnUrl = relayState.returnUrl || `http://localhost:${relayState.appName === 'app4' ? '3003' : '3002'}`;

        console.log('🔄 Redirecting back to:', returnUrl);
        res.redirect(returnUrl);

    } catch (error) {
        console.error('❌ SAML Response validation failed:', error);
        res.status(400).json({ error: 'Invalid SAML response', details: error.message });
    }
});

// SAML Session Status
app.get('/saml/session/status', (req, res) => {
    if (req.session.authenticated && req.session.samlAssertion) {
        const { notOnOrAfter } = req.session.samlAssertion;

        // Check if assertion is still valid
        if (notOnOrAfter && new Date() > new Date(notOnOrAfter)) {
            req.session.destroy();
            return res.json({ authenticated: false, reason: 'SAML assertion expired' });
        }

        res.json({
            authenticated: true,
            authMethod: 'saml',
            assertion: req.session.samlAssertion
        });
    } else {
        res.json({ authenticated: false });
    }
});

// SAML middleware for protecting routes
const requireSAMLAuth = (req, res, next) => {
    if (!req.session.authenticated || !req.session.samlAssertion) {
        return res.status(401).json({
            error: 'SAML authentication required',
            message: 'Please authenticate with SAML Identity Provider'
        });
    }

    // Check assertion expiration
    const { notOnOrAfter } = req.session.samlAssertion;
    if (notOnOrAfter && new Date() > new Date(notOnOrAfter)) {
        req.session.destroy();
        return res.status(401).json({
            error: 'SAML assertion expired',
            message: 'Your SAML session has expired. Please re-authenticate.'
        });
    }

    req.samlUser = req.session.samlAssertion;
    next();
};

// Protected endpoints for App 3 and App 4
app.get('/api/protected/app3', requireSAMLAuth, (req, res) => {
    res.json({
        message: 'This is protected data for SAML App 3!',
        timestamp: new Date().toISOString(),
        samlUser: req.session.samlAssertion,
        appId: 'app3',
        authMethod: 'saml',
        specialData: {
            feature: 'SAML Analytics Dashboard',
            permissions: ['read', 'write', 'saml-admin'],
            customMessage: 'Welcome to SAML App 3 - Advanced Analytics'
        }
    });
});

app.get('/api/protected/app4', requireSAMLAuth, (req, res) => {
    res.json({
        message: 'This is protected data for SAML App 4!',
        timestamp: new Date().toISOString(),
        samlUser: req.session.samlAssertion,
        appId: 'app4',
        authMethod: 'saml',
        specialData: {
            feature: 'SAML Reporting Suite',
            permissions: ['read', 'export', 'saml-reports'],
            customMessage: 'Welcome to SAML App 4 - Enterprise Reporting'
        }
    });
});

// Test endpoint with fake token (for testing)
app.get('/api/protected/test', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token === 'fake-saml-token') {
        return res.status(401).json({
            error: 'Invalid token',
            message: 'As expected, fake token was rejected'
        });
    }

    res.status(401).json({
        error: 'No valid authentication',
        message: 'Please use SAML authentication'
    });
});

// SAML Single Logout initiation
app.post('/saml/slo/initiate', requireSAMLAuth, (req, res) => {
    try {
        const { id, context: logoutRequestXML } = sp.createLogoutRequest(idp, 'redirect', {
            nameID: req.samlUser.subject,
            sessionIndex: req.samlUser.sessionIndex
        });

        console.log('🚪 Initiating SAML Single Logout');
        console.log('📝 Logout Request ID:', id);

        // Destroy local session
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
            }
        });

        // Redirect to IdP for global logout
        const sloUrl = `http://localhost:4001/saml/slo?SAMLRequest=${encodeURIComponent(logoutRequestXML)}`;

        res.json({
            success: true,
            message: 'Local SAML session destroyed',
            globalLogoutUrl: sloUrl
        });
    } catch (error) {
        console.error('❌ Error creating SAML logout request:', error);
        res.status(500).json({ error: 'Failed to initiate SAML logout' });
    }
});

// SAML Single Logout Service (SLS) - Handle logout response from IdP  
app.get('/saml/sls', (req, res) => {
    console.log('🔄 Received SAML Logout Response from IdP');

    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>SAML Logout Complete</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; text-align: center; }
        .success { color: green; }
      </style>
    </head>
    <body>
      <h2>🚪 SAML Single Logout Complete</h2>
      <p class="success">✅ You have been successfully logged out from all SAML sessions.</p>
      <a href="http://localhost:3002">Return to App 3</a> | 
      <a href="http://localhost:3003">Return to App 4</a>
    </body>
    </html>
  `);
});

// Simple logout endpoint (destroy local session only)
app.post('/saml/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Failed to logout' });
        }

        res.json({
            success: true,
            message: 'Local session destroyed successfully'
        });
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'SAML Service Provider',
        timestamp: new Date().toISOString()
    });
});

// Error handling
app.use((err, req, res, next) => {
    console.error('SAML SP Error:', err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error',
        type: 'saml_sp_error'
    });
});

if (process.env.NODE_ENV === 'dev') {
    app.listen(4003, () => {
        console.log('🔐 SAML Service Provider is running on http://localhost:4003');
        console.log('📋 Available endpoints:');
        console.log('   - Metadata: http://localhost:4003/saml/metadata');
        console.log('   - SSO Initiate: http://localhost:4003/saml/sso/initiate');
        console.log('   - Session Status: http://localhost:4003/saml/session/status');
        console.log('   - Protected App3: http://localhost:4003/api/protected/app3');
        console.log('   - Protected App4: http://localhost:4003/api/protected/app4');
    });
}

export default app;
