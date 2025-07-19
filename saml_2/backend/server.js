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

// SAML Identity Provider Configuration (for SP to know about IdP)
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

// Initiate SAML SSO
app.get('/saml/sso/initiate', (req, res) => {
    const { app: appName, returnUrl } = req.query;

    // Store app context and return URL in session
    req.session.appContext = { appName, returnUrl };

    try {
        const { id, context: requestXML } = sp.createLoginRequest(idp, 'redirect');

        // Store request ID for validation
        req.session.samlRequestId = id;

        console.log('🚀 Initiating SAML SSO for:', appName);
        console.log('📝 SAML Request ID:', id);

        // Redirect to IdP with SAML Request
        const ssoUrl = `${idp.singleSignOnService[0].Location}?SAMLRequest=${encodeURIComponent(requestXML)}&RelayState=${encodeURIComponent(JSON.stringify({ appName, returnUrl }))}`;

        res.redirect(ssoUrl);
    } catch (error) {
        console.error('❌ Error creating SAML login request:', error);
        res.status(500).json({ error: 'Failed to initiate SAML SSO' });
    }
});

// SAML Assertion Consumer Service (ACS)
app.post('/saml/acs', (req, res) => {
    const { SAMLResponse, RelayState } = req.body;

    try {
        const relayState = JSON.parse(decodeURIComponent(RelayState || '{}'));
        console.log('📨 Received SAML Response, RelayState:', relayState);

        // Parse and validate SAML response
        const { extract } = sp.parseLoginResponse(idp, 'post', { body: req.body });

        console.log('✅ SAML Response validated successfully');
        console.log('👤 SAML Subject:', extract.subject);
        console.log('📋 SAML Attributes:', extract.attributes);

        // Store SAML assertion in session
        req.session.samlAssertion = {
            subject: extract.subject,
            attributes: extract.attributes,
            sessionIndex: extract.sessionIndex,
            issuer: extract.issuer,
            audience: extract.audience,
            notBefore: extract.conditions?.notBefore,
            notOnOrAfter: extract.conditions?.notOnOrAfter,
            authnStatement: extract.authnStatement
        };

        req.session.authenticated = true;

        // Redirect back to the original app
        const returnUrl = relayState.returnUrl || `http://localhost:${relayState.appName === 'app2' ? '3003' : '3002'}`;
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

// Protected endpoints
app.get('/api/protected/app1', requireSAMLAuth, (req, res) => {
    res.json({
        message: 'This is protected data for SAML App 1!',
        timestamp: new Date().toISOString(),
        samlSubject: req.samlUser.subject,
        samlAttributes: req.samlUser.attributes,
        appId: 'saml-app1',
        specialData: {
            feature: 'SAML Advanced Analytics',
            permissions: ['read', 'write', 'admin'],
            customMessage: 'Welcome to SAML App 1 - The Main Dashboard'
        }
    });
});

app.get('/api/protected/app2', requireSAMLAuth, (req, res) => {
    res.json({
        message: 'This is protected data for SAML App 2!',
        timestamp: new Date().toISOString(),
        samlSubject: req.samlUser.subject,
        samlAttributes: req.samlUser.attributes,
        appId: 'saml-app2',
        specialData: {
            feature: 'SAML Reporting Module',
            permissions: ['read', 'export'],
            customMessage: 'Welcome to SAML App 2 - The Reporting Suite'
        }
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

        // Destroy local session
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
            }
        });

        // Redirect to IdP for global logout
        const sloUrl = `${idp.singleLogoutService[0].Location}?SAMLRequest=${encodeURIComponent(logoutRequestXML)}`;

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
      <a href="http://localhost:3002">Return to App 1</a> | 
      <a href="http://localhost:3003">Return to App 2</a>
    </body>
    </html>
  `);
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
        console.log('   - Protected App1: http://localhost:4003/api/protected/app1');
        console.log('   - Protected App2: http://localhost:4003/api/protected/app2');
    });
}

export default app;
