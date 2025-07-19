import express from 'express';
import cors from 'cors';
import session from 'express-session';
import { IdentityProvider } from 'samlify';
import { v4 as uuidv4 } from 'uuid';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Session for IdP user sessions
app.use(session({
  name: 'idp_session',
  secret: 'saml-identity-provider-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Mock user database
const users = {
  'john@example.com': {
    password: 'password123',
    firstName: 'John',
    lastName: 'Doe',
    email: 'john@example.com',
    department: 'Engineering',
    role: 'Senior Developer'
  },
  'jane@example.com': {
    password: 'password123',
    firstName: 'Jane',
    lastName: 'Smith',
    email: 'jane@example.com',
    department: 'Marketing',
    role: 'Marketing Manager'
  }
};

// SAML Identity Provider Configuration
const idp = IdentityProvider({
  entityID: 'http://localhost:4001/saml/metadata',
  authnRequestsSigned: false,
  wantAuthnRequestsSigned: false,
  messageSigningOrder: 'encrypt-then-sign',
  singleSignOnService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://localhost:4001/saml/sso'
  }],
  singleLogoutService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://localhost:4001/saml/slo'
  }],
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
  signingCert: '', // In production, add proper certificates
  encryptionCert: ''
});

// Service Provider Configuration (for IdP to know about SP)
const sp = {
  entityID: 'http://localhost:4003/saml/metadata',
  assertionConsumerService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    Location: 'http://localhost:4003/saml/acs'
  }]
};

// Store for SAML requests and sessions
const samlRequestStore = new Map();
const activeSessions = new Map();

// IdP Metadata endpoint
app.get('/saml/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(idp.getMetadata());
});

// SAML SSO Endpoint - Receive AuthnRequest
app.get('/saml/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;

  console.log('📨 Received SAML AuthnRequest, RelayState:', RelayState);

  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  try {
    // Parse the SAML AuthnRequest using samlify
    const { extract } = idp.parseLoginRequest(sp, 'redirect', { query: req.query });

    console.log('🔍 Parsed SAML AuthnRequest');
    console.log('📝 Request ID:', extract.request.id);
    console.log('🏢 Issuer:', extract.request.issuer);
    console.log('📍 ACS URL:', extract.request.assertionConsumerServiceURL);

    // Store SAML request context
    const requestId = extract.request.id;
    samlRequestStore.set(requestId, {
      request: extract.request,
      relayState: RelayState,
      timestamp: Date.now()
    });

    // Check if user is already authenticated
    if (req.session && req.session.authenticatedUser) {
      console.log('✅ User already authenticated, generating SAML Response');
      return generateAndSendSAMLResponse(req.session.authenticatedUser, requestId, res);
    }

    // Show login form
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SAML Identity Provider - Login</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
          .form-group { margin: 15px 0; }
          label { display: block; margin-bottom: 5px; }
          input { width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ddd; }
          button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
          button:hover { background: #0056b3; }
          .error { color: red; margin: 10px 0; }
          .info { background: #e9ecef; padding: 15px; margin-bottom: 20px; border-left: 4px solid #007bff; }
        </style>
      </head>
      <body>
        <h2>🔐 SAML Identity Provider</h2>
        <div class="info">
          <strong>Service Provider:</strong> ${extract.request.issuer}<br>
          <strong>Authentication Request ID:</strong> ${requestId}<br>
          <strong>ACS URL:</strong> ${extract.request.assertionConsumerServiceURL}
        </div>
        
        <form method="post" action="/saml/authenticate">
          <input type="hidden" name="requestId" value="${requestId}">
          <input type="hidden" name="relayState" value="${RelayState || ''}">
          
          <div class="form-group">
            <label>Email:</label>
            <input type="email" name="username" value="john@example.com" required>
          </div>
          
          <div class="form-group">
            <label>Password:</label>
            <input type="password" name="password" value="password123" required>
          </div>
          
          <button type="submit">🚀 Authenticate & Continue to Service Provider</button>
        </form>
        
        <div style="margin-top: 30px; padding: 15px; background: #f8f9fa; border: 1px solid #dee2e6;">
          <h4>Demo Users:</h4>
          <p><strong>john@example.com</strong> / password123</p>
          <p><strong>jane@example.com</strong> / password123</p>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('❌ Error processing SAML AuthnRequest:', error);
    res.status(500).json({ error: 'Failed to process SAML authentication request', details: error.message });
  }
});

// Process authentication
app.post('/saml/authenticate', (req, res) => {
  const { username, password, requestId, relayState } = req.body;

  console.log(`🔐 Authentication attempt for user: ${username}`);

  // Validate credentials
  const user = users[username];
  if (!user || user.password !== password) {
    console.log('❌ Invalid credentials');
    return res.status(401).send(`
      <html><body>
        <h2>❌ Authentication Failed</h2>
        <p>Invalid username or password.</p>
        <a href="/saml/sso?SAMLRequest=${req.query.SAMLRequest}&RelayState=${relayState}">Try Again</a>
      </body></html>
    `);
  }

  console.log('✅ User authenticated successfully');

  // Store user in IdP session
  req.session.authenticatedUser = user;

  // Generate session index for SSO
  const sessionIndex = uuidv4();
  activeSessions.set(sessionIndex, {
    user: user,
    loginTime: new Date(),
    sessionId: req.session.id
  });

  // Generate and send SAML Response
  generateAndSendSAMLResponse(user, requestId, res, sessionIndex);
});

// Helper function to generate and send SAML Response using samlify
const generateAndSendSAMLResponse = (user, requestId, res, sessionIndex = null) => {
  const requestContext = samlRequestStore.get(requestId);

  if (!requestContext) {
    return res.status(400).json({ error: 'Invalid or expired SAML request' });
  }

  console.log(`📤 Generating SAML Response for user: ${user.email}`);

  try {
    // Generate session index if not provided
    const currentSessionIndex = sessionIndex || uuidv4();

    // Create user info for SAML response
    const userInfo = {
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      department: user.department,
      role: user.role
    };

    // Generate SAML Response using samlify
    const { id, context: samlResponse } = idp.createLoginResponse(
      sp,
      requestContext.request,
      'post',
      user.email, // Subject/NameID
      {
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        department: user.department,
        role: user.role
      }, // Attributes
      false, // Not encrypted
      requestContext.relayState,
      {
        sessionIndex: currentSessionIndex,
        authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      }
    );

    // Clean up request store
    samlRequestStore.delete(requestId);

    console.log(`✅ SAML Response generated with ID: ${id}`);
    console.log(`📋 Session Index: ${currentSessionIndex}`);

    // Send SAML Response via POST binding
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SAML Response</title>
      </head>
      <body onload="document.forms[0].submit()">
        <form method="post" action="${requestContext.request.assertionConsumerServiceURL}">
          <input type="hidden" name="SAMLResponse" value="${samlResponse}">
          <input type="hidden" name="RelayState" value="${requestContext.relayState || ''}">
          <p>🔄 Redirecting back to Service Provider...</p>
          <button type="submit">Continue if not redirected automatically</button>
        </form>
      </body>
      </html>
    `);

    console.log(`✅ SAML Response sent to SP: ${requestContext.request.assertionConsumerServiceURL}`);

  } catch (error) {
    console.error('❌ Error generating SAML Response:', error);
    res.status(500).json({ error: 'Failed to generate SAML response', details: error.message });
  }
};

// SAML Single Logout endpoint
app.get('/saml/slo', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;

  console.log('🚪 Received SAML Logout Request');

  try {
    if (SAMLRequest) {
      // Parse logout request
      const { extract } = idp.parseLogoutRequest(sp, 'redirect', { query: req.query });

      console.log('👤 Logout request for:', extract.request.nameID);
      console.log('🗝️ Session Index:', extract.request.sessionIndex);

      // Find and destroy the session
      const sessionIndex = extract.request.sessionIndex;
      if (activeSessions.has(sessionIndex)) {
        activeSessions.delete(sessionIndex);
        console.log('✅ Session destroyed');
      }

      // Destroy current session
      req.session.destroy();

      // Generate logout response
      const { context: logoutResponse } = idp.createLogoutResponse(
        sp,
        extract.request,
        'redirect',
        RelayState
      );

      console.log('📤 Sending SAML Logout Response');

      // Redirect back to SP with logout response
      const sloUrl = `${sp.assertionConsumerService[0].Location.replace('/acs', '/sls')}?SAMLResponse=${encodeURIComponent(logoutResponse)}&RelayState=${encodeURIComponent(RelayState || '')}`;

      res.redirect(sloUrl);
    } else {
      // Direct logout without SAML request
      req.session.destroy();
      res.send(`
        <html><body>
          <h2>🚪 Logout Complete</h2>
          <p>✅ You have been logged out successfully.</p>
        </body></html>
      `);
    }
  } catch (error) {
    console.error('❌ Error processing SAML Logout Request:', error);
    res.status(500).json({ error: 'Failed to process SAML logout request', details: error.message });
  }
});

// Get active sessions (for debugging)
app.get('/saml/sessions', (req, res) => {
  const sessions = Array.from(activeSessions.entries()).map(([sessionIndex, data]) => ({
    sessionIndex,
    user: data.user.email,
    loginTime: data.loginTime
  }));

  res.json({
    totalSessions: sessions.length,
    sessions: sessions
  });
});

// User info endpoint (protected)
app.get('/saml/userinfo', (req, res) => {
  if (!req.session.authenticatedUser) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const { password, ...userInfo } = req.session.authenticatedUser;
  res.json({
    authenticated: true,
    user: userInfo,
    sessionId: req.session.id
  });
});

// Logout endpoint
app.post('/saml/logout', (req, res) => {
  if (req.session.authenticatedUser) {
    console.log(`🚪 Logging out user: ${req.session.authenticatedUser.email}`);
  }
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ error: 'Failed to logout' });
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'SAML Identity Provider',
    timestamp: new Date().toISOString(),
    activeSessions: activeSessions.size
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('SAML IdP Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    type: 'saml_idp_error'
  });
});

// Clean up expired sessions periodically
setInterval(() => {
  const now = Date.now();
  const expiredSessions = [];

  for (const [sessionIndex, data] of activeSessions.entries()) {
    // Remove sessions older than 24 hours
    if (now - data.loginTime.getTime() > 24 * 60 * 60 * 1000) {
      expiredSessions.push(sessionIndex);
    }
  }

  expiredSessions.forEach(sessionIndex => {
    activeSessions.delete(sessionIndex);
    console.log(`🗑️ Cleaned up expired session: ${sessionIndex}`);
  });
}, 60 * 60 * 1000); // Run every hour

if (process.env.NODE_ENV === 'dev') {
  app.listen(4001, () => {
    console.log('🔐 SAML Identity Provider is running on http://localhost:4001');
    console.log('📋 Available endpoints:');
    console.log('   - Metadata: http://localhost:4001/saml/metadata');
    console.log('   - SSO: http://localhost:4001/saml/sso');
    console.log('   - SLO: http://localhost:4001/saml/slo');
    console.log('   - User Info: http://localhost:4001/saml/userinfo');
    console.log('   - Sessions: http://localhost:4001/saml/sessions');
    console.log('   - Health: http://localhost:4001/health');
  });
}

export default app;
