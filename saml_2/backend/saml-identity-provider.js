import express from 'express';
import cors from 'cors';
import session from 'express-session';
import { IdentityProvider, ServiceProvider, setSchemaValidator } from 'samlify';
import { v4 as uuidv4 } from 'uuid';
import * as validator from '@authenio/samlify-node-xmllint';

// Set schema validator (IMPORTANT - this was missing!)
setSchemaValidator(validator);

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

// SIMPLIFIED SAML Identity Provider Configuration (no certificates for demo)
const idp = IdentityProvider({
  entityID: 'http://localhost:4001/saml/metadata',
  wantAuthnRequestsSigned: false,
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
  singleSignOnService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://localhost:4001/saml/sso'
  }],
  singleLogoutService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://localhost:4001/saml/slo'
  }]
});

// Service Provider Configuration (for parsing requests)
const sp = ServiceProvider({
  entityID: 'http://localhost:4003/saml/metadata',
  authnRequestsSigned: false,
  wantAssertionsSigned: false,
  assertionConsumerService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    Location: 'http://localhost:4003/saml/acs'
  }]
});

// Store for SAML requests and sessions
const samlRequestStore = new Map();
const activeSessions = new Map();

// IdP Metadata endpoint
app.get('/saml/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(idp.getMetadata());
});

// SAML SSO Endpoint - USING ONLY SAMLIFY
app.get('/saml/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;

  console.log('📨 Received SAML AuthnRequest, RelayState:', RelayState);

  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  try {
    // Parse the SAML AuthnRequest using samlify ONLY
    const { extract } = idp.parseLoginRequest(sp, 'redirect', { query: req.query });

    console.log('🔍 Parsed SAML extract:', extract);

    // Handle different extract structures from samlify
    const requestId = extract.request?.id || extract.id || `_${uuidv4()}`;
    const issuer = extract.request?.issuer || extract.issuer || sp.entityID;
    const acsUrl = extract.request?.assertionConsumerServiceURL ||
      extract.assertionConsumerServiceURL ||
      sp.assertionConsumerService[0].Location;

    console.log('📝 Request ID:', requestId);
    console.log('🏢 Issuer:', issuer);
    console.log('📍 ACS URL:', acsUrl);

    // Store the request context
    samlRequestStore.set(requestId, {
      extract: extract,
      relayState: RelayState,
      timestamp: Date.now(),
      acsUrl: acsUrl,
      issuer: issuer
    });

    // Check if user is already authenticated
    if (req.session && req.session.authenticatedUser) {
      console.log('✅ User already authenticated');
      return generateAndSendSAMLResponse(req.session.authenticatedUser, requestId, res);
    }

    // Show login form
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>SAML Identity Provider - Login</title></head>
      <body>
        <h2>🔐 SAML Identity Provider</h2>
        <form method="post" action="/saml/authenticate">
          <input type="hidden" name="requestId" value="${requestId}">
          <input type="hidden" name="relayState" value="${RelayState || ''}">
          <input type="email" name="username" value="john@example.com" required>
          <input type="password" name="password" value="password123" required>
          <button type="submit">🚀 Login</button>
        </form>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('❌ Error processing SAML AuthnRequest:', error);
    res.status(500).json({
      error: 'Failed to process SAML authentication request',
      details: error.message
    });
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
        <a href="javascript:history.back()">Try Again</a>
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

    // Create user attributes for SAML response
    const userAttributes = {
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      department: user.department,
      role: user.role
    };

    // Generate SAML Response using samlify
    const { id, context: samlResponse } = idp.createLoginResponse(
      sp,
      requestContext.extract,
      'post',
      user.email, // Subject/NameID
      userAttributes, // Attributes
      false, // Not encrypted
      requestContext.relayState
    );

    // Clean up request store
    samlRequestStore.delete(requestId);

    console.log(`✅ SAML Response generated with ID: ${id}`);

    // Send SAML Response via POST binding
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>SAML Response</title></head>
      <body onload="document.forms[0].submit()">
        <form method="post" action="${requestContext.acsUrl}">
          <input type="hidden" name="SAMLResponse" value="${samlResponse}">
          <input type="hidden" name="RelayState" value="${requestContext.relayState || ''}">
          <p>🔄 Redirecting back to Service Provider...</p>
          <button type="submit">Continue</button>
        </form>
      </body>
      </html>
    `);

    console.log(`✅ SAML Response sent to SP: ${requestContext.acsUrl}`);

  } catch (error) {
    console.error('❌ Error generating SAML Response:', error);
    res.status(500).json({ error: 'Failed to generate SAML response', details: error.message });
  }
};

// Rest of your endpoints (logout, health, etc.)
app.get('/saml/slo', (req, res) => {
  console.log('🚪 Received SAML Logout Request');
  req.session.destroy(() => {
    res.send('<html><body><h2>🚪 Logout Complete</h2></body></html>');
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'SAML Identity Provider',
    timestamp: new Date().toISOString()
  });
});

if (process.env.NODE_ENV === 'dev') {
  app.listen(4001, () => {
    console.log('🔐 SAML Identity Provider is running on http://localhost:4001');
  });
}

export default app;
