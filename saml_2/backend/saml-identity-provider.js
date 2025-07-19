import express from 'express';
import cors from 'cors';
import session from 'express-session';
import { v4 as uuidv4 } from 'uuid';
import zlib from 'zlib';

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

// Store for SAML requests and sessions
const samlRequestStore = new Map();
const activeSessions = new Map();

// Helper function to parse SAML request with decompression
const parseSamlRequest = (samlRequest) => {
  try {
    // Step 1: Base64 decode
    const decodedBuffer = Buffer.from(samlRequest, 'base64');

    // Step 2: Inflate (decompress) the data
    const decompressedBuffer = zlib.inflateRawSync(decodedBuffer);
    const decodedXml = decompressedBuffer.toString('utf-8');

    console.log('🔍 Decompressed SAML XML (first 300 chars):', decodedXml.substring(0, 300));

    // Step 3: Parse XML manually
    const idMatch = decodedXml.match(/ID="([^"]+)"/);
    const issuerMatch = decodedXml.match(/<saml:Issuer[^>]*>([^<]+)<\/saml:Issuer>/);
    const acsMatch = decodedXml.match(/AssertionConsumerServiceURL="([^"]+)"/);
    const destinationMatch = decodedXml.match(/Destination="([^"]+)"/);

    return {
      id: idMatch ? idMatch[1] : `_${uuidv4()}`,
      issuer: issuerMatch ? issuerMatch[1] : 'http://localhost:4003/saml/metadata',
      assertionConsumerServiceURL: acsMatch ? acsMatch[1] : 'http://localhost:4003/saml/acs',
      destination: destinationMatch ? destinationMatch[1] : 'http://localhost:4001/saml/sso',
      rawXml: decodedXml
    };
  } catch (error) {
    console.error('❌ Error parsing SAML request:', error);
    // Fallback values
    return {
      id: `_${uuidv4()}`,
      issuer: 'http://localhost:4003/saml/metadata',
      assertionConsumerServiceURL: 'http://localhost:4003/saml/acs',
      destination: 'http://localhost:4001/saml/sso',
      rawXml: 'Error parsing XML'
    };
  }
};

// Helper function to generate SAML Response
const generateSAMLResponse = (user, request, relayState) => {
  const responseId = '_' + uuidv4().replace(/-/g, '');
  const assertionId = '_' + uuidv4().replace(/-/g, '');
  const sessionIndex = uuidv4().replace(/-/g, '');

  const now = new Date();
  const notBefore = new Date(now.getTime() - 5 * 60 * 1000); // 5 minutes ago
  const notOnOrAfter = new Date(now.getTime() + 8 * 60 * 60 * 1000); // 8 hours from now
  const authnInstant = now.toISOString();
  const issueInstant = now.toISOString();

  const samlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response 
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${responseId}"
  Version="2.0"
  IssueInstant="${issueInstant}"
  Destination="${request.assertionConsumerServiceURL}"
  InResponseTo="${request.id}">
  <saml:Issuer>http://localhost:4001/saml/metadata</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion 
    ID="${assertionId}"
    Version="2.0"
    IssueInstant="${issueInstant}">
    <saml:Issuer>http://localhost:4001/saml/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${user.email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData 
          NotOnOrAfter="${notOnOrAfter.toISOString()}"
          Recipient="${request.assertionConsumerServiceURL}"
          InResponseTo="${request.id}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions 
      NotBefore="${notBefore.toISOString()}"
      NotOnOrAfter="${notOnOrAfter.toISOString()}">
      <saml:AudienceRestriction>
        <saml:Audience>${request.issuer}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement 
      AuthnInstant="${authnInstant}"
      SessionIndex="${sessionIndex}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>${user.email}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="firstName">
        <saml:AttributeValue>${user.firstName}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="lastName">
        <saml:AttributeValue>${user.lastName}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="department">
        <saml:AttributeValue>${user.department}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role">
        <saml:AttributeValue>${user.role}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

  // Store session info
  activeSessions.set(sessionIndex, {
    user: user,
    loginTime: new Date(),
    sessionId: 'session-' + sessionIndex
  });

  return { samlResponse, sessionIndex };
};

// IdP Metadata endpoint
app.get('/saml/metadata', (req, res) => {
  const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor entityID="http://localhost:4001/saml/metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:4001/saml/sso"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:4001/saml/slo"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;

  res.header('Content-Type', 'text/xml').send(metadata);
});

// SAML SSO Endpoint - MANUAL PARSING ONLY
app.get('/saml/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;

  console.log('📨 Received SAML AuthnRequest, RelayState:', RelayState);

  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  try {
    // Parse the SAML AuthnRequest manually with decompression
    const parsedRequest = parseSamlRequest(SAMLRequest);

    console.log('🔍 Parsed SAML AuthnRequest');
    console.log('📝 Request ID:', parsedRequest.id);
    console.log('🏢 Issuer:', parsedRequest.issuer);
    console.log('📍 ACS URL:', parsedRequest.assertionConsumerServiceURL);

    // Store SAML request context
    samlRequestStore.set(parsedRequest.id, {
      request: parsedRequest,
      relayState: RelayState,
      timestamp: Date.now()
    });

    // Check if user is already authenticated
    if (req.session && req.session.authenticatedUser) {
      console.log('✅ User already authenticated, generating SAML Response');
      return generateAndSendSAMLResponse(req.session.authenticatedUser, parsedRequest.id, res);
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
          .info { background: #e9ecef; padding: 15px; margin-bottom: 20px; border-left: 4px solid #007bff; }
        </style>
      </head>
      <body>
        <h2>🔐 SAML Identity Provider</h2>
        <div class="info">
          <strong>Service Provider:</strong> ${parsedRequest.issuer}<br>
          <strong>Authentication Request ID:</strong> ${parsedRequest.id}<br>
          <strong>ACS URL:</strong> ${parsedRequest.assertionConsumerServiceURL}
        </div>
        
        <form method="post" action="/saml/authenticate">
          <input type="hidden" name="requestId" value="${parsedRequest.id}">
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
        <a href="javascript:history.back()">Try Again</a>
      </body></html>
    `);
  }

  console.log('✅ User authenticated successfully');

  // Store user in IdP session
  req.session.authenticatedUser = user;

  // Generate and send SAML Response
  generateAndSendSAMLResponse(user, requestId, res);
});

// Helper function to generate and send SAML Response
const generateAndSendSAMLResponse = (user, requestId, res) => {
  const requestContext = samlRequestStore.get(requestId);

  if (!requestContext) {
    return res.status(400).json({ error: 'Invalid or expired SAML request' });
  }

  console.log(`📤 Generating SAML Response for user: ${user.email}`);

  try {
    const { samlResponse, sessionIndex } = generateSAMLResponse(user, requestContext.request, requestContext.relayState);
    const encodedResponse = Buffer.from(samlResponse).toString('base64');

    // Clean up request store
    samlRequestStore.delete(requestId);

    console.log(`✅ SAML Response generated with session index: ${sessionIndex}`);

    // Send SAML Response via POST binding
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SAML Response</title>
      </head>
      <body onload="document.forms[0].submit()">
        <form method="post" action="${requestContext.request.assertionConsumerServiceURL}">
          <input type="hidden" name="SAMLResponse" value="${encodedResponse}">
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
  console.log('🚪 Received SAML Logout Request');

  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }

    res.send(`
      <html><body>
        <h2>🚪 Logout Complete</h2>
        <p>✅ You have been logged out successfully.</p>
        <a href="http://localhost:3002">Return to App 3</a> | 
        <a href="http://localhost:3003">Return to App 4</a>
      </body></html>
    `);
  });
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

// Graceful error handling for unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('⚠️ Unhandled Promise Rejection at:', promise, 'reason:', reason);
  // Don't exit the process, just log the error
});

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
