import express from 'express';
import cors from 'cors';
import session from 'express-session';
import crypto from 'crypto';
import { URLSearchParams } from 'url';

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

// SAML IdP Configuration
const IDP_ENTITY_ID = 'http://localhost:4001/saml/metadata';
const SSO_ENDPOINT = 'http://localhost:4001/saml/sso';
const SLO_ENDPOINT = 'http://localhost:4001/saml/slo';

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

// Store for SAML requests
const samlRequestStore = new Map();

// Helper function to generate SAML Response
const generateSAMLResponse = (user, inResponseTo, destination) => {
  const responseId = '_' + crypto.randomBytes(16).toString('hex');
  const assertionId = '_' + crypto.randomBytes(16).toString('hex');
  const sessionIndex = crypto.randomBytes(8).toString('hex');
  
  const now = new Date();
  const notBefore = new Date(now.getTime() - 5 * 60 * 1000); // 5 minutes ago
  const notOnOrAfter = new Date(now.getTime() + 8 * 60 * 60 * 1000); // 8 hours from now
  const authnInstant = now.toISOString();
  const issueInstant = now.toISOString();
  
  return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response 
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${responseId}"
  Version="2.0"
  IssueInstant="${issueInstant}"
  Destination="${destination}"
  InResponseTo="${inResponseTo}">
  <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion 
    ID="${assertionId}"
    Version="2.0"
    IssueInstant="${issueInstant}">
    <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${user.email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData 
          NotOnOrAfter="${notOnOrAfter.toISOString()}"
          Recipient="${destination}"
          InResponseTo="${inResponseTo}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions 
      NotBefore="${notBefore.toISOString()}"
      NotOnOrAfter="${notOnOrAfter.toISOString()}">
      <saml:AudienceRestriction>
        <saml:Audience>http://localhost:4003/saml/metadata</saml:Audience>
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
};

// Routes

// SAML SSO Endpoint - Receive AuthnRequest
app.get('/saml/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;
  
  console.log('📨 Received SAML AuthnRequest, RelayState:', RelayState);
  
  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }
  
  try {
    // Decode SAML AuthnRequest
    const decodedRequest = Buffer.from(SAMLRequest, 'base64').toString('utf8');
    console.log('🔍 Decoded SAML AuthnRequest');
    
    // Parse request ID (simplified parsing)
    const requestIdMatch = decodedRequest.match(/ID="([^"]+)"/);
    const acsMatch = decodedRequest.match(/AssertionConsumerServiceURL="([^"]+)"/);
    const issuerMatch = decodedRequest.match(/<saml:Issuer>([^<]+)<\/saml:Issuer>/);
    
    if (!requestIdMatch || !acsMatch) {
      return res.status(400).json({ error: 'Invalid SAML AuthnRequest' });
    }
    
    const requestId = requestIdMatch[1];
    const acsUrl = acsMatch[1];
    const issuer = issuerMatch ? issuerMatch[1] : 'unknown';
    
    // Store SAML request context
    samlRequestStore.set(requestId, {
      acsUrl,
      issuer,
      relayState: RelayState,
      timestamp: Date.now()
    });
    
    console.log(`🔐 Processing AuthnRequest from SP: ${issuer}`);
    console.log(`📍 ACS URL: ${acsUrl}`);
    
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
          <strong>Service Provider:</strong> ${issuer}<br>
          <strong>Authentication Request ID:</strong> ${requestId}
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
    res.status(500).json({ error: 'Failed to process SAML authentication request' });
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
  
  const samlResponse = generateSAMLResponse(user, requestId, requestContext.acsUrl);
  const encodedResponse = Buffer.from(samlResponse).toString('base64');
  
  // Clean up request store
  samlRequestStore.delete(requestId);
  
  // Send SAML Response via POST binding
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>SAML Response</title>
    </head>
    <body onload="document.forms[0].submit()">
      <form method="post" action="${requestContext.acsUrl}">
        <input type="hidden" name="SAMLResponse" value="${encodedResponse}">
        <input type="hidden" name="RelayState" value="${requestContext.relayState || ''}">
        <p>🔄 Redirecting back to Service Provider...</p>
        <button type="submit">Continue if not redirected automatically</button>
      </form>
    </body>
    </html>
  `);
  
  console.log(`✅ SAML Response sent to SP: ${requestContext.acsUrl}`);
};

// IdP Metadata endpoint