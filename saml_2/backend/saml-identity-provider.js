import express from 'express';
import cookieSession from 'cookie-session';
import { setSchemaValidator, IdentityProvider, ServiceProvider } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import urlencoded from 'body-parser';
import json from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import cors from 'cors';

const app = express();
app.use(urlencoded({ extended: true }));
app.use(json());
app.use(cors({
  origin: ['http://localhost:4003', 'http://localhost:4004'],
  credentials: true
}));
app.use(cookieSession({
  name: 'idp_session',
  keys: ['idp-secret-key'],
  maxAge: 24 * 60 * 60 * 1000
}));

setSchemaValidator(validator);

// Demo users
const users = {
  'john@example.com': {
    password: 'password123',
    givenName: 'John',
    sn: 'Doe',
    email: 'john@example.com',
    cn: 'John Doe',
    uid: 'john',
    mail: 'john@example.com',
    title: 'Senior Developer'
  }
};

// Simple IdP configuration
const idp = IdentityProvider({
  entityID: 'http://localhost:4002/idp/metadata',
  wantAuthnRequestsSigned: false,
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
  singleSignOnService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://localhost:4002/idp/sso'
  }]
});

// SP configuration
const sp = ServiceProvider({
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
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress']
});

// Store current SAML context in session instead of separate store
app.get('/idp/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(idp.getMetadata());
});

// SIMPLIFIED SSO endpoint - store extract in session
app.get('/idp/sso', async (req, res) => {
  const { SAMLRequest, RelayState } = req.query;

  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  try {
    const { extract } = await idp.parseLoginRequest(sp, 'redirect', req);
    
    // Generate a requestId for the form (even though we store in session)
    const requestId = extract.request?.id || extract.id || `_${uuidv4()}`;
    
    // Store in session instead of separate store
    req.session.samlContext = {
      extract: extract,
      relayState: RelayState,
      timestamp: Date.now(),
      requestId: requestId  // Store for reference
    };

    // Check if already authenticated
    if (req.session.authenticatedUser) {
      return handleAuthenticatedUser(req, res);
    }

    // Show login form - ADD BACK the requestId hidden input
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
          <title>Demo SAML IdP - Login</title>
          <style>
              body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
              input { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
              button { background: #007bff; color: white; padding: 10px; border: none; width: 100%; cursor: pointer; }
          </style>
      </head>
      <body>
          <h2>🔐 Demo SAML Identity Provider</h2>
          <form method="post" action="/idp/authenticate">
              <input type="hidden" name="requestId" value="${requestId}">
              <input type="hidden" name="relayState" value="${RelayState || ''}">
              <label>Email:</label>
              <input type="email" name="username" value="john@example.com" required>
              <label>Password:</label>
              <input type="password" name="password" value="password123" required>
              <button type="submit">🚀 Login</button>
          </form>
          <p><small>Demo users: john@example.com (password: password123)</small></p>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('❌ Error processing SAML AuthnRequest:', error);
    res.status(500).json({ error: 'Failed to process SAML request' });
  }
});

// Authentication endpoint - accept requestId but use session context
app.post('/idp/authenticate', (req, res) => {
  const { username, password, requestId } = req.body;
  console.log(`🔐 Authentication attempt for user: ${username}, requestId: ${requestId}`);

  const user = users[username];
  if (!user || user.password !== password) {
    console.log('❌ Invalid credentials');
    return res.status(401).send(`
      <html><body style="font-family: Arial; text-align: center;">
          <h2>❌ Authentication Failed</h2>
          <p>Invalid username or password.</p>
          <a href="javascript:history.back()">Try Again</a>
      </body></html>
    `);
  }

  console.log('✅ User authenticated successfully');
  req.session.authenticatedUser = user;
  handleAuthenticatedUser(req, res);
});

// Handle authenticated user - generate SAML response immediately
async function handleAuthenticatedUser(req, res) {
  if (!req.session.samlContext) {
    return res.status(400).json({ error: 'No SAML context found' });
  }

  const user = req.session.authenticatedUser;
  const { extract, relayState } = req.session.samlContext;

  try {
    const userAttributes = {
      'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': user.email,
      'urn:oid:2.5.4.3': user.cn,
      'urn:oid:2.5.4.4': user.sn,
      'urn:oid:2.5.4.42': user.givenName,
      'urn:oid:0.9.2342.19200300.100.1.3': user.mail,
      'urn:oid:2.5.4.12': user.title
    };

    console.log('🔍 Creating login response for:', user.email);

    // Generate SAML response immediately
    const loginResponse = await idp.createLoginResponse(
      sp,
      extract,
      'post',
      user.email,
      userAttributes
    );

    // Clear SAML context
    req.session.samlContext = null;

    console.log('✅ SAML Response generated successfully');

    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>SAML Response</title></head>
      <body onload="document.forms[0].submit()">
        <form method="post" action="http://localhost:4001/sp/acs">
          <input type="hidden" name="SAMLResponse" value="${loginResponse.context}">
          <input type="hidden" name="RelayState" value="${relayState || ''}">
          <p>🔄 Redirecting back to Service Provider...</p>
          <button type="submit">Continue</button>
        </form>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('❌ Error generating SAML Response:', error);
    res.status(500).json({ error: 'Failed to generate SAML response' });
  }
}

app.listen(4002, () => {
  console.log('🔐 SAML Identity Provider running on http://localhost:4002');
});
