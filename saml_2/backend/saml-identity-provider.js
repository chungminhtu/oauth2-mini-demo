import express from 'express';
import cookieSession from 'cookie-session';
import { setSchemaValidator, IdentityProvider, ServiceProvider } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import urlencoded from 'body-parser';
import json from 'body-parser';
import { v4 as uuidv4 } from 'uuid';

const app = express();

app.use(urlencoded({ extended: true }));
app.use(json());

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
  },
  'jane@example.com': {
    password: 'password123',
    givenName: 'Jane',
    sn: 'Smith',
    email: 'jane@example.com',
    cn: 'Jane Smith',
    uid: 'jane',
    mail: 'jane@example.com',
    title: 'Marketing Manager'
  }
};

// Identity Provider configuration
const idp = IdentityProvider({
  entityID: 'http://localhost:4001/saml/metadata',
  wantAuthnRequestsSigned: false,
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
  singleSignOnService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://localhost:4001/saml/sso'
  }]
});

// Service Provider configuration (for parsing requests)
const sp = ServiceProvider({
  entityID: 'http://localhost:4003/saml/metadata',
  authnRequestsSigned: false,
  wantAssertionsSigned: false,
  assertionConsumerService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    Location: 'http://localhost:4003/saml/acs'
  }]
});

const samlRequestStore = new Map();

// IdP Metadata endpoint
app.get('/saml/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(idp.getMetadata());
});

// SAML SSO endpoint
app.get('/saml/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;

  console.log('📨 Received SAML AuthnRequest, RelayState:', RelayState);

  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  try {
    const { extract } = idp.parseLoginRequest(sp, 'redirect', { query: req.query });
    const requestId = extract.request?.id || extract.id || `_${uuidv4()}`;

    samlRequestStore.set(requestId, {
      extract: extract,
      relayState: RelayState,
      timestamp: Date.now()
    });

    // Check if user already authenticated
    if (req.session && req.session.authenticatedUser) {
      console.log('✅ User already authenticated');
      return generateAndSendSAMLResponse(req.session.authenticatedUser, requestId, res);
    }

    // Show login form
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
                <form method="post" action="/saml/authenticate">
                    <input type="hidden" name="requestId" value="${requestId}">
                    <input type="hidden" name="relayState" value="${RelayState || ''}">
                    <label>Email:</label>
                    <input type="email" name="username" value="john@example.com" required>
                    <label>Password:</label>
                    <input type="password" name="password" value="password123" required>
                    <button type="submit">🚀 Login</button>
                </form>
                <p><small>Demo users: john@example.com / jane@example.com (password: password123)</small></p>
            </body>
            </html>
        `);

  } catch (error) {
    console.error('❌ Error processing SAML AuthnRequest:', error);
    res.status(500).json({ error: 'Failed to process SAML request' });
  }
});

// Authentication processing
app.post('/saml/authenticate', (req, res) => {
  const { username, password, requestId } = req.body;

  console.log(`🔐 Authentication attempt for user: ${username}`);

  const user = users[username];
  if (!user || user.password !== password) {
    console.log('❌ Invalid credentials');
    return res.status(401).send(`
            <html><body style="font-family: Arial; text-align: center; margin: 100px auto; max-width: 400px;">
                <h2>❌ Authentication Failed</h2>
                <p>Invalid username or password.</p>
                <a href="javascript:history.back()">Try Again</a>
            </body></html>
        `);
  }

  console.log('✅ User authenticated successfully');
  req.session.authenticatedUser = user;
  generateAndSendSAMLResponse(user, requestId, res);
});

// Generate SAML Response
const generateAndSendSAMLResponse = (user, requestId, res) => {
  const requestContext = samlRequestStore.get(requestId);

  if (!requestContext) {
    return res.status(400).json({ error: 'Invalid SAML request' });
  }

  console.log(`📤 Generating SAML Response for user: ${user.email}`);

  try {
    // User attributes matching the SP's INVERSE_ATTRIBUTE_MAP
    const userAttributes = {
      'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': user.email,     // email
      'urn:oid:2.5.4.3': user.cn,                          // cn  
      'urn:oid:2.5.4.4': user.sn,                          // sn
      'urn:oid:2.5.4.42': user.givenName,                  // givenName
      'urn:oid:0.9.2342.19200300.100.1.3': user.mail,     // mail
      'urn:oid:2.5.4.12': user.title                       // title
    };

    const { context: samlResponse } = idp.createLoginResponse(
      sp,
      requestContext.extract,
      'post',
      user.email, // Subject/NameID
      userAttributes,
      false, // Not encrypted
      requestContext.relayState
    );

    samlRequestStore.delete(requestId);
    console.log(`✅ SAML Response generated and sending to SP`);

    // Send SAML Response via POST binding
    res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>SAML Response</title></head>
            <body onload="document.forms[0].submit()">
                <form method="post" action="http://localhost:4003/saml/acs">
                    <input type="hidden" name="SAMLResponse" value="${samlResponse}">
                    <input type="hidden" name="RelayState" value="${requestContext.relayState || ''}">
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
};

app.listen(4001, () => {
  console.log('🔐 SAML Identity Provider running on http://localhost:4001');
  console.log('📋 Demo users: john@example.com, jane@example.com (password: password123)');
});
