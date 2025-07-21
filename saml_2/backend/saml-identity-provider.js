import express from 'express';
import urlencoded from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import { DOMParser } from '@xmldom/xmldom';
import cors from 'cors';

const app = express();
const PORT = 4002;
const SP_ACS_URL = 'http://localhost:4001/sp/acs';
const IDP_ENTITY_ID = 'http://localhost:4002/idp/metadata';

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
  'test@example.com': {
    password: 'password',
    givenName: 'Test',
    sn: 'User',
    email: 'test@example.com',
    cn: 'Test User',
    uid: 'test',
    mail: 'test@example.com',
    title: 'Test User'
  }
};

app.use(cors({
  origin: ['http://localhost:4003', 'http://localhost:4004', 'http://localhost:4001'],
  credentials: true
}));

app.use(urlencoded({ extended: true }));

// IdP metadata endpoint - support both bindings
app.get('/idp/metadata', (req, res) => {
  const metadata = `<?xml version="1.0" encoding="UTF-8"?>
      <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                           entityID="${IDP_ENTITY_ID}">
          <md:IDPSSODescriptor WantAuthnRequestsSigned="false" 
                               protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
              <!-- Support both POST and Redirect bindings -->
              <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
                                      Location="http://localhost:4002/idp/sso"/>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                      Location="http://localhost:4002/idp/sso"/>
              <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                    Location="http://localhost:4002/idp/slo"/>
              <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                    Location="http://localhost:4002/idp/slo"/>
          </md:IDPSSODescriptor>
      </md:EntityDescriptor>`;

  res.header('Content-Type', 'text/xml').send(metadata);
});

// ========== SSO ENDPOINTS - Handle both GET (redirect) and POST requests ==========

// SSO endpoint - GET (HTTP-Redirect binding)
app.get('/idp/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;
  console.log('📥 Received GET /idp/sso request (HTTP-Redirect binding)');
  console.log('📋 SAMLRequest present:', !!SAMLRequest);
  console.log('📋 RelayState:', RelayState);
  handleSSORequest(req, res, SAMLRequest, RelayState, 'GET');
});

// SSO endpoint - POST (HTTP-POST binding)
app.post('/idp/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.body;
  console.log('📥 Received POST /idp/sso request (HTTP-POST binding)');
  console.log('📋 SAMLRequest present:', !!SAMLRequest);
  console.log('📋 RelayState:', RelayState);
  handleSSORequest(req, res, SAMLRequest, RelayState, 'POST');
});

// Unified SSO request handler
function handleSSORequest(req, res, SAMLRequest, RelayState, method) {
  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  console.log(`🔍 Processing ${method} SSO request`);

  try {
    // Decode and parse the SAMLRequest to extract the request ID
    const decodedRequest = Buffer.from(SAMLRequest, 'base64').toString('utf8');
    console.log('🔍 Decoded SAMLRequest');

    // Parse RelayState to show app-specific info
    let appInfo = '';
    let relayData = null;

    if (RelayState) {
      try {
        if (method === 'GET') {
          relayData = JSON.parse(decodeURIComponent(RelayState));
        } else {
          relayData = JSON.parse(RelayState);
        }

        if (relayData.app) {
          appInfo = `<div style="background: #e9ecef; padding: 10px; border-radius: 4px; margin-bottom: 15px;">
                        <strong>🎯 Requested by:</strong> ${relayData.app}<br>
                        <strong>🔗 Method:</strong> ${method}<br>
                        ${relayData.returnUrl ? `<strong>📍 Return URL:</strong> ${relayData.returnUrl}` : ''}
                    </div>`;
        }
      } catch (e) {
        console.log('⚠️ Could not parse RelayState:', e.message);
      }
    }

    const html = `<!DOCTYPE html>
            <html>
            <head>
                <title>Demo SAML IdP - Login</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        max-width: 400px; 
                        margin: 100px auto; 
                        padding: 20px; 
                        background-color: #f5f5f5;
                    }
                    .login-form {
                        background: white;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }
                    input { 
                        width: 100%; 
                        padding: 12px; 
                        margin: 8px 0; 
                        box-sizing: border-box; 
                        border: 1px solid #ddd;
                        border-radius: 4px;
                    }
                    button { 
                        background: #007bff; 
                        color: white; 
                        padding: 12px; 
                        border: none; 
                        width: 100%; 
                        cursor: pointer; 
                        border-radius: 4px;
                        font-size: 16px;
                    }
                    button:hover {
                        background: #0056b3;
                    }
                    .demo-users {
                        background: #e9ecef;
                        padding: 10px;
                        border-radius: 4px;
                        margin-top: 20px;
                        font-size: 12px;
                    }
                    .method-badge {
                        display: inline-block;
                        background: ${method === 'GET' ? '#28a745' : '#dc3545'};
                        color: white;
                        padding: 4px 8px;
                        border-radius: 3px;
                        font-size: 11px;
                        font-weight: bold;
                        margin-bottom: 10px;
                    }
                </style>
            </head>
            <body>
                <div class="login-form">
                    <div class="method-badge">${method} Method</div>
                    <h2>🔐 Demo SAML Identity Provider</h2>
                    ${appInfo}
                    <form method="post" action="/idp/login">
                        <input type="hidden" name="SAMLRequest" value="${SAMLRequest}">
                        <input type="hidden" name="RelayState" value="${RelayState || ''}">
                        <input type="hidden" name="originalMethod" value="${method}">
                        <label>Email:</label>
                        <input type="email" name="email" value="john@example.com" required>
                        <label>Password:</label>
                        <input type="password" name="password" value="password123" required>
                        <button type="submit">🚀 Login</button>
                    </form>
                    <div class="demo-users">
                        <strong>Demo users:</strong><br>
                        • john@example.com (password: password123)<br>
                        • test@example.com (password: password)
                    </div>
                </div>
            </body>
            </html>`;

    res.send(html);

  } catch (error) {
    console.error('❌ Error processing SAML AuthnRequest:', error);
    res.status(500).json({ error: 'Failed to process SAML request' });
  }
}

// ========== LOGIN PROCESSING ==========

// Login endpoint - processes user credentials
app.post('/idp/login', (req, res) => {
  const { email, password, SAMLRequest, RelayState, originalMethod } = req.body;
  console.log(`🔐 Authentication attempt for user: ${email}`);
  console.log(`📋 Original request method: ${originalMethod}`);

  if (!SAMLRequest) {
    return res.status(400).send("Missing SAMLRequest");
  }

  const user = users[email];
  if (!user || user.password !== password) {
    console.log('❌ Invalid credentials for:', email);
    return res.status(401).send(`
            <html>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2>❌ Authentication Failed</h2>
                <p>Invalid email or password.</p>
                <p>Please check your credentials and try again.</p>
                <button onclick="history.back()">Try Again</button>
            </body>
            </html>
        `);
  }

  console.log('✅ User authenticated successfully:', email);

  try {
    // Parse the original SAMLRequest to extract the InResponseTo ID
    const decodedRequest = Buffer.from(SAMLRequest, 'base64').toString('utf8');
    const doc = new DOMParser().parseFromString(decodedRequest, 'text/xml');
    const authnRequestID = doc.documentElement.getAttribute('ID');

    console.log('📋 Original request ID:', authnRequestID);

    // Generate SAML Response
    const issueInstant = new Date().toISOString();
    const responseId = '_' + uuidv4();
    const assertionId = '_' + uuidv4();
    const notBefore = new Date(Date.now() - 60 * 1000).toISOString(); // 1 minute ago
    const notOnOrAfter = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 minutes from now

    // Build SAML Response with user attributes
    const samlResponse = `<?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                            ID="${responseId}"
                            Version="2.0"
                            IssueInstant="${issueInstant}"
                            Destination="${SP_ACS_URL}"
                            InResponseTo="${authnRequestID}">
                <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
                <samlp:Status>
                    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
                </samlp:Status>
                <saml:Assertion ID="${assertionId}" 
                                Version="2.0" 
                                IssueInstant="${issueInstant}">
                    <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
                    <saml:Subject>
                        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${email}</saml:NameID>
                        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                            <saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" 
                                                          Recipient="${SP_ACS_URL}" 
                                                          InResponseTo="${authnRequestID}"/>
                        </saml:SubjectConfirmation>
                    </saml:Subject>
                    <saml:Conditions NotBefore="${notBefore}" 
                                     NotOnOrAfter="${notOnOrAfter}">
                        <saml:AudienceRestriction>
                            <saml:Audience>http://localhost:4001/sp/metadata</saml:Audience>
                        </saml:AudienceRestriction>
                    </saml:Conditions>
                    <saml:AuthnStatement AuthnInstant="${issueInstant}" 
                                         SessionIndex="${assertionId}">
                        <saml:AuthnContext>
                            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
                        </saml:AuthnContext>
                    </saml:AuthnStatement>
                    <saml:AttributeStatement>
                        <saml:Attribute Name="urn:oid:2.5.4.42" 
                                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                            <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                                                 xsi:type="xs:string">${user.givenName}</saml:AttributeValue>
                        </saml:Attribute>
                        <saml:Attribute Name="urn:oid:2.5.4.4" 
                                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                            <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                                                 xsi:type="xs:string">${user.sn}</saml:AttributeValue>
                        </saml:Attribute>
                        <saml:Attribute Name="urn:oid:2.5.4.3" 
                                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                            <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                                                 xsi:type="xs:string">${user.cn}</saml:AttributeValue>
                        </saml:Attribute>
                        <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" 
                                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                            <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                                                 xsi:type="xs:string">${user.email}</saml:AttributeValue>
                        </saml:Attribute>
                        <saml:Attribute Name="urn:oid:2.5.4.12" 
                                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                            <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                                                 xsi:type="xs:string">${user.title}</saml:AttributeValue>
                        </saml:Attribute>
                    </saml:AttributeStatement>
                </saml:Assertion>
            </samlp:Response>`;

    const samlResponseB64 = Buffer.from(samlResponse).toString('base64');

    console.log('✅ SAML Response generated successfully');
    console.log('🔗 Sending response back to SP ACS:', SP_ACS_URL);

    // Parse RelayState for display
    let relayInfo = '';
    if (RelayState) {
      try {
        const relayData = JSON.parse(RelayState);
        relayInfo = `<p><strong>Target App:</strong> ${relayData.app || 'Unknown'}</p>
                           <p><strong>Method Used:</strong> ${originalMethod || 'Unknown'}</p>`;
      } catch (e) {
        relayInfo = `<p><strong>RelayState:</strong> ${RelayState}</p>`;
      }
    }

    const html = `<!DOCTYPE html>
            <html>
            <head>
                <title>SAML Response</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        text-align: center; 
                        padding: 50px;
                        background-color: #f8f9fa;
                    }
                    .redirect-info {
                        background: white;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        max-width: 500px;
                        margin: 0 auto;
                    }
                    button {
                        background: #28a745;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 4px;
                        font-size: 16px;
                        cursor: pointer;
                    }
                    .method-badge {
                        display: inline-block;
                        background: ${originalMethod === 'GET' ? '#28a745' : '#dc3545'};
                        color: white;
                        padding: 4px 8px;
                        border-radius: 3px;
                        font-size: 11px;
                        font-weight: bold;
                        margin-bottom: 10px;
                    }
                </style>
            </head>
            <body onload="document.forms[0].submit()">
                <div class="redirect-info">
                    <div class="method-badge">Response via ${originalMethod || 'POST'}</div>
                    <h2>✅ Authentication Successful</h2>
                    <p>Welcome, <strong>${user.cn}</strong>!</p>
                    ${relayInfo}
                    <p>🔄 Redirecting back to Service Provider...</p>
                    <p><small>If you are not redirected automatically, click the button below.</small></p>
                    <form method="POST" action="${SP_ACS_URL}">
                        <input type="hidden" name="SAMLResponse" value="${samlResponseB64}" />
                        <input type="hidden" name="RelayState" value="${RelayState || ''}" />
                        <button type="submit">Continue to Application</button>
                    </form>
                </div>
            </body>
            </html>`;

    res.send(html);

  } catch (error) {
    console.error('❌ Error generating SAML Response:', error);
    res.status(500).json({
      error: 'Failed to generate SAML response',
      details: error.message
    });
  }
});

// ========== SINGLE LOGOUT ENDPOINTS ==========

// SLO endpoint - GET (HTTP-Redirect binding)
app.get('/idp/slo', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;
  console.log('🚪 Received GET /idp/slo request (HTTP-Redirect binding)');
  handleSLORequest(req, res, SAMLRequest, RelayState, 'GET');
});

// SLO endpoint - POST (HTTP-POST binding)
app.post('/idp/slo', (req, res) => {
  const { SAMLRequest, RelayState } = req.body;
  console.log('🚪 Received POST /idp/slo request (HTTP-POST binding)');
  handleSLORequest(req, res, SAMLRequest, RelayState, 'POST');
});

// Unified SLO request handler
function handleSLORequest(req, res, SAMLRequest, RelayState, method) {
  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  try {
    console.log(`🚪 Processing ${method} SAML Logout Request...`);

    // Decode the SAMLRequest
    const logoutRequest = Buffer.from(SAMLRequest, 'base64').toString('utf8');
    console.log('Logout request received and decoded');

    // Parse the request to get the request ID
    const doc = new DOMParser().parseFromString(logoutRequest, 'text/xml');
    const logoutRequestId = doc.documentElement.getAttribute('ID');

    // Clear the user session safely
    if (req.session) {
      req.session.authenticatedUser = null;
      req.session.samlContext = null;
      console.log('✅ IdP session cleared');
    } else {
      console.log('⚠️ No session to clear');
    }

    // Generate LogoutResponse
    const logoutResponseId = `_${uuidv4()}`;
    const issueInstant = new Date().toISOString();

    const logoutResponse = `<?xml version="1.0" encoding="UTF-8"?>
        <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                              ID="${logoutResponseId}"
                              Version="2.0"
                              IssueInstant="${issueInstant}"
                              Destination="http://localhost:4001/sp/slo"
                              InResponseTo="${logoutRequestId}">
            <saml:Issuer>http://localhost:4002/idp/metadata</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
        </samlp:LogoutResponse>`;

    const logoutResponseB64 = Buffer.from(logoutResponse).toString('base64');

    console.log('✅ Logout response generated');

    // Send auto-submit form back to SP (always use POST for logout response)
    res.send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>SAML Logout Response</title>
            <style>
              body { 
                font-family: Arial, sans-serif; 
                text-align: center; 
                padding: 50px;
                background-color: #f8f9fa;
              }
              .logout-info {
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                max-width: 400px;
                margin: 0 auto;
              }
              .method-badge {
                display: inline-block;
                background: #6c757d;
                color: white;
                padding: 4px 8px;
                border-radius: 3px;
                font-size: 11px;
                font-weight: bold;
                margin-bottom: 10px;
              }
              button {
                background: #dc3545;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 4px;
                font-size: 16px;
                cursor: pointer;
              }
            </style>
          </head>
          <body onload="document.forms[0].submit()">
            <div class="logout-info">
              <div class="method-badge">Logout via ${method}</div>
              <h2>🚪 Logging Out...</h2>
              <p>🔄 Processing logout...</p>
              <form method="post" action="http://localhost:4001/sp/slo">
                <input type="hidden" name="SAMLResponse" value="${logoutResponseB64}">
                <input type="hidden" name="RelayState" value="${RelayState || ''}">
                <button type="submit">Complete Logout</button>
              </form>
            </div>
          </body>
          </html>
        `);

  } catch (error) {
    console.error('❌ Error processing logout request:', error);
    console.error('Error details:', error.message);
    console.error('Session exists:', !!req.session);
    res.status(500).json({
      error: 'Failed to process logout request',
      details: error.message
    });
  }
}

// ========== UTILITY AND STATUS ENDPOINTS ==========

// Health check endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'SAML Identity Provider',
    status: 'running',
    supportedMethods: ['HTTP-POST', 'HTTP-Redirect'],
    endpoints: {
      metadata: '/idp/metadata',
      sso_get: '/idp/sso (GET)',
      sso_post: '/idp/sso (POST)',
      login: '/idp/login',
      slo_get: '/idp/slo (GET)',
      slo_post: '/idp/slo (POST)',
      status: '/idp/status'
    },
    users: Object.keys(users),
    bindings: {
      sso: ['HTTP-POST', 'HTTP-Redirect'],
      slo: ['HTTP-POST', 'HTTP-Redirect'],
      response: 'HTTP-POST'
    }
  });
});

// Additional endpoint for testing and status
app.get('/idp/status', (req, res) => {
  res.json({
    service: 'Demo SAML Identity Provider',
    version: '2.0.0',
    status: 'running',
    timestamp: new Date().toISOString(),
    supportedBindings: {
      sso: [
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
      ],
      slo: [
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
      ]
    },
    availableUsers: Object.keys(users).map(email => ({
      email: email,
      name: users[email].cn,
      title: users[email].title
    })),
    testEndpoints: {
      sso_post: 'http://localhost:4002/idp/sso (POST)',
      sso_get: 'http://localhost:4002/idp/sso (GET)',
      metadata: 'http://localhost:4002/idp/metadata'
    }
  });
});

// Test endpoint to verify both methods work
app.get('/idp/test', (req, res) => {
  const testSAMLRequest = Buffer.from(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_test123" Version="2.0" IssueInstant="${new Date().toISOString()}">
        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://localhost:4001/sp/metadata</saml:Issuer>
    </samlp:AuthnRequest>`).toString('base64');

  const testRelayState = JSON.stringify({ app: 'test', method: 'test' });

  res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>SAML IdP Method Testing</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
                .test-section { background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 5px; }
                button { padding: 10px 15px; margin: 5px; border: none; border-radius: 3px; cursor: pointer; }
                .post-btn { background: #dc3545; color: white; }
                .get-btn { background: #28a745; color: white; }
            </style>
        </head>
        <body>
            <h1>🧪 SAML IdP Method Testing</h1>
            
            <div class="test-section">
                <h3>HTTP-POST Method Test</h3>
                <form method="POST" action="/idp/sso">
                    <input type="hidden" name="SAMLRequest" value="${testSAMLRequest}">
                    <input type="hidden" name="RelayState" value="${testRelayState}">
                    <button type="submit" class="post-btn">Test POST Method</button>
                </form>
            </div>
            
            <div class="test-section">
                <h3>HTTP-Redirect Method Test</h3>
                <a href="/idp/sso?SAMLRequest=${encodeURIComponent(testSAMLRequest)}&RelayState=${encodeURIComponent(testRelayState)}">
                    <button class="get-btn">Test GET Method</button>
                </a>
            </div>
            
            <div class="test-section">
                <h3>Available Test URLs:</h3>
                <ul>
                    <li><a href="http://localhost:4001/sp/sso/initiate-post?app=app3">App3 POST Method</a></li>
                    <li><a href="http://localhost:4001/sp/sso/initiate-redirect?app=app3">App3 Redirect Method</a></li>
                    <li><a href="http://localhost:4001/sp/sso/initiate-post?app=app4">App4 POST Method</a></li>
                    <li><a href="http://localhost:4001/sp/sso/initiate-redirect?app=app4">App4 Redirect Method</a></li>
                </ul>
            </div>
        </body>
        </html>
    `);
});

// Start the server
app.listen(PORT, () => {
  console.log('🔐 SAML Identity Provider running on http://localhost:4002');
  console.log('📋 Supported Methods: HTTP-POST, HTTP-Redirect');
  console.log('📋 Available endpoints:');
  console.log('   - GET  /idp/metadata (IdP metadata)');
  console.log('   - GET  /idp/sso (SSO via HTTP-Redirect)');
  console.log('   - POST /idp/sso (SSO via HTTP-POST)');
  console.log('   - POST /idp/login (Process user authentication)');
  console.log('   - GET  /idp/slo (SLO via HTTP-Redirect)');
  console.log('   - POST /idp/slo (SLO via HTTP-POST)');
  console.log('   - GET  /idp/status (Service status)');
  console.log('   - GET  /idp/test (Method testing page)');
  console.log('📋 Demo users:');
  Object.keys(users).forEach(email => {
    console.log(`   - ${email} (password: ${users[email].password}) - ${users[email].cn}`);
  });
  console.log('');
  console.log('🧪 Test both methods at:');
  console.log('   - POST Method: http://localhost:4001/sp/sso/initiate-post?app=app3');
  console.log('   - Redirect Method: http://localhost:4001/sp/sso/initiate-redirect?app=app3');
  console.log('   - Testing Page: http://localhost:4002/idp/test');
});

