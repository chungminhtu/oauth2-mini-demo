import express from 'express';
import urlencoded from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import { DOMParser } from '@xmldom/xmldom';
import cors from 'cors';

const app = express();
const PORT = 4002;

// Only 4003 is officially registered, but we support requests from both
const SP_ACS_URL = 'http://localhost:4001/sp/acs';
const IDP_ENTITY_ID = 'http://localhost:4002/idp/metadata';
const OFFICIAL_SP_DOMAIN = 'http://localhost:4003'; // Only this is "registered"

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

// IdP metadata - Only references official domain (4003)
app.get('/idp/metadata', (req, res) => {
  const metadata = `<?xml version="1.0" encoding="UTF-8"?>
      <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                           entityID="${IDP_ENTITY_ID}">
          <md:IDPSSODescriptor WantAuthnRequestsSigned="false" 
                               protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
              <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
                                      Location="http://localhost:4002/idp/sso"/>
              <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" 
                                      Location="http://localhost:4002/idp/sso"/>
              <!-- Only official domain registered -->
              <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                           Location="${SP_ACS_URL}"
                                           index="0"/>
          </md:IDPSSODescriptor>
      </md:EntityDescriptor>`;

  res.header('Content-Type', 'text/xml').send(metadata);
});

// SSO endpoint - handles both GET and POST
app.get('/idp/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;
  console.log('📥 Received GET /idp/sso request');
  handleSSORequest(req, res, SAMLRequest, RelayState);
});

app.post('/idp/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.body;
  console.log('📥 Received POST /idp/sso request');
  handleSSORequest(req, res, SAMLRequest, RelayState);
});
function handleSSORequest(req, res, SAMLRequest, RelayState) {
  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  console.log('📋 SAMLRequest received:', !!SAMLRequest);
  console.log('📋 RelayState:', RelayState);

  // Parse RelayState to determine target app
  let targetApp = 'unknown';
  let returnUrl = OFFICIAL_SP_DOMAIN;

  if (RelayState) {
    try {
      const relayData = JSON.parse(RelayState);
      targetApp = relayData.app || 'unknown';
      returnUrl = relayData.returnUrl || relayData.targetDomain || returnUrl;
      console.log('🎯 Target app from RelayState:', targetApp);
      console.log('🔗 Return URL from RelayState:', returnUrl);
    } catch (e) {
      console.log('⚠️ Could not parse RelayState, using defaults');
    }
  }

  try {
    // FIX: URL-decode first, then base64 decode
    const urlDecodedRequest = decodeURIComponent(SAMLRequest);
    const decodedRequest = Buffer.from(urlDecodedRequest, 'base64').toString('utf8');
    console.log('🔍 Decoded SAMLRequest successfully');
    console.log('📋 SAMLRequest preview:', decodedRequest.substring(0, 200) + '...');

    const html = `<!DOCTYPE html>
            <html>
            <head>
                <title>Demo SAML IdP - Login</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        max-width: 500px; 
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
                    .app-info {
                        background: #e3f2fd;
                        padding: 15px;
                        border-radius: 5px;
                        margin-bottom: 20px;
                        border-left: 4px solid #2196f3;
                    }
                    .registered-info {
                        background: #f3e5f5;
                        padding: 10px;
                        border-radius: 5px;
                        margin-top: 10px;
                        font-size: 12px;
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
                </style>
            </head>
            <body>
                <div class="login-form">
                    <h2>🔐 Demo SAML Identity Provider</h2>
                    
                    <div class="app-info">
                        <strong>🎯 Authentication Request From:</strong><br>
                        App: <strong>${targetApp.toUpperCase()}</strong><br>
                        Will redirect to: <strong>${returnUrl}</strong>
                    </div>
                    
                    <div class="registered-info">
                        <strong>📋 Registration Info:</strong><br>
                        Official SP Domain: <strong>localhost:4003</strong><br>
                        Redirect Method: <strong>RelayState-based</strong>
                    </div>
                    
                    <form method="post" action="/idp/login">
                        <input type="hidden" name="SAMLRequest" value="${urlDecodedRequest}">
                        <input type="hidden" name="RelayState" value="${RelayState || ''}">
                        <label>Email:</label>
                        <input type="email" name="email" value="john@example.com" required>
                        <label>Password:</label>
                        <input type="password" name="password" value="password123" required>
                        <button type="submit">🚀 Login & Auto-Redirect to ${targetApp.toUpperCase()}</button>
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
    console.error('❌ SAMLRequest value:', SAMLRequest);
    res.status(500).json({
      error: 'Failed to process SAML request',
      details: error.message,
      samlRequestReceived: !!SAMLRequest
    });
  }
}

// Login endpoint - FIXED parsing
app.post('/idp/login', (req, res) => {
  const { email, password, SAMLRequest, RelayState } = req.body;
  console.log(`🔐 Authentication attempt for user: ${email}`);

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

  // Parse RelayState for redirect information
  let targetApp = 'app3';
  let returnUrl = OFFICIAL_SP_DOMAIN;

  if (RelayState) {
    try {
      const relayData = JSON.parse(RelayState);
      targetApp = relayData.app || targetApp;
      returnUrl = relayData.returnUrl || relayData.targetDomain || returnUrl;
      console.log('🎯 Will redirect to app:', targetApp, '→', returnUrl);
    } catch (e) {
      console.log('⚠️ Could not parse RelayState for redirect, using defaults');
    }
  }

  try {
    // FIX: SAMLRequest is already URL-decoded from form submission, just base64 decode
    const decodedRequest = Buffer.from(SAMLRequest, 'base64').toString('utf8');
    console.log('🔍 Successfully decoded SAMLRequest');
    console.log('📋 SAMLRequest preview:', decodedRequest.substring(0, 200) + '...');

    const doc = new DOMParser().parseFromString(decodedRequest, 'text/xml');

    // Check if parsing was successful
    if (doc.documentElement.tagName === 'parsererror') {
      throw new Error('XML parsing failed: ' + doc.documentElement.textContent);
    }

    const authnRequestID = doc.documentElement.getAttribute('ID');
    console.log('📋 Extracted request ID:', authnRequestID);

    if (!authnRequestID) {
      console.log('⚠️ No ID attribute found, using fallback');
    }

    // Generate SAML Response
    const issueInstant = new Date().toISOString();
    const responseId = '_' + uuidv4();
    const assertionId = '_' + uuidv4();
    const notBefore = new Date(Date.now() - 60 * 1000).toISOString();
    const notOnOrAfter = new Date(Date.now() + 30 * 60 * 1000).toISOString();

    // SAML Response - References official domain but supports RelayState redirect
    const samlResponse = `<?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                            ID="${responseId}"
                            Version="2.0"
                            IssueInstant="${issueInstant}"
                            Destination="${SP_ACS_URL}"
                            ${authnRequestID ? `InResponseTo="${authnRequestID}"` : ''}>
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
                                                          ${authnRequestID ? `InResponseTo="${authnRequestID}"` : ''}/>
                        </saml:SubjectConfirmation>
                    </saml:Subject>
                    <saml:Conditions NotBefore="${notBefore}" 
                                     NotOnOrAfter="${notOnOrAfter}">
                        <saml:AudienceRestriction>
                            <saml:Audience>${OFFICIAL_SP_DOMAIN}/sp/metadata</saml:Audience>
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
    console.log('🔗 Will auto-redirect to:', returnUrl);

    const html = `<!DOCTYPE html>
            <html>
            <head>
                <title>SAML Response - Auto Redirect</title>
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
                        max-width: 600px;
                        margin: 0 auto;
                    }
                    .app-info {
                        background: #d4edda;
                        padding: 15px;
                        border-radius: 5px;
                        margin: 20px 0;
                        border-left: 4px solid #28a745;
                    }
                    .redirect-details {
                        background: #e3f2fd;
                        padding: 15px;
                        border-radius: 5px;
                        margin: 20px 0;
                        border-left: 4px solid #2196f3;
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
                </style>
            </head>
            <body onload="document.forms[0].submit()">
                <div class="redirect-info">
                    <h2>✅ Authentication Successful</h2>
                    
                    <div class="app-info">
                        <strong>🎯 Authenticated for:</strong> ${user.cn} (${email})<br>
                        <strong>📧 Email:</strong> ${email}<br>
                        <strong>🏷️ Title:</strong> ${user.title}
                    </div>
                    
                    <div class="redirect-details">
                        <strong>🚀 Auto-redirecting to:</strong><br>
                        <strong>Target App:</strong> ${targetApp.toUpperCase()}<br>
                        <strong>URL:</strong> ${returnUrl}<br>
                        <strong>Method:</strong> RelayState-based redirect
                    </div>
                    
                    <p>🔄 Redirecting automatically...</p>
                    
                    <form method="POST" action="${SP_ACS_URL}">
                        <input type="hidden" name="SAMLResponse" value="${samlResponseB64}" />
                        <input type="hidden" name="RelayState" value="${RelayState || ''}" />
                        <button type="submit">Continue to ${targetApp.toUpperCase()}</button>
                    </form>
                    
                    <p><small>If you are not redirected automatically, click the button above.</small></p>
                </div>
            </body>
            </html>`;

    res.send(html);

  } catch (error) {
    console.error('❌ Error generating SAML Response:', error);
    console.error('❌ Error details:', error.message);
    console.error('❌ SAMLRequest length:', SAMLRequest ? SAMLRequest.length : 'null');

    // Try to show more debugging info
    if (SAMLRequest) {
      try {
        const decodedRequest = Buffer.from(SAMLRequest, 'base64').toString('utf8');
        console.error('❌ Decoded request preview:', decodedRequest.substring(0, 300));
      } catch (decodeError) {
        console.error('❌ Could not decode SAMLRequest for debugging:', decodeError.message);
      }
    }

    res.status(500).json({
      error: 'Failed to generate SAML response',
      details: error.message,
      debugInfo: {
        samlRequestPresent: !!SAMLRequest,
        relayStatePresent: !!RelayState,
        userAuthenticated: !!users[email]
      }
    });
  }
});


// Health check endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'SAML Identity Provider',
    status: 'running',
    configuration: {
      officialDomain: OFFICIAL_SP_DOMAIN,
      registeredSP: 'localhost:4003 only',
      supportedApps: ['app3 (official)', 'app4 (via RelayState)'],
      redirectMethod: 'RelayState-based'
    },
    endpoints: {
      metadata: '/idp/metadata',
      sso: '/idp/sso',
      login: '/idp/login'
    },
    users: Object.keys(users)
  });
});

app.listen(PORT, () => {
  console.log('🔐 SAML Identity Provider running on http://localhost:4002');
  console.log('📋 Configuration:');
  console.log('   - Official SP Domain: http://localhost:4003 (registered)');
  console.log('   - Support Method: RelayState-based redirects');
  console.log('   - Supported Apps: app3 (direct), app4 (via RelayState)');
  console.log('📋 Available endpoints:');
  console.log('   - GET  /idp/metadata (References 4003 only)');
  console.log('   - GET  /idp/sso (SSO initiation)');
  console.log('   - POST /idp/login (RelayState-aware authentication)');
  console.log('📋 Demo users:');
  Object.keys(users).forEach(email => {
    console.log(`   - ${email} (password: ${users[email].password})`);
  });
});
