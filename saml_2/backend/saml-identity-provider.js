import express from 'express';
import session from 'express-session';
import { IdentityProvider, ServiceProvider, setSchemaValidator } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import cors from 'cors';

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors({
  origin: ['http://localhost:4001', 'http://localhost:4003', 'http://localhost:4004'],
  credentials: true
}));

app.use(session({
  secret: 'idp-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

setSchemaValidator(validator);

// Demo users
const users = {
  'john@example.com': {
    password: 'password123',
    givenName: 'John',
    surname: 'Doe',
    email: 'john@example.com',
    title: 'Senior Developer'
  },
  'jane@example.com': {
    password: 'password456',
    givenName: 'Jane',
    surname: 'Smith',
    email: 'jane@example.com',
    title: 'Product Manager'
  }
};

let idp, sp;

// Initialize SAML
function initializeSAML() {
  // Create IdP
  idp = IdentityProvider({
    entityID: 'http://localhost:4002/idp/metadata',
    singleSignOnService: [{
      Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
      Location: 'http://localhost:4002/idp/sso'
    }]
  });

  // Create SP for parsing requests
  sp = ServiceProvider({
    entityID: 'http://localhost:4001/sp/metadata',
    assertionConsumerService: [{
      Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      Location: 'http://localhost:4001/sp/acs'
    }]
  });

  console.log('✅ IdP SAML initialized');
}

// Initialize on startup
initializeSAML();

// Health check
app.get('/', (req, res) => {
  res.json({
    service: 'SAML Identity Provider',
    status: 'running',
    version: '2.0.0',
    endpoints: {
      metadata: '/idp/metadata',
      sso: '/idp/sso',
      authenticate: '/idp/authenticate'
    },
    demoUsers: Object.keys(users)
  });
});

// IdP Metadata
app.get('/idp/metadata', (req, res) => {
  const metadata = idp.getMetadata();
  res.set('Content-Type', 'text/xml');
  res.send(metadata);
});

// SSO Endpoint
app.get('/idp/sso', async (req, res) => {
  try {
    const { extract } = await idp.parseLoginRequest(sp, 'redirect', req);

    // Store SAML request info
    req.session.samlRequest = extract;

    // If user already authenticated, proceed
    if (req.session.user) {
      return handleAuthentication(req, res);
    }

    // Show login form
    res.send(getLoginForm());

  } catch (error) {
    console.error('❌ SSO processing failed:', error);
    res.status(500).json({
      error: 'Failed to process SSO request',
      details: error.message
    });
  }
});

// Authentication
app.post('/idp/authenticate', (req, res) => {
  const { username, password } = req.body;

  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).send(getLoginForm('Invalid credentials'));
  }

  // Store user in session
  req.session.user = user;

  console.log('✅ User authenticated:', username);

  // Handle SAML response
  handleAuthentication(req, res);
});

// Handle authentication and create SAML response
function handleAuthentication(req, res) {
  if (!req.session.samlRequest || !req.session.user) {
    return res.status(400).json({ error: 'Invalid session state' });
  }

  try {
    const user = req.session.user;
    const { extract } = req.session.samlRequest;

    // Create SAML response
    const { context } = idp.createLoginResponse(
      sp,
      extract,
      'post',
      user.email,
      createTemplateCallback(user)
    );

    // Clear SAML request from session
    req.session.samlRequest = null;

    console.log('✅ SAML response created');

    // Send auto-submit form
    res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Redirecting...</title>
                <style>
                    body { font-family: Arial; text-align: center; margin-top: 100px; }
                    .loading { color: #007bff; }
                </style>
            </head>
            <body onload="document.forms[0].submit()">
                <div class="loading">
                    <h3>✅ Authentication Successful</h3>
                    <p>🔄 Redirecting back to application...</p>
                </div>
                <form method="post" action="http://localhost:4001/sp/acs">
                    <input type="hidden" name="SAMLResponse" value="${context}">
                    <button type="submit">Continue</button>
                </form>
            </body>
            </html>
        `);

  } catch (error) {
    console.error('❌ SAML response creation failed:', error);
    res.status(500).json({
      error: 'Failed to create SAML response',
      details: error.message
    });
  }
}

// Template callback for SAML response
function createTemplateCallback(user) {
  return (template) => {
    const now = new Date();
    const id = '_' + Math.random().toString(36).substr(2, 9);

    const templateMap = {
      ID: id,
      AssertionID: '_' + Math.random().toString(36).substr(2, 9),
      Issuer: 'http://localhost:4002/idp/metadata',
      IssueInstant: now.toISOString(),
      NotBefore: now.toISOString(),
      NotOnOrAfter: new Date(now.getTime() + 300000).toISOString(), // 5 minutes
      Audience: 'http://localhost:4001/sp/metadata',
      InResponseTo: template.context?.extract?.request?.id || '',
      Recipient: 'http://localhost:4001/sp/acs',
      NameID: user.email,
      NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      AuthnInstant: now.toISOString(),
      SessionIndex: id,
      // User attributes
      'attrName:givenName': 'givenName',
      'attrValue:givenName': user.givenName,
      'attrName:surname': 'surname',
      'attrValue:surname': user.surname,
      'attrName:email': 'email',
      'attrValue:email': user.email,
      'attrName:title': 'title',
      'attrValue:title': user.title
    };

    let processedTemplate = template.context || template;

    Object.keys(templateMap).forEach(key => {
      const regex = new RegExp(`{${key}}`, 'g');
      processedTemplate = processedTemplate.replace(regex, templateMap[key]);
    });

    return processedTemplate;
  };
}

// Get login form HTML
function getLoginForm(error = '') {
  return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>SAML Identity Provider - Sign In</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: #f5f5f5;
                    margin: 0;
                    padding: 50px 20px;
                }
                .container {
                    max-width: 400px;
                    margin: 0 auto;
                    background: white;
                    padding: 40px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h2 {
                    text-align: center;
                    color: #333;
                    margin-bottom: 30px;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                    font-weight: bold;
                    color: #555;
                }
                input[type="email"], input[type="password"] {
                    width: 100%;
                    padding: 12px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    font-size: 14px;
                    box-sizing: border-box;
                }
                button {
                    width: 100%;
                    background: #007bff;
                    color: white;
                    padding: 12px;
                    border: none;
                    border-radius: 4px;
                    font-size: 16px;
                    cursor: pointer;
                    transition: background 0.3s;
                }
                button:hover {
                    background: #0056b3;
                }
                .error {
                    color: #dc3545;
                    text-align: center;
                    margin-bottom: 20px;
                    padding: 10px;
                    background: #f8d7da;
                    border: 1px solid #f5c6cb;
                    border-radius: 4px;
                }
                .demo-users {
                    background: #e9ecef;
                    padding: 20px;
                    border-radius: 4px;
                    margin-top: 30px;
                    font-size: 14px;
                }
                .demo-users h4 {
                    margin-top: 0;
                    color: #495057;
                }
                .user-item {
                    margin: 8px 0;
                    font-family: monospace;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>🔐 Identity Provider</h2>
                <p style="text-align: center; color: #666;">Please sign in to continue</p>
                
                ${error ? `<div class="error">${error}</div>` : ''}
                
                <form method="post" action="/idp/authenticate">
                    <div class="form-group">
                        <label for="username">Email Address:</label>
                        <input type="email" id="username" name="username" value="john@example.com" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" value="password123" required>
                    </div>
                    
                    <button type="submit">🚀 Sign In</button>
                </form>
                
                <div class="demo-users">
                    <h4>📋 Demo Users Available:</h4>
                    <div class="user-item">👤 john@example.com / password123</div>
                    <div class="user-item">👤 jane@example.com / password456</div>
                </div>
            </div>
        </body>
        </html>
    `;
}

// Status endpoint
app.get('/idp/status', (req, res) => {
  res.json({
    service: 'SAML Identity Provider',
    status: 'running',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      metadata: '/idp/metadata',
      sso: '/idp/sso',
      authenticate: '/idp/authenticate'
    },
    demoUsers: Object.keys(users),
    activeSession: !!req.session.user
  });
});

// Logout
app.get('/idp/logout', (req, res) => {
  req.session.destroy();
  res.send(`
        <html>
        <body style="font-family: Arial; text-align: center; margin-top: 100px;">
            <div style="max-width: 400px; margin: 0 auto; padding: 30px; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2>✅ Logged Out</h2>
                <p>You have been successfully logged out.</p>
                <a href="/idp/status" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">View Status</a>
            </div>
        </body>
        </html>
    `);
});

// Start IdP server
app.listen(4002, () => {
  console.log('🔐 SAML Identity Provider running on http://localhost:4002');
  console.log('📋 Endpoints available:');
  console.log('   - GET  /idp/metadata');
  console.log('   - GET  /idp/sso');
  console.log('   - POST /idp/authenticate');
  console.log('   - GET  /idp/status');
  console.log('   - GET  /idp/logout');
  console.log('👥 Demo users:');
  Object.entries(users).forEach(([email, user]) => {
    console.log(`   - ${email} / ${user.password} (${user.givenName} ${user.surname})`);
  });
});
