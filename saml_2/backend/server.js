import express from 'express';
import session from 'express-session';
import urlencoded from 'body-parser';
import json from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import { DOMParser } from '@xmldom/xmldom';
import cors from 'cors';

const app = express();
const PORT = 4001;
const IDP_SSO_URL = 'http://localhost:4002/idp/sso';
const SP_ENTITY_ID = 'http://localhost:4001/sp/metadata';
const SP_ACS_URL = 'http://localhost:4001/sp/acs';

app.use(cors({
    origin: ['http://localhost:4003', 'http://localhost:4004'],
    credentials: true
}));

app.use(urlencoded({ extended: true }));
app.use(json());
app.use(session({
    secret: 'sp-secret-key-for-saml',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// SSO Initiation endpoint (mapped from your /login-post)
app.get('/sp/sso/initiate', (req, res) => {
    const { app: appName, returnUrl } = req.query;
    console.log(`🚀 Initiating SAML login for app: ${appName}`);
    console.log(`🔗 Return URL: ${returnUrl}`);

    const id = '_' + uuidv4();
    const issueInstant = new Date().toISOString();

    // Store the relay state in session
    req.session.relayState = {
        app: appName,
        returnUrl: returnUrl,
        timestamp: new Date().toISOString(),
        requestId: id
    };

    const authnRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="${id}"
        Version="2.0"
        IssueInstant="${issueInstant}"
        Destination="${IDP_SSO_URL}"
        AssertionConsumerServiceURL="${SP_ACS_URL}"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
        <saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>
    </samlp:AuthnRequest>`;

    const samlRequest = Buffer.from(authnRequest).toString('base64');
    const relayStateParam = JSON.stringify({
        app: appName,
        returnUrl: returnUrl
    });

    const html = `<html>
        <body onload="document.forms[0].submit()">
            <form method="POST" action="${IDP_SSO_URL}">
                <input type="hidden" name="SAMLRequest" value="${samlRequest}" />
                <input type="hidden" name="RelayState" value="${relayStateParam}" />
            </form>
            <p>🔄 Redirecting to Identity Provider...</p>
        </body>
    </html>`;

    res.send(html);
});

// ACS endpoint (mapped from your /assert)
app.post('/sp/acs', (req, res) => {
    console.log('📥 Received /sp/acs post request...');
    console.log('📋 Request body keys:', Object.keys(req.body));
    console.log('📋 SAMLResponse present:', !!req.body.SAMLResponse);

    const relayState = req.body.RelayState;
    console.log('📋 Relay state:', relayState);

    if (!req.body.SAMLResponse) {
        console.error('❌ Missing SAMLResponse');
        return res.status(400).json({
            error: 'Missing SAMLResponse'
        });
    }

    try {
        const samlResponse = Buffer.from(req.body.SAMLResponse, 'base64').toString('utf8');
        console.log('🔍 Parsing SAML Response...');

        const doc = new DOMParser().parseFromString(samlResponse, 'text/xml');
        const nameId = doc.getElementsByTagName('saml:NameID')[0]?.textContent;

        if (!nameId) {
            console.error('❌ No NameID found in SAML response');
            return res.status(401).send("Authentication failed - no NameID");
        }

        console.log('✅ SAML Response parsed successfully');
        console.log('📋 NameID:', nameId);

        // Extract attributes if present
        const attributes = {};
        const attributeStatements = doc.getElementsByTagName('saml:AttributeStatement');
        if (attributeStatements.length > 0) {
            const attributeNodes = doc.getElementsByTagName('saml:Attribute');
            for (let i = 0; i < attributeNodes.length; i++) {
                const attr = attributeNodes[i];
                const name = attr.getAttribute('Name');
                const valueNode = attr.getElementsByTagName('saml:AttributeValue')[0];
                if (valueNode) {
                    attributes[name] = valueNode.textContent;
                }
            }
        }

        // Set session data
        req.session.loggedIn = true;
        req.session.user = {
            email: nameId,
            nameId: nameId
        };
        req.session.attributes = attributes;
        req.session.samlAssertion = {
            subject: nameId,
            attributes: attributes,
            timestamp: new Date().toISOString(),
            validUntil: new Date(Date.now() + 30 * 60 * 1000).toISOString() // 30 minutes
        };

        console.log('✅ User session created for:', nameId);

        // Handle redirect based on RelayState
        let returnUrl = 'http://localhost:4003'; // Change default to app3

        if (relayState) {
            try {
                const relayData = JSON.parse(relayState);
                console.log('📋 Parsed RelayState:', relayData);

                if (relayData.returnUrl) {
                    returnUrl = relayData.returnUrl;
                } else if (relayData.app === 'app3') {
                    returnUrl = 'http://localhost:4003';
                } else if (relayData.app === 'app4') {
                    returnUrl = 'http://localhost:4004';
                }
            } catch (e) {
                console.log('⚠️ Could not parse RelayState as JSON, using default');
                console.log('RelayState value:', relayState);
            }
        } else {
            console.log('⚠️ No RelayState provided, using default app3 URL');
        }

        console.log(`🔗 Redirecting to: ${returnUrl}`);
        return res.redirect(returnUrl);

    } catch (error) {
        console.error('❌ Error parsing SAML response:', error);
        return res.status(500).json({
            error: 'Failed to process SAML response',
            details: error.message
        });
    }
});

// Session status endpoint
app.get('/sp/session/status', (req, res) => {
    console.log('📋 Session status check');
    console.log('Session logged in:', req.session.loggedIn);

    if (req.session.loggedIn && req.session.user) {
        // Check if session is still valid
        if (req.session.samlAssertion?.validUntil) {
            const validUntil = new Date(req.session.samlAssertion.validUntil);
            if (validUntil <= new Date()) {
                req.session.destroy();
                return res.json({ authenticated: false, reason: 'Session expired' });
            }
        }

        res.json({
            authenticated: true,
            authMethod: 'saml',
            user: req.session.user,
            assertion: req.session.samlAssertion
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Logout endpoint
app.get('/sp/logout', (req, res) => {
    console.log('🚪 User logout requested');
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Could not log out' });
        }
        res.json({ message: 'Logged out successfully' });
    });
});

// Protected endpoints
app.get('/api/protected/app3', (req, res) => {
    console.log('🔒 Protected endpoint /api/protected/app3 accessed');

    if (!req.session.loggedIn || !req.session.user) {
        const returnUrl = encodeURIComponent('http://localhost:4003');
        const loginUrl = `/sp/sso/initiate?app=app3&returnUrl=${returnUrl}`;
        return res.status(401).json({
            error: 'Authentication required',
            loginUrl: loginUrl
        });
    }

    // Check session validity
    if (req.session.samlAssertion?.validUntil) {
        const validUntil = new Date(req.session.samlAssertion.validUntil);
        if (validUntil <= new Date()) {
            req.session.destroy();
            const returnUrl = encodeURIComponent('http://localhost:4003');
            const loginUrl = `/sp/sso/initiate?app=app3&returnUrl=${returnUrl}`;
            return res.status(401).json({
                error: 'Session expired',
                loginUrl: loginUrl
            });
        }
    }

    const name = req.session.user.email || 'Anonymous';
    res.json({
        message: `Hello ${name}! This is protected data for App 3!`,
        timestamp: new Date().toISOString(),
        user: req.session.user,
        appId: 'app3',
        attributes: req.session.attributes
    });
});

app.get('/api/protected/app4', (req, res) => {
    console.log('🔒 Protected endpoint /api/protected/app4 accessed');

    if (!req.session.loggedIn || !req.session.user) {
        const returnUrl = encodeURIComponent('http://localhost:4004');
        const loginUrl = `/sp/sso/initiate?app=app4&returnUrl=${returnUrl}`;
        return res.status(401).json({
            error: 'Authentication required',
            loginUrl: loginUrl
        });
    }

    // Check session validity
    if (req.session.samlAssertion?.validUntil) {
        const validUntil = new Date(req.session.samlAssertion.validUntil);
        if (validUntil <= new Date()) {
            req.session.destroy();
            const returnUrl = encodeURIComponent('http://localhost:4004');
            const loginUrl = `/sp/sso/initiate?app=app4&returnUrl=${returnUrl}`;
            return res.status(401).json({
                error: 'Session expired',
                loginUrl: loginUrl
            });
        }
    }

    const name = req.session.user.email || 'Anonymous';
    res.json({
        message: `Hello ${name}! This is protected data for App 4!`,
        timestamp: new Date().toISOString(),
        user: req.session.user,
        appId: 'app4',
        attributes: req.session.attributes
    });
});

// Single Logout initiation endpoint
app.get('/sp/slo/initiate', (req, res) => {
  console.log('🚪 Initiating SAML Single Logout...');
  
  if (!req.session.loggedIn || !req.session.user) {
    return res.json({ message: 'No active session to logout' });
  }
  
  const logoutRequestId = '_' + uuidv4();
  const issueInstant = new Date().toISOString();
  const nameId = req.session.user.email || req.session.samlAssertion?.subject;
  
  const logoutRequest = `<?xml version="1.0" encoding="UTF-8"?>
  <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                       xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                       ID="${logoutRequestId}"
                       Version="2.0"
                       IssueInstant="${issueInstant}"
                       Destination="http://localhost:4002/idp/slo">
      <saml:Issuer>http://localhost:4001/sp/metadata</saml:Issuer>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>
  </samlp:LogoutRequest>`;
  
  const samlRequest = Buffer.from(logoutRequest).toString('base64');
  const relayState = JSON.stringify({ action: 'slo', timestamp: Date.now() });
  
  // Create auto-submit form to IdP
  const html = `<html>
      <body onload="document.forms[0].submit()">
          <form method="GET" action="http://localhost:4002/idp/slo">
              <input type="hidden" name="SAMLRequest" value="${samlRequest}" />
              <input type="hidden" name="RelayState" value="${relayState}" />
          </form>
          <p>🔄 Initiating Single Logout...</p>
      </body>
  </html>`;

  res.send(html);
});

// Single Logout Response handler
app.post('/sp/slo', (req, res) => {
  console.log('📥 Received SAML Logout Response...');
  
  const { SAMLResponse, RelayState } = req.body;
  
  if (!SAMLResponse) {
    return res.status(400).json({ error: 'Missing SAMLResponse' });
  }

  try {
    // Decode and parse the logout response
    const logoutResponse = Buffer.from(SAMLResponse, 'base64').toString('utf8');
    console.log('🔍 Parsing logout response...');
    
    // Check if logout was successful (simple check for Success status)
    if (logoutResponse.includes('urn:oasis:names:tc:SAML:2.0:status:Success')) {
      console.log('✅ Logout successful according to IdP');
      
      // Clear the session
      req.session.destroy(err => {
        if (err) {
          console.error('Error destroying session:', err);
        }
      });
      
      // Redirect to a logout success page
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Logout Successful</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .success { background: #d4edda; color: #155724; padding: 20px; border-radius: 5px; margin: 20px auto; max-width: 500px; }
          </style>
        </head>
        <body>
          <div class="success">
            <h2>🎉 Logout Successful</h2>
            <p>You have been successfully logged out from all applications.</p>
            <div style="margin-top: 20px;">
              <a href="http://localhost:4003" style="margin: 0 10px; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 3px;">Go to App 3</a>
              <a href="http://localhost:4004" style="margin: 0 10px; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 3px;">Go to App 4</a>
            </div>
          </div>
        </body>
        </html>
      `);
      
    } else {
      console.log('❌ Logout failed according to IdP');
      res.status(500).json({ error: 'Logout failed' });
    }
    
  } catch (error) {
    console.error('❌ Error processing logout response:', error);
    res.status(500).json({ error: 'Failed to process logout response' });
  }
});

// SP metadata endpoint
app.get('/sp/metadata', (req, res) => {
    const metadata = `<?xml version="1.0" encoding="UTF-8"?>
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                         entityID="${SP_ENTITY_ID}">
        <md:SPSSODescriptor AuthnRequestsSigned="false" 
                            WantAssertionsSigned="false" 
                            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
                                         Location="${SP_ACS_URL}" 
                                         index="0" 
                                         isDefault="true"/>
            <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                  Location="http://localhost:4001/sp/slo"/>
        </md:SPSSODescriptor>
    </md:EntityDescriptor>`;

    res.header('Content-Type', 'text/xml').send(metadata);
});

// Health check
app.get('/', (req, res) => {
    res.json({
        service: 'SAML Service Provider',
        status: 'running',
        endpoints: {
            metadata: '/sp/metadata',
            sso_initiate: '/sp/sso/initiate',
            acs: '/sp/acs',
            session_status: '/sp/session/status',
            logout: '/sp/logout',
            protected_app3: '/api/protected/app3',
            protected_app4: '/api/protected/app4'
        }
    });
});

app.listen(PORT, () => {
    console.log('🔐 SAML Service Provider running on http://localhost:4001');
    console.log('📋 Available endpoints:');
    console.log('   - GET  /sp/metadata (SP metadata)');
    console.log('   - GET  /sp/sso/initiate (Initiate SAML login)');
    console.log('   - POST /sp/acs (Assertion Consumer Service)');
    console.log('   - GET  /sp/session/status (Check auth status)');
    console.log('   - GET  /sp/logout (Logout)');
    console.log('   - GET  /api/protected/app3 (Protected endpoint for App 3)');
    console.log('   - GET  /api/protected/app4 (Protected endpoint for App 4)');
});
