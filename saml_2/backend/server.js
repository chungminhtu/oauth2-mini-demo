import express from 'express';
import cors from 'cors';
import session from 'express-session';
import crypto from 'crypto';
import { URLSearchParams } from 'url';
import axios from 'axios';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: ['http://localhost:3002', 'http://localhost:3003'],
    credentials: true
}));

// Session configuration for SAML sessions
app.use(session({
  name: 'saml_session',
  secret: 'saml-service-provider-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000 // 8 hours (typical SAML session duration)
  }
}));

// SAML Configuration
const SAML_IDP_URL = 'http://localhost:4001';
const SERVICE_PROVIDER_ENTITY_ID = 'http://localhost:4003/saml/metadata';
const ACS_URL = 'http://localhost:4003/saml/acs';

// Store for mapping SAML RequestID to app context
const samlRequestStore = new Map();

// SAML Session validation middleware
const requireSAMLSession = (req, res, next) => {
  if (!req.session || !req.session.samlAssertion) {
    return res.status(401).json({ 
      error: 'SAML authentication required',
      type: 'saml_session_required' 
    });
  }
  
  // Check if SAML assertion is still valid (not expired)
  const assertion = req.session.samlAssertion;
  const now = new Date();
  const notOnOrAfter = new Date(assertion.conditions.notOnOrAfter);
  
  if (now >= notOnOrAfter) {
    req.session.destroy();
    return res.status(401).json({ 
      error: 'SAML assertion expired',
      type: 'saml_assertion_expired' 
    });
  }
  
  next();
};

// Helper function to generate SAML AuthnRequest
const generateSAMLAuthnRequest = (requestId, relayState) => {
  const issueInstant = new Date().toISOString();
  
  return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest 
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${requestId}"
  Version="2.0"
  IssueInstant="${issueInstant}"
  Destination="${SAML_IDP_URL}/saml/sso"
  AssertionConsumerServiceURL="${ACS_URL}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>${SERVICE_PROVIDER_ENTITY_ID}</saml:Issuer>
  <samlp:NameIDPolicy 
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" 
    AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`;
};

// Routes

// Check SAML session status
app.get('/saml/session/status', (req, res) => {
  if (req.session && req.session.samlAssertion) {
    // Check assertion validity
    const assertion = req.session.samlAssertion;
    const now = new Date();
    const notOnOrAfter = new Date(assertion.conditions.notOnOrAfter);
    
    if (now < notOnOrAfter) {
      res.json({
        authenticated: true,
        assertion: {
          nameID: assertion.subject.nameID,
          attributes: assertion.attributeStatement,
          sessionIndex: assertion.authnStatement.sessionIndex,
          conditions: assertion.conditions
        }
      });
    } else {
      req.session.destroy();
      res.json({ authenticated: false, reason: 'assertion_expired' });
    }
  } else {
    res.json({ authenticated: false });
  }
});

// SP-Initiated SSO - Generate SAML AuthnRequest
app.get('/saml/sso/initiate', (req, res) => {
  const { app, returnUrl } = req.query;
  
  // Generate unique SAML Request ID
  const requestId = '_' + crypto.randomBytes(16).toString('hex');
  const relayState = crypto.randomBytes(16).toString('hex');
  
  // Store request context
  samlRequestStore.set(requestId, { 
    app, 
    returnUrl, 
    relayState,
    timestamp: Date.now()
  });
  
  console.log(`🔐 Initiating SAML SSO for app: ${app}, RequestID: ${requestId}`);
  
  try {
    // Generate SAML AuthnRequest
    const samlRequest = generateSAMLAuthnRequest(requestId, relayState);
    const encodedRequest = Buffer.from(samlRequest).toString('base64');
    
    // Build redirect URL to Identity Provider
    const params = new URLSearchParams({
      SAMLRequest: encodedRequest,
      RelayState: relayState
    });
    
    const ssoUrl = `${SAML_IDP_URL}/saml/sso?${params.toString()}`;
    console.log(`📤 Redirecting to Identity Provider: ${ssoUrl}`);
    
    res.redirect(ssoUrl);
  } catch (error) {
    console.error('❌ Error generating SAML AuthnRequest:', error);
    res.status(500).json({ error: 'Failed to initiate SAML SSO' });
  }
});

// Assertion Consumer Service (ACS) - Process SAML Response
app.post('/saml/acs', (req, res) => {
  try {
    const { SAMLResponse, RelayState } = req.body;
    console.log('📨 Received SAML Response at ACS, RelayState:', RelayState);
    
    if (!SAMLResponse) {
      return res.status(400).json({ error: 'Missing SAMLResponse in SAML assertion' });
    }

    // Decode SAML Response
    const decodedResponse = Buffer.from(SAMLResponse, 'base64').toString('utf8');
    console.log('🔍 Decoded SAML Response received');
    
    // Parse SAML Response (simplified parsing - in production use proper SAML library)
    const samlAssertion = parseSAMLResponse(decodedResponse);
    
    if (!samlAssertion || !samlAssertion.isValid) {
      console.error('❌ Invalid SAML Assertion');
      return res.status(401).json({ error: 'Invalid SAML assertion' });
    }
    
    // Store SAML assertion in session
    req.session.samlAssertion = samlAssertion;
    
    console.log('✅ SAML Assertion validated and stored in session');
    console.log('👤 Authenticated user:', samlAssertion.subject.nameID);
    
    // Find original request context using RelayState
    const requestContext = Array.from(samlRequestStore.values())
      .find(ctx => ctx.relayState === RelayState);
    
    if (requestContext) {
      // Clean up request store
      const requestId = Array.from(samlRequestStore.keys())
        .find(key => samlRequestStore.get(key).relayState === RelayState);
      if (requestId) {
        samlRequestStore.delete(requestId);
      }
      
      // Redirect back to original application
      if (requestContext.returnUrl) {
        return res.redirect(requestContext.returnUrl);
      }
    }
    
    // Default redirect based on app
    const defaultUrls = {
      app1: 'http://localhost:3002',
      app2: 'http://localhost:3003'
    };
    res.redirect(defaultUrls[requestContext?.app] || 'http://localhost:3002');
    
  } catch (error) {
    console.error('❌ Error processing SAML Response:', error);
    res.status(500).json({ error: 'Failed to process SAML authentication' });
  }
});

// Helper function to parse SAML Response (simplified)
const parseSAMLResponse = (samlResponseXml) => {
  try {
    // Extract key elements (in production, use proper XML parser and validation)
    const nameIDMatch = samlResponseXml.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
    const sessionIndexMatch = samlResponseXml.match(/SessionIndex="([^"]+)"/);
    const notOnOrAfterMatch = samlResponseXml.match(/NotOnOrAfter="([^"]+)"/);
    const notBeforeMatch = samlResponseXml.match(/NotBefore="([^"]+)"/);
    
    // Extract attributes
    const emailMatch = samlResponseXml.match(/<saml:Attribute Name="email"[^>]*>[\s\S]*?<saml:AttributeValue[^>]*>([^<]+)<\/saml:AttributeValue>/);
    const firstNameMatch = samlResponseXml.match(/<saml:Attribute Name="firstName"[^>]*>[\s\S]*?<saml:AttributeValue[^>]*>([^<]+)<\/saml:AttributeValue>/);
    const lastNameMatch = samlResponseXml.match(/<saml:Attribute Name="lastName"[^>]*>[\s\S]*?<saml:AttributeValue[^>]*>([^<]+)<\/saml:AttributeValue>/);
    
    const now = new Date();
    const notBefore = notBeforeMatch ? new Date(notBeforeMatch[1]) : now;
    const notOnOrAfter = notOnOrAfterMatch ? new Date(notOnOrAfterMatch[1]) : new Date(now.getTime() + 8 * 60 * 60 * 1000);
    
    // Validate time conditions
    const isValid = now >= notBefore && now < notOnOrAfter;
    
    return {
      isValid,
      subject: {
        nameID: nameIDMatch ? nameIDMatch[1] : 'unknown@example.com',
        format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
      },
      conditions: {
        notBefore: notBefore.toISOString(),
        notOnOrAfter: notOnOrAfter.toISOString(),
        audience: SERVICE_PROVIDER_ENTITY_ID
      },
      attributeStatement: {
        email: emailMatch ? emailMatch[1] : 'user@example.com',
        firstName: firstNameMatch ? firstNameMatch[1] : 'John',
        lastName: lastNameMatch ? lastNameMatch[1] : 'Doe'
      },
      authnStatement: {
        sessionIndex: sessionIndexMatch ? sessionIndexMatch[1] : crypto.randomBytes(8).toString('hex'),
        authnInstant: now.toISOString(),
        authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      }
    };
  } catch (error) {
    console.error('Error parsing SAML Response:', error);
    return { isValid: false };
  }
};

// Single Logout (SLO) - Initiate logout
app.post('/saml/slo/initiate', (req, res) => {
  if (req.session && req.session.samlAssertion) {
    const assertion = req.session.samlAssertion;
    console.log('🚪 Initiating SAML Single Logout for user:', assertion.subject.nameID);
    
    // Destroy local session
    req.session.destroy((err) => {
      if (err) {
        console.error('Error destroying SAML session:', err);
        return res.status(500).json({ error: 'Failed to logout' });
      }
      
      console.log('✅ SAML session destroyed');
      res.json({ success: true, message: 'SAML Single Logout successful' });
    });
  } else {
    res.json({ success: true, message: 'No active SAML session' });
  }
});

// Protected Resources

// Protected endpoint for App 1
app.get('/api/protected/app1', requireSAMLSession, (req, res) => {
  const assertion = req.session.samlAssertion;
  
  res.json({
    message: 'This is protected data for App 1 via SAML!',
    timestamp: new Date().toISOString(),
    samlSubject: assertion.subject,
    samlAttributes: assertion.attributeStatement,
    appId: 'app1',
    protectedData: {
      feature: 'Advanced Analytics Dashboard',
      permissions: ['read', 'write', 'admin'],
      customMessage: 'Welcome to App 1 - Authenticated via SAML 2.0'
    },
    sessionInfo: {
      sessionIndex: assertion.authnStatement.sessionIndex,
      validUntil: assertion.conditions.notOnOrAfter
    }
  });
});

// Protected endpoint for App 2  
app.get('/api/protected/app2', requireSAMLSession, (req, res) => {
  const assertion = req.session.samlAssertion;
  
  res.json({
    message: 'This is protected data for App 2 via SAML!',
    timestamp: new Date().toISOString(),
    samlSubject: assertion.subject,
    samlAttributes: assertion.attributeStatement,
    appId: 'app2',
    protectedData: {
      feature: 'Reporting Suite',
      permissions: ['read', 'export'],
      customMessage: 'Welcome to App 2 - Authenticated via SAML 2.0'
    },
    sessionInfo: {
      sessionIndex: assertion.authnStatement.sessionIndex,
      validUntil: assertion.conditions.notOnOrAfter
    }
  });
});

// Service Provider Metadata endpoint
app.get('/saml/metadata', (req, res) => {
  const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor 
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${SERVICE_PROVIDER_ENTITY_ID}">
  <md:SPSSODescriptor 
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
        WantAssertionsSigned="false">
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${ACS_URL}"
      index="0"/>
    <md:SingleLogoutService 
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="http://localhost:4003/saml/slo"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

    res.set('Content-Type', 'application/xml');
    res.send(metadata);
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('SAML Service Provider Error:', err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error',
        type: 'saml_service_provider_error'
    });
});

// Cleanup old SAML requests (prevent memory leaks)
setInterval(() => {
    const now = Date.now();
    const maxAge = 10 * 60 * 1000; // 10 minutes

    for (const [requestId, context] of samlRequestStore.entries()) {
        if (now - context.timestamp > maxAge) {
            samlRequestStore.delete(requestId);
        }
    }
}, 5 * 60 * 1000); // Run cleanup every 5 minutes

if (process.env.NODE_ENV === 'dev') {
    app.listen(4003, () => {
        console.log('🛡️  SAML Service Provider is running on http://localhost:4003');
    });
}

export default app;
