import express from 'express';
import cookieSession from 'cookie-session';
import { setSchemaValidator, IdentityProvider, ServiceProvider } from 'samlify';
import samlify from 'samlify'; // Import the default export

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

// Identity Provider configuration - Fix: Add SingleLogoutService
const idp = IdentityProvider({
  entityID: 'http://localhost:4002/idp/metadata',
  wantAuthnRequestsSigned: false,
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
  singleSignOnService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://localhost:4002/idp/sso'
  }],
  singleLogoutService: [{ // Fix: Add missing SLO service
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://localhost:4002/idp/slo'
  }]
});

// Service Provider configuration (for parsing requests)
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

const samlRequestStore = new Map();

// IdP Metadata endpoint
app.get('/idp/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(idp.getMetadata());
});

// SAML SSO endpoint
app.get('/idp/sso', async (req, res) => {
  const { SAMLRequest, RelayState } = req.query;

  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  try {
    const { extract } = await idp.parseLoginRequest(sp, 'redirect', req);
    console.log('Query:', req.query);
    console.log('Extracted data:', extract);

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
                <form method="post" action="/idp/authenticate">
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
app.post('/idp/authenticate', (req, res) => {
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


// Generate SAML Response - Using SamlLib.replaceTagsByValue
// const generateAndSendSAMLResponse = async (user, requestId, res) => {
//   const requestContext = samlRequestStore.get(requestId);
//   if (!requestContext) {
//     console.error('❌ Request context not found for requestId:', requestId);
//     return res.status(400).json({ error: 'Invalid SAML request' });
//   }

//   console.log(`📤 Generating SAML Response for user: ${user.email}`);
//   console.log('📋 Request context extract:', JSON.stringify(requestContext.extract, null, 2));

//   try {
//     const createTemplateCallback = (_idp, _sp, _binding, user, requestContext) => {
//       const _id = `_${uuidv4()}`;
//       const now = new Date();
//       const spEntityID = _sp.entityMeta.getEntityID();
//       const idpSetting = _idp.entitySetting;
//       const fiveMinutesLater = new Date(now.getTime());
//       fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);

//       let inResponseTo = `_${uuidv4()}`;
//       if (requestContext.extract) {
//         if (requestContext.extract.request && requestContext.extract.request.id) {
//           inResponseTo = requestContext.extract.request.id;
//         } else if (requestContext.extract.id) {
//           inResponseTo = requestContext.extract.id;
//         }
//       }

//       const tvalue = {
//         ID: _id,
//         AssertionID: idpSetting.generateID ? idpSetting.generateID() : `_${uuid.v4()}`,
//         Destination: _sp.entityMeta.getAssertionConsumerService(_binding),
//         Audience: spEntityID,
//         SubjectRecipient: spEntityID,
//         NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
//         NameID: user.email,
//         Issuer: _idp.entityMeta.getEntityID(),
//         IssueInstant: now.toISOString(),
//         ConditionsNotBefore: now.toISOString(),
//         ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
//         SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
//         AssertionConsumerServiceURL: _sp.entityMeta.getAssertionConsumerService(_binding),
//         EntityID: spEntityID,
//         InResponseTo: inResponseTo,
//         StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
//         attrUserEmail: user.email,
//         attrUserName: user.cn || user.givenName,
//         attrGivenName: user.givenName,
//         attrSurname: user.sn,
//         attrMail: user.mail,
//         attrTitle: user.title,
//       };

//       // Return object with both the callback function AND debug values
//       return {
//         // The actual callback function for samlify
//         callback: (template) => {
//           return {
//             id: _id,
//             context: samlify.SamlLib.replaceTagsByValue(template, tvalue),
//           };
//         },
//         // Debug values you can inspect
//         debugValues: {
//           _id,
//           tvalue,
//           spEntityID,
//           inResponseTo,
//           now: now.toISOString(),
//           fiveMinutesLater: fiveMinutesLater.toISOString()
//         }
//       };
//     };

//     // Now you can debug:
//     const templateData = createTemplateCallback(idp, sp, 'post', user, requestContext);
//     const fuck = templateData.debugValues; // <-- All your debug values here
//     const templateCallBack = templateData.callback; // <-- The actual callback for samlify

//     // Use the destructuring pattern
//     const { id, context } = await idp.createLoginResponse(
//       sp,                                                    // Service Provider
//       requestContext,                          // Request extract
//       'post',                                               // Binding type
//       user,                                           // NameID (subject)
//       templateCallBack,       // Template callback with SamlLib
//       undefined,                                            // Custom template (optional)
//       requestContext.relayState                             // RelayState
//     );

//     samlRequestStore.delete(requestId);
//     console.log(`✅ SAML Response generated successfully with ID: ${id}`);

//     // Send SAML Response via POST binding to SP's ACS
//     res.send(`
//       <!DOCTYPE html>
//       <html>
//       <head><title>SAML Response</title></head>
//       <body onload="document.forms[0].submit()">
//         <form method="post" action="http://localhost:4001/sp/acs">
//           <input type="hidden" name="SAMLResponse" value="${context}">
//           <input type="hidden" name="RelayState" value="${requestContext.relayState || ''}">
//           <p>🔄 Redirecting back to Service Provider...</p>
//           <button type="submit">Continue</button>
//         </form>
//       </body>
//       </html>
//     `);
//   } catch (error) {
//     console.error('❌ Error generating SAML Response:', error);
//     console.error('Error details:', error.message);
//     console.error('Error stack:', error.stack);
//     res.status(500).json({
//       error: 'Failed to generate SAML response',
//       details: error.message
//     });
//   }
// };

const generateAndSendSAMLResponse = async (user, requestId, res) => {
  const requestContext = samlRequestStore.get(requestId);
  if (!requestContext) {
    return res.status(400).json({ error: 'Invalid SAML request' });
  }

  try {
    const userAttributes = {
      'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': user.email,
      'urn:oid:2.5.4.3': user.cn,
      'urn:oid:2.5.4.4': user.sn,
      'urn:oid:2.5.4.42': user.givenName,
      'urn:oid:0.9.2342.19200300.100.1.3': user.mail,
      'urn:oid:2.5.4.12': user.title
    };

    // Simple approach - no custom template callback
    const loginResponse = await idp.createLoginResponse(
      sp,
      requestContext.extract,
      'post',
      user.email,
      userAttributes
    );

    samlRequestStore.delete(requestId);

    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>SAML Response</title></head>
      <body onload="document.forms[0].submit()">
        <form method="post" action="http://localhost:4001/sp/acs">
          <input type="hidden" name="SAMLResponse" value="${loginResponse.context}">
          <input type="hidden" name="RelayState" value="${requestContext.relayState || ''}">
          <p>🔄 Redirecting back to Service Provider...</p>
          <button type="submit">Continue</button>
        </form>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ error: 'Failed to generate SAML response' });
  }
};


// Add SLO endpoint (placeholder)
app.get('/idp/slo', (req, res) => {
  console.log('🚪 Single Logout initiated');
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Logout</title></head>
    <body style="font-family: Arial; text-align: center; margin: 100px auto;">
      <h2>✅ Successfully Logged Out</h2>
      <p>You have been logged out from the Identity Provider.</p>
    </body>
    </html>
  `);
});

app.listen(4002, () => {
  console.log('🔐 SAML Identity Provider running on http://localhost:4002');
  console.log('📋 Demo users: john@example.com, jane@example.com (password: password123)');
});
