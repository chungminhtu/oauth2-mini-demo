import express from 'express';
import cookieSession from 'cookie-session';
import { setSchemaValidator, IdentityProvider, ServiceProvider } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import urlencoded from 'body-parser';
import json from 'body-parser';
import { randomUUID } from 'crypto';
import { addMinutes } from 'date-fns';
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

// Better ID generation following the working code pattern
const generateRequestID = () => {
  return '_' + randomUUID();
}

// Template callback function similar to working code
const createTemplateCallback = (idp, sp, user, inResponseTo = null) => template => {
  const assertionConsumerServiceUrl = sp.entityMeta.getAssertionConsumerService('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
  const nameIDFormat = idp.entitySetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;

  const id = generateRequestID();
  const assertionId = generateRequestID();
  const now = new Date();
  const fiveMinutesLater = addMinutes(now, 5);

  const tagValues = {
    ID: id,
    AssertionID: assertionId,
    Destination: assertionConsumerServiceUrl,
    Audience: sp.entityMeta.getEntityID(),
    EntityID: sp.entityMeta.getEntityID(),
    SubjectRecipient: assertionConsumerServiceUrl,
    Issuer: idp.entityMeta.getEntityID(),
    IssueInstant: now.toISOString(),
    AssertionConsumerServiceURL: assertionConsumerServiceUrl,
    StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    ConditionsNotBefore: now.toISOString(),
    ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
    NameIDFormat: selectedNameIDFormat,
    NameID: user.email,
    InResponseTo: inResponseTo || 'null',
    // User attributes
    firstName: user.givenName,
    lastName: user.sn,
    email: user.email,
    commonName: user.cn,
    title: user.title
  };

  return {
    id,
    context: template.replace(/{(\w+)}/g, (match, key) => tagValues[key] || match)
  };
}

// IdP configuration with custom login response template
const idp = IdentityProvider({
  entityID: 'http://localhost:4002/idp/metadata',
  wantAuthnRequestsSigned: false,
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
  singleSignOnService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://localhost:4002/idp/sso'
  }],
  loginResponseTemplate: {
    context: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}">
      <saml:Issuer>{Issuer}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="{StatusCode}"/>
      </samlp:Status>
      <saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}">
        <saml:Issuer>{Issuer}</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}">
          <saml:AudienceRestriction>
            <saml:Audience>{Audience}</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
          <saml:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{firstName}</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{lastName}</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{email}</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{commonName}</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="urn:oid:2.5.4.12" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>{title}</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>`,
    attributes: [
      { name: 'firstName', valueTag: 'firstName', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', valueXsiType: 'xs:string' },
      { name: 'lastName', valueTag: 'lastName', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', valueXsiType: 'xs:string' },
      { name: 'email', valueTag: 'email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', valueXsiType: 'xs:string' },
      { name: 'commonName', valueTag: 'commonName', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', valueXsiType: 'xs:string' },
      { name: 'title', valueTag: 'title', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', valueXsiType: 'xs:string' },
    ]
  }
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

app.get('/idp/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(idp.getMetadata());
});

app.get('/idp/sso', async (req, res) => {
  const { SAMLRequest, RelayState } = req.query;

  if (!SAMLRequest) {
    return res.status(400).json({ error: 'Missing SAMLRequest parameter' });
  }

  try {
    const { extract } = await idp.parseLoginRequest(sp, 'redirect', req);

    const requestId = extract.request?.id || extract.id || generateRequestID();

    req.session.samlContext = {
      extract: extract,
      relayState: RelayState,
      timestamp: Date.now(),
      requestId: requestId
    };

    if (req.session.authenticatedUser) {
      return handleAuthenticatedUser(req, res);
    }

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

// Enhanced function using the template callback pattern
async function handleAuthenticatedUser(req, res) {
  if (!req.session.samlContext) {
    return res.status(400).json({ error: 'No SAML context found' });
  }

  const user = req.session.authenticatedUser;
  const { extract, relayState } = req.session.samlContext;

  try {
    console.log('🔍 Creating login response for:', user.email);

    // Use the template callback approach from working code
    const inResponseTo = extract.request?.id || extract.id;
    const templateCallback = createTemplateCallback(idp, sp, user, inResponseTo);

    // Create login response using the template callback
    const loginResponse = await idp.createLoginResponse(
      sp,
      extract,
      'post',
      user.email,
      templateCallback
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
