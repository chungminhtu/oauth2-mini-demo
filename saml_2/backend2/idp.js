import express from 'express';
import  urlencoded    from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import { DOMParser } from '@xmldom/xmldom';

const app = express();
const PORT = 4002;

const SP_ACS_URL = 'http://localhost:4001/assert';
const IDP_ENTITY_ID = 'http://localhost:4002/idp';
const DUMMY_USER = { email: 'test@example.com', password: 'password' };

app.use(urlencoded({ extended: true }));

app.post('/sso', (req, res) => {
    const { SAMLRequest } = req.body;
    const html = `
<html>
<body>
    <h2>IdP Login</h2>
    <form action="/login" method="POST">
        <input type="hidden" name="SAMLRequest" value="${SAMLRequest}" />
        <p>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" value="${DUMMY_USER.email}" required>
        </p>
        <p>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" value="${DUMMY_USER.password}" required>
        </p>
        <button type="submit">Login</button>
    </form>
</body>
</html>`;
    res.send(html);
});

app.post('/login', (req, res) => {
    const { email, password, SAMLRequest } = req.body;

    if (email !== DUMMY_USER.email || password !== DUMMY_USER.password) {
        return res.status(401).send("Invalid credentials");
    }

    const decodedRequest = Buffer.from(SAMLRequest, 'base64').toString('utf8');
    const doc = new DOMParser().parseFromString(decodedRequest, 'text/xml');
    const authnRequestID = doc.documentElement.getAttribute('ID');

    const issueInstant = new Date().toISOString();
    const responseId = '_' + uuidv4();
    const assertionId = '_' + uuidv4();

    const samlResponse = `
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
    <saml:Assertion ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">
        <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${email}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="${new Date(Date.now() + 5 * 60 * 1000).toISOString()}" Recipient="${SP_ACS_URL}" InResponseTo="${authnRequestID}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="${new Date(Date.now() - 60 * 1000).toISOString()}" NotOnOrAfter="${new Date(Date.now() + 5 * 60 * 1000).toISOString()}">
            <saml:AudienceRestriction>
                <saml:Audience>http://localhost:4001/sp</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${assertionId}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>
    `;

    const samlResponseB64 = Buffer.from(samlResponse).toString('base64');

    const html = `
<html lang="en">
<body onload="document.forms[0].submit()">
    <form method="POST" action="${SP_ACS_URL}">
        <input type="hidden" name="SAMLResponse" value="${samlResponseB64}" />
    </form>
</body>
</html>`;
    res.send(html);
});

app.listen(PORT, () => {
    console.log(`Identity Provider listening on port ${PORT}`);
});
