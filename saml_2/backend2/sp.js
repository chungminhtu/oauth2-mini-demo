import express from 'express';
import session from 'express-session';
import  urlencoded   from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import { DOMParser } from '@xmldom/xmldom';
import cors from 'cors';
import path from 'path';

const app = express();
const PORT = 4001;

const IDP_SSO_URL = 'http://localhost:4002/sso';
const SP_ENTITY_ID = 'http://localhost:4001/sp';
const SP_ACS_URL = 'http://localhost:4001/assert';

app.use(cors({
    origin: 'http://localhost:5173', // Vite default port
    credentials: true,
}));
app.use(urlencoded({ extended: true }));
app.use(session({
    secret: 'a-very-secret-key-for-sp',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

app.get('/login-post', (req, res) => {
    const id = '_' + uuidv4();
    const issueInstant = new Date().toISOString();
    const authnRequest = `
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="${id}"
    Version="2.0"
    IssueInstant="${issueInstant}"
    Destination="${IDP_SSO_URL}"
    AssertionConsumerServiceURL="${SP_ACS_URL}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>
</samlp:AuthnRequest>
    `;
    const samlRequest = Buffer.from(authnRequest).toString('base64');

    const html = `
<html>
<body onload="document.forms[0].submit()">
    <form method="POST" action="${IDP_SSO_URL}">
        <input type="hidden" name="SAMLRequest" value="${samlRequest}" />
    </form>
</body>
</html>`;
    res.send(html);
});

app.post('/assert', (req, res) => {
    const samlResponse = Buffer.from(req.body.SAMLResponse, 'base64').toString('utf8');
    const doc = new DOMParser().parseFromString(samlResponse, 'text/xml');
    const nameId = doc.getElementsByTagName('saml:NameID')[0].textContent;

    if (nameId) {
        req.session.user = { email: nameId };
        res.redirect('http://localhost:5173/profile'); // Redirect to your React app's profile page
    } else {
        res.status(401).send("Login failed");
    }
});

app.get('/me', (req, res) => {
    if (req.session.user) {
        res.json(req.session.user);
    } else {
        res.status(401).json({ message: 'Not authenticated' });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        }
        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logged out successfully' });
    });
});

app.listen(PORT, () => {
    console.log(`Service Provider listening on port ${PORT}`);
});
