import express from 'express';
import cookieSession from 'cookie-session';
import { setSchemaValidator, IdentityProvider, ServiceProvider } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import get from 'axios';
import urlencoded from 'body-parser';
import json from 'body-parser';
import cors from 'cors';

// ATTRIBUTE MAPPING (from your working code)
const INVERSE_ATTRIBUTE_MAP = {
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'email',
    'urn:oid:2.5.4.3': 'cn',
    'urn:oid:2.5.4.4': 'sn',
    'urn:oid:2.5.4.42': 'givenName',
    'urn:oid:2.16.840.1.113730.3.1.241': 'displayName',
    'urn:oid:0.9.2342.19200300.100.1.1': 'uid',
    'urn:oid:0.9.2342.19200300.100.1.3': 'mail',
    'urn:oid:2.5.4.20': 'telephoneNumber',
    'urn:oid:2.5.4.12': 'title'
};

const app = express(); 

app.use(urlencoded({ extended: true }));
app.use(json());
app.use(cors({
    origin: ['http://localhost:4003', 'http://localhost:4004'],
    credentials: true
}));

app.use(cookieSession({
    name: 'session',
    keys: ['my-favorite-secret'],
    maxAge: 8 * 60 * 60 * 1000
}));


setSchemaValidator(validator);

const URI_IDP_METADATA = 'http://localhost:4002/idp/metadata';

get(URI_IDP_METADATA).then(response => {
    const idp = IdentityProvider({
        metadata: response.data,
        wantAuthnRequestsSigned: false
    });

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

    app.post('/sp/acs', async (req, res) => {
        console.log('Received /sp/acs post request...');
        const relayState = req.body.RelayState;
        console.log('Relay state:', relayState);

        try {
            console.log('req.body:', req.body);
            const { extract } = await sp.parseLoginResponse(idp, 'post', req);
            console.log('Extract:', extract);

            req.session.loggedIn = true;
            const attributes = {};
            for (const key in extract.attributes) {
                attributes[INVERSE_ATTRIBUTE_MAP[key] || key] = extract.attributes[key];
            }
            req.session.attributes = attributes;
            req.session.samlAssertion = {
                subject: extract.nameID,
                attributes: attributes,
                sessionIndex: extract.sessionIndex,
                issuer: extract.issuer
            };

            console.log('SAML attributes:', JSON.stringify(attributes));

            let returnUrl = 'http://localhost:4004';
            try {
                const relayData = JSON.parse(relayState);
                returnUrl = relayData.returnUrl || (relayData.app === 'app4' ? 'http://localhost:4003' : 'http://localhost:4004');
            } catch (e) {
                console.log('Using default return URL');
            }

            return res.redirect(returnUrl);
        } catch (e) {
            console.error('[FATAL] when parsing login response...', e);
            return res.redirect('/');
        }
    });

    // Login endpoint
    app.get('/sp/sso/initiate', (req, res) => {
        const { app: appName, returnUrl } = req.query;
        console.log(`🚀 Initiating SAML login for app: ${appName}`);

        const { id, context } = sp.createLoginRequest(idp, 'redirect');
        console.log('Id: %s', id);

        const parsedUrl = new URL(context);
        const relayState = JSON.stringify({ app: appName, returnUrl: returnUrl });
        parsedUrl.searchParams.append('RelayState', relayState);

        console.log('🔗 Redirect URL: %s', parsedUrl);
        return res.redirect(parsedUrl);
    });

    // SP metadata
    app.get('/sp/metadata', (req, res) => {
        res.header('Content-Type', 'text/xml').send(sp.getMetadata());
    });

    // Session status endpoint
    app.get('/sp/session/status', (req, res) => {
        if (req.session.loggedIn && req.session.samlAssertion) {
            res.json({
                authenticated: true,
                authMethod: 'saml',
                assertion: req.session.samlAssertion
            });
        } else {
            res.json({ authenticated: false });
        }
    });

    // Protected endpoints for both apps
    app.get('/api/protected/app3', (req, res) => {
        if (!req.session.loggedIn) {
            const returnUrl = encodeURIComponent(req.originalUrl);
            return res.redirect(`/login?returnUrl=${returnUrl}`);
        }

        const name = req.session.attributes?.givenName || 'Anonymous';
        res.json({
            message: `Hello ${name}! This is protected data for App 3!`,
            timestamp: new Date().toISOString(),
            samlUser: req.session.samlAssertion,
            appId: 'app3',
            attributes: req.session.attributes
        });
    });

    app.get('/api/protected/app4', (req, res) => {
        if (!req.session.loggedIn) {
            const returnUrl = encodeURIComponent(req.originalUrl);
            return res.redirect(`/login?returnUrl=${returnUrl}`);
        }

        const name = req.session.attributes?.givenName || 'Anonymous';
        res.json({
            message: `Hello ${name}! This is protected data for App 4!`,
            timestamp: new Date().toISOString(),
            samlUser: req.session.samlAssertion,
            appId: 'app4',
            attributes: req.session.attributes
        });
    });

    app.listen(4001, () => {
        console.log('🔐 SAML Service Provider running on http://localhost:4001');
    });

}).catch(error => {
    console.error('❌ Failed to fetch IdP metadata:', error.message);
});
