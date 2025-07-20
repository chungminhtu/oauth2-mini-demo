import express from 'express';
import cookieSession from 'cookie-session';
import { setSchemaValidator, IdentityProvider, ServiceProvider } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import urlencoded from 'body-parser';
import json from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import cors from 'cors';
import axios  from 'axios';

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

  
setSchemaValidator(validator);

const URI_IDP_METADATA = 'http://localhost:4002/idp/metadata';

axios.get(URI_IDP_METADATA).then(response => { // Fix: use axios properly
    console.log('✅ Successfully fetched IdP metadata');

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

    // Fix: Enhanced ACS endpoint with better error handling
    app.post('/sp/acs', async (req, res) => {
        console.log('📥 Received /sp/acs post request...');
        console.log('📋 Request body keys:', Object.keys(req.body));
        console.log('📋 SAMLResponse present:', !!req.body.SAMLResponse);
        console.log('📋 SAMLResponse length:', req.body.SAMLResponse ? req.body.SAMLResponse.length : 0);

        const relayState = req.body.RelayState;
        console.log('📋 Relay state:', relayState);

        // Fix: Validate SAMLResponse is present and not undefined
        if (!req.body.SAMLResponse || req.body.SAMLResponse === 'undefined') {
            console.error('❌ Invalid or missing SAMLResponse');
            return res.status(400).json({
                error: 'Invalid SAMLResponse received',
                receivedKeys: Object.keys(req.body),
                samlResponseValue: req.body.SAMLResponse
            });
        }

        try {
            console.log('🔍 Parsing SAML Response...');
            const { extract } = await sp.parseLoginResponse(idp, 'post', req);
            console.log('✅ SAML Response parsed successfully');
            console.log('📋 Extract keys:', Object.keys(extract));
            console.log('📋 NameID:', extract.nameID);
            console.log('📋 Attributes:', JSON.stringify(extract.attributes, null, 2));

            req.session.loggedIn = true;

            // Process attributes
            const attributes = {};
            if (extract.attributes) {
                for (const key in extract.attributes) {
                    const mappedKey = INVERSE_ATTRIBUTE_MAP[key] || key;
                    attributes[mappedKey] = extract.attributes[key];
                }
            }

            req.session.attributes = attributes;
            req.session.samlAssertion = {
                subject: extract.nameID,
                attributes: attributes,
                sessionIndex: extract.sessionIndex,
                issuer: extract.issuer
            };

            console.log('✅ SAML attributes processed:', JSON.stringify(attributes, null, 2));

            // Handle RelayState for redirect
            let returnUrl = 'http://localhost:4004'; // default

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
                    console.log('⚠️ Could not parse RelayState as JSON, using default return URL');
                    console.log('RelayState value:', relayState);
                }
            }

            console.log(`🔗 Redirecting to: ${returnUrl}`);
            return res.redirect(returnUrl);

        } catch (error) {
            console.error('❌ [FATAL] Error parsing SAML login response:', error);
            console.error('Error details:', error.message);
            console.error('Error stack:', error.stack);

            return res.status(500).json({
                error: 'Failed to process SAML response',
                details: error.message,
                samlResponseReceived: !!req.body.SAMLResponse
            });
        }
    });

    // Login endpoint
    app.get('/sp/sso/initiate', (req, res) => {
        const { app: appName, returnUrl } = req.query;
        console.log(`🚀 Initiating SAML login for app: ${appName}`);
        console.log(`🔗 Return URL: ${returnUrl}`);

        try {
            const { id, context } = sp.createLoginRequest(idp, 'redirect');
            console.log('✅ SAML Login Request created with ID: %s', id);

            const parsedUrl = new URL(context);
            const relayState = JSON.stringify({
                app: appName,
                returnUrl: returnUrl
            });

            parsedUrl.searchParams.append('RelayState', relayState);
            console.log('🔗 Final redirect URL: %s', parsedUrl.toString());

            return res.redirect(parsedUrl.toString());
        } catch (error) {
            console.error('❌ Error creating SAML login request:', error);
            return res.status(500).json({
                error: 'Failed to initiate SAML login',
                details: error.message
            });
        }
    });

    // SP metadata
    app.get('/sp/metadata', (req, res) => {
        try {
            const metadata = sp.getMetadata();
            res.header('Content-Type', 'text/xml').send(metadata);
        } catch (error) {
            console.error('❌ Error generating SP metadata:', error);
            res.status(500).json({ error: 'Failed to generate metadata' });
        }
    });

    // Session status endpoint
    app.get('/sp/session/status', (req, res) => {
        console.log('📋 Session status check');
        console.log('Session logged in:', req.session.loggedIn);
        console.log('Session keys:', Object.keys(req.session || {}));

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

    // Logout endpoint
    app.get('/sp/logout', (req, res) => {
        console.log('🚪 User logout requested');
        req.session = null; // Clear session
        res.json({ message: 'Logged out successfully' });
    });

    // Protected endpoints for both apps
    app.get('/api/protected/app3', (req, res) => {
        console.log('🔒 Protected endpoint /api/protected/app3 accessed');
        console.log('Session logged in:', req.session.loggedIn);

        if (!req.session.loggedIn) {
            const returnUrl = encodeURIComponent('http://localhost:4003');
            const loginUrl = `/sp/sso/initiate?app=app3&returnUrl=${returnUrl}`;
            console.log('❌ Not authenticated, redirecting to:', loginUrl);
            return res.status(401).json({
                error: 'Authentication required',
                loginUrl: loginUrl
            });
        }

        const name = req.session.attributes?.givenName || req.session.attributes?.cn || 'Anonymous';
        const responseData = {
            message: `Hello ${name}! This is protected data for App 3!`,
            timestamp: new Date().toISOString(),
            samlUser: req.session.samlAssertion,
            appId: 'app3',
            attributes: req.session.attributes
        };

        console.log('✅ Returning protected data for App 3');
        res.json(responseData);
    });

    app.get('/api/protected/app4', (req, res) => {
        console.log('🔒 Protected endpoint /api/protected/app4 accessed');
        console.log('Session logged in:', req.session.loggedIn);

        if (!req.session.loggedIn) {
            const returnUrl = encodeURIComponent('http://localhost:4004');
            const loginUrl = `/sp/sso/initiate?app=app4&returnUrl=${returnUrl}`;
            console.log('❌ Not authenticated, redirecting to:', loginUrl);
            return res.status(401).json({
                error: 'Authentication required',
                loginUrl: loginUrl
            });
        }

        const name = req.session.attributes?.givenName || req.session.attributes?.cn || 'Anonymous';
        const responseData = {
            message: `Hello ${name}! This is protected data for App 4!`,
            timestamp: new Date().toISOString(),
            samlUser: req.session.samlAssertion,
            appId: 'app4',
            attributes: req.session.attributes
        };

        console.log('✅ Returning protected data for App 4');
        res.json(responseData);
    });

    // Root endpoint for health check
    app.get('/', (req, res) => {
        res.json({
            service: 'SAML Service Provider',
            status: 'running',
            endpoints: {
                metadata: '/sp/metadata',
                sso_initiate: '/sp/sso/initiate',
                acs: '/sp/acs',
                session_status: '/sp/session/status',
                logout: '/sp/logout'
            }
        });
    });

    app.listen(4001, () => {
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

}).catch(error => {
    console.error('❌ Failed to fetch IdP metadata:', error.message);
    console.error('Make sure the Identity Provider is running on http://localhost:4002');
    process.exit(1);
});
