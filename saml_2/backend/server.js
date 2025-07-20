import express from 'express';
import cookieSession from 'cookie-session';
import { setSchemaValidator, IdentityProvider, ServiceProvider } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import urlencoded from 'body-parser';
import json from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import cors from 'cors';
import axios from 'axios';

const app = express();
app.use(urlencoded({ extended: true }));
app.use(json());

// CORS - Allow both apps but only 4003 is "officially" registered
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

const URI_IDP_METADATA = 'http://localhost:4002/idp/metadata';

axios.get(URI_IDP_METADATA).then(response => {
    console.log('✅ Successfully fetched IdP metadata');

    const idp = IdentityProvider({
        metadata: response.data,
        wantAuthnRequestsSigned: false
    });

    // SP configuration - Only 4003 is officially registered
    const sp = ServiceProvider({
        entityID: 'http://localhost:4003/sp/metadata', // Only 4003 registered
        authnRequestsSigned: false,
        wantAssertionsSigned: false,
        wantMessageSigned: false,
        wantLogoutResponseSigned: false,
        wantLogoutRequestSigned: false,
        assertionConsumerService: [{
            Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            Location: 'http://localhost:4001/sp/acs', // Backend handles all apps
        }],
        nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress']
    });

    // SSO Initiation - Enhanced RelayState handling
    app.get('/sp/sso/initiate', (req, res) => {
        const { app: appName, returnUrl } = req.query;
        console.log(`🚀 Initiating SAML login for app: ${appName}`);
        console.log(`🔗 Return URL: ${returnUrl}`);

        try {
            const { id, context } = sp.createLoginRequest(idp, 'redirect');
            console.log('✅ SAML Login Request created with ID: %s', id);

            const parsedUrl = new URL(context);

            // Enhanced RelayState with app routing information
            const relayState = JSON.stringify({
                app: appName,
                returnUrl: returnUrl,
                requestId: id,
                timestamp: Date.now(),
                // Add routing logic
                targetDomain: appName === 'app3' ? 'http://localhost:4003' :
                    appName === 'app4' ? 'http://localhost:4004' :
                        returnUrl || 'http://localhost:4003'
            });

            parsedUrl.searchParams.append('RelayState', relayState);
            console.log('🔗 Final redirect URL with RelayState: %s', parsedUrl.toString());

            return res.redirect(parsedUrl.toString());
        } catch (error) {
            console.error('❌ Error creating SAML login request:', error);
            return res.status(500).json({
                error: 'Failed to initiate SAML login',
                details: error.message
            });
        }
    });

    // ACS - Enhanced RelayState-based redirect
    app.post('/sp/acs', async (req, res) => {
        console.log('📥 Received /sp/acs post request...');
        console.log('📋 Request body keys:', Object.keys(req.body));
        console.log('📋 SAMLResponse present:', !!req.body.SAMLResponse);

        const relayState = req.body.RelayState;
        console.log('📋 Raw RelayState:', relayState);

        if (!req.body.SAMLResponse || req.body.SAMLResponse === 'undefined') {
            console.error('❌ Invalid or missing SAMLResponse');
            return res.status(400).json({
                error: 'Invalid SAMLResponse received'
            });
        }

        try {
            console.log('🔍 Parsing SAML Response...');
            const { extract } = await sp.parseLoginResponse(idp, 'post', req);
            console.log('✅ SAML Response parsed successfully');
            console.log('📋 Extract keys:', Object.keys(extract));
            console.log('📋 NameID:', extract.nameID);
            console.log('📋 Raw attributes:', JSON.stringify(extract.attributes, null, 2));

            req.session.loggedIn = true;

            // Process attributes with improved mapping
            const attributes = {};
            if (extract.attributes) {
                for (const key in extract.attributes) {
                    const mappedKey = INVERSE_ATTRIBUTE_MAP[key] || key;
                    
                    // Handle both string and array values
                    let value = extract.attributes[key];
                    if (Array.isArray(value) && value.length === 1) {
                        value = value[0]; // Convert single-item arrays to strings
                    }
                    
                    attributes[mappedKey] = value;
                    console.log(`📋 Mapped attribute: ${key} → ${mappedKey} = ${value}`);
                }
            }

            req.session.attributes = attributes;
            req.session.samlAssertion = {
                subject: extract.nameID,
                attributes: attributes,
                sessionIndex: extract.sessionIndex,
                issuer: extract.issuer,
                timestamp: new Date().toISOString()
            };

            console.log('✅ SAML attributes processed:', JSON.stringify(attributes, null, 2));

            // RelayState-based redirect logic
            let returnUrl = 'http://localhost:4003'; // Default to registered domain

            if (relayState) {
                try {
                    const relayData = JSON.parse(relayState);
                    console.log('📋 Parsed RelayState:', relayData);

                    // Priority order for redirect URL
                    if (relayData.returnUrl) {
                        returnUrl = relayData.returnUrl;
                        console.log('🎯 Using returnUrl from RelayState:', returnUrl);
                    } else if (relayData.targetDomain) {
                        returnUrl = relayData.targetDomain;
                        console.log('🎯 Using targetDomain from RelayState:', returnUrl);
                    } else if (relayData.app) {
                        // App-based routing
                        const appRouting = {
                            'app3': 'http://localhost:4003',
                            'app4': 'http://localhost:4004'
                        };
                        returnUrl = appRouting[relayData.app] || returnUrl;
                        console.log('🎯 Using app-based routing for:', relayData.app, '→', returnUrl);
                    }
                } catch (e) {
                    console.log('⚠️ Could not parse RelayState as JSON, using default return URL');
                    console.log('RelayState value:', relayState);
                }
            }

            console.log(`🔗 Auto-redirecting to: ${returnUrl}`);
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

    // SP metadata - Only 4003 is officially registered
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

    // Protected endpoints for both apps (even though only 4003 is registered)
    app.get('/api/protected/app3', (req, res) => {
        console.log('🔒 Protected endpoint /api/protected/app3 accessed');

        if (!req.session.loggedIn) {
            const returnUrl = encodeURIComponent('http://localhost:4003');
            const loginUrl = `/sp/sso/initiate?app=app3&returnUrl=${returnUrl}`;
            return res.status(401).json({
                error: 'Authentication required',
                loginUrl: loginUrl
            });
        }

        const name = req.session.attributes?.givenName || req.session.attributes?.cn || 'Anonymous';
        res.json({
            message: `Hello ${name}! This is protected data for App 3 (Official Domain)!`,
            timestamp: new Date().toISOString(),
            samlUser: req.session.samlAssertion,
            appId: 'app3',
            officialDomain: true,
            attributes: req.session.attributes
        });
    });

    app.get('/api/protected/app4', (req, res) => {
        console.log('🔒 Protected endpoint /api/protected/app4 accessed');

        if (!req.session.loggedIn) {
            const returnUrl = encodeURIComponent('http://localhost:4004');
            const loginUrl = `/sp/sso/initiate?app=app4&returnUrl=${returnUrl}`;
            return res.status(401).json({
                error: 'Authentication required',
                loginUrl: loginUrl
            });
        }

        const name = req.session.attributes?.givenName || req.session.attributes?.cn || 'Anonymous';
        res.json({
            message: `Hello ${name}! This is protected data for App 4 (Via RelayState Redirect)!`,
            timestamp: new Date().toISOString(),
            samlUser: req.session.samlAssertion,
            appId: 'app4',
            officialDomain: false,
            viaRelayState: true,
            attributes: req.session.attributes
        });
    });

    // Logout endpoint
    app.get('/sp/logout', (req, res) => {
        console.log('🚪 User logout requested');
        req.session = null;
        res.json({ message: 'Logged out successfully' });
    });

    // Root endpoint
    app.get('/', (req, res) => {
        res.json({
            service: 'SAML Service Provider',
            status: 'running',
            officialDomain: 'http://localhost:4003',
            supportedApps: ['app3', 'app4'],
            redirectStrategy: 'RelayState-based',
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
        console.log('📋 Configuration:');
        console.log('   - Official Domain: http://localhost:4003 (registered with IdP)');
        console.log('   - Supported Apps: app3, app4');
        console.log('   - Redirect Strategy: RelayState-based auto-redirect');
        console.log('📋 Available endpoints:');
        console.log('   - GET  /sp/metadata (SP metadata - references 4003 only)');
        console.log('   - GET  /sp/sso/initiate (Initiate SAML login)');
        console.log('   - POST /sp/acs (Auto-redirect based on RelayState)');
        console.log('   - GET  /sp/session/status (Check auth status)');
        console.log('   - GET  /sp/logout (Logout)');
        console.log('   - GET  /api/protected/app3 (Protected - Official)');
        console.log('   - GET  /api/protected/app4 (Protected - Via RelayState)');
    });

}).catch(error => {
    console.error('❌ Failed to fetch IdP metadata:', error.message);
    console.error('Make sure the Identity Provider is running on http://localhost:4002');
    process.exit(1);
});
