import express from 'express';
import { Provider } from 'oidc-provider';
import bodyParser from 'body-parser';
import cors from 'cors';

const oidcApp = express();
oidcApp.use(bodyParser.json());
oidcApp.use(cors());

const configuration = {
    clients: [{
        client_id: 'my-random-client-id',
        client_secret: 'my-random-and-very-long-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        grant_types: [
            'refresh_token',
            'authorization_code'
        ],
        response_types: ['code'],
        scopes: ['openid', 'profile', 'offline_access'],
        // scope: 'openid offline_access profile email',

    }],
    pkce: {
        required: () => false,
    },
    scopes: ['openid', 'profile', 'offline_access'],
    claims: {
        openid: ['sub', 'name', 'email'],
        profile: ['name', 'email']
    },
    features: {
        introspection: { enabled: true },
        revocation: { enabled: true },
    },
    ttl: {
        AccessToken: 2 * 60 * 60, // 2 hours in seconds
        AuthorizationCode: 10 * 60, // 10 minutes in seconds
        ClientCredentials: 10 * 60, // 10 minutes in seconds
        IdToken: 2 * 60 * 60, // 2 hours in seconds
        RefreshToken: 30 * 24 * 60 * 60, // 30 days in seconds
    },
    findAccount: (ctx, id) => {
        return {
            accountId: id,
            async claims() {
                return {
                    sub: id,
                    address: {
                        country: '000',
                        formatted: '000',
                        locality: '000',
                        postal_code: '000',
                        region: '000',
                        street_address: '000',
                    },
                    birthdate: '1987-10-16',
                    email: 'johndoe@example.com',
                    email_verified: false,
                    family_name: 'Doe',
                    gender: 'male',
                    given_name: 'John',
                    locale: 'en-US',
                    middle_name: 'Middle',
                    name: 'John Doe',
                    nickname: 'Johny',
                    phone_number: '+49 000 000000',
                    phone_number_verified: false,
                    picture: 'http://lorempixel.com/400/200/',
                    preferred_username: 'johnny',
                    profile: 'https://johnswebsite.com',
                    updated_at: 1454704946,
                    website: 'http://example.com',
                    zoneinfo: 'Europe/Berlin',
                };
            },
        };
    },
};

const oidc = new Provider('http://localhost:3001', configuration);

oidc.on('grant.success', (ctx) => {
    console.log('Grant Success:', ctx.oidc.entities);
    console.log('Issued Tokens:', ctx.oidc.entities.AccessToken ? 'AccessToken' : 'No AccessToken',
        ctx.oidc.entities.RefreshToken ? 'RefreshToken' : 'No RefreshToken');
});


// Example login and consent views (you may want to customize these)
oidcApp.get('/interaction/:uid', async (req, res) => {
    try {
        const details = await oidc.interactionDetails(req, res);
        const { prompt: { name } } = details;

        if (name === 'login') {
            return res.send(`
        <form method="post" action="/interaction/${details.uid}/login">
          <input type="text" name="login" value="anyuser" placeholder="Enter any login" />
          <input type="password" name="password"  value="anypass" placeholder="and password" />
          <button type="submit">Sign-in</button>
        </form>
      `);
        } else if (name === 'consent') {
            return res.send(`
        <form method="post" action="/interaction/${details.uid}/confirm">
          <button type="submit">Confirm</button>
        </form>
      `);
        }
        return res.status(404).end('Interaction not supported');
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

oidcApp.post('/interaction/:uid/login', async (req, res) => {
    try {
        const result = {
            login: {
                account: req.body.login,
            },
        };
        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

oidcApp.post('/interaction/:uid/confirm', async (req, res) => {
    try {
        const result = {
            consent: {
                rejectedScopes: [],
                rejectedClaims: [],
            },
        };
        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

oidcApp.use('/oidc', oidc.callback());

// Error handling
oidcApp.use((err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error',
    });
});
if (process.env.NODE_ENV === 'dev') {
    const port = 3001;
    oidcApp.listen(port, () => {
        console.log(`OIDC Provider is listening on http://localhost:${port}`);
    });
}

export default oidcApp;