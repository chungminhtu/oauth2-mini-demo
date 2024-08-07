import express from 'express';
import { Provider } from 'oidc-provider';
import bodyParser from 'body-parser';
import cors from 'cors';

const app = express();
app.use(bodyParser.json());
app.use(cors());

const configuration = {
    clients: [{
        client_id: 'my-random-client-id',
        client_secret: 'my-random-and-very-long-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
    }],
    pkce: {
        required: () => false,
    },
    claims: {
        openid: ['sub'],
        profile: ['name', 'email']
    },
    features: {
        introspection: { enabled: true },
        revocation: { enabled: true }
    },
    jwks: {
    keys: [
      {
        d: 'VEZOsY07JTFzGTqv6cC2Y32vsfChind2I_TTuvV225_-0zrSej3XLRg8iE_u0-3GSgiGi4WImmTwmEgLo4Qp3uEcxCYbt4NMJC7fwT2i3dfRZjtZ4yJwFl0SIj8TgfQ8ptwZbFZUlcHGXZIr4nL8GXyQT0CK8wy4COfmymHrrUoyfZA154ql_OsoiupSUCRcKVvZj2JHL2KILsq_sh_l7g2dqAN8D7jYfJ58MkqlknBMa2-zi5I0-1JUOwztVNml_zGrp27UbEU60RqV3GHjoqwI6m01U7K0a8Q_SQAKYGqgepbAYOA-P4_TLl5KC4-WWBZu_rVfwgSENwWNEhw8oQ',
        dp: 'E1Y-SN4bQqX7kP-bNgZ_gEv-pixJ5F_EGocHKfS56jtzRqQdTurrk4jIVpI-ZITA88lWAHxjD-OaoJUh9Jupd_lwD5Si80PyVxOMI2xaGQiF0lbKJfD38Sh8frRpgelZVaK_gm834B6SLfxKdNsP04DsJqGKktODF_fZeaGFPH0',
        dq: 'F90JPxevQYOlAgEH0TUt1-3_hyxY6cfPRU2HQBaahyWrtCWpaOzenKZnvGFZdg-BuLVKjCchq3G_70OLE-XDP_ol0UTJmDTT-WyuJQdEMpt_WFF9yJGoeIu8yohfeLatU-67ukjghJ0s9CBzNE_LrGEV6Cup3FXywpSYZAV3iqc',
        e: 'AQAB',
        kty: 'RSA',
        n: 'xwQ72P9z9OYshiQ-ntDYaPnnfwG6u9JAdLMZ5o0dmjlcyrvwQRdoFIKPnO65Q8mh6F_LDSxjxa2Yzo_wdjhbPZLjfUJXgCzm54cClXzT5twzo7lzoAfaJlkTsoZc2HFWqmcri0BuzmTFLZx2Q7wYBm0pXHmQKF0V-C1O6NWfd4mfBhbM-I1tHYSpAMgarSm22WDMDx-WWI7TEzy2QhaBVaENW9BKaKkJklocAZCxk18WhR0fckIGiWiSM5FcU1PY2jfGsTmX505Ub7P5Dz75Ygqrutd5tFrcqyPAtPTFDk8X1InxkkUwpP3nFU5o50DGhwQolGYKPGtQ-ZtmbOfcWQ',
        p: '5wC6nY6Ev5FqcLPCqn9fC6R9KUuBej6NaAVOKW7GXiOJAq2WrileGKfMc9kIny20zW3uWkRLm-O-3Yzze1zFpxmqvsvCxZ5ERVZ6leiNXSu3tez71ZZwp0O9gys4knjrI-9w46l_vFuRtjL6XEeFfHEZFaNJpz-lcnb3w0okrbM',
        q: '3I1qeEDslZFB8iNfpKAdWtz_Wzm6-jayT_V6aIvhvMj5mnU-Xpj75zLPQSGa9wunMlOoZW9w1wDO1FVuDhwzeOJaTm-Ds0MezeC4U6nVGyyDHb4CUA3ml2tzt4yLrqGYMT7XbADSvuWYADHw79OFjEi4T3s3tJymhaBvy1ulv8M',
        qi: 'wSbXte9PcPtr788e713KHQ4waE26CzoXx-JNOgN0iqJMN6C4_XJEX-cSvCZDf4rh7xpXN6SGLVd5ibIyDJi7bbi5EQ5AXjazPbLBjRthcGXsIuZ3AtQyR0CEWNSdM7EyM5TRdyZQ9kftfz9nI03guW3iKKASETqX2vh0Z8XRjyU',
        use: 'sig',
      }, {
        crv: 'P-256',
        d: 'K9xfPv773dZR22TVUB80xouzdF7qCg5cWjPjkHyv7Ws',
        kty: 'EC',
        use: 'sig',
        x: 'FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4',
        y: '_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4',
      },
    ],
  },
    ttl: {
        AccessToken: 3600,
        IdToken: 3600,
        RefreshToken: 1209600,
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

// Example login and consent views (you may want to customize these)
app.get('/interaction/:uid', async (req, res) => {
    try {
        const details = await oidc.interactionDetails(req, res);
        const { prompt: { name } } = details;

        if (name === 'login') {
            return res.send(`
        <form method="post" action="/interaction/${details.uid}/login">
          <input type="text" name="login" placeholder="Enter any login" />
          <input type="password" name="password" placeholder="and password" />
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

app.post('/interaction/:uid/login', async (req, res) => {
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

app.post('/interaction/:uid/confirm', async (req, res) => {
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

app.use('/oidc', oidc.callback());

// Error handling
app.use((err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error',
    });
});

const port = 3001;
app.listen(port, () => {
    console.log(`OIDC Provider is listening on http://localhost:${port}`);
});

export default app;