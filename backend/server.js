import express from 'express';
import cors from 'cors';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const app = express();
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true
}));

const OIDC_ISSUER = 'http://localhost:4000';
const CLIENT_ID = 'my-random-client-id';
const CLIENT_SECRET = 'my-random-and-very-long-client-secret';

const client = jwksClient({
    jwksUri: `${OIDC_ISSUER}/oidc/jwks`
});

const getKey = (header, callback) => {
    client.getSigningKey(header.kid, (err, key) => {
        if (err) {
            return callback(err);
        }
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
};

const verifyTokenWithJWKS = (token) => {
    return new Promise((resolve, reject) => {
        jwt.verify(token, getKey, {
            algorithms: ['RS256']
        }, (err, decoded) => {
            if (err) {
                return reject(err);
            }
            resolve(decoded);
        });
    });
};

const authenticateTokenJWKS = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    try {
        const decodedToken = await verifyTokenWithJWKS(token);
        req.user = decodedToken;
        console.log({ decodedToken });
        
        next();
    } catch (error) {
        console.error('Token validation failed:', error.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

const exchangeCodeForToken = async (code, redirect_uri) => {  // Accept redirect_uri parameter
    // Validate redirect_uri for security
    const validRedirectUris = [
        'http://localhost:3000/callback',
        'http://localhost:3001/callback'
    ];
    
    if (!validRedirectUris.includes(redirect_uri)) {
        throw new Error('Invalid redirect URI');
    }
    
    try {
        const response = await axios.post(`${OIDC_ISSUER}/oidc/token`,
            `grant_type=authorization_code&code=${code}&redirect_uri=${redirect_uri}&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}`,  // Use the passed redirect_uri
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );
        console.log("Raw response data:", response.data);
        return response.data;
    } catch (error) {
        console.error('Error exchanging code for token:', error.response?.data || error.message);
        throw error;
    }
};
 
const verifyToken = async (token) => {
    try {
        const response = await axios.get(`${OIDC_ISSUER}/oidc/.well-known/openid-configuration`);
        const config = response.data;
        const introspectionEndpoint = config.introspection_endpoint;

        const introspectionResponse = await axios.post(introspectionEndpoint,
            `token=${token}`,
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                auth: {
                    username: CLIENT_ID,
                    password: CLIENT_SECRET
                }
            }
        );

        console.log('Introspection response:', introspectionResponse.data);

        if (introspectionResponse.data.active === true) {
            return { isValid: true, tokenInfo: introspectionResponse.data };
        } else {
            console.log('Token is not active. Expiration:', introspectionResponse.data.exp);
            return { isValid: false, tokenInfo: introspectionResponse.data };
        }
    } catch (error) {
        console.error('Token introspection failed:', error.response?.data || error.message);
        return { isValid: false, error: error.message };
    }
};

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    const { isValid, tokenInfo, error } = await verifyToken(token);
    if (!isValid) {
        console.error('Token validation failed:', tokenInfo || error);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    req.user = tokenInfo;
    next();
};

app.post('/exchange', async (req, res) => {
    const { code, redirect_uri } = req.body;  // Accept redirect_uri from frontend
    
    try {
        const tokenData = await exchangeCodeForToken(code, redirect_uri);
        res.json(tokenData);
    } catch (error) {
        res.status(400).json({ error: 'Failed to exchange code for token' });
    }
});

app.post('/refresh', async (req, res) => {
    const { refresh_token } = req.body;
    try {
        const response = await axios.post(`${OIDC_ISSUER}/oidc/token`,
            `grant_type=refresh_token&refresh_token=${refresh_token}&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}`,
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );
        res.json(response.data);
    } catch (error) {
        console.error('Error refreshing token:', error.response?.data || error.message);
        res.status(400).json({ error: 'Failed to refresh token' });
    }
});

app.get('/api/privateJWKS', authenticateTokenJWKS, (req, res) => {
    res.json({ message: 'This is private data!', timestamp: new Date().toISOString(), user: req.user });
});

app.get('/api/private', authenticateToken, (req, res) => {
    res.json({ message: 'This is private data!', timestamp: new Date().toISOString(), user: req.user });
});

if (process.env.NODE_ENV === 'dev') {
    app.listen(4002, () => {
        console.log('🖥️  Shared Backend Service is running on http://localhost:4002');
    });
}

export default app;
