import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_ENDPOINT = 'http://localhost:4002/api/private';
const CLIENT_ID = 'my-random-client-id';
const REDIRECT_URI = 'http://localhost:3001/callback';

const App = () => {
    const [token, setToken] = useState(localStorage.getItem('access_token'));
    const [idToken, setIdToken] = useState(localStorage.getItem('id_token'));
    const [privateData, setPrivateData] = useState(null);

    useEffect(() => {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');

        if (code) {
            exchangeCodeForToken(code);
        }
    }, []);

    const exchangeCodeForToken = async (code) => {
        try {
            const response = await axios.post('http://localhost:4002/exchange', { code });
            console.log('Token exchange response:', response.data);
            const { access_token, refresh_token, expires_in, id_token } = response.data;
            setToken(access_token);
            localStorage.setItem('access_token', access_token);
            localStorage.setItem('refresh_token', refresh_token);
            setIdToken(id_token);
            localStorage.setItem('id_token', id_token);
            if (refresh_token) {
                localStorage.setItem('refresh_token', refresh_token);
            }
            setTimeout(() => refreshToken(), (expires_in - 300) * 1000);
            window.history.replaceState({}, document.title, "/");
        } catch (error) {
            console.error('Error exchanging code for token:', error.response?.data || error.message);
        }
    };

    const refreshToken = async () => {
        const refresh_token = localStorage.getItem('refresh_token');
        if (refresh_token) {
            try {
                const response = await axios.post('http://localhost:4002/refresh', { refresh_token });
                console.log('Token refresh response:', response.data);
                const { access_token, refresh_token, expires_in, id_token } = response.data;
                setToken(access_token);
                localStorage.setItem('access_token', access_token);
                localStorage.setItem('refresh_token', refresh_token);
                setIdToken(id_token);
                localStorage.setItem('id_token', id_token);
                setTimeout(() => refreshToken(), (expires_in - 300) * 1000);
            } catch (error) {
                console.error('Error refreshing token:', error.response?.data || error.message);
            }
        }
    };

    const fetchPrivateData = async (useJwks = false) => {
        try {
            const endpoint = useJwks ? `${API_ENDPOINT}JWKS` : API_ENDPOINT;
            console.log(`Fetching private data from: ${endpoint}`);
            const response = await axios.get(endpoint, {
                headers: { Authorization: `Bearer ${useJwks ? idToken : token}` },
            });
            setPrivateData(response.data);
        } catch (error) {
            console.error('Error fetching private data:', error.response?.data || error.message);
            if (error.response && error.response.status === 401) {
                alert('Your session has expired. Please log out and log in again.');
            }
        }
    };

    const fetchPrivateDataWithFakeToken = async () => {
        try {
            const response = await axios.get(API_ENDPOINT, {
                headers: { Authorization: `Bearer iamafaketoken` },
            });
            setPrivateData(response.data);
        } catch (error) {
            console.error('Error fetching private data with fake token:', error.response?.data || error.message);
            alert('As expected, the request with a fake token was rejected.');
        }
    };

    const handleLogin = () => {
        const params = new URLSearchParams({
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: 'code',
            scope: 'openid profile email offline_access'
        });

        window.location.href = `http://localhost:4000/oidc/auth?${params.toString()}`;
    };

    const handleLogout = () => {
        setToken(null);
        setIdToken(null);
        localStorage.removeItem('access_token');
        localStorage.removeItem('id_token');
        localStorage.removeItem('refresh_token');
        setPrivateData(null);
    };

    return (
        <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
            <h1 style={{ color: '#f5576c' }}>🚀 OAuth 2.0 App 2</h1>
            <p style={{ color: '#666' }}>Running on localhost:3001</p>

            {!token ? (
                <button
                    onClick={handleLogin}
                    style={{
                        padding: '10px 20px',
                        backgroundColor: '#f5576c',
                        color: 'white',
                        border: 'none',
                        borderRadius: '5px',
                        cursor: 'pointer',
                        fontSize: '16px'
                    }}
                >
                    🔑 Login with OAuth2
                </button>
            ) : (
                <div>
                    <p style={{ color: '#28a745', fontWeight: 'bold' }}>✅ You are logged in!</p>
                    <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '20px' }}>
                        <button
                            onClick={() => fetchPrivateData(false)}
                            style={{
                                padding: '8px 16px',
                                backgroundColor: '#007bff',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            📊 Fetch Data (Introspection)
                        </button>
                        <button
                            onClick={() => fetchPrivateData(true)}
                            style={{
                                padding: '8px 16px',
                                backgroundColor: '#6f42c1',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            🔐 Fetch Data (JWKS)
                        </button>
                        <button
                            onClick={() => refreshToken()}
                            style={{
                                padding: '8px 16px',
                                backgroundColor: '#28a745',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            🔄 Refresh Token
                        </button>
                        <button
                            onClick={fetchPrivateDataWithFakeToken}
                            style={{
                                padding: '8px 16px',
                                backgroundColor: '#dc3545',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            🚨 Test Fake Token
                        </button>
                        <button
                            onClick={handleLogout}
                            style={{
                                padding: '8px 16px',
                                backgroundColor: '#6c757d',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            🚪 Logout
                        </button>
                    </div>
                    {privateData && (
                        <div style={{
                            backgroundColor: '#f8f9fa',
                            padding: '15px',
                            borderRadius: '5px',
                            border: '1px solid #dee2e6'
                        }}>
                            <h3>📋 API Response:</h3>
                            <pre style={{ fontSize: '12px', overflow: 'auto' }}>
                                {JSON.stringify(privateData, null, 2)}
                            </pre>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default App;