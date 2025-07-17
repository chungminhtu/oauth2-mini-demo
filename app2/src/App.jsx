import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_ENDPOINT = 'http://localhost:4002/api/private';
const CLIENT_ID = 'test-client-id';
const REDIRECT_URI = 'http://localhost:3001/callback';

const App = () => {
    const [token, setToken] = useState(localStorage.getItem('access_token'));
    const [idToken, setIdToken] = useState(localStorage.getItem('id_token'));
    const [privateData, setPrivateData] = useState(null);

    useEffect(() => {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');

        if (code && !token) {  // Only exchange if we don't already have a token
            exchangeCodeForToken(code);
            // Clear the URL parameters immediately to prevent reuse
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }, []); // Empty dependency array to run only once

    const exchangeCodeForToken = async (code) => {
        try {
            // Clear the URL immediately to prevent code reuse
            window.history.replaceState({}, document.title, "/");
            
            const response = await axios.post('http://localhost:4002/exchange', { 
                code,
                redirect_uri: REDIRECT_URI
            });
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
            const endpoint = useJwks ? `${API_ENDPOINT}jwks` : API_ENDPOINT;
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
            scope: 'openid profile offline_access'
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
        <div>
            <h1>OAuth 2.0 Client - App 2</h1>  
            {!token ? (
                <button onClick={handleLogin}>Login</button>
            ) : (
                <div>
                    <p>You are logged in!</p>
                    <button onClick={() => fetchPrivateData(false)}>Fetch Private Data via Introspection</button>
                    <button onClick={() => fetchPrivateData(true)}>Fetch Private Data via JWKS</button>
                    <button onClick={() => refreshToken()}>Refresh new token</button>
                    <button onClick={fetchPrivateDataWithFakeToken}>Test with Fake Token</button>
                    <button onClick={handleLogout}>Logout</button>
                    {privateData && (
                        <pre>{JSON.stringify(privateData, null, 2)}</pre>
                    )}
                </div>
            )}
        </div>
    );
};

export default App;