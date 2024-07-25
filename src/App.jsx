import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_ENDPOINT = 'http://localhost:3002/api/private';
const CLIENT_ID = 'my-random-client-id';
const REDIRECT_URI = 'http://localhost:3000/callback';

const App = () => {
  const [token, setToken] = useState(localStorage.getItem('access_token'));
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
      const response = await axios.post('http://localhost:3002/exchange', { code });
      const { access_token, refresh_token, expires_in } = response.data;
      setToken(access_token);
      localStorage.setItem('access_token', access_token);
      if (refresh_token) {
        localStorage.setItem('refresh_token', refresh_token);
      }
      // Set a timer to refresh the token before it expires
      setTimeout(() => refreshToken(), (expires_in - 300) * 1000);

      // Clear the URL parameters
      window.history.replaceState({}, document.title, "/");
    } catch (error) {
      console.error('Error exchanging code for token:', error);
    }
  };

  const refreshToken = async () => {
    const refresh_token = localStorage.getItem('refresh_token');
    if (refresh_token) {
      try {
        const response = await axios.post('http://localhost:3002/refresh', { refresh_token });
        const { access_token, expires_in } = response.data;
        setToken(access_token);
        localStorage.setItem('access_token', access_token);
        // Set a new timer for the next refresh
        setTimeout(() => refreshToken(), (expires_in - 300) * 1000);
      } catch (error) {
        console.error('Error refreshing token:', error);
        // Handle refresh error (e.g., logout user)
        handleLogout();
      }
    }
  };

  const fetchPrivateData = async () => {
    try {
      const response = await axios.get(API_ENDPOINT, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setPrivateData(response.data);
    } catch (error) {
      console.error('Error fetching private data:', error);
      if (error.response && error.response.status === 401) {
        handleLogout();
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
      console.error('Error fetching private data:', error);
      if (error.response && error.response.status === 401) {
        alert('Your session has expired or you dont have permission. Please log out and log in again.');
      }
    }
  };

  const handleLogin = () => {
    window.location.href = `http://localhost:3001/oidc/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=openid`;
  };

  const handleLogout = () => {
    setToken(null);
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setPrivateData(null);
  };

  return (
    <div>
      <h1>OAuth 2.0 Client</h1>
      {!token ? (
        <button onClick={handleLogin}>Login</button>
      ) : (
        <div>
          <p>You are logged in!</p>
          <button onClick={fetchPrivateDataWithFakeToken}>Fetch Private Data with fake token</button>
          <button onClick={fetchPrivateData}>Fetch Private Data</button>
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