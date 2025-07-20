import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_ENDPOINT = 'http://localhost:4001/api/protected/app3';
const SAML_BACKEND = 'http://localhost:4001';

const App = () => {
  const [authenticated, setAuthenticated] = useState(false);
  const [samlUser, setSamlUser] = useState(null);
  const [privateData, setPrivateData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkSAMLSession();
  }, []);

  const checkSAMLSession = async () => {
    try {
      const response = await axios.get(`${SAML_BACKEND}/sp/session/status`, {
        withCredentials: true
      });

      console.log('Session check response:', response.data);

      if (response.data.authenticated) {
        setAuthenticated(true);
        setSamlUser(response.data.assertion);
        console.log('✅ SAML session active:', response.data.assertion);
      } else {
        setAuthenticated(false);
        console.log('❌ No active SAML session:', response.data.reason || 'Not authenticated');
      }
    } catch (error) {
      console.error('Error checking SAML session:', error);
      setAuthenticated(false);
    } finally {
      setLoading(false);
    }
  };

  const handleSAMLLogin = () => {
    // More explicit RelayState for app3
    const returnUrl = encodeURIComponent(window.location.href);
    const loginUrl = `${SAML_BACKEND}/sp/sso/initiate?app=app3&returnUrl=${returnUrl}`;
    
    console.log('🚀 App3 initiating SAML login:', loginUrl);
    window.location.href = loginUrl;
  };

  const fetchPrivateData = async () => {
    try {
      setError(null);
      console.log(`🔒 Fetching private data from: ${API_ENDPOINT}`);

      const response = await axios.get(API_ENDPOINT, {
        withCredentials: true
      });

      setPrivateData(response.data);
      console.log('📊 Private data received:', response.data);

    } catch (error) {
      console.error('Error fetching private data:', error);

      if (error.response?.status === 401) {
        setError('Your SAML session has expired. Please log in again.');
        setAuthenticated(false);
        setSamlUser(null);
      } else {
        setError(`Failed to fetch private data: ${error.response?.data?.error || error.message}`);
      }
    }
  };

  const fetchPrivateDataWithFakeToken = async () => {
    try {
      const response = await axios.get(`${SAML_BACKEND}/api/protected/test`, {
        headers: { Authorization: `Bearer fake-saml-token` },
        withCredentials: true
      });
      setPrivateData(response.data);
    } catch (error) {
      console.error('Error with fake token:', error.response?.data || error.message);
      alert('As expected, the request with a fake token was rejected.');
    }
  };

  const handleSingleLogout = () => {
    console.log('🔐 Initiating SAML Single Logout...');
    window.location.href = `${SAML_BACKEND}/sp/slo/initiate`;
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '50px' }}>
        <h2>🔄 Checking SAML Session...</h2>
      </div>
    );
  }

  return (
    <div style={{ fontFamily: 'Arial, sans-serif', maxWidth: '800px', margin: '0 auto', padding: '20px' }}>
      <h1>🔐 SAML App 3 - Advanced Analytics</h1>

      {error && (
        <div style={{ background: '#f8d7da', color: '#721c24', padding: '15px', marginBottom: '20px', border: '1px solid #f5c6cb', borderRadius: '5px' }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {!authenticated ? (
        <div>
          <p>Please authenticate with SAML Identity Provider to access this application.</p>
          <button
            onClick={handleSAMLLogin}
            style={{
              background: '#007bff',
              color: 'white',
              padding: '10px 20px',
              border: 'none',
              cursor: 'pointer',
              fontSize: '16px',
              borderRadius: '5px'
            }}
          >
            🚀 Login with SAML
          </button>
        </div>
      ) : (
        <div>
          <div style={{ background: '#d4edda', padding: '15px', marginBottom: '20px', border: '1px solid #c3e6cb', borderRadius: '5px' }}>
            <h3>✅ SAML Authentication Successful</h3>
            <p><strong>User:</strong> {samlUser?.subject}</p>
            <p><strong>Email:</strong> {samlUser?.attributes?.email}</p>
            <p><strong>Given Name:</strong> {samlUser?.attributes?.givenName}</p>
            <p><strong>Common Name:</strong> {samlUser?.attributes?.cn}</p>
            <p><strong>Title:</strong> {samlUser?.attributes?.title}</p>
            <p><strong>Session Index:</strong> {samlUser?.sessionIndex}</p>

            {/* Debug info */}
            <details style={{ marginTop: '10px' }}>
              <summary>🔍 Debug Info (Click to expand)</summary>
              <pre style={{ fontSize: '12px', background: '#f8f9fa', padding: '10px', marginTop: '5px' }}>
                {JSON.stringify(samlUser, null, 2)}
              </pre>
            </details>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <button
              onClick={fetchPrivateData}
              style={{
                background: '#28a745',
                color: 'white',
                padding: '10px 15px',
                border: 'none',
                cursor: 'pointer',
                margin: '5px',
                borderRadius: '5px'
              }}
            >
              📊 Fetch Private Data (SAML)
            </button>

            <button
              onClick={fetchPrivateDataWithFakeToken}
              style={{
                background: '#ffc107',
                color: 'black',
                padding: '10px 15px',
                border: 'none',
                cursor: 'pointer',
                margin: '5px',
                borderRadius: '5px'
              }}
            >
              🔴 Test with Fake Token
            </button>

            <button
              onClick={handleSingleLogout}
              style={{
                background: '#dc3545',
                color: 'white',
                padding: '10px 15px',
                border: 'none',
                cursor: 'pointer',
                margin: '5px',
                borderRadius: '5px'
              }}
            >
              🌐 SAML Single Logout
            </button>
          </div>

          {privateData && (
            <div style={{ background: '#f8f9fa', padding: '15px', border: '1px solid #dee2e6', borderRadius: '5px' }}>
              <h3>📋 Private Data Response:</h3>
              <div style={{ background: 'white', padding: '10px', borderRadius: '3px' }}>
                <h4>{privateData.message}</h4>
                <p><strong>App ID:</strong> {privateData.appId}</p>
                <p><strong>Timestamp:</strong> {privateData.timestamp}</p>

                {privateData.user && (
                  <div>
                    <h5>User Info:</h5>
                    <p>Email: {privateData.user.email}</p>
                  </div>
                )}

                {privateData.attributes && (
                  <div>
                    <h5>SAML Attributes:</h5>
                    <ul>
                      {Object.entries(privateData.attributes).map(([key, value]) => (
                        <li key={key}><strong>{key}:</strong> {value}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <details style={{ marginTop: '10px' }}>
                  <summary>🔍 Full Response Data</summary>
                  <pre style={{ whiteSpace: 'pre-wrap', fontSize: '12px', marginTop: '5px' }}>
                    {JSON.stringify(privateData, null, 2)}
                  </pre>
                </details>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default App;
