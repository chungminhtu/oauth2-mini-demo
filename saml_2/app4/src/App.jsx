import React, { useState, useEffect } from 'react';
import axios from 'axios';

const SAML_BACKEND = 'http://localhost:4001';
const APP_NAME = 'app4';

const App = () => {
  const [samlSession, setSamlSession] = useState(null);
  const [privateData, setPrivateData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedMethod, setSelectedMethod] = useState('post');

  useEffect(() => {
    checkSamlSession();
  }, []);

  const checkSamlSession = async () => {
    try {
      const response = await axios.get(`${SAML_BACKEND}/sp/session/status`, {
        withCredentials: true
      });

      console.log('Session check response:', response.data);

      if (response.data.authenticated) {
        setSamlSession(response.data.assertion);
        console.log('✅ SAML session active:', response.data.assertion);
      } else {
        setSamlSession(null);
        console.log('❌ No active SAML session');
      }
    } catch (error) {
      console.error('Error checking SAML session:', error);
      setSamlSession(null);
    } finally {
      setLoading(false);
    }
  };

  const handleSamlLogin = (method = 'post') => {
    const returnUrl = encodeURIComponent(window.location.href);
    
    const endpoint = method === 'redirect' 
      ? '/sp/sso/initiate-redirect' 
      : '/sp/sso/initiate';
    
    window.location.href = `${SAML_BACKEND}${endpoint}?app=${APP_NAME}&returnUrl=${returnUrl}`;
  };

  const fetchPrivateData = async () => {
    try {
      setError(null);
      console.log(`🔒 Fetching private data for ${APP_NAME}...`);

      const response = await axios.get(`${SAML_BACKEND}/api/protected/${APP_NAME}`, {
        withCredentials: true
      });

      setPrivateData(response.data);
      console.log('📊 Private data received:', response.data);
    } catch (error) {
      console.error('Error fetching private data:', error);

      if (error.response?.status === 401) {
        setError('Your SAML session has expired. Please log in again.');
        setSamlSession(null);
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
      <h1>🔐 SAML 2.0 Client - App 4</h1>

      {error && (
        <div style={{ background: '#f8d7da', color: '#721c24', padding: '15px', marginBottom: '20px', border: '1px solid #f5c6cb', borderRadius: '5px' }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {!samlSession ? (
        <div>
          <p>You are not logged in with SAML.</p>
          <button
            onClick={() => handleSamlLogin('post')}
            style={{
              padding: '10px 20px',
              backgroundColor: '#007bff',
              color: 'white',
              border: 'none',
              cursor: 'pointer',
              fontSize: '16px',
              borderRadius: '5px',
              margin: '5px'
            }}
          >
            🚀 Login with SAML (POST)
          </button>
          <button
            onClick={() => handleSamlLogin('redirect')}
            style={{
              padding: '10px 20px',
              backgroundColor: '#28a745',
              color: 'white',
              border: 'none',
              cursor: 'pointer',
              fontSize: '16px',
              borderRadius: '5px',
              margin: '5px'
            }}
          >
            🔄 Login with SAML (Redirect)
          </button>
        </div>
      ) : (
        <div>
          <div style={{
            backgroundColor: '#d4edda',
            padding: '15px',
            margin: '20px 0',
            border: '1px solid #c3e6cb',
            borderRadius: '5px'
          }}>
            <h3>✅ SAML Authenticated</h3>
            <p><strong>Subject:</strong> {samlSession.subject}</p>
            <p><strong>Email:</strong> {samlSession.attributes?.email}</p>
            <p><strong>Given Name:</strong> {samlSession.attributes?.givenName}</p>
            <p><strong>Common Name:</strong> {samlSession.attributes?.cn}</p>
            <p><strong>Title:</strong> {samlSession.attributes?.title}</p>
            <p><strong>Session Index:</strong> {samlSession.sessionIndex}</p>
            <p><strong>Issuer:</strong> {samlSession.issuer}</p>
            <p><strong>Auth Method:</strong> <span style={{
              background: samlSession?.method === 'GET' ? '#28a745' : '#dc3545',
              color: 'white',
              padding: '2px 6px',
              borderRadius: '3px',
              fontSize: '12px'
            }}>{samlSession?.method || 'POST'}</span></p>

            {samlSession.attributes && (
              <details style={{ marginTop: '10px' }}>
                <summary>🔍 All User Attributes (Click to expand)</summary>
                <pre style={{ backgroundColor: '#f8f9fa', padding: '10px', fontSize: '12px', marginTop: '5px' }}>
                  {JSON.stringify(samlSession.attributes, null, 2)}
                </pre>
              </details>
            )}

            <details style={{ marginTop: '10px' }}>
              <summary>🔍 Full Session Data (Click to expand)</summary>
              <pre style={{ backgroundColor: '#f8f9fa', padding: '10px', fontSize: '12px', marginTop: '5px' }}>
                {JSON.stringify(samlSession, null, 2)}
              </pre>
            </details>
          </div>

          <div style={{ margin: '20px 0' }}>
            <button
              onClick={fetchPrivateData}
              style={{
                padding: '10px 20px',
                backgroundColor: '#28a745',
                color: 'white',
                border: 'none',
                cursor: 'pointer',
                marginRight: '10px',
                borderRadius: '5px'
              }}
            >
              📊 Fetch Private Data
            </button>

            <button
              onClick={fetchPrivateDataWithFakeToken}
              style={{
                padding: '10px 20px',
                backgroundColor: '#ffc107',
                color: 'black',
                border: 'none',
                cursor: 'pointer',
                marginRight: '10px',
                borderRadius: '5px'
              }}
            >
              🔍 Test with Fake Token
            </button>

            <button
              onClick={handleSingleLogout}
              style={{
                padding: '10px 20px',
                backgroundColor: '#dc3545',
                color: 'white',
                border: 'none',
                cursor: 'pointer',
                borderRadius: '5px'
              }}
            >
              🔐 SAML Single Logout
            </button>
          </div>

          {privateData && (
            <div style={{
              backgroundColor: '#f8f9fa',
              padding: '15px',
              margin: '20px 0',
              border: '1px solid #dee2e6',
              borderRadius: '5px'
            }}>
              <h3>📊 Private Data Response:</h3>
              <div style={{ background: 'white', padding: '10px', borderRadius: '3px' }}>
                <h4>{privateData.message}</h4>
                <p><strong>App ID:</strong> {privateData.appId}</p>
                <p><strong>Timestamp:</strong> {privateData.timestamp}</p>
                <p><strong>SAML Method:</strong> <span style={{
                  background: privateData.samlMethod === 'GET' ? '#28a745' : '#dc3545',
                  color: 'white',
                  padding: '2px 6px',
                  borderRadius: '3px',
                  fontSize: '12px'
                }}>{privateData.samlMethod || 'Unknown'}</span></p>

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
                  <pre style={{ fontSize: '12px', overflow: 'auto', marginTop: '5px' }}>
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

 
