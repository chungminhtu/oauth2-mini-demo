import React, { useState, useEffect } from 'react';
import axios from 'axios';

const SAML_BACKEND = 'http://localhost:4001';
const APP_NAME = 'app4';

const App = () => {
  const [samlSession, setSamlSession] = useState(null);
  const [privateData, setPrivateData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkSamlSession();
  }, []);

  const checkSamlSession = async () => {
    try {
      const response = await axios.get(`${SAML_BACKEND}/sp/session/status`, {
        withCredentials: true
      });

      if (response.data.authenticated) {
        setSamlSession(response.data.assertion);
      }
    } catch (error) {
      console.log('No SAML session found');
    } finally {
      setLoading(false);
    }
  };

  const handleSamlLogin = () => {
    const returnUrl = window.location.origin;
    window.location.href = `${SAML_BACKEND}/sp/sso/initiate?app=${APP_NAME}&returnUrl=${encodeURIComponent(returnUrl)}`;
  };

  const fetchPrivateData = async () => {
    try {
      const response = await axios.get(`${SAML_BACKEND}/api/protected/${APP_NAME}`, {
        withCredentials: true
      });
      setPrivateData(response.data);
    } catch (error) {
      console.error('Error fetching private data:', error);
      if (error.response && error.response.status === 401) {
        alert('Your SAML session has expired. Please log in again.');
        setSamlSession(null);
      }
    }
  };

  const fetchPrivateDataWithFakeToken = async () => {
    try {
      const response = await axios.get(`${SAML_BACKEND}/api/protected/test`, {
        headers: { Authorization: `Bearer fake-saml-token` },
      });
      setPrivateData(response.data);
    } catch (error) {
      console.error('Error with fake token:', error.response?.data || error.message);
      alert('As expected, the request with a fake token was rejected.');
    }
  };

  // CORRECTED logout functions for App4
  const handleLogout = async () => {
    try {
      await axios.get(`${SAML_BACKEND}/sp/logout`, {
        withCredentials: true
      });
      // App4 uses this state variable:
      setSamlSession(null);
      setPrivateData(null);
      console.log('✅ Local logout successful');
    } catch (error) {
      console.error('Error during logout:', error);
    }
  };

  const handleSingleLogout = () => {
    console.log('🔐 Initiating SAML Single Logout...');
    window.location.href = `${SAML_BACKEND}/sp/slo/initiate`;
  };
  
  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
      <h1>🔐 SAML 2.0 Client - App 4</h1>

      {!samlSession ? (
        <div>
          <p>You are not logged in with SAML.</p>
          <button
            onClick={handleSamlLogin}
            style={{
              padding: '10px 20px',
              backgroundColor: '#007bff',
              color: 'white',
              border: 'none',
              cursor: 'pointer'
            }}
          >
            🚀 Login with SAML
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
            <p><strong>Session Index:</strong> {samlSession.sessionIndex}</p>
            <p><strong>Issuer:</strong> {samlSession.issuer}</p>

            {samlSession.attributes && (
              <div>
                <h4>👤 User Attributes:</h4>
                <pre style={{ backgroundColor: '#f8f9fa', padding: '10px', fontSize: '12px' }}>
                  {JSON.stringify(samlSession.attributes, null, 2)}
                </pre>
              </div>
            )}
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
                marginRight: '10px'
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
                marginRight: '10px'
              }}
            >
              🔍 Test with Fake Token
            </button>

            <button
              onClick={handleLogout}
              style={{
                padding: '10px 20px',
                backgroundColor: '#6c757d',
                color: 'white',
                border: 'none',
                cursor: 'pointer',
                marginRight: '10px'
              }}
            >
              🚪 Local Logout
            </button>

            <button
              onClick={handleSingleLogout}
              style={{
                padding: '10px 20px',
                backgroundColor: '#dc3545',
                color: 'white',
                border: 'none',
                cursor: 'pointer'
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
