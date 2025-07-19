import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_ENDPOINT = 'http://localhost:4001/api/protected/app3';
const SAML_BACKEND = 'http://localhost:4001';

const App = () => {
  const [authenticated, setAuthenticated] = useState(false);
  const [samlUser, setSamlUser] = useState(null);
  const [privateData, setPrivateData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkSAMLSession();
  }, []);

  const checkSAMLSession = async () => {
    try {
      const response = await axios.get(`${SAML_BACKEND}/saml/session/status`, {
        withCredentials: true
      });

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
    const returnUrl = encodeURIComponent(window.location.href);
    window.location.href = `${SAML_BACKEND}/saml/sso/initiate?app=app3&returnUrl=${returnUrl}`;
  };

  const fetchPrivateData = async () => {
    try {
      console.log(`🔒 Fetching private data from: ${API_ENDPOINT}`);
      const response = await axios.get(API_ENDPOINT, {
        withCredentials: true
      });
      setPrivateData(response.data);
      console.log('📊 Private data received:', response.data);
    } catch (error) {
      console.error('Error fetching private data:', error);
      if (error.response?.status === 401) {
        alert('Your SAML session has expired. Please log in again.');
        setAuthenticated(false);
        setSamlUser(null);
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

  const handleLogout = async () => {
    try {
      await axios.post(`${SAML_BACKEND}/saml/logout`, {}, {
        withCredentials: true
      });
      setAuthenticated(false);
      setSamlUser(null);
      setPrivateData(null);
      console.log('🚪 Logged out successfully');
    } catch (error) {
      console.error('Error during logout:', error);
    }
  };

  const handleSingleLogout = async () => {
    try {
      const response = await axios.post(`${SAML_BACKEND}/saml/slo/initiate`, {}, {
        withCredentials: true
      });

      if (response.data.globalLogoutUrl) {
        // Redirect to IdP for global logout
        window.location.href = response.data.globalLogoutUrl;
      } else {
        // Local logout only
        setAuthenticated(false);
        setSamlUser(null);
        setPrivateData(null);
      }
    } catch (error) {
      console.error('Error during single logout:', error);
      // Fallback to local logout
      handleLogout();
    }
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
              fontSize: '16px'
            }}
          >
            🚀 Login with SAML
          </button>
        </div>
      ) : (
        <div>
          <div style={{ background: '#d4edda', padding: '15px', marginBottom: '20px', border: '1px solid #c3e6cb' }}>
            <h3>✅ SAML Authentication Successful</h3>
            <p><strong>User:</strong> {samlUser?.subject}</p>
            <p><strong>Email:</strong> {samlUser?.attributes?.email}</p>
            <p><strong>Name:</strong> {samlUser?.attributes?.firstName} {samlUser?.attributes?.lastName}</p>
            <p><strong>Department:</strong> {samlUser?.attributes?.department}</p>
            <p><strong>Role:</strong> {samlUser?.attributes?.role}</p>
            <p><strong>Session Index:</strong> {samlUser?.sessionIndex}</p>
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
                margin: '5px'
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
                margin: '5px'
              }}
            >
              🔴 Test with Fake Token
            </button>

            <button
              onClick={handleLogout}
              style={{
                background: '#6c757d',
                color: 'white',
                padding: '10px 15px',
                border: 'none',
                cursor: 'pointer',
                margin: '5px'
              }}
            >
              🚪 Local Logout
            </button>

            <button
              onClick={handleSingleLogout}
              style={{
                background: '#dc3545',
                color: 'white',
                padding: '10px 15px',
                border: 'none',
                cursor: 'pointer',
                margin: '5px'
              }}
            >
              🌐 SAML Single Logout
            </button>
          </div>

          {privateData && (
            <div style={{ background: '#f8f9fa', padding: '15px', border: '1px solid #dee2e6' }}>
              <h3>📋 Private Data Response:</h3>
              <pre style={{ whiteSpace: 'pre-wrap', fontSize: '12px' }}>
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
