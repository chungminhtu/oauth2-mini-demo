import React, { useState, useEffect } from 'react';
import axios from 'axios';

const SAML_BACKEND = 'http://localhost:4003';
const APP_NAME = 'app3'; // Changed from app1 to app3

const App = () => {
  const [samlSession, setSamlSession] = useState(null);
  const [privateData, setPrivateData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkSamlSession();
  }, []);

  const checkSamlSession = async () => {
    try {
      const response = await axios.get(`${SAML_BACKEND}/saml/session/status`, {
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
    window.location.href = `${SAML_BACKEND}/saml/sso/initiate?app=${APP_NAME}&returnUrl=${encodeURIComponent(returnUrl)}`;
  };

  const initiateSAMLSLO = async () => {
    try {
      await axios.post(`${SAML_BACKEND}/saml/slo/initiate`, {}, {
        withCredentials: true
      });
      setSamlSession(null);
      setPrivateData(null);
    } catch (error) {
      console.error('Error during SAML Single Logout:', error);
    }
  };

  const fetchPrivateData = async () => {
    try {
      const response = await axios.get(`${SAML_BACKEND}/api/protected/${APP_NAME}`, {
        withCredentials: true
      });
      setPrivateData(response.data);
    } catch (error) {
      console.error('Error fetching private data:', error.response?.data || error.message);
      if (error.response && error.response.status === 401) {
        alert('Your SAML session has expired. Please log in again.');
        setSamlSession(null);
      }
    }
  };

  const testWithInvalidSession = async () => {
    try {
      const response = await axios.get(API_ENDPOINT, {
        headers: { 'Cookie': 'saml_session=invalid_session_id' }
      });
      setProtectedData(response.data);
    } catch (error) {
      console.error('Error with invalid SAML session:', error.response?.data || error.message);
      alert('As expected, the request with invalid SAML session was rejected.');
    }
  };

  if (loading) {
    return <div>Loading SAML session...</div>;
  }

  return (
    <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
      <h1>🔐 SAML 2.0 Client - App 3</h1>
      {!samlSession ? (
        <div>
          <p>Please authenticate with SAML Identity Provider</p>
          <button onClick={handleSamlLogin}>Initiate SAML SSO</button>
        </div>
      ) : (
        <div>
          <p>✅ SAML Authentication Successful!</p>
          {samlSession && (
            <div>
              <h3>SAML Assertion Details:</h3>
              <pre>{JSON.stringify(samlSession, null, 2)}</pre>
            </div>
          )}
          <button onClick={fetchPrivateData}>Access Protected Resource</button>
          <button onClick={testWithInvalidSession}>Test with Invalid Session</button>
          <button onClick={initiateSAMLSLO}>SAML Single Logout</button>
          {privateData && (
            <div>
              <h3>Protected Resource Data:</h3>
              <pre>{JSON.stringify(privateData, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default App;