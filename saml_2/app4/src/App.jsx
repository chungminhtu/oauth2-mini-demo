import React, { useState, useEffect } from 'react';
import axios from 'axios';

const SAML_BACKEND = 'http://localhost:4003';
const APP_NAME = 'app4'; // Changed from app1 to app2

const App = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [samlAssertion, setSamlAssertion] = useState(null);
  const [protectedData, setProtectedData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkSAMLSession();
  }, []);

  const checkSAMLSession = async () => {
    try {
      const response = await axios.get(`${SERVICE_PROVIDER_URL}/saml/session/status`, {
        withCredentials: true
      });
      if (response.data.authenticated) {
        setIsAuthenticated(true);
        setSamlAssertion(response.data.assertion);
      }
    } catch (error) {
      console.error('Error checking SAML session status:', error);
      setIsAuthenticated(false);
    } finally {
      setLoading(false);
    }
  };

  const initiateSAMLSSO = () => {
    window.location.href = `${SERVICE_PROVIDER_URL}/saml/sso/initiate?app=app2&returnUrl=${encodeURIComponent(window.location.href)}`;
  };

  const initiateSAMLSLO = async () => {
    try {
      await axios.post(`${SERVICE_PROVIDER_URL}/saml/slo/initiate`, {}, {
        withCredentials: true
      });
      setIsAuthenticated(false);
      setSamlAssertion(null);
      setProtectedData(null);
    } catch (error) {
      console.error('Error during SAML Single Logout:', error);
    }
  };

  const fetchProtectedDataWithAssertion = async () => {
    try {
      console.log(`Fetching protected data from: ${API_ENDPOINT}`);
      const response = await axios.get(API_ENDPOINT, {
        withCredentials: true
      });
      setProtectedData(response.data);
    } catch (error) {
      console.error('Error fetching protected data:', error.response?.data || error.message);
      if (error.response && error.response.status === 401) {
        alert('Your SAML session has expired. Please authenticate again.');
        setIsAuthenticated(false);
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
      <h1>🔐 SAML 2.0 Client - App 4</h1>  {/* Changed from App 1 to App 2 */}
      {!isAuthenticated ? (
        <div>
          <p>Please authenticate with SAML Identity Provider</p>
          <button onClick={initiateSAMLSSO}>Initiate SAML SSO</button>
        </div>
      ) : (
        <div>
          <p>✅ SAML Authentication Successful!</p>
          {samlAssertion && (
            <div>
              <h3>SAML Assertion Details:</h3>
              <pre>{JSON.stringify(samlAssertion, null, 2)}</pre>
            </div>
          )}
          <button onClick={fetchProtectedDataWithAssertion}>Access Protected Resource</button>
          <button onClick={testWithInvalidSession}>Test with Invalid Session</button>
          <button onClick={initiateSAMLSLO}>SAML Single Logout</button>
          {protectedData && (
            <div>
              <h3>Protected Resource Data:</h3>
              <pre>{JSON.stringify(protectedData, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default App;