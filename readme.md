sequenceDiagram
    participant User
    participant ReactApp as React App (Client)
    participant BackendServer as Backend Server
    participant OIDCProvider as OIDC Provider

    User->>ReactApp: Clicks Login
    ReactApp->>OIDCProvider: Redirect to /oidc/auth
    OIDCProvider->>User: Present Login Form
    User->>OIDCProvider: Enter Credentials
    OIDCProvider->>ReactApp: Redirect with Authorization Code
    ReactApp->>BackendServer: POST /exchange (code)
    BackendServer->>OIDCProvider: POST /oidc/token (code, client_id, client_secret)
    OIDCProvider->>BackendServer: Access Token, Refresh Token
    BackendServer->>ReactApp: Access Token, Refresh Token
    ReactApp->>ReactApp: Store Tokens

    Note over ReactApp,BackendServer: Later, when accessing private data

    ReactApp->>BackendServer: GET /api/private (with Access Token)
    BackendServer->>OIDCProvider: POST /oidc/introspect (Access Token)
    OIDCProvider->>BackendServer: Token Info (active: true/false)
    alt Token is valid
        BackendServer->>ReactApp: Private Data
    else Token is invalid
        BackendServer->>ReactApp: 401 Unauthorized
        ReactApp->>BackendServer: POST /refresh (with Refresh Token)
        BackendServer->>OIDCProvider: POST /oidc/token (refresh_token, client_id, client_secret)
        OIDCProvider->>BackendServer: New Access Token
        BackendServer->>ReactApp: New Access Token
        ReactApp->>ReactApp: Store New Access Token
        ReactApp->>BackendServer: Retry GET /api/private (with New Access Token)
        BackendServer->>OIDCProvider: POST /oidc/introspect (New Access Token)
        OIDCProvider->>BackendServer: Token Info (active: true)
        BackendServer->>ReactApp: Private Data
    end