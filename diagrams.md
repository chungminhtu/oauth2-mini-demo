
### Diagram 1: Login and Token Exchange

```mermaid
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
    OIDCProvider->>BackendServer: Access Token, Refresh Token, ID Token
    BackendServer->>ReactApp: Access Token, Refresh Token, ID Token
    ReactApp->>ReactApp: Store Tokens
```

### Diagram 2: Accessing Protected Resources with Introspection Token Verification

```mermaid
sequenceDiagram
    participant User
    participant ReactApp as React App (Client)
    participant BackendServer as Backend Server
    participant OIDCProvider as OIDC Provider

    User->>ReactApp: Requests Protected Resource
    ReactApp->>BackendServer: GET /api/private (with Access Token)
    BackendServer->>OIDCProvider: POST /oidc/introspect (Access Token)
    OIDCProvider->>BackendServer: Token Info (active: true/false)
    alt Token is valid
        BackendServer->>ReactApp: Private Data
    else Token is invalid
        BackendServer->>ReactApp: 401 Unauthorized
    end
```

### Diagram 3: Accessing Protected Resources with JWKS Token Verification

```mermaid
sequenceDiagram
    participant User
    participant ReactApp as React App (Client)
    participant BackendServer as Backend Server
    participant OIDCProvider as OIDC Provider

    User->>ReactApp: Requests Protected Resource
    ReactApp->>BackendServer: GET /api/privateJWKS (with ID Token)
    BackendServer->>BackendServer: Check JWKS Cache
    alt JWKS is cached
        BackendServer->>BackendServer: Use cached JWKS
    else JWKS not cached
        BackendServer->>OIDCProvider: GET /oidc/jwks
        OIDCProvider->>BackendServer: JWKS
        BackendServer->>BackendServer: Cache JWKS
    end
    BackendServer->>BackendServer: Verify ID Token Signature using JWKS
    alt Signature is valid
        BackendServer->>ReactApp: Private Data
    else Signature is invalid
        BackendServer->>ReactApp: 401 Unauthorized
    end
```

### Diagram 4: Refresh Token Flow

```mermaid
sequenceDiagram
    participant User
    participant ReactApp as React App (Client)
    participant BackendServer as Backend Server
    participant OIDCProvider as OIDC Provider

    User->>ReactApp: Accesses Resource After Token Expiry
    ReactApp->>BackendServer: GET /api/private (with Access Token)
    BackendServer->>OIDCProvider: POST /oidc/introspect (Access Token)
    OIDCProvider->>BackendServer: Token Info (active: true/false)
    alt Token is invalid
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
    else Token is valid
        BackendServer->>ReactApp: Private Data
    end
```
