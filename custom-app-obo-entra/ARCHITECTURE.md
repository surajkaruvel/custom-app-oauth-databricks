# On-Behalf-Of (OBO) Flow Architecture

## Overview

This document explains the OAuth 2.0 On-Behalf-Of (OBO) flow implementation for Databricks access using Microsoft Entra ID.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         OBO Flow Architecture                             │
└──────────────────────────────────────────────────────────────────────────┘

┌─────────────┐                ┌──────────────────┐                ┌─────────────────┐
│             │   Step 1       │                  │   Step 2       │                 │
│    User     │ ─────────────→ │  Middle-Tier     │ ─────────────→ │ Microsoft Entra │
│  (Browser)  │  Auth Code     │  Service (API1)  │  OBO Request   │      ID         │
│             │ ←───────────── │                  │ ←───────────── │                 │
│             │   Redirect     │  This Flask App  │  OBO Token     │                 │
└─────────────┘                └──────────────────┘                └─────────────────┘
                                        │                                    │
                                        │ Step 3                             │
                                        │ (Token works directly!)            │
                                        ↓                                    │
                                ┌──────────────────┐                        │
                                │                  │                        │
                                │   Databricks     │                        │
                                │     APIs         │                        │
                                │  (SQL, Genie)    │                        │
                                └──────────────────┘                        │
                                                                             │
                                        Federation Policy                   │
                                        (Trusts API2)                        │
                                        ←────────────────────────────────────┘
```

## Flow Sequence

### Step 1: User Authentication (Authorization Code + PKCE)

**Participants**: User Browser, Middle-Tier Service, Entra ID

1. User navigates to the middle-tier application
2. User clicks "Authenticate"
3. Middle-tier generates PKCE code verifier and challenge
4. Middle-tier redirects user to Entra ID authorization endpoint:
   ```
   https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize
   ?client_id={middletier_client_id}
   &response_type=code
   &redirect_uri=http://localhost:9001/callback
   &scope=openid profile api://{middletier_client_id}/access_as_user
   &state={random_state}
   &code_challenge={code_challenge}
   &code_challenge_method=S256
   ```
5. User authenticates with Microsoft credentials
6. Entra ID redirects back with authorization code:
   ```
   http://localhost:9001/callback?code={auth_code}&state={state}
   ```
7. Middle-tier exchanges authorization code for access token:
   ```
   POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
   Content-Type: application/x-www-form-urlencoded
   
   grant_type=authorization_code
   &client_id={middletier_client_id}
   &client_secret={middletier_client_secret}
   &code={auth_code}
   &redirect_uri=http://localhost:9001/callback
   &code_verifier={code_verifier}
   ```
8. Entra ID returns access token for middle-tier (API1):
   ```json
   {
     "access_token": "eyJ0eXAi...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "scope": "openid profile api://{middletier_client_id}/access_as_user"
   }
   ```

### Step 2: On-Behalf-Of Token Exchange

**Participants**: Middle-Tier Service, Entra ID

9. Middle-tier initiates OBO token exchange for Databricks access:
   ```
   POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
   Content-Type: application/x-www-form-urlencoded
   
   grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
   &client_id={middletier_client_id}
   &client_secret={middletier_client_secret}
   &assertion={middle_tier_access_token}
   &requested_token_use=on_behalf_of
   &scope={databricks_client_id}/user_impersonation
   ```

10. Entra ID validates:
    - Middle-tier app credentials
    - User's consent for delegation
    - Delegated permission from middle-tier to Databricks app
    - User's token validity

11. Entra ID returns OBO token for Databricks (API2):
    ```json
    {
      "access_token": "eyJ0eXAi...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "{databricks_client_id}/user_impersonation"
    }
    ```

**Key Token Claims**:
- `aud`: Databricks app client ID (your-databricks-client-id)
- `iss`: https://login.microsoftonline.com/{tenant}/v2.0
- `scp`: user_impersonation
- `sub`: User's unique identifier (preserved from original token)

### Step 3: Direct Databricks API Access

**Participants**: Middle-Tier Service, Databricks

12. Middle-tier stores OBO token in session
13. User navigates to SQL or AI Assistant interface
14. Middle-tier makes API calls to Databricks with OBO token:
    ```
    POST https://{workspace}.cloud.databricks.com/api/2.0/sql/statements
    Authorization: Bearer {obo_token}
    Content-Type: application/json
    
    {
      "statement": "SELECT * FROM table",
      "warehouse_id": "abc123"
    }
    ```

15. Databricks validates token:
    - Checks issuer matches federation policy
    - Verifies audience matches configured app ID
    - Validates signature and expiration
    - Extracts user context

16. Databricks executes query with user's permissions
17. Returns results to middle-tier
18. Middle-tier displays results to user

## Key Components

### App Registrations

#### Middle-Tier App (API1)
- **Purpose**: Authenticates users and acts as OBO client
- **Client ID**: `your-middletier-client-id`
- **Redirect URI**: `http://localhost:9001/callback`
- **Exposed API**: `api://{client_id}/access_as_user`
- **Permissions**: Delegated permission to Databricks app

#### Databricks App (API2)
- **Purpose**: Target resource for OBO token
- **Client ID**: `your-databricks-client-id`
- **Exposed API**: `{client_id}/user_impersonation`
- **Federation**: Configured in Databricks workspace

### Token Types

#### Middle-Tier Token (API1)
- **Audience**: `api://your-middletier-client-id`
- **Scope**: `access_as_user`
- **Purpose**: Represents user's authentication to middle-tier

#### OBO Token (API2)
- **Audience**: `your-databricks-client-id`
- **Scope**: `user_impersonation`
- **Purpose**: Enables middle-tier to access Databricks on behalf of user
- **Usage**: Works **directly** with Databricks APIs (no additional exchange)

## Security Model

### User Context Preservation

The OBO flow maintains the user's identity through the token chain:
- Original token contains user's `sub` (subject) claim
- OBO token inherits the `sub` claim
- Databricks sees the original user, not the middle-tier service
- User's permissions apply to all operations

### Consent and Permissions

1. **User Consent**: User must consent to allow middle-tier to access Databricks
2. **Delegated Permission**: Middle-tier must have delegated permission to Databricks app
3. **Admin Consent**: Typically required for delegated permissions
4. **Scope Limitation**: OBO token is scoped only to Databricks access

### Token Lifecycle

```
┌────────────────────────────────────────────────────────────────┐
│                      Token Lifecycle                            │
└────────────────────────────────────────────────────────────────┘

User Auth → Middle-Tier Token (3600s) → OBO Exchange → OBO Token (3600s)
                    │                                        │
                    │                                        │
              Refresh Token                          Refresh Token
              (if requested)                         (if requested)
                    │                                        │
                    ↓                                        ↓
              Token Refresh                          Token Refresh
              (transparent)                          (via OBO again)
```

## Comparison to Other Flows

### OBO vs Direct Databricks OAuth

| Aspect | OBO Flow | Direct OAuth |
|--------|----------|--------------|
| **User Experience** | Authenticate to middle-tier | Authenticate to Databricks |
| **Token Exchange** | Via Entra ID OBO | Via Databricks /oidc/v1/token |
| **API Access** | Direct with OBO token | Direct with Databricks token |
| **Middle-Tier** | Required | Optional |
| **Complexity** | Higher (2 app registrations) | Lower (1 app registration) |
| **Use Case** | Multi-tier architecture | Single-tier applications |

### Key Differences

1. **No Databricks Token Exchange**: OBO token works directly, unlike direct OAuth which requires `/oidc/v1/token` exchange
2. **User Context**: Maintained through token delegation
3. **Credential Security**: User never authenticates directly to Databricks
4. **Flexibility**: Middle-tier can add business logic, rate limiting, etc.

## Implementation Details

### MSAL Usage

```python
# Create confidential client
msal_app = msal.ConfidentialClientApplication(
    client_id=config.client_id,
    authority=config.authority,
    client_credential=config.client_secret
)

# Step 1: Build auth URL
auth_url = msal_app.get_authorization_request_url(
    scopes=["openid", "profile", f"api://{client_id}/access_as_user"],
    state=random_state,
    redirect_uri=redirect_uri,
    code_challenge=code_challenge,
    code_challenge_method='S256'
)

# Step 2: Exchange auth code
result = msal_app.acquire_token_by_authorization_code(
    code=auth_code,
    scopes=scopes,
    redirect_uri=redirect_uri,
    code_verifier=code_verifier
)

# Step 3: OBO exchange
obo_result = msal_app.acquire_token_on_behalf_of(
    user_assertion=result['access_token'],
    scopes=[f"{databricks_client_id}/user_impersonation"]
)
```

### Session Management

```python
# Store only essential tokens
session['databricks_token'] = obo_result['access_token']
session['refresh_token'] = obo_result.get('refresh_token')
session['expires_at'] = (datetime.now() + timedelta(seconds=expires_in)).isoformat()

# Clear temporary data
session.pop('oauth_state', None)
session.pop('code_verifier', None)
```

## Troubleshooting Guide

### Common Issues

#### 1. OBO Exchange Fails with `invalid_grant`

**Causes**:
- Missing delegated permission from middle-tier to Databricks app
- Admin consent not granted
- Incorrect scope format

**Solutions**:
- Verify delegated permission exists in middle-tier app
- Grant admin consent
- Ensure scope is `{databricks_client_id}/user_impersonation`

#### 2. Token Works But API Calls Fail

**Causes**:
- Databricks federation not configured
- Audience mismatch
- User lacks permissions in Databricks

**Solutions**:
- Configure federation policy in Databricks
- Verify token audience matches Databricks app ID
- Check user permissions in Databricks workspace

#### 3. User Gets Consent Screen Every Time

**Causes**:
- Refresh token not stored/used
- Session cleared too frequently

**Solutions**:
- Store refresh token in session
- Implement token refresh logic
- Adjust session lifetime

## Best Practices

1. **Token Refresh**: Implement refresh token logic to avoid re-authentication
2. **Error Handling**: Catch and handle OBO-specific errors gracefully
3. **Logging**: Log OBO exchanges for debugging (without token values)
4. **Security**: Never log or expose actual token values
5. **Expiration**: Check token expiration before API calls
6. **User Context**: Preserve user identity through the token chain

## References

- [Microsoft OBO Flow Documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow)
- [MSAL Python OBO](https://msal-python.readthedocs.io/en/latest/#msal.ClientApplication.acquire_token_on_behalf_of)
- [Databricks OAuth](https://docs.databricks.com/dev-tools/auth/oauth.html)

---

**Last Updated**: November 2024

