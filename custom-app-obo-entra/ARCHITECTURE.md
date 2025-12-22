# On-Behalf-Of (OBO) Flow Architecture

## Overview

This document explains the OAuth 2.0 On-Behalf-Of (OBO) flow implementation for **Databricks** and **Snowflake** access using Microsoft Entra ID. The middle-tier service exchanges user tokens for service-specific tokens to access APIs on behalf of the user.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    Multi-Service OBO Flow Architecture                    │
└──────────────────────────────────────────────────────────────────────────┘

┌─────────────┐                ┌──────────────────┐                ┌─────────────────┐
│             │   Step 1       │                  │   Step 2       │                 │
│    User     │ ─────────────→ │  Middle-Tier     │ ─────────────→ │ Microsoft Entra │
│  (Browser)  │  Auth Code     │  Service (API1)  │  OBO Request   │      ID         │
│             │ ←───────────── │                  │ ←───────────── │                 │
│             │   Redirect     │  This Flask App  │  OBO Token     │                 │
└─────────────┘                └──────────────────┘                └─────────────────┘
                                        │                                    
                                        │ Step 3                             
                                        │ (Tokens work directly!)            
                                        ↓                                    
                     ┌──────────────────┴──────────────────┐
                     │                                      │
              ┌──────▼──────────┐                  ┌───────▼────────┐
              │   Databricks    │                  │   Snowflake    │
              │     APIs        │                  │     APIs       │
              │  (SQL Execution)│                  │  (SQL API v2)  │
              └─────────────────┘                  └────────────────┘
                     ▲                                      ▲
                     │                                      │
         Federation Policy                      Security Integration
         (Trusts Entra API2)                    (Trusts Entra API4)
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
- **Permissions**: Delegated permission to Databricks and Snowflake apps

#### Databricks App (API2)
- **Purpose**: Target resource for Databricks OBO token
- **Client ID**: `your-databricks-client-id`
- **Exposed API**: `{client_id}/user_impersonation`
- **Federation**: Configured in Databricks workspace

#### Snowflake App (API4)
- **Purpose**: Target resource for Snowflake OBO token
- **Client ID**: `your-snowflake-client-id`
- **Exposed API**: `api://{client_id}/session:scope:ACCOUNTADMIN` (or other roles)
- **Integration**: SECURITY INTEGRATION configured in Snowflake account

### Token Types

#### Middle-Tier Token (API1)
- **Audience**: `api://your-middletier-client-id`
- **Scope**: `access_as_user`
- **Purpose**: Represents user's authentication to middle-tier
- **Usage**: Exchanged for service-specific OBO tokens

#### Databricks OBO Token (API2)
- **Audience**: `your-databricks-client-id`
- **Scope**: `user_impersonation`
- **Purpose**: Enables middle-tier to access Databricks on behalf of user
- **Usage**: Works **directly** with Databricks APIs (no additional exchange)

#### Snowflake OBO Token (API4)
- **Audience**: `api://your-snowflake-client-id`
- **Scope**: `session:scope:ACCOUNTADMIN` (or other role)
- **Purpose**: Enables middle-tier to access Snowflake on behalf of user with specified role
- **Usage**: Works **directly** with Snowflake SQL API v2
- **Role**: Embedded in token scope for automatic role assumption

## Security Model

### User Context Preservation

The OBO flow maintains the user's identity through the token chain:
- Original token contains user's `sub` (subject) claim
- OBO tokens inherit the `sub` claim
- Services (Databricks, Snowflake) see the original user, not the middle-tier service
- User's permissions apply to all operations
- Each service token is scoped only to that service

### Consent and Permissions

1. **User Consent**: User must consent to allow middle-tier to access services
2. **Delegated Permissions**: Middle-tier must have delegated permission to each service app
3. **Admin Consent**: Typically required for delegated permissions
4. **Scope Limitation**: Each OBO token is scoped only to its target service
5. **Service Isolation**: Databricks token cannot access Snowflake and vice versa

### Token Lifecycle

```
┌────────────────────────────────────────────────────────────────┐
│                      Token Lifecycle                            │
└────────────────────────────────────────────────────────────────┘

                    ┌─── Middle-Tier Token (3600s) ───┐
                    │                                  │
User Auth ──────────┤                                  ├─── Store in session
                    │                                  │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
            OBO Exchange (Databricks)     OBO Exchange (Snowflake)
                    │                             │
                    ↓                             ↓
          Databricks Token (3600s)      Snowflake Token (3600s)
                    │                             │
                    │                             │
          Works with Databricks APIs    Works with Snowflake APIs
```

## Comparison to Other Flows

### OBO vs Direct Service OAuth

| Aspect | OBO Flow | Direct OAuth |
|--------|----------|--------------|
| **User Experience** | Authenticate to middle-tier | Authenticate to each service |
| **Token Exchange** | Via Entra ID OBO | Via service /oidc/v1/token |
| **API Access** | Direct with OBO token | Direct with service token |
| **Middle-Tier** | Required | Optional |
| **Multi-Service** | Single auth for multiple services | Separate auth per service |
| **Complexity** | Higher (multiple app registrations) | Lower per service |
| **Use Case** | Multi-tier/multi-service architecture | Single-tier applications |

### Key Advantages of OBO Flow

1. **Single Sign-On**: User authenticates once, accesses multiple services
2. **No Service Token Exchange**: OBO tokens work directly (no `/oidc/v1/token` for Databricks)
3. **User Context**: Identity maintained through token delegation
4. **Credential Security**: User never authenticates directly to downstream services
5. **Flexibility**: Middle-tier can add business logic, rate limiting, etc.
6. **Role-Based Access**: Snowflake roles embedded in token scope

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

# Step 3: OBO exchange for Databricks
databricks_result = msal_app.acquire_token_on_behalf_of(
    user_assertion=result['access_token'],
    scopes=[f"{databricks_client_id}/user_impersonation"]
)

# Step 4: OBO exchange for Snowflake (when needed)
snowflake_result = msal_app.acquire_token_on_behalf_of(
    user_assertion=result['access_token'],
    scopes=[f"api://{snowflake_client_id}/session:scope:ACCOUNTADMIN"]
)
```

### Session Management

```python
# Store middle-tier token for future OBO exchanges
session['middle_tier_token'] = result['access_token']
session['user_email'] = result.get('id_token_claims', {}).get('preferred_username')

# Store service-specific tokens (on-demand when user accesses service)
session['databricks_token'] = databricks_result['access_token']
session['databricks_expires_at'] = (datetime.now() + timedelta(seconds=expires_in)).isoformat()

session['snowflake_token'] = snowflake_result['access_token']
session['snowflake_expires_at'] = (datetime.now() + timedelta(seconds=expires_in)).isoformat()

# Clear temporary data
session.pop('oauth_state', None)

# Note: For cookie size optimization, remove middle_tier_token after OBO exchanges
# or implement server-side session storage (Redis) for production
```

## Troubleshooting Guide

### Common Issues

#### 1. OBO Exchange Fails with `invalid_grant`

**Causes**:
- Missing delegated permission from middle-tier to service app
- Admin consent not granted
- Incorrect scope format

**Solutions**:
- Verify delegated permission exists in middle-tier app
- Grant admin consent for all required API permissions
- Ensure Databricks scope: `{databricks_client_id}/user_impersonation`
- Ensure Snowflake scope: `api://{snowflake_client_id}/session:scope:ACCOUNTADMIN`

#### 2. Databricks: Token Works But API Calls Fail

**Causes**:
- Databricks federation not configured
- Audience mismatch
- User lacks permissions in Databricks

**Solutions**:
- Configure federation policy in Databricks
- Verify token audience matches Databricks app ID
- Check user permissions in Databricks workspace

#### 3. Snowflake: Error 390317 (Role Not in Access Token)

**Causes**:
- SECURITY INTEGRATION missing `EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'`
- User not mapped correctly in Snowflake
- Role not granted to user

**Solutions**:
```sql
-- Enable role mode
ALTER SECURITY INTEGRATION entra_oauth SET 
  EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE';

-- Grant role to user
GRANT ROLE ACCOUNTADMIN TO USER "user@domain.com";

-- Set default role
ALTER USER "user@domain.com" SET DEFAULT_ROLE = 'ACCOUNTADMIN';
```

#### 4. Snowflake: Error 390194 (No Default Role)

**Solution**: Either set a default role in Snowflake, or use role-based scope (recommended)

#### 5. Session Cookie Too Large Warning

**Causes**:
- Multiple large JWT tokens stored in session (middle-tier + databricks + snowflake)
- Cookie size exceeds 4093 byte browser limit

**Solutions**:
- Remove middle-tier token after OBO exchanges
- Only store one service token at a time (swap when switching services)
- Implement server-side session storage (Redis) for production

#### 6. User Gets Consent Screen Every Time

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

