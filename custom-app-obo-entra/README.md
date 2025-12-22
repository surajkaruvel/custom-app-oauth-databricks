# OAuth 2.0 On-Behalf-Of (OBO) Flow - Databricks & Snowflake

> ⚠️ **EXPERIMENTAL - NOT FOR PRODUCTION USE**  
> This is a demonstration application for OAuth 2.0 On-Behalf-Of flow. Use at your own risk.

## Overview

This application demonstrates the **OAuth 2.0 On-Behalf-Of (OBO) flow** with Microsoft Entra ID for accessing **Databricks** and **Snowflake** APIs. In this flow, a middle-tier service exchanges a user's token for service-specific tokens to access APIs on behalf of the user.

### Key Features

- ✅ **OBO Token Exchange**: Middle-tier exchanges user token for Databricks & Snowflake access
- ✅ **Direct API Access**: Tokens work directly with service APIs (no additional exchange)
- ✅ **Multi-Service Support**: Access both Databricks and Snowflake in the same session
- ✅ **User Context Preservation**: Maintains user identity through token delegation
- ✅ **MSAL Integration**: Uses Microsoft Authentication Library for Python
- ✅ **PKCE Support**: Implements Proof Key for Code Exchange for security
- ✅ **Databricks SQL**: Execute SQL queries on Databricks with OBO token
- ✅ **Snowflake SQL**: Execute SQL queries on Snowflake with role-based access
- ✅ **Role-Based Authentication**: Embed Snowflake roles in token scope

## Architecture

```
                                              ┌─────────────────┐
                                         ┌───→│   Databricks    │
                                         │    │     APIs        │
┌─────────────┐    ┌──────────────────┐  │    └─────────────────┘
│    User     │───→│  Middle-Tier     │──┤
│             │    │  (This App)      │  │    ┌─────────────────┐
└─────────────┘    └──────────────────┘  └───→│   Snowflake     │
                            │                 │     APIs        │
                            │                 └─────────────────┘
                            ↓ OBO Exchange
                   ┌─────────────────────┐
                   │   Microsoft Entra   │
                   │  (Token Exchange)   │
                   └─────────────────────┘
```

### Flow Steps

1. **User Authentication**: User authenticates to the middle-tier app with authorization code flow + PKCE
2. **Token Acquisition**: Middle-tier receives user's access token
3. **Service Selection**: User chooses to access Databricks or Snowflake
4. **OBO Exchange**: Middle-tier calls Entra ID to exchange the user token for a service-specific token
5. **API Access**: The OBO token works **directly** with service APIs (no additional token exchange)

## Prerequisites

1. **Microsoft Entra ID Tenant** with admin access
2. **App Registrations in Entra ID**:
   - Middle-Tier App (this application)
   - Databricks App (for Databricks OBO token scope)
   - Snowflake App (for Snowflake OBO token scope)
3. **Databricks Workspace** with federation configured (optional)
4. **Snowflake Account** with OAuth integration configured (optional)
5. **Python 3.8+** installed

## Setup Instructions

### 1. Middle-Tier App Registration (API1)

1. Create a new app registration in Entra ID
2. Set **Redirect URI**: `http://localhost:9001/callback` (Web)
3. Create a **client secret** and save it securely
4. **Expose an API**:
   - Add scope: `api://<middletier-client-id>/access_as_user`
   - Description: "Access the application on behalf of the user"
5. **API Permissions**:
   - Add delegated permission to Databricks app (created in step 2)
   - Grant admin consent

### 2. Databricks App Registration (API2)

1. Create a separate app registration for Databricks
2. **Expose an API**:
   - Add scope: `user_impersonation`
   - Description: "Access Databricks on behalf of the user"
3. Note the **Application (client) ID** - this will be used in the OBO token scope

### 3. Snowflake App Registration (API4)

1. Create a separate app registration for Snowflake
2. **Expose an API**:
   - Add scope: `session:scope:ACCOUNTADMIN` (or other role names like PUBLIC, SYSADMIN)
   - Description: "Access Snowflake with specific role on behalf of the user"
3. Note the **Application (client) ID** - this will be used in the Snowflake token scope

**Role-Based Scopes:**
- `session:scope:PUBLIC` - Basic access
- `session:scope:SYSADMIN` - System admin access
- `session:scope:ACCOUNTADMIN` - Full admin access

### 4. Configure Databricks Federation

Configure your Databricks workspace to trust tokens from your Databricks app registration:

```bash
# Example: Configure federation policy in Databricks
# This is typically done via Databricks Account Console or API
```

### 4. Configure Application

1. Copy `config.env.example` to `config.env`
2. Fill in your configuration:

```bash
# Middle-Tier App (API1)
MIDDLETIER_TENANT_ID=your-tenant-id
MIDDLETIER_CLIENT_ID=your-middletier-client-id
MIDDLETIER_CLIENT_SECRET=your-middletier-client-secret

# Databricks Scope (API2)
DATABRICKS_SCOPE=<databricks-app-client-id>/user_impersonation

# Snowflake Scope (API4) - role is embedded in scope
SNOWFLAKE_SCOPE=api://<snowflake-app-client-id>/session:scope:ACCOUNTADMIN

# App Configuration
PORT=9001
REDIRECT_URI=http://localhost:9001/callback
FLASK_SECRET_KEY=your-secure-random-secret-key
```

### 7. Install Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 8. Run Application

```bash
# Using the provided script
chmod +x run.sh
./run.sh

# Or directly with Python
python app.py
```

The application will be available at: `http://localhost:9001`

## Usage

### Accessing Databricks

1. **Navigate** to `http://localhost:9001`
2. **Authenticate** with your Microsoft credentials
3. **Click** "Databricks SQL" card on the dashboard
4. **Enter** workspace URL and warehouse ID
5. **Execute** SQL queries using the OBO token

### Accessing Snowflake

1. **Navigate** to `http://localhost:9001`
2. **Authenticate** with your Microsoft credentials
3. **Click** "Snowflake SQL" card on the dashboard
4. **Enter** Snowflake account details:
   - Account (e.g., `mycompany.us-east-1`)
   - Database (optional)
   - Schema (optional)
   - Warehouse (optional)
   - Role (optional, defaults to token scope role)
5. **Execute** SQL queries using the OBO token

## OBO Flow Details

### Token Exchange Requests

The middle-tier uses MSAL to perform OBO exchanges for each service:

**Databricks:**
```python
result = msal_app.acquire_token_on_behalf_of(
    user_assertion=middle_tier_token,
    scopes=["<databricks-app-client-id>/user_impersonation"]
)
```

**Snowflake:**
```python
result = msal_app.acquire_token_on_behalf_of(
    user_assertion=middle_tier_token,
    scopes=["api://<snowflake-app-client-id>/session:scope:ACCOUNTADMIN"]
)
```

### Key Points

- **No Additional Token Exchange**: OBO tokens work directly with service APIs
- **User Context**: Tokens maintain the user's identity and permissions
- **Role-Based Access**: Snowflake roles embedded in token scope
- **Delegated Permissions**: The middle-tier acts on behalf of the user
- **Secure**: The middle-tier never sees the user's credentials
- **Multi-Service**: Can access both services in the same session

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page - initial login screen |
| `/login` | GET | Initiate OAuth login |
| `/callback` | GET | OAuth callback handler |
| `/dashboard` | GET | Service selection dashboard |
| **Databricks** | | |
| `/sql-setup` | GET/POST | Databricks SQL interface setup |
| `/sql-interface` | GET | Databricks SQL execution interface |
| `/api/execute-sql` | POST | Execute SQL query on Databricks |
| **Snowflake** | | |
| `/snowflake-setup` | GET/POST | Snowflake SQL interface setup |
| `/snowflake-interface` | GET | Snowflake SQL execution interface |
| `/api/execute-snowflake-sql` | POST | Execute SQL query on Snowflake |
| **Common** | | |
| `/logout` | GET | Clear session and logout |

## Troubleshooting

### Databricks Issues

**OBO Exchange Fails** (`invalid_grant`)
1. Verify the middle-tier app has delegated permission to the Databricks app
2. Ensure admin consent is granted
3. Check that the Databricks scope is correctly configured
4. Verify the user token has the correct audience

**Token Works with Some APIs But Not Others**
1. Check Databricks federation policy configuration
2. Verify the OBO token has the correct scopes
3. Ensure the user has appropriate permissions in Databricks

### Snowflake Issues

**Error 390317**: "Role not listed in Access Token"
1. Enable `EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'` in SECURITY INTEGRATION
2. Grant the role to the user: `GRANT ROLE ACCOUNTADMIN TO USER "user@domain.com"`
3. Set default role: `ALTER USER "user@domain.com" SET DEFAULT_ROLE = 'ACCOUNTADMIN'`

**SSL Certificate Error** (hostname mismatch)
- Ensure Snowflake account format is correct: `mycompany.us-east-1` or full hostname
- App automatically handles both formats

**User Not Found or Authentication Fails**
1. Create user with correct LOGIN_NAME matching the `sub` claim from token
2. Ensure SECURITY INTEGRATION audience matches your Snowflake app client ID
3. Verify user has required role granted

### Session Issues

**Cookie Size Warning**
- Session stores tokens for active services
- Only one service token active at a time to stay under 4KB limit
- For production, consider Redis-based session storage

**Other Session Issues**
1. Clear browser cookies
2. Generate a new `FLASK_SECRET_KEY`
3. Check that `config.env` values are correct

## Security Considerations

⚠️ **This is a demonstration app. For production use:**

1. **Use HTTPS**: Set `SESSION_COOKIE_SECURE=True`
2. **Implement Token Refresh**: Handle token expiration properly
3. **Add Rate Limiting**: Prevent abuse of API endpoints
4. **Secure Secrets**: Use Azure Key Vault or similar for secrets
5. **Input Validation**: Validate and sanitize all user inputs
6. **Error Handling**: Don't expose sensitive information in errors
7. **Audit Logging**: Log all authentication and API access events

## References

**OAuth & Authentication:**
- [Microsoft Entra ID OBO Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow)
- [MSAL Python Documentation](https://msal-python.readthedocs.io/)

**Databricks:**
- [Databricks OAuth Documentation](https://docs.databricks.com/dev-tools/auth/oauth.html)
- [Databricks SQL Execution API](https://docs.databricks.com/api/workspace/statementexecution)

**Snowflake:**
- [Snowflake OAuth with Azure AD](https://docs.snowflake.com/en/user-guide/oauth-azure)
- [Snowflake External OAuth](https://docs.snowflake.com/en/user-guide/oauth-external)
- [Snowflake SQL API v2](https://docs.snowflake.com/en/developer-guide/sql-api/index)

## License

This is a demonstration application provided as-is with no warranties. Use at your own risk.

---

**Last Updated**: November 2024  
**Author**: Experimental OAuth Demo Project

