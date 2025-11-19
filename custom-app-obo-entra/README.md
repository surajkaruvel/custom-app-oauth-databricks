# Databricks OAuth - On-Behalf-Of (OBO) Flow with Microsoft Entra ID

> ⚠️ **EXPERIMENTAL - NOT FOR PRODUCTION USE**  
> This is a demonstration application for OAuth 2.0 On-Behalf-Of flow. Use at your own risk.

## Overview

This application demonstrates the **OAuth 2.0 On-Behalf-Of (OBO) flow** with Microsoft Entra ID for Databricks access. In this flow, a middle-tier service exchanges a user's token for another token to access Databricks APIs on behalf of the user.

### Key Features

- ✅ **OBO Token Exchange**: Middle-tier exchanges user token for Databricks access
- ✅ **Direct API Access**: Token works directly with Databricks (no /oidc/v1/token exchange)
- ✅ **User Context Preservation**: Maintains user identity through token delegation
- ✅ **MSAL Integration**: Uses Microsoft Authentication Library for Python
- ✅ **PKCE Support**: Implements Proof Key for Code Exchange for security
- ✅ **SQL Execution**: Run SQL queries with OBO token
- ✅ **AI Assistant**: Interact with Databricks Genie using OBO token

## Architecture

```
┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐
│    User     │───→│  Middle-Tier     │───→│   Databricks    │
│             │    │  (This App)      │    │     APIs        │
└─────────────┘    └──────────────────┘    └─────────────────┘
                            │
                            ↓ OBO Exchange
                   ┌─────────────────────┐
                   │   Microsoft Entra   │
                   │  (Token Exchange)   │
                   └─────────────────────┘
```

### Flow Steps

1. **User Authentication**: User authenticates to the middle-tier app with authorization code flow + PKCE
2. **Token Acquisition**: Middle-tier receives user's access token
3. **OBO Exchange**: Middle-tier calls Entra ID to exchange the user token for a Databricks token
4. **API Access**: The OBO token works **directly** with Databricks APIs (no additional token exchange)

## Prerequisites

1. **Microsoft Entra ID Tenant** with admin access
2. **Two App Registrations in Entra ID**:
   - Middle-Tier App (this application)
   - Databricks App (for OBO token scope)
3. **Databricks Workspace** with federation configured
4. **Python 3.8+** installed

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

### 3. Configure Databricks Federation

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

# App Configuration
PORT=9001
REDIRECT_URI=http://localhost:9001/callback
FLASK_SECRET_KEY=your-secure-random-secret-key
```

### 5. Install Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 6. Run Application

```bash
# Using the provided script
chmod +x run.sh
./run.sh

# Or directly with Python
python app.py
```

The application will be available at: `http://localhost:9001`

## Usage

1. **Navigate** to `http://localhost:9001`
2. **Enter** your Databricks workspace URL
3. **Authenticate** with your Microsoft credentials
4. **Choose** SQL Interface or AI Assistant
5. **Execute** queries or chat with Genie using the OBO token

## OBO Flow Details

### Token Exchange Request

The middle-tier uses MSAL to perform the OBO exchange:

```python
result = msal_app.acquire_token_on_behalf_of(
    user_assertion=middle_tier_token,
    scopes=["<databricks-app-client-id>/user_impersonation"]
)
```

### Key Points

- **No Databricks Token Exchange**: The OBO token works directly with Databricks APIs
- **User Context**: The token maintains the user's identity and permissions
- **Delegated Permissions**: The middle-tier acts on behalf of the user
- **Secure**: The middle-tier never sees the user's credentials

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page |
| `/login` | POST | Initiate OAuth login |
| `/callback` | GET | OAuth callback handler |
| `/databricks` | GET | Interface selection page |
| `/sql-setup` | GET | SQL interface setup |
| `/sql-interface` | GET | SQL execution interface |
| `/chat-setup` | GET | AI assistant setup |
| `/chat-interface` | GET | AI chat interface |
| `/api/execute-sql` | POST | Execute SQL query |
| `/api/chat` | POST | Send message to Genie |
| `/logout` | GET | Clear session and logout |

## Troubleshooting

### OBO Exchange Fails

**Error**: `invalid_grant` or similar

**Solutions**:
1. Verify the middle-tier app has delegated permission to the Databricks app
2. Ensure admin consent is granted
3. Check that the Databricks scope is correctly configured
4. Verify the user token has the correct audience

### Token Works with Some APIs But Not Others

**Solutions**:
1. Check Databricks federation policy configuration
2. Verify the OBO token has the correct scopes
3. Ensure the user has appropriate permissions in Databricks

### Session Issues

**Solutions**:
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

- [Microsoft Entra ID OBO Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow)
- [MSAL Python Documentation](https://msal-python.readthedocs.io/)
- [Databricks OAuth Documentation](https://docs.databricks.com/dev-tools/auth/oauth.html)

## License

This is a demonstration application provided as-is with no warranties. Use at your own risk.

---

**Last Updated**: November 2024  
**Author**: Experimental OAuth Demo Project

