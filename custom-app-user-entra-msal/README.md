# Databricks OAuth with Microsoft Entra ID (MSAL)

A Flask application that authenticates users with Microsoft Entra ID (Azure AD) using **Microsoft Authentication Library (MSAL)** and exchanges tokens for Databricks workspace access. Provides SQL Analytics and AI Assistant interfaces.

## 🎯 What's Different About This Version?

This application uses **MSAL (Microsoft Authentication Library)** instead of manual OAuth implementation. Key benefits:

### MSAL Advantages

✅ **Simplified Code** - MSAL handles OAuth mechanics automatically  
✅ **Automatic PKCE** - Built-in Proof Key for Code Exchange security  
✅ **Token Caching** - Smart token management and storage  
✅ **Token Refresh** - Automatic token refresh without re-authentication  
✅ **Best Practices** - Microsoft-recommended OAuth patterns  
✅ **Error Handling** - Better error messages and debugging  
✅ **Standards Compliant** - Follows all OAuth 2.0 specifications  

### Code Comparison

**Without MSAL (Manual OAuth):**
```python
# Generate PKCE manually
code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32))
code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest())

# Build auth URL manually
auth_params = {
    'client_id': client_id,
    'response_type': 'code',
    'redirect_uri': redirect_uri,
    'scope': scope,
    'state': state,
    'nonce': nonce,
    'code_challenge': code_challenge,
    'code_challenge_method': 'S256'
}
auth_url = f"{auth_endpoint}?" + urllib.parse.urlencode(auth_params)

# Exchange code manually
token_data = {
    'grant_type': 'authorization_code',
    'client_id': client_id,
    'code': code,
    'code_verifier': code_verifier,
    # ... more parameters
}
response = requests.post(token_endpoint, data=token_data)
```

**With MSAL (This Version):**
```python
# MSAL handles everything automatically!
msal_app = msal.ConfidentialClientApplication(
    client_id=client_id,
    client_credential=client_secret,
    authority=authority
)

# Get auth URL - MSAL handles PKCE, state, nonce automatically
auth_url = msal_app.get_authorization_request_url(
    scopes=scopes,
    state=state,
    redirect_uri=redirect_uri
)

# Exchange code - MSAL handles all parameters automatically
result = msal_app.acquire_token_by_authorization_code(
    code=code,
    scopes=scopes,
    redirect_uri=redirect_uri
)
```

## Features

- 🔐 **MSAL Authentication** - Microsoft's official OAuth library
- 🔄 **Token Exchange** - Seamless conversion from Entra ID to Databricks tokens
- 🔒 **Automatic PKCE** - Enhanced OAuth 2.0 security built-in
- 📊 **SQL Interface** - Execute queries on Databricks SQL warehouses
- 🤖 **AI Chat Interface** - Interact with Databricks model serving endpoints
- ♻️ **Smart Token Management** - MSAL handles caching and refresh automatically

## Prerequisites

- Python 3.7+
- Microsoft Entra ID application registration (Web Application or SPA)
- Databricks workspace with federation configured
- SQL Warehouse ID (for SQL interface)
- Model Serving Endpoint (for AI chat interface)

## Quick Start

### 1. Configure Entra ID Application

Your Entra ID app should be configured with:
- **Application Type**: Web Application (confidential) or SPA (public)
- **Redirect URI**: `http://localhost:9001/callback`
- **Scope**: `api://{CLIENT_ID}/databricks-token-federation`
- **Client Secret**: Required for Web Apps, optional for SPAs

### 2. Set Up Configuration

Copy the example configuration file:

```bash
cp config.env.example config.env
```

Edit `config.env` with your values:

```bash
# Microsoft Entra ID Configuration
ENTRA_TENANT_ID=your-tenant-id
ENTRA_CLIENT_ID=your-client-id
ENTRA_CLIENT_SECRET=your-client-secret  # Optional for SPAs

# Application Configuration
PORT=9001
REDIRECT_URI=http://localhost:9001/callback
FLASK_SECRET_KEY=generate-a-secure-random-key

# OAuth Scope
OAUTH_SCOPE=api://your-client-id/databricks-token-federation
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install MSAL along with other dependencies.

### 4. Run the Application

```bash
./run.sh
```

Or manually:

```bash
python app.py
```

The application will start on `http://localhost:9001`

## Usage

1. Open your browser to `http://localhost:9001`
2. Enter your Databricks workspace URL
3. Click "Start Entra ID Authentication"
4. Log in with your Microsoft credentials (MSAL handles the OAuth flow)
5. Choose SQL Interface or AI Chat Interface
6. Start querying data or chatting with AI models!

## Authentication Flow

```
User → MSAL Initiates OAuth → Entra ID (Login) → Authorization Code → 
  → MSAL Exchanges Code for Token (with automatic PKCE) → 
    → Exchange for Databricks Token → 
      → Access Databricks Resources
```

## MSAL Integration Details

### Public Client (SPA)

```python
msal_app = msal.PublicClientApplication(
    client_id=client_id,
    authority=authority
)
```

- No client secret required
- PKCE automatically applied
- User-to-Machine (U2M) authentication
- Perfect for single-page applications

### Confidential Client (Web App)

```python
msal_app = msal.ConfidentialClientApplication(
    client_id=client_id,
    client_credential=client_secret,
    authority=authority
)
```

- Requires client secret
- More secure for server-side applications
- PKCE optionally applied
- Perfect for web applications

### Token Acquisition

```python
# Get authorization URL
auth_url = msal_app.get_authorization_request_url(
    scopes=['api://my-app/my-scope'],
    state=state,
    redirect_uri=redirect_uri
)

# Exchange code for token
result = msal_app.acquire_token_by_authorization_code(
    code=authorization_code,
    scopes=['api://my-app/my-scope'],
    redirect_uri=redirect_uri
)

# Token refresh (automatic with MSAL cache)
result = msal_app.acquire_token_silent(
    scopes=['api://my-app/my-scope'],
    account=accounts[0]
)
```

## Configuration Details

### Entra ID Settings

- **Tenant ID**: Your Azure AD tenant identifier
- **Client ID**: Application (client) ID from Entra ID
- **Client Secret**: Secret value (optional for public clients)
- **Scope**: Must match format: `api://{CLIENT_ID}/databricks-token-federation`

### Application Settings

- **Port**: Local port for the Flask app (default: 9001)
- **Redirect URI**: Must match the redirect URI configured in Entra ID
- **Flask Secret Key**: Used for session encryption

## API Endpoints

- `GET /` - Main landing page
- `POST /login` - Initiate OAuth flow (MSAL)
- `GET /callback` - OAuth callback handler (MSAL)
- `GET /databricks` - Interface selection page
- `GET /sql-setup` - SQL warehouse configuration
- `POST /sql-interface` - SQL query interface
- `GET /chat-setup` - AI model configuration
- `POST /chat-interface` - AI chat interface
- `POST /execute-sql` - Execute SQL queries
- `POST /send-message` - Send messages to AI models
- `GET /clear` - Clear session
- `GET /health` - Health check endpoint

## Project Structure

```
custom-app-obo-user-entra-msal/
├── app.py                  # Main Flask application with MSAL
├── config.env              # Your configuration (gitignored)
├── config.env.example      # Configuration template
├── requirements.txt        # Python dependencies (includes msal)
├── run.sh                  # Start script
├── README.md              # This file
└── templates/             # HTML templates
    ├── base.html
    ├── index.html
    ├── databricks_interface.html
    ├── sql_setup.html
    ├── sql_interface.html
    ├── chat_setup.html
    └── chat_interface.html
```

## Comparison with Manual OAuth Version

| Feature | Manual OAuth | MSAL Version |
|---------|-------------|--------------|
| **Code Complexity** | High - Manual PKCE, state, nonce | Low - MSAL handles it |
| **PKCE Implementation** | Manual SHA256 hashing | Automatic |
| **Token Caching** | Manual session management | Built-in MSAL cache |
| **Token Refresh** | Manual refresh logic | Automatic with `acquire_token_silent` |
| **Error Handling** | Custom error parsing | MSAL standardized errors |
| **Security** | Manual implementation | Microsoft best practices |
| **Maintenance** | High - Track OAuth spec changes | Low - MSAL updates automatically |
| **Testing** | Complex - Mock OAuth endpoints | Easier - Mock MSAL calls |

## Security Notes

- Never commit `config.env` to version control
- Use a strong, random `FLASK_SECRET_KEY`
- Keep your `ENTRA_CLIENT_SECRET` secure
- In production, use HTTPS and set `SESSION_COOKIE_SECURE=True`
- MSAL handles token security and storage automatically

## MSAL Benefits Summary

1. **Simplified Development**
   - Less code to write and maintain
   - Microsoft-tested implementation
   - Automatic security best practices

2. **Better Security**
   - Automatic PKCE for all flows
   - Secure token storage
   - Built-in protection against common attacks

3. **Easier Maintenance**
   - MSAL updates automatically handle spec changes
   - Better error messages and debugging
   - Comprehensive logging

4. **Production Ready**
   - Battle-tested by Microsoft
   - Used in production by thousands of apps
   - Regular security updates

## Troubleshooting

### Authentication fails with 401

- Verify your Entra ID credentials are correct
- Check that the redirect URI matches exactly in both config and Entra ID
- Ensure MSAL library is installed: `pip install msal>=1.24.0`

### Token exchange fails

- Verify Databricks federation is configured for your Entra ID tenant
- Check that the scope format is correct: `api://{CLIENT_ID}/databricks-token-federation`
- Ensure the Databricks workspace URL is correct

### MSAL import errors

- Install MSAL: `pip install msal>=1.24.0`
- Check Python version: MSAL requires Python 3.7+
- Verify virtual environment is activated

## Documentation

- [MSAL Python Documentation](https://msal-python.readthedocs.io/)
- [Microsoft Identity Platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- [OAuth 2.0 with PKCE](https://oauth.net/2/pkce/)
- [Databricks Token Federation](https://docs.databricks.com/)

## License

MIT

