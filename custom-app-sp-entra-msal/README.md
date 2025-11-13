# Databricks OAuth with Service Principal (MSAL)

A Flask application that authenticates using **Service Principal (Application)** credentials with Microsoft Authentication Library (MSAL) and exchanges tokens for Databricks workspace access.

## 🎯 What Makes This Different?

This application uses **Service Principal** authentication - a **NON-INTERACTIVE** flow perfect for:
- 🤖 Automation & Scripts
- 🔧 Backend Services & APIs
- 🚀 CI/CD Pipelines
- 📊 Data Processing Jobs
- ⏰ Scheduled Tasks

**NO USER LOGIN REQUIRED** - Authenticates automatically using app credentials!

## Key Features

- 🔐 **Service Principal Auth** - Client Credentials Flow with MSAL
- ⚡ **Non-Interactive** - No browser redirect, instant authentication
- 🔄 **Long-Lived Tokens** - ~24 hour expiry (vs ~1 hour for user tokens)
- 📊 **SQL Interface** - Execute queries on Databricks SQL warehouses
- 🤖 **AI Chat Interface** - Interact with Databricks model serving endpoints
- 🔧 **Automation Ready** - Perfect for scripts and pipelines

## Authentication Flow Comparison

| Feature | Service Principal (This App) | User Authentication |
|---------|------------------------------|---------------------|
| **Interaction** | None (Automatic) | Required (Browser Login) |
| **MSAL Method** | `acquire_token_for_client()` | `acquire_token_by_authorization_code()` |
| **Flow Type** | Client Credentials | Authorization Code + PKCE |
| **Token Lifetime** | ~24 hours | ~1 hour |
| **Identity** | Application ID | User email/name |
| **Use Case** | Automation, Services | Interactive Apps |
| **Redirect URI** | Not needed | Required |
| **PKCE** | Not needed | Required |

## Prerequisites

- Python 3.7+
- **Service Principal** in Microsoft Entra ID (Azure AD)
- Service Principal **Client Secret**
- Databricks workspace with federation configured
- SQL Warehouse ID (for SQL interface)
- Model Serving Endpoint (for AI chat interface)

## Quick Start

### 1. Create Service Principal in Entra ID

#### Step 1: Register Application
```bash
# In Azure Portal
1. Go to Azure Active Directory → App registrations
2. Click "New registration"
3. Name: "Databricks Service Principal"
4. Supported account types: Single tenant
5. Redirect URI: Leave blank (not needed for SP)
6. Click "Register"
```

#### Step 2: Generate Client Secret
```bash
1. Go to "Certificates & secrets"
2. Click "New client secret"
3. Description: "Databricks SP Secret"
4. Expires: 24 months
5. Click "Add"
6. **COPY THE SECRET VALUE IMMEDIATELY** (you won't see it again!)
```

#### Step 3: Note Down Credentials
```bash
# Save these values:
Tenant ID: ________________________________________
Client ID (Application ID): ________________________
Client Secret: _____________________________________
```

#### Step 4: Expose API Scope (if not already done)
```bash
1. Go to "Expose an API"
2. Click "Add a scope"
3. Application ID URI: Accept default or set custom
4. Scope name: databricks-token-federation
5. Who can consent: Admins only
6. Save
```

### 2. Configure Databricks Federation

```bash
# In Databricks workspace settings
1. Go to Settings → Identity and access → OAuth
2. Add your Service Principal:
   Issuer: https://login.microsoftonline.com/{TENANT_ID}/v2.0
   Audience: {CLIENT_ID}
```

### 3. Set Up Application

```bash
# Clone or navigate to directory
cd /path/to/custom-app-sp-entra-msal

# Copy configuration template
cp config.env.example config.env

# Edit config.env with your Service Principal credentials
```

**config.env:**
```bash
SP_TENANT_ID=your-tenant-id
SP_CLIENT_ID=your-service-principal-app-id
SP_CLIENT_SECRET=your-service-principal-secret

PORT=9001
FLASK_SECRET_KEY=generate-a-secure-random-key
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the Application

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
3. Click "Authenticate with Service Principal"
4. **Instant authentication** - no browser redirect!
5. Choose SQL Interface or AI Chat Interface
6. Start querying data or chatting with AI models!

## MSAL Client Credentials Flow

```python
# How it works:
sp_app = msal.ConfidentialClientApplication(
    client_id=client_id,
    client_credential=client_secret,
    authority=authority
)

# Acquire token - NO USER INTERACTION!
result = sp_app.acquire_token_for_client(
    scopes=[f"api://{client_id}/.default"]
)

# Get access token instantly
access_token = result['access_token']

# Exchange for Databricks token
databricks_token = exchange_for_databricks_token(access_token, workspace_url)
```

## Configuration Details

### Service Principal Settings

- **SP_TENANT_ID**: Your Azure AD tenant identifier
- **SP_CLIENT_ID**: Service Principal (Application) ID
- **SP_CLIENT_SECRET**: Secret value generated in Entra ID

### Application Settings

- **PORT**: Local port for the Flask app (default: 9001)
- **FLASK_SECRET_KEY**: Used for session encryption

## API Endpoints

- `GET /` - Main landing page
- `POST /authenticate` - Authenticate with Service Principal (instant)
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
custom-app-sp-entra-msal/
├── app.py                      # Main Flask application (SP auth)
├── config.env                  # Your configuration (gitignored)
├── config.env.example          # Configuration template
├── requirements.txt            # Python dependencies (includes msal)
├── run.sh                      # Start script
├── .gitignore                  # Git ignore rules
├── README.md                   # This file
└── templates/                  # HTML templates
    ├── base.html
    ├── index.html
    ├── databricks_interface.html
    ├── sql_setup.html
    ├── sql_interface.html
    ├── chat_setup.html
    └── chat_interface.html
```

## Use Cases

### 1. Data Pipeline Automation
```python
# Perfect for scheduled ETL jobs
# No user login needed - runs automatically
import requests

response = requests.post('http://localhost:9001/authenticate', 
    data={'workspace_url': workspace_url})
# Instant authentication!
```

### 2. CI/CD Integration
```bash
# In your CI/CD pipeline
python app.py &
curl -X POST http://localhost:9001/authenticate \
  -d "workspace_url=https://your-workspace.databricks.com"
# Run tests using Databricks token
```

### 3. Backend API Service
```python
# Authenticate once at startup
# Long-lived token (~24 hours)
# No user interaction needed
```

### 4. Monitoring & Health Checks
```python
# Periodic health checks
# Automated reporting
# No user intervention
```

## Security Notes

- Never commit `config.env` to version control
- Keep your `SP_CLIENT_SECRET` secure
- Use Azure Key Vault for production secrets
- Service Principal has **app-level permissions** (not user-specific)
- Token lifetime: ~24 hours (longer than user tokens)
- In production, use HTTPS and set `SESSION_COOKIE_SECURE=True`

## Troubleshooting

### Authentication fails

**Check:**
- SP credentials are correct in `config.env`
- Client secret hasn't expired
- Service Principal has proper permissions
- Databricks federation is configured

### Token exchange fails

**Check:**
- Databricks federation includes your SP tenant ID and client ID
- Scope is configured correctly: `api://{CLIENT_ID}/.default`
- Workspace URL is correct

### "Invalid client secret"

**Solution:**
1. Generate a new client secret in Entra ID
2. Copy it immediately
3. Update `config.env` with new secret
4. Restart application

## Comparison with User Auth

| Aspect | Service Principal | User Authentication |
|--------|------------------|---------------------|
| **Setup Complexity** | Simple (3 values) | Complex (redirect URIs, scopes) |
| **Authentication Speed** | Instant (~100ms) | Slow (~5-10 seconds) |
| **Token Lifetime** | Long (~24 hours) | Short (~1 hour) |
| **User Interaction** | None | Required |
| **Use Case** | Automation | End Users |
| **Scaling** | Excellent | Limited |
| **Permissions** | App-level | User-level |
| **Port** | 9001 | 9001 (same - can't run both simultaneously) |

## When to Use Service Principal vs User Auth

### Use Service Principal When:
✅ Building automation/scripts  
✅ Backend services/APIs  
✅ CI/CD pipelines  
✅ Scheduled jobs  
✅ Data processing  
✅ No user interaction possible  
✅ Need long-lived tokens  
✅ App-level permissions are OK  

### Use User Authentication When:
✅ Interactive web applications  
✅ Need user-specific permissions  
✅ User identity matters  
✅ Compliance requires user tracking  
✅ Conditional access policies needed  

## Benefits Over Manual Implementation

Using MSAL for Service Principal authentication provides:

✅ **Simplified Code** - One method call vs complex OAuth flow  
✅ **Automatic Token Management** - MSAL handles expiry/refresh  
✅ **Error Handling** - Standardized error format  
✅ **Production Ready** - Microsoft-tested implementation  
✅ **Best Practices** - Follows OAuth 2.0 specifications  

## Port Configuration

- **Default Port**: 9001 (same as user auth app)
- **Note**: Cannot run both apps simultaneously (same port)
- **Recommendation**: Stop user auth app before running SP app, or vice versa

## Documentation

- [MSAL Python Documentation](https://msal-python.readthedocs.io/)
- [Client Credentials Flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
- [Service Principal Best Practices](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)
- [Databricks Token Federation](https://docs.databricks.com/)

## Example: Automation Script

```python
#!/usr/bin/env python3
"""
Example: Automated Databricks Query
Using Service Principal authentication
"""
import requests

# 1. Authenticate with Service Principal (instant!)
auth_response = requests.post(
    'http://localhost:9001/authenticate',
    data={'workspace_url': 'https://your-workspace.databricks.com'}
)

# 2. Execute SQL query (no user interaction needed)
sql_response = requests.post(
    'http://localhost:9001/execute-sql',
    json={'query': 'SELECT * FROM my_table LIMIT 10'}
)

# 3. Process results
results = sql_response.json()
print(f"Got {results['result']['row_count']} rows")

# Perfect for cron jobs, pipelines, automation!
```

## License

MIT

## Support

For issues or questions:
1. Check the logs in terminal
2. Verify SP credentials in `config.env`
3. Ensure Databricks federation is configured
4. Check Service Principal permissions

---

**Ready for Automation!** 🚀

This app provides instant, non-interactive authentication perfect for scripts, services, and automation workflows.

