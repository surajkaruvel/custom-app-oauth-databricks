# Quick Start Guide - Service Principal OAuth (5 Minutes!)

Get up and running with Service Principal (non-interactive) authentication in under 5 minutes!

## What You'll Get

✅ **Instant Authentication** - No browser redirect, no user login  
✅ **Automation Ready** - Perfect for scripts and pipelines  
✅ **Long-Lived Tokens** - ~24 hour expiry  
✅ **MSAL Powered** - Microsoft's official OAuth library  

## Prerequisites

- [ ] Python 3.7+
- [ ] Azure AD admin access (to create Service Principal)
- [ ] Databricks workspace URL

## Step 1: Create Service Principal (2 minutes)

### In Azure Portal

1. **Go to Azure AD** → **App registrations** → **New registration**

2. **Fill in details:**
   ```
   Name: Databricks-SP-Automation
   Supported account types: Single tenant
   Redirect URI: (leave blank - not needed for SP!)
   ```

3. **Click Register**

4. **Note down these values:**
   ```
   Tenant ID: ________________________________________
   Client ID: ________________________________________
   ```

5. **Create Client Secret:**
   - Go to **Certificates & secrets** → **New client secret**
   - Description: `Databricks Secret`
   - Expires: 24 months
   - Click **Add**
   - **COPY THE SECRET NOW!** (You won't see it again)
   ```
   Client Secret: ________________________________________
   ```

## Step 2: Configure Databricks (1 minute)

### In Databricks Workspace

1. **Go to Settings** → **Identity and access** → **OAuth**

2. **Add your Service Principal:**
   ```
   Issuer: https://login.microsoftonline.com/{YOUR_TENANT_ID}/v2.0
   Audience: {YOUR_CLIENT_ID}
   ```

3. **Save**

## Step 3: Set Up Application (1 minute)

```bash
# Navigate to the folder
cd /path/to/custom-app-sp-entra-msal

# Copy configuration
cp config.env.example config.env

# Edit config.env
nano config.env  # or use your favorite editor
```

**Edit config.env:**
```bash
SP_TENANT_ID=paste-your-tenant-id-here
SP_CLIENT_ID=paste-your-client-id-here
SP_CLIENT_SECRET=paste-your-secret-here

PORT=9001
FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
```

## Step 4: Run! (1 minute)

```bash
# Install and run (one command!)
./run.sh
```

Or manually:
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python app.py
```

You should see:
```
🚀 Starting Databricks Service Principal App with MSAL...
📍 Port: 9001
🔗 URL: http://localhost:9001
🔧 Auth Type: Service Principal (Non-Interactive)

✅ Starting Flask application with MSAL (Service Principal)...
```

## Step 5: Test! (30 seconds)

1. **Open browser:** http://localhost:9001

2. **Enter your Databricks workspace URL:**
   ```
   https://adb-1234567890123456.7.azuredatabricks.net
   ```

3. **Click "Authenticate with Service Principal"**

4. **DONE!** ✅ Instant authentication - no browser redirect!

5. **Choose interface:**
   - **SQL Analytics** - Execute queries
   - **AI Chat** - Chat with models

## What Just Happened?

### MSAL Client Credentials Flow

```python
# Your SP authenticated instantly:
sp_app = msal.ConfidentialClientApplication(
    client_id=your_client_id,
    client_credential=your_client_secret,
    authority=f"https://login.microsoftonline.com/{tenant_id}"
)

# Got token automatically (no user login!)
result = sp_app.acquire_token_for_client(
    scopes=["api://your_client_id/.default"]
)

# Exchanged for Databricks token
databricks_token = exchange(result['access_token'])

# Ready to use!
```

## Troubleshooting

### Error: "Invalid client secret"

**Fix:**
1. Generate new secret in Azure AD
2. Update `config.env`
3. Restart app

### Error: "Token exchange failed"

**Fix:**
1. Check Databricks OAuth settings
2. Verify Issuer: `https://login.microsoftonline.com/{TENANT_ID}/v2.0`
3. Verify Audience: `{CLIENT_ID}`

### Error: "Module 'msal' not found"

**Fix:**
```bash
pip install msal>=1.24.0
```

## Configuration Template

```bash
# Quick fill template
SP_TENANT_ID=________________________________________
SP_CLIENT_ID=________________________________________
SP_CLIENT_SECRET=____________________________________
PORT=9001
FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
```

## Verify Setup

- [ ] App starts without errors
- [ ] Can access http://localhost:9001
- [ ] Authentication happens instantly (no browser redirect)
- [ ] Databricks token acquired successfully
- [ ] Can execute SQL queries
- [ ] Can access AI chat interface

## Service Principal vs User Auth

| Feature | Service Principal | User Auth |
|---------|------------------|-----------|
| **Speed** | Instant (~100ms) | Slow (~5-10s) |
| **Interaction** | None | Browser Login |
| **Token Life** | ~24 hours | ~1 hour |
| **Use Case** | Automation | End Users |
| **Port** | 9001 | 9001 (same) |

## Use Cases

Perfect for:
- ✅ **Automation Scripts** - Cron jobs, scheduled tasks
- ✅ **CI/CD Pipelines** - Build and deployment workflows
- ✅ **Backend Services** - APIs, microservices
- ✅ **Data Pipelines** - ETL, data processing
- ✅ **Monitoring** - Health checks, alerts

## Example: Automation Script

```python
#!/usr/bin/env python3
import requests

# 1. Authenticate (instant!)
response = requests.post(
    'http://localhost:9001/authenticate',
    data={'workspace_url': 'https://your-workspace.databricks.com'}
)

# 2. Execute query (automated!)
sql = requests.post(
    'http://localhost:9001/execute-sql',
    json={'query': 'SELECT * FROM my_table'}
)

# 3. Process results
print(sql.json())

# Perfect for automation - no user needed!
```

## Next Steps

### Production Deployment

1. **Use HTTPS**
   ```python
   SESSION_COOKIE_SECURE=True
   ```

2. **Secure Secrets**
   - Use Azure Key Vault
   - Environment variables
   - Secret management service

3. **Monitor**
   - Add logging
   - Health checks
   - Alerts

### Advanced Usage

- **Multiple Workspaces** - Configure different SPs
- **CI/CD Integration** - Add to pipeline
- **Scheduled Jobs** - Use cron/scheduler
- **API Wrapper** - Build REST API around it

## Success! 🎉

You now have a working Service Principal authentication app that:
- ✅ Authenticates instantly (no user login)
- ✅ Uses MSAL for Python
- ✅ Gets long-lived tokens (~24 hours)
- ✅ Perfect for automation

**Total setup time: ~5 minutes** ⚡

---

## Quick Links

- [Full README](README.md) - Complete documentation
- [MSAL Python Docs](https://msal-python.readthedocs.io/)
- [Azure AD SP Guide](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

## Support

Questions? Check:
1. Terminal logs (detailed error messages)
2. `config.env` values (correct SP credentials?)
3. Databricks OAuth settings (SP configured?)
4. Network connectivity (can reach Azure AD?)

Enjoy your automated Databricks access! 🚀

