# Quick Start Guide - MSAL OAuth App

Get up and running with the MSAL-based Databricks OAuth app in under 5 minutes!

## Prerequisites Checklist

- [ ] Python 3.7+ installed
- [ ] Databricks workspace URL
- [ ] Microsoft Entra ID (Azure AD) account with app registration privileges

## Step 1: Configure Entra ID (5 minutes)

### Create App Registration

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations** → **New registration**

3. Fill in the details:
   ```
   Name: Databricks OAuth MSAL App
   Supported account types: Single tenant
   Redirect URI: http://localhost:9001/callback
   ```

4. Click **Register**

### Note Down Credentials

After registration, save these values:
```bash
Tenant ID: ________________________________________
Client ID: ________________________________________
```

### Generate Client Secret (for Web Apps)

1. Go to **Certificates & secrets** → **New client secret**
2. Description: `Databricks OAuth Secret`
3. Expires: 24 months
4. Click **Add**
5. **Copy the secret value immediately** (you won't see it again!)
   ```bash
   Client Secret: ________________________________________
   ```

### Expose API Scope

1. Go to **Expose an API** → **Add a scope**
2. Application ID URI: Click **Save and continue** (accepts default)
3. Scope name: `databricks-token-federation`
4. Who can consent: `Admins only`
5. Admin consent display name: `Databricks Token Federation`
6. Admin consent description: `Allow token exchange for Databricks access`
7. Click **Add scope**

### Configure Authentication

1. Go to **Authentication**
2. Under **Implicit grant and hybrid flows**, check:
   - [ ] Access tokens
   - [ ] ID tokens
3. Click **Save**

## Step 2: Configure Databricks (2 minutes)

### Set Up Federation

1. Go to your Databricks workspace
2. Navigate to **Settings** → **Identity and access** → **Custom OAuth**
3. Add your Entra ID app:
   ```
   Issuer: https://login.microsoftonline.com/{YOUR_TENANT_ID}/v2.0
   Audience: api://{YOUR_CLIENT_ID}
   ```

## Step 3: Set Up Application (2 minutes)

### Clone/Navigate to Directory

```bash
cd /path/to/custom-app-obo-user-entra-msal
```

### Create Configuration File

```bash
cp config.env.example config.env
```

### Edit Configuration

Open `config.env` and fill in your values:

```bash
# Microsoft Entra ID Configuration
ENTRA_TENANT_ID=your-tenant-id-from-step-1
ENTRA_CLIENT_ID=your-client-id-from-step-1
ENTRA_CLIENT_SECRET=your-client-secret-from-step-1

# Application Configuration
PORT=9001
REDIRECT_URI=http://localhost:9001/callback
FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# OAuth Scope (auto-generated format)
OAUTH_SCOPE=api://your-client-id-from-step-1/databricks-token-federation
```

### Quick Fill Script

Or use this one-liner to generate the secret key:
```bash
echo "FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> config.env
```

## Step 4: Install Dependencies (1 minute)

### Option A: Using run.sh (Recommended)

```bash
chmod +x run.sh
./run.sh
```

This script will:
- Create virtual environment
- Install all dependencies (including MSAL)
- Start the application

### Option B: Manual Installation

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate     # On Windows

# Install dependencies
pip install -r requirements.txt

# Start application
python app.py
```

## Step 5: Test the Application (1 minute)

### Start the App

If not already running:
```bash
./run.sh
```

You should see:
```
🚀 Starting Databricks OAuth App with Microsoft Entra ID (MSAL)...
📍 Port: 9001
🔗 URL: http://localhost:9001
📚 Using: MSAL for Python

✅ Starting Flask application with MSAL...
🌐 Open your browser to: http://localhost:9001
```

### Access the Application

1. Open browser to: http://localhost:9001
2. Enter your Databricks workspace URL:
   ```
   https://adb-1234567890123456.7.azuredatabricks.net
   ```
3. Click **Start Entra ID Authentication**
4. Log in with your Microsoft credentials
5. Grant consent if prompted
6. You'll be redirected back to the app with a Databricks token! 🎉

## Step 6: Use the Interfaces

### SQL Interface

1. Click **SQL Analytics**
2. Enter your SQL Warehouse ID
3. Execute queries:
   ```sql
   SELECT * FROM samples.nyctaxi.trips LIMIT 10;
   ```

### AI Chat Interface

1. Click **AI Assistant**
2. Enter your Model Serving Endpoint URL
3. Start chatting with your AI model!

## Troubleshooting

### Error: "Invalid redirect URI"

**Solution**: Make sure the redirect URI in `config.env` exactly matches what's in Entra ID:
```
Entra ID: http://localhost:9001/callback
config.env: http://localhost:9001/callback
```

### Error: "Invalid client secret"

**Solution**: 
1. Generate a new client secret in Entra ID
2. Copy it immediately
3. Update `config.env` with the new secret
4. Restart the application

### Error: "Token exchange failed"

**Solution**: Verify Databricks federation is configured:
1. Check Databricks Settings → Custom OAuth
2. Verify Issuer: `https://login.microsoftonline.com/{TENANT_ID}/v2.0`
3. Verify Audience: `api://{CLIENT_ID}`

### Error: "Module 'msal' not found"

**Solution**:
```bash
pip install msal>=1.24.0
```

### Port Already in Use

**Solution**: Change the port in `config.env`:
```bash
PORT=9002  # or any available port
REDIRECT_URI=http://localhost:9002/callback
```

**Remember**: Update the redirect URI in Entra ID too!

## Verification Checklist

After setup, verify these work:

- [ ] App starts without errors
- [ ] Can access http://localhost:9001
- [ ] Login redirects to Microsoft
- [ ] Can authenticate with Microsoft account
- [ ] Token exchange succeeds
- [ ] Can access SQL interface
- [ ] Can execute SQL queries
- [ ] Can access chat interface (if configured)

## Next Steps

### Production Deployment

1. **Enable HTTPS**
   ```python
   # In app.py, change:
   SESSION_COOKIE_SECURE=True
   ```

2. **Update Redirect URI**
   ```
   https://your-domain.com/callback
   ```

3. **Use Production Secrets**
   - Generate new client secret
   - Use environment variables instead of config.env
   - Use proper secret management (Azure Key Vault, etc.)

4. **Configure Production Databricks**
   - Update workspace URL
   - Configure warehouse IDs
   - Set up model endpoints

### Learn More

- Read [README.md](README.md) for detailed documentation
- Read [MSAL-BENEFITS.md](MSAL-BENEFITS.md) to understand MSAL advantages
- Read [COMPARISON.md](COMPARISON.md) to see MSAL vs manual OAuth
- Check [MSAL Python Docs](https://msal-python.readthedocs.io/)

## Quick Reference

### Important URLs

```bash
# Local development
Application: http://localhost:9001
Health Check: http://localhost:9001/health
Clear Session: http://localhost:9001/clear

# Azure Portal
Entra ID: https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade
App Registrations: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps
```

### Useful Commands

```bash
# Start application
./run.sh

# Install dependencies
pip install -r requirements.txt

# Check MSAL version
pip show msal

# Generate secret key
python3 -c 'import secrets; print(secrets.token_hex(32))'

# Check Python version
python3 --version

# Activate virtual environment
source venv/bin/activate
```

### Configuration Template

```bash
# Copy this to config.env and fill in your values
ENTRA_TENANT_ID=________________________________________
ENTRA_CLIENT_ID=________________________________________
ENTRA_CLIENT_SECRET=____________________________________
PORT=9001
REDIRECT_URI=http://localhost:9001/callback
FLASK_SECRET_KEY=_______________________________________
OAUTH_SCOPE=api://______________________________________/databricks-token-federation
```

## Support

If you run into issues:

1. Check the application logs in the terminal
2. Check [TROUBLESHOOTING](README.md#troubleshooting) section in README
3. Verify all configuration values are correct
4. Try clearing your browser cache/cookies
5. Try clearing the session: http://localhost:9001/clear

## Success! 🎉

You now have a working MSAL-based OAuth application that:
- ✅ Uses Microsoft Authentication Library
- ✅ Implements automatic PKCE security
- ✅ Provides smart token management
- ✅ Exchanges Entra ID tokens for Databricks tokens
- ✅ Supports SQL Analytics
- ✅ Supports AI Assistant interfaces

Total setup time: **~10 minutes** ⚡

Enjoy your simplified OAuth experience with MSAL!

