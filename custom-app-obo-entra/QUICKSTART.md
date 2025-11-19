# Quick Start Guide - OBO Flow Demo

Get up and running with the On-Behalf-Of (OBO) flow demo in 5 minutes!

## Prerequisites

- Python 3.8+
- Microsoft Entra ID tenant with admin access
- Two app registrations configured (see README.md for details)
- Databricks workspace

## Quick Setup

### 1. Clone and Navigate

```bash
cd custom-app-obo-entra
```

### 2. Configure Environment

```bash
# Copy example config
cp config.env.example config.env

# Edit config.env with your values
nano config.env  # or use your preferred editor
```

Required values:
- `MIDDLETIER_TENANT_ID`: Your Entra ID tenant ID
- `MIDDLETIER_CLIENT_ID`: Middle-tier app client ID
- `MIDDLETIER_CLIENT_SECRET`: Middle-tier app client secret
- `DATABRICKS_SCOPE`: `<databricks-app-client-id>/user_impersonation`

### 3. Install and Run

```bash
# Make run script executable
chmod +x run.sh

# Run the application
./run.sh
```

The script will:
- Create a virtual environment
- Install dependencies
- Start the Flask application on port 9001

### 4. Access Application

Open your browser and navigate to: `http://localhost:9001`

## Quick Test

1. **Enter Workspace URL**: e.g., `https://adb-1234567890123456.7.azuredatabricks.net`
2. **Click "Authenticate"**: Sign in with your Microsoft credentials
3. **OBO Exchange**: The app will automatically exchange your token
4. **Access Databricks**: Use SQL Interface or AI Assistant

## What's Happening?

```
Step 1: You → Middle-Tier
        ↓ (Auth code + PKCE)
        
Step 2: Middle-Tier → Entra ID
        ↓ (OBO token exchange)
        
Step 3: Token → Databricks APIs
        ✅ (Works directly!)
```

## Troubleshooting

### Port Already in Use

```bash
# Change port in config.env
PORT=9002
REDIRECT_URI=http://localhost:9002/callback

# Also update redirect URI in Entra ID app registration
```

### OBO Exchange Fails

1. Check that middle-tier app has delegated permission to Databricks app
2. Verify admin consent is granted
3. Ensure `DATABRICKS_SCOPE` is correct format: `<client-id>/user_impersonation`

### Authentication Loop

1. Clear browser cookies
2. Verify redirect URI matches exactly in both `config.env` and Entra ID
3. Check that client secret is correct

## Next Steps

- Read the full [README.md](README.md) for detailed architecture
- Review [Microsoft OBO documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow)
- Test SQL queries and AI Assistant features

## Need Help?

Check the application logs for detailed information:
- Authentication flow logs
- OBO token exchange details
- API call responses

The application provides verbose logging to help debug any issues.

---

**Ready to explore?** 🚀 Visit http://localhost:9001 to get started!

