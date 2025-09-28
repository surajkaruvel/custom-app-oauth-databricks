# Custom OAuth Apps for Databricks

A collection of OAuth 2.0 integration examples for Databricks, demonstrating different authentication flows and use cases.

## 🚀 Available Applications

### 1. **Custom App - On Behalf of User (Okta SPA)** 📱
**Directory:** `custom-app-obo-user-okta-spa/`

A Flask web application that authenticates users via Okta OAuth 2.0 with PKCE and provides a SQL interface to Databricks.

**Features:**
- ✅ User Authentication (OAuth 2.0 + PKCE)
- ✅ No client secrets needed (SPA configuration)
- ✅ SQL query interface for Databricks
- ✅ Token refresh (tied to Okta web session)
- ✅ Modern responsive UI

**Quick Start:**
```bash
cd custom-app-obo-user-okta-spa
cp config.env.example config.env
# Edit config.env with your Okta/Databricks settings
python app.py
```

### 2. **Custom App - On Behalf of User (Okta Web App)** 🌐
**Directory:** `custom-app-obo-user-okta-web/`

A Flask web application that authenticates users via Okta OAuth 2.0 with client secret + PKCE and provides a SQL interface to Databricks.

**Features:**
- ✅ User Authentication (OAuth 2.0 + Client Secret + PKCE)
- ✅ Persistent refresh tokens (survive Okta session logout)
- ✅ SQL query interface for Databricks
- ✅ Enhanced security for web applications
- ✅ Modern responsive UI

**Quick Start:**
```bash
cd custom-app-obo-user-okta-web
cp config.env.example config.env
# Edit config.env with your Okta/Databricks settings
python app.py
```

## 📋 OAuth Flows Supported

### Authorization Code + PKCE (SPA)

```
User → Okta → Authorization Code → App → Access Token → Databricks
```

**Benefits:**
- No client secrets to manage
- Enhanced security with PKCE
- Preserves user identity in queries
- Simple setup and configuration

### Authorization Code + Client Secret + PKCE (Web App)

```
User → Okta → Authorization Code → App (with secret) → Access Token → Databricks
```

**Benefits:**
- Persistent refresh tokens
- Enhanced security with client secret + PKCE
- Preserves user identity in queries
- Survives Okta web session logout

## 🛠️ Prerequisites

### General Requirements
- Python 3.8+
- Okta account with SPA application configured
- Databricks workspace with SQL warehouse
- Modern web browser

### Okta Configuration

#### For SPA App (`custom-app-obo-user-okta-spa`)
- **Application Type**: Single-Page App (SPA)
- **Grant Types**: Authorization Code with PKCE
- **Redirect URIs**: `http://localhost:5000/callback`
- **Scopes**: `openid`, `profile`, `email`, `all-apis`, `offline_access`

#### For Web App (`custom-app-obo-user-okta-web`)
- **Application Type**: Web Application
- **Grant Types**: Authorization Code with PKCE
- **Redirect URIs**: `http://localhost:6001/callback`
- **Scopes**: `openid`, `profile`, `email`, `all-apis`, `offline_access`
- **Client Authentication**: Client Secret (Basic)

### Databricks Configuration
- SQL warehouse configured and running
- User permissions set up in Databricks workspace
- Federation policies configured for external OAuth

## 🔒 Security Features

### ✅ What's Included
- Environment-based configuration (no hardcoded secrets)
- PKCE for enhanced OAuth security
- Secure session management
- Automatic token refresh (session-based)
- Proper error handling

### ⚠️ Important Notes
- Never commit `config.env` files to git
- Use HTTPS in production environments
- SPA refresh tokens are tied to Okta web session
- For persistent refresh tokens, consider the Web App flow

## 🚀 Quick Setup Guide

### 1. Clone and Navigate
```bash
git clone https://github.com/surajkaruvel/custom-app-oauth-databricks.git
cd custom-app-oauth-databricks/custom-app-obo-user-okta-spa
```

### 2. Configure Environment
```bash
cp config.env.example config.env
# Edit config.env with your specific settings
```

### 3. Install and Run
```bash
pip install -r requirements.txt
python app.py
# Or use the startup script: ./run.sh
```

### 4. Access Application
Open `http://localhost:5000` in your browser and sign in with Okta.

## 📁 Project Structure

```
custom-app-oauth-databricks/
├── custom-app-obo-user-okta-spa/  # SPA User Authentication App
├── custom-app-obo-user-okta-web/  # Web App User Authentication
│   ├── app.py                  # Main Flask application
│   ├── config.env.example     # Configuration template
│   ├── requirements.txt       # Python dependencies
│   ├── run.sh                 # Startup script
│   ├── templates/             # HTML templates
│   └── README.md              # App-specific documentation
└── README.md                  # This file
```

## 🔄 Authentication Flow Details

### SPA OAuth 2.0 + PKCE Flow
1. User clicks "Sign In with Okta"
2. App generates PKCE code verifier and challenge
3. User redirected to Okta for authentication
4. Okta redirects back with authorization code
5. App exchanges code for tokens using PKCE verifier
6. Federated token exchanged for Databricks workspace token
7. User can now execute SQL queries as their authenticated identity

## 🆘 Troubleshooting

### Common Issues

#### OAuth Configuration Errors
- Verify redirect URIs match exactly: `http://localhost:5000/callback`
- Check client ID and ensure application is configured as SPA
- Ensure proper scopes are configured in Okta

#### Token Exchange Failures
- Verify Databricks federation policies are configured
- Check that user exists in Databricks workspace
- Validate token format and claims

#### Session Issues
- SPA refresh tokens expire when Okta web session ends
- Clear browser cookies if experiencing persistent issues
- Check Flask session configuration

### Getting Help

1. Check application logs for detailed error messages
2. Review the app-specific README in `custom-app-obo-user-okta-spa/`
3. Verify configuration against the example files
4. Test with minimal sample queries first

## 🔗 Useful Links

- [Okta SPA Documentation](https://developer.okta.com/docs/guides/sign-into-spa-redirect/)
- [OAuth 2.0 PKCE Specification](https://tools.ietf.org/html/rfc7636)
- [Databricks OAuth Documentation](https://docs.databricks.com/dev-tools/auth.html)
- [Flask Documentation](https://flask.palletsprojects.com/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is provided as-is for educational and development purposes. Use in accordance with your organization's security policies and Databricks/Okta terms of service.

---

**Last Updated:** September 2024  
**Maintained by:** Suraj Karuvel
