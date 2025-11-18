# Custom OAuth Apps for Databricks

A collection of OAuth 2.0 integration examples for Databricks, demonstrating different authentication flows and use cases.

> ## ⚠️ DISCLAIMER
> 
> **These applications are EXPERIMENTAL and provided for EDUCATIONAL PURPOSES ONLY.**
> 
> - ❌ **NOT intended for production use**
> - 🔬 Designed to demonstrate OAuth token federation flows with Databricks
> - 📚 Educational examples of OAuth 2.0 Authorization Code + PKCE and Client Credentials flows
> - 🛡️ **USE AT YOUR OWN RISK** - The end user assumes all responsibility and liability
> - 🔒 Ensure proper security reviews before using in any non-development environment
> - ⚡ No warranties or guarantees of any kind are provided
> 
> For production deployments, consult Databricks official documentation and your security team.

## 🚀 Available Applications

### 1. **Custom App - User Authentication (Entra ID + MSAL)** 🔐
**Directory:** `custom-app-user-entra-msal/`

A Flask web application that authenticates users via Microsoft Entra ID (Azure AD) using the MSAL library with OAuth 2.0 Authorization Code Flow + PKCE.

**Features:**
- ✅ MSAL for Python library integration
- ✅ OAuth 2.0 Authorization Code Flow with PKCE
- ✅ Automatic token exchange with Databricks
- ✅ Optimized session management (prevents large cookies)
- ✅ SQL Analytics and AI Assistant interfaces
- ✅ Token debugging and analysis

**Quick Start:**
```bash
cd custom-app-user-entra-msal
cp config.env.example config.env
# Edit config.env with your Entra ID/Databricks settings
python app.py
```

### 2. **Custom App - Service Principal (Entra ID + MSAL)** 🤖
**Directory:** `custom-app-sp-entra-msal/`

A Flask web application that authenticates as a service principal via Microsoft Entra ID using MSAL with Client Credentials Flow (non-interactive).

**Features:**
- ✅ MSAL-based Service Principal authentication
- ✅ Client Credentials Flow (no user interaction)
- ✅ Separate Databricks SP client ID support
- ✅ Token expiry tracking with countdown
- ✅ SQL Analytics and AI Assistant interfaces
- ✅ Ideal for automation and M2M workflows

**Quick Start:**
```bash
cd custom-app-sp-entra-msal
cp config.env.example config.env
# Edit config.env with your Entra ID service principal credentials
python app.py
```

### 3. **Custom App - User Authentication (Okta SPA)** 📱
**Directory:** `custom-app-user-okta-spa/`

A Flask web application that authenticates users via Okta OAuth 2.0 with PKCE (Single Page App configuration).

**Features:**
- ✅ User Authentication (OAuth 2.0 + PKCE)
- ✅ No client secrets needed (SPA configuration)
- ✅ SQL query interface for Databricks
- ✅ Token refresh (tied to Okta web session)
- ✅ Modern responsive UI

**Quick Start:**
```bash
cd custom-app-user-okta-spa
cp config.env.example config.env
# Edit config.env with your Okta/Databricks settings
python app.py
```

### 4. **Custom App - User Authentication (Okta Web App)** 🌐
**Directory:** `custom-app-user-okta-web/`

A Flask web application that authenticates users via Okta OAuth 2.0 with client secret + PKCE (Web App configuration).

**Features:**
- ✅ User Authentication (OAuth 2.0 + Client Secret + PKCE)
- ✅ Persistent refresh tokens (survive Okta session logout)
- ✅ SQL query interface for Databricks
- ✅ Enhanced security for web applications
- ✅ Modern responsive UI

**Quick Start:**
```bash
cd custom-app-user-okta-web
cp config.env.example config.env
# Edit config.env with your Okta/Databricks settings
python app.py
```

### 5. **Custom App - Service Principal (Okta)** 🔧
**Directory:** `custom-app-sp-okta-service/`

A Flask web application that authenticates as a service principal via Okta OAuth 2.0 Client Credentials flow.

**Features:**
- ✅ Service Principal Authentication (Client Credentials flow)
- ✅ Machine-to-machine (M2M) authentication
- ✅ No user interaction required
- ✅ SQL query interface for Databricks
- ✅ Automated workflows and batch processing

**Quick Start:**
```bash
cd custom-app-sp-okta-service
cp config.env.example config.env
# Edit config.env with your Okta service principal credentials
python app.py
```

### 6. **Custom App - OAuth Confidential Client (Direct Databricks)** 🔐
**Directory:** `custom-app-oauth-confidential-dbrx-direct/`

A Flask web application demonstrating direct OAuth 2.0 authentication with Databricks using a confidential client (with client secret).

**Features:**
- ✅ Direct OAuth 2.0 flow with Databricks (no external IdP)
- ✅ Confidential client authentication
- ✅ Authorization Code Flow with PKCE
- ✅ SQL query interface
- ✅ Minimal dependencies

**Quick Start:**
```bash
cd custom-app-oauth-confidential-dbrx-direct
cp config.env.example config.env
# Edit config.env with your Databricks settings
python app.py
```

### 7. **Custom App - OAuth Public Client (Direct Databricks)** 🌍
**Directory:** `custom-app-oauth-public-dbrx-direct/`

A Flask web application demonstrating direct OAuth 2.0 authentication with Databricks using a public client (no client secret).

**Features:**
- ✅ Direct OAuth 2.0 flow with Databricks (no external IdP)
- ✅ Public client authentication (no secrets)
- ✅ Authorization Code Flow with PKCE
- ✅ SQL query interface
- ✅ Suitable for client-side applications

**Quick Start:**
```bash
cd custom-app-oauth-public-dbrx-direct
cp config.env.example config.env
# Edit config.env with your Databricks settings
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

### Client Credentials (Service Principal)

```
App → Okta → Access Token → Databricks (No user interaction)
```

**Benefits:**
- No user interaction required
- Ideal for automated workflows
- Service principal permissions
- Machine-to-machine authentication

## 🛠️ Prerequisites

### General Requirements
- Python 3.8+
- Okta account with SPA application configured
- Databricks workspace with SQL warehouse
- Modern web browser

### Okta Configuration

#### For SPA App (`custom-app-user-okta-spa`)
- **Application Type**: Single-Page App (SPA)
- **Grant Types**: Authorization Code with PKCE
- **Redirect URIs**: `http://localhost:5000/callback`
- **Scopes**: `openid`, `profile`, `email`, `all-apis`, `offline_access`

#### For Web App (`custom-app-user-okta-web`)
- **Application Type**: Web Application
- **Grant Types**: Authorization Code with PKCE
- **Redirect URIs**: `http://localhost:6001/callback`
- **Scopes**: `openid`, `profile`, `email`, `all-apis`, `offline_access`
- **Client Authentication**: Client Secret (Basic)

#### For Service Principal (`custom-app-sp-okta-service`)
- **Application Type**: API Services (Service App)
- **Grant Types**: Client Credentials
- **Scopes**: `all-apis`
- **Client Authentication**: Client Secret (Basic)
- **No redirect URIs needed** (machine-to-machine)

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
cd custom-app-oauth-databricks/custom-app-user-okta-spa
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
├── custom-app-user-entra-msal/            # 🔐 Entra ID User Auth (MSAL)
├── custom-app-sp-entra-msal/              # 🤖 Entra ID Service Principal (MSAL)
├── custom-app-user-okta-spa/              # 📱 Okta SPA User Auth
├── custom-app-user-okta-web/              # 🌐 Okta Web App User Auth
├── custom-app-sp-okta-service/            # 🔧 Okta Service Principal
├── custom-app-oauth-confidential-dbrx-direct/  # 🔐 Databricks Confidential Client
├── custom-app-oauth-public-dbrx-direct/   # 🌍 Databricks Public Client
│   ├── app.py                             # Main Flask application
│   ├── config.env.example                 # Configuration template
│   ├── requirements.txt                   # Python dependencies
│   ├── run.sh                             # Startup script
│   ├── templates/                         # HTML templates
│   └── README.md                          # App-specific documentation
└── README.md                              # This file
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
2. Review the app-specific README in `custom-app-user-okta-spa/`
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

**Last Updated:** November 2024  
**Maintained by:** Suraj Karuvel
