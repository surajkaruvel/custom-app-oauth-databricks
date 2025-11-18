# Databricks SQL Interface - User Authentication

A secure Flask application that authenticates users via Okta OAuth 2.0 with PKCE and provides a SQL interface to Databricks endpoints.

## 🚀 Features

- **User Authentication**: OAuth 2.0 Authorization Code Flow with PKCE (SPA configuration)
- **Secure**: No client secrets needed, PKCE prevents code interception
- **SQL Interface**: Execute SQL queries on Databricks as the authenticated user
- **Modern UI**: Beautiful, responsive web interface
- **Real-time Results**: Interactive query execution with formatted results
- **Sample Queries**: Built-in examples for common operations

## 🛠️ Quick Start

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment**:
   Update `config.env` with your values:
   ```bash
   # Okta SPA Configuration (PKCE Flow)
   ISSUER_URL=https://your-okta-domain.okta.com/oauth2/your-auth-server
   CLIENT_ID=your-spa-client-id
   REDIRECT_URI=http://localhost:5000/callback
   
   # Databricks SQL Endpoint
   DATABRICKS_SERVER_HOSTNAME=your-workspace.cloud.databricks.com
   DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/your-warehouse-id
   ```

3. **Run the Application**:
   ```bash
   python app.py
   # The app automatically loads config.env if present
   ```

4. **Access the Application**:
   Open `http://localhost:5000` in your browser

## 🔧 Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `ISSUER_URL` | Okta authorization server URL | `https://dev-123.okta.com/oauth2/default` |
| `CLIENT_ID` | Okta SPA application client ID | `0oabc123def456ghi789` |
| `REDIRECT_URI` | OAuth callback URL | `http://localhost:5000/callback` |
| `DATABRICKS_SERVER_HOSTNAME` | Databricks workspace hostname | `dbc-12345678-9abc.cloud.databricks.com` |
| `DATABRICKS_HTTP_PATH` | SQL warehouse path | `/sql/1.0/warehouses/abc123def456` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5000` | Application port |
| `FLASK_DEBUG` | `True` | Debug mode |
| `OAUTH_SCOPE` | `openid profile email offline_access` | OAuth scopes |

### Okta SPA Application Setup

Configure your Okta application as:
- **Application Type**: Single-Page App (SPA)
- **Grant Types**: Authorization Code with PKCE
- **Redirect URIs**: `http://localhost:5000/callback`
- **Scopes**: `openid`, `profile`, `email`, `offline_access`

## 🎯 Usage

1. **Login**: Click "Sign In with Okta" on the homepage
2. **Authenticate**: Complete Okta authentication in your browser
3. **Query**: Use the SQL interface to execute queries on Databricks
4. **Results**: View formatted results in real-time

### Sample Queries

- `SELECT current_user()` - Check your authenticated user
- `SHOW DATABASES` - List available databases
- `SHOW TABLES` - List tables in current database
- `SELECT current_timestamp()` - Get current server time

## 🔒 Security Features

- **PKCE (Proof Key for Code Exchange)**: Prevents authorization code interception
- **SPA Configuration**: No client secrets stored or transmitted
- **Secure Sessions**: HTTPOnly cookies with proper security headers
- **User Permissions**: Queries execute with authenticated user's permissions
- **Token Exchange**: Federated tokens exchanged for Databricks workspace tokens

## 🌐 Local Development

Run the application locally:
```bash
python app.py
# The app automatically loads config.env if present
```

## 📁 Project Structure

```
custom-app-obo-user-okta-spa/
├── app.py                 # Main Flask application
├── config.env            # Environment configuration
├── config.env.example    # Configuration template
├── requirements.txt      # Python dependencies
├── run.sh                # Startup script
└── templates/
    ├── base.html          # Base template
    ├── index.html         # Login page
    └── sql_interface.html # SQL query interface
```

## 🤝 Authentication Flow

1. User clicks "Sign In with Okta"
2. App generates PKCE code verifier and challenge
3. User redirected to Okta for authentication
4. Okta redirects back with authorization code
5. App exchanges code for tokens using PKCE verifier
6. Federated token exchanged for Databricks workspace token
7. User can now execute SQL queries

## 🔄 Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Browser   │    │  Flask App       │    │  Okta (SPA)     │
│                 │    │  (External)      │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         │  1. Sign In with Okta  │                        │
         ├───────────────────────►│                        │
         │                        │  2. PKCE Challenge     │
         │                        ├───────────────────────►│
         │  3. User Authentication│                        │
         ├────────────────────────┼───────────────────────►│
         │                        │  4. Auth Code Callback│
         │◄───────────────────────┼────────────────────────┤
         │                        │  5. PKCE Token Exchange│
         │                        ├───────────────────────►│
         │                        │◄───────────────────────┤
         │  6. SQL Interface      │  7. Databricks Token   │
         │◄───────────────────────┤     Exchange           │
         │                        │                        │
         │  8. Execute SQL        │  9. Databricks SQL API │
         ├───────────────────────►├───────────────────────►│
         │◄───────────────────────┤◄───────────────────────┤
```

## 🛠️ API Endpoints

### Web Interface
- `GET /` - Main page (login or redirect to SQL interface)
- `GET /login` - Initiate OAuth flow with PKCE
- `GET /callback` - OAuth callback handler
- `GET /sql` - SQL query interface (authenticated users only)
- `GET /logout` - Clear session and logout

### API Endpoints
- `POST /execute-sql` - Execute SQL query (authenticated users only)
- `GET /health` - Health check endpoint

## 🔍 Troubleshooting

### Common Issues

#### 1. OAuth Configuration Errors
- **Symptom**: "Invalid client" or redirect URI mismatch
- **Solution**: Verify Okta SPA configuration
- **Check**: Ensure redirect URI matches exactly

#### 2. Authentication Failures
- **Symptom**: "Failed to exchange authorization code"
- **Solution**: Check client ID and PKCE configuration
- **Check**: Ensure application is configured as SPA

#### 3. SQL Execution Errors
- **Symptom**: "Failed to execute SQL query"
- **Solution**: Verify warehouse configuration and user permissions
- **Check**: Ensure user has access to the SQL warehouse

#### 4. Token Exchange Errors
- **Symptom**: "Failed to exchange for workspace token"
- **Solution**: Check Databricks federation configuration
- **Check**: Verify user exists in Databricks workspace

### Debug Mode

Enable debug mode for detailed error information:
```bash
export FLASK_DEBUG=True
python app.py
```

## 📋 Requirements

- Python 3.8+
- Okta account with SPA application configured
- Databricks workspace with SQL warehouse
- Modern web browser with JavaScript enabled

## 🆚 Comparison with Service Principal Approach

| Feature | User Authentication | Service Principal |
|---------|-------------------|------------------|
| **Authentication** | User credentials | Application credentials |
| **Query Permissions** | User's permissions | Service principal permissions |
| **Setup Complexity** | Simple (SPA config) | Complex (federation policies) |
| **Security** | PKCE (no secrets) | Client credentials |
| **User Context** | Preserves user identity | Generic service identity |
| **Audit Trail** | User-specific logs | Service principal logs |

## 📄 License

This application is provided as-is for OAuth token management and SQL execution with Databricks. Use in accordance with your organization's security policies and Databricks terms of service.

## 🤝 Support

For issues and questions:
1. Check the troubleshooting section
2. Review Okta SPA configuration
3. Check application logs for detailed error information
4. Verify Databricks SQL warehouse configuration and user permissions