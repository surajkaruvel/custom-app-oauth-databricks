# Databricks OAuth with Microsoft Entra ID

A Flask application that authenticates users with Microsoft Entra ID (Azure AD) and exchanges tokens for Databricks workspace access. Provides SQL Analytics and AI Assistant interfaces.

## Features

- 🔐 **Entra ID Authentication** - Enterprise SSO with Microsoft identity
- 🔄 **Token Exchange** - Seamless conversion from Entra ID to Databricks tokens
- 🔒 **PKCE Security** - Enhanced OAuth 2.0 security with Proof Key for Code Exchange
- 📊 **SQL Interface** - Execute queries on Databricks SQL warehouses
- 🤖 **AI Chat Interface** - Interact with Databricks model serving endpoints
- ♻️ **Auto Token Refresh** - Automatic session management

## Prerequisites

- Python 3.7+
- Microsoft Entra ID application registration (Web Application type)
- Databricks workspace with federation configured
- SQL Warehouse ID (for SQL interface)
- Model Serving Endpoint (for AI chat interface)

## Quick Start

### 1. Configure Entra ID Application

Your Entra ID app should be configured with:
- **Application Type**: Web Application (confidential client)
- **Redirect URI**: `http://localhost:9001/callback`
- **Scope**: `api://{CLIENT_ID}/databricks-token-federation`
- **Client Secret**: Generated and saved

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
ENTRA_CLIENT_SECRET=your-client-secret

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
4. Log in with your Microsoft credentials
5. Choose SQL Interface or AI Chat Interface
6. Start querying data or chatting with AI models!

## Authentication Flow

```
User → Entra ID (Login) → Authorization Code → 
  → Exchange for Entra ID Token → 
    → Exchange for Databricks Token → 
      → Access Databricks Resources
```

## Configuration Details

### Entra ID Settings

- **Tenant ID**: Your Azure AD tenant identifier
- **Client ID**: Application (client) ID from Entra ID
- **Client Secret**: Secret value generated in Entra ID
- **Scope**: Must match the Application ID URI format: `api://{CLIENT_ID}/databricks-token-federation`

### Application Settings

- **Port**: Local port for the Flask app (default: 9001)
- **Redirect URI**: Must match the redirect URI configured in Entra ID
- **Flask Secret Key**: Used for session encryption (generate a random string)

## API Endpoints

- `GET /` - Main landing page
- `POST /login` - Initiate OAuth flow
- `GET /callback` - OAuth callback handler
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
custom-app-obo-user-entra/
├── app.py                  # Main Flask application
├── config.env              # Your configuration (gitignored)
├── config.env.example      # Configuration template
├── requirements.txt        # Python dependencies
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

## Security Notes

- Never commit `config.env` to version control
- Use a strong, random `FLASK_SECRET_KEY`
- Keep your `ENTRA_CLIENT_SECRET` secure
- In production, use HTTPS and set `SESSION_COOKIE_SECURE=True`

## Troubleshooting

### Authentication fails with 401

- Verify your Entra ID credentials are correct
- Check that the redirect URI matches exactly in both config and Entra ID
- Ensure the application type is set to "Web Application" in Entra ID

### Token exchange fails

- Verify Databricks federation is configured for your Entra ID tenant
- Check that the scope format is correct: `api://{CLIENT_ID}/databricks-token-federation`
- Ensure the Databricks workspace URL is correct

### SQL queries fail

- Verify the SQL Warehouse ID is correct
- Check that your user has permission to access the warehouse
- Ensure the Databricks token is valid

## License

MIT
