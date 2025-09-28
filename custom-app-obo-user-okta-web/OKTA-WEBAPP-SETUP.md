# 🔧 Okta Web Application Setup Guide

## **Step 1: Create Okta Web Application**

### **1.1 Access Okta Admin Console**
1. Go to your Okta Admin Console: `https://integrator-9643557.okta.com/admin`
2. Login with your admin credentials

### **1.2 Create New Application**
1. Navigate to **Applications** → **Applications**
2. Click **Create App Integration**
3. Choose **OIDC - OpenID Connect**
4. Choose **Web Application** (NOT Single-Page Application)

### **1.3 Configure Application Settings**

**Basic Settings:**
```
App integration name: Databricks SQL Interface (Web App)
Logo: (optional)
```

**Grant Types:**
- ✅ **Authorization Code** (required)
- ✅ **Refresh Token** (required for session-independent tokens)
- ❌ **Implicit (Hybrid)** (not needed)
- ❌ **Client Credentials** (not needed for user auth)

**PKCE Settings:**
- ✅ **Require PKCE for public clients** (enhanced security)
- ✅ **Allow PKCE for confidential clients** (we want both PKCE + Client Secret)

**Sign-in redirect URIs:**
```
http://localhost:6000/callback
```

**Sign-out redirect URIs:**
```
http://localhost:6000/logout
```

**Controlled access:**
- Choose your preferred assignment method
- Assign to yourself or relevant groups

### **1.4 Save and Get Credentials**
1. Click **Save**
2. **Copy the Client ID** (will look like: `0oaXXXXXXXXXXXXXX`)
3. **Copy the Client Secret** (will look like: `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`)

⚠️ **Important**: Keep the Client Secret secure - it's like a password!

## **Step 2: Configure the Web App**

### **2.1 Update config.env**

Create or update `/Users/suraj.karuvel/API/external-oauth-webapp/config.env`:

```bash
# Enhanced Web Application Configuration - PKCE + Client Secret + Session-Independent Refresh Tokens
PORT=6000
FLASK_DEBUG=True
FLASK_SECRET_KEY=webapp-oauth-app-secret

# Okta Web Application Configuration (Authorization Code Flow + PKCE + Client Secret)
ISSUER_URL=https://integrator-9643557.okta.com/oauth2/ausvfdqujxnd7xdnj697
CLIENT_ID=YOUR_NEW_WEB_APP_CLIENT_ID_HERE
CLIENT_SECRET=YOUR_NEW_WEB_APP_CLIENT_SECRET_HERE
REDIRECT_URI=http://localhost:6000/callback
OAUTH_SCOPE=openid profile email all-apis offline_access

# Databricks SQL Endpoint Configuration
DATABRICKS_SERVER_HOSTNAME=dbc-c91403c4-666c.cloud.databricks.com
DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/168bbc0657bfe886
```

### **2.2 Replace Placeholders**
Replace these values with your actual Okta Web App credentials:
- `YOUR_NEW_WEB_APP_CLIENT_ID_HERE` → Your actual Client ID
- `YOUR_NEW_WEB_APP_CLIENT_SECRET_HERE` → Your actual Client Secret

## **Step 3: Test the Setup**

### **3.1 Start the Web App**
```bash
cd /Users/suraj.karuvel/API/external-oauth-webapp
python app.py
```

### **3.2 Verify Configuration**
You should see:
```
🔄 Using Authorization Code Flow with PKCE + Client Secret (session-independent refresh tokens)
Starting Web Application OAuth App on port 6000
Client ID: 0oaXXXXXXXXXXXXXX
Client Secret: ****************************************
```

### **3.3 Test OAuth Flow**
1. Open: http://localhost:6000
2. Click "Start OAuth Flow"
3. Login with your Okta credentials
4. Should redirect back to SQL interface

## **Step 4: Compare with SPA**

### **Key Differences You'll See:**

| Aspect | SPA (Port 5000) | Enhanced Web App (Port 6000) |
|--------|-----------------|------------------------------|
| **Authorization URL** | Has `code_challenge` | Has `code_challenge` + `client_id` |
| **Token Exchange** | Uses `code_verifier` | Uses `code_verifier` + `client_secret` |
| **Security Level** | High (PKCE only) | Maximum (PKCE + Client Secret) |
| **Refresh Behavior** | Fails after Okta logout | Works after Okta logout |

### **Test Session Independence:**
1. **Login to Web App** (port 6000)
2. **Execute SQL queries** (should work)
3. **Open new tab** → Logout of Okta
4. **Return to Web App** → **Execute more queries**
5. **Result**: ✅ Should still work (session-independent!)

## **Troubleshooting**

### **Common Issues:**

**1. "Client authentication failed"**
- Check Client ID and Client Secret are correct
- Ensure you're using Web Application (not SPA) credentials

**2. "Redirect URI mismatch"**
- Verify redirect URI in Okta matches: `http://localhost:6000/callback`
- Check port number is 6000

**3. "Invalid grant"**
- This is expected if you try to use SPA credentials with Web App flow
- Create a new Web Application in Okta

---

## **Ready to Proceed?**

Once you have:
1. ✅ Created Okta Web Application
2. ✅ Copied Client ID and Client Secret
3. ✅ Updated config.env

We can test the session-independent refresh token behavior! 🚀
