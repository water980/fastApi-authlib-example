# FastAPI OAuth2 Integration

A simple example demonstrating how to integrate Authlib's OAuth2 Authorization Server with FastAPI. Pull request #977
`https://github.com/authlib/authlib/pull/977`

This example covers:

- OAuth2 server initialization
- Client authentication
- Token generation
- Authorization and token endpoints


## Testing the OAuth2 Flow

The following commands demonstrate how to test the OAuth2 authorization code flow using `curl`.

### 1. Request an Authorization Code

Send a request to the authorization endpoint:

```bash
curl -i "http://127.0.0.1:8000/oauth/authorize?response_type=code&client_id=my-client-id&redirect_uri=http://localhost:3000/callback&scope=profile"
```

The server responds with an HTTP `302 Found` redirect. The `Location` header contains the authorization code:

```http
HTTP/1.1 302 Found
Location: http://localhost:3000/callback?code=YOUR_CODE
```

Replace `YOUR_CODE` in the following request with the actual authorization code returned by the server.

### 2. Exchange the Authorization Code for Tokens

```bash
curl -X POST "http://127.0.0.1:8000/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_CODE" \
  -d "client_id=my-client-id" \
  -d "client_secret=my-secret" \
  -d "redirect_uri=http://localhost:3000/callback"
```

A successful response contains an access token and a refresh token:

```json
{
  "token_type": "Bearer",
  "access_token": "YOUR_ACCESS_TOKEN",
  "expires_in": 3600,
  "refresh_token": "YOUR_REFRESH_TOKEN",
  "scope": "profile"
}
```

### 3. Access a Protected Endpoint

Use the access token to make an authenticated request to the protected `/user` endpoint:

```bash
curl "http://localhost:8000/user" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Example response:

```json
{
  "user_id": 1
}
```

Replace `YOUR_ACCESS_TOKEN` with the actual access token returned in step 2.

**Note:** These examples assume the authorization server is running locally on port `8000` and that the client is configured with the example credentials shown above. The authorization code must be exchanged for tokens before it expires or is used again.
