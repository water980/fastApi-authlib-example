import importlib

from authlib.common.security import generate_token
from authlib.oauth2.rfc6749 import AuthorizationCodeGrant
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from fastapi import Depends, FastAPI, Request
from pydantic import BaseModel
from authlib.integrations.fastapi_oauth2.resource_protector import (
    ResourceProtector,
)
from time import time

from authlib.oauth2.rfc6750 import BearerTokenValidator

from authlib.authlib.integrations.fastapi_oauth2.authorization_server import (
    AuthorizationServer,
)

app = FastAPI()


def import_string(import_name):
    if not isinstance(import_name, str):
        return import_name
    import_name = import_name.replace(":", ".")
    module_name, _, obj_name = import_name.rpartition(".")
    if not module_name:
        raise ImportError(f"Invalid import string {import_name!r}")
    module = importlib.import_module(module_name)
    return getattr(module, obj_name)


def create_token_expires_in_generator(expires_in_conf=None):
    if isinstance(expires_in_conf, str):
        return import_string(expires_in_conf)
    data = {}
    data.update(BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN)
    if isinstance(expires_in_conf, dict):
        data.update(expires_in_conf)

    def expires_in(client, grant_type):
        return data.get(grant_type, BearerTokenGenerator.DEFAULT_EXPIRES_IN)

    return expires_in


def create_token_generator(token_generator_conf, length=42):
    if callable(token_generator_conf):
        return token_generator_conf
    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:

        def token_generator(*args, **kwargs):
            return generate_token(length)

        return token_generator


class Client:
    def __init__(self, client_id, client_secret, redirect_uris, grant_types):
        self.client_id = client_id
        self.client_secret = client_secret
        self._redirect_uris = redirect_uris
        self._grant_types = grant_types

    def get_default_redirect_uri(self):
        return self._redirect_uris[0]

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self._redirect_uris

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        return True

    def check_grant_type(self, grant_type):
        return grant_type in self._grant_types

    def check_response_type(self, response_type):
        return response_type == "code"

    def get_allowed_scope(self, scope):
        return scope if scope else "openid"


FAKE_CLIENTS_DB = {
    "my-client-id": Client(
        client_id="my-client-id",
        client_secret="my-secret",
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code", "refresh_token"],
    )
}

AUTHORIZATION_CODES_DB = {}
TOKENS_DB = {}


def query_client(client_id):
    return FAKE_CLIENTS_DB.get(client_id)


def save_token(token, request):
    access_token = token.get("access_token")
    TOKENS_DB[access_token] = {
        "client_id": request.client.client_id,
        "user_id": request.user.id if request.user else None,
        **token,
    }
    print(f"Token saved successfully: {token}")


OAUTH2_CONFIG = {
    "OAUTH2_ACCESS_TOKEN_GENERATOR": True,
    "OAUTH2_REFRESH_TOKEN_GENERATOR": True,
    "OAUTH2_TOKEN_EXPIRES_IN": {
        "authorization_code": 3600,
        "refresh_token": 86400 * 14,
    },
}

server = AuthorizationServer(
    config=OAUTH2_CONFIG, query_client=query_client, save_token=save_token
)


class AuthorizationCode(BaseModel):
    code: str
    client_id: str
    redirect_uri: str
    scope: str
    user_id: int

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_user_id(self):
        return self.user_id


class MyAuthorizationCodeGrant(AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        scope = getattr(request, "scope", None) or getattr(
            request.payload, "scope", "openid"
        )
        redirect_uri = getattr(request, "redirect_uri", None) or getattr(
            request.payload, "redirect_uri", ""
        )

        code_data = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            user_id=request.user.id if request.user else None,
        )
        AUTHORIZATION_CODES_DB[code] = code_data
        return code

    def query_authorization_code(self, code, client):
        code_data = AUTHORIZATION_CODES_DB.get(code)
        if code_data and code_data.client_id == client.client_id:
            return code_data
        return None

    def delete_authorization_code(self, authorization_code):
        code = getattr(authorization_code, "code", authorization_code)
        AUTHORIZATION_CODES_DB.pop(code, None)

    def authenticate_user(self, authorization_code):
        class User:
            def __init__(self, user_id):
                self.id = user_id

        if authorization_code.user_id:
            return User(authorization_code.user_id)
        return None


server.register_grant(MyAuthorizationCodeGrant)




class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        token_data = TOKENS_DB.get(token_string)

        if not token_data:
            return None

        class Token:
            def __init__(self, data):
                self.access_token = data["access_token"]
                self.client_id = data["client_id"]
                self.user_id = data["user_id"]
                self.scope = data.get("scope", "")
                self.expires_at = data.get("expires_at")
                self.revoked = data.get("revoked", False)

            def get_scope(self):
                return self.scope

            def is_expired(self):
                return self.expires_at is not None and self.expires_at < time()

            def is_revoked(self):
                return self.revoked

        return Token(token_data)



require_oauth = ResourceProtector()
require_oauth.register_token_validator(MyBearerTokenValidator())


@app.get("/oauth/authorize")
async def authorize(request: Request):
    class MockUser:
        id = 1
        username = "admin"

    grant_user = MockUser()
    return await server.create_authorization_response(request, grant_user=grant_user)


@app.post("/oauth/token")
async def issue_token(request: Request):
    return await server.create_token_response(request)


@app.get("/user")
async def get_user(token=Depends(require_oauth(["profile"]))):
    return {
        "user_id": token.user_id,
    }
