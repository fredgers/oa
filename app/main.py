import tomllib
import json
import datetime
import secrets
from jwcrypto import jwk, jws
from contextlib import asynccontextmanager
import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool
from urllib import parse

from fastapi import FastAPI, Response, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from pydantic import BaseModel
from oauthlib.oauth2 import FatalClientError, OAuth2Error
from oauthlib.oauth2.rfc6749.endpoints import TokenEndpoint, AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.tokens import BearerToken, signed_token_generator
from oauthlib.oauth2.rfc6749.utils import scope_to_list
from oauthlib.oauth2.rfc6749.clients import WebApplicationClient
from oauthlib.oauth2.rfc6749.grant_types import ClientCredentialsGrant, AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator
from oauthlib.oauth2.rfc6749.errors import FatalClientError, InvalidRequestError, OAuth2Error
from oauthlib.openid.connect.core.grant_types import AuthorizationCodeGrantDispatcher
from oauthlib.openid.connect.core.tokens import JWTToken
from oauthlib.openid.connect.core.grant_types.dispatchers import AuthorizationCodeGrantDispatcher, AuthorizationTokenGrantDispatcher

import oauthlib.common as ocommon

# import logging
# import oauthlib
# import sys

# oauthlib.set_debug(True)
# log = logging.getLogger('oauthlib')
# log.addHandler(logging.StreamHandler(sys.stdout))
# log.setLevel(logging.DEBUG)

pool = ConnectionPool.from_url(url="redis://localhost", decode_responses=True)
r = redis.Redis(connection_pool=pool)

@asynccontextmanager
async def lifespan(_: FastAPI):
    yield



app = FastAPI(lifespan=lifespan)

f = open("key.pem","rb")
k = f.read()
key = jwk.JWK.from_pem(k, password=None)
keys = jwk.JWKSet()
keys.add(key)

with open("oadb.toml", "rb") as f:
    oadb = tomllib.load(f)

from fastapi import Request, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse

# This must be randomly generated
RANDON_SESSION_ID = "iskksioskassyidd"

# This must be a lookup on user database
USER_CORRECT = ("admin", "admin")

# This must be Redis, Memcached, SQLite, KV, etc...
SESSION_DB = {}


@app.post("/login")
async def session_login(username: str, password: str):
    """/login?username=ssss&password=1234234234"""
    allow = (username, password) == USER_CORRECT
    if allow is False:
        raise HTTPException(status_code=401)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(key="Authorization", value=RANDON_SESSION_ID)
    SESSION_DB[RANDON_SESSION_ID] = username
    return response


@app.post("/logout")
async def session_logout(response: Response):
    response.delete_cookie(key="Authorization")
    SESSION_DB.pop(RANDON_SESSION_ID, None)
    return {"status": "logged out"}


def get_auth_user(request: Request):
    """verify that user has a valid session"""
    session_id = request.cookies.get("Authorization")
    if not session_id:
        raise HTTPException(status_code=401)
    if session_id not in SESSION_DB:
        raise HTTPException(status_code=403)
    return True


@app.get("/", dependencies=[Depends(get_auth_user)])
async def secret():
    return {"secret": "info"}


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"error": "access_denied", "error_description": "Unauthorized"},
    )

class Client():
  def __init__(self, client_id, audience, scopes, grant_type):
    self.client_id = client_id
    self.audience = audience
    self.scopes = scopes
    self.grant_type = grant_type
    

class RV(RequestValidator):
    def authenticate_client(self, request, *args, **kwargs):
        print("auth cli")
        client_id = request.client_id
        client_secret = request.client_secret
        audience = request.audience
        try:
            c = [cl for cl in oadb["apps"]
             if cl["client_id"] == client_id and cl["client_secret"] == client_secret and cl["audience"] == audience
                 ][0]                        
            request.client = Client(client_id, audience, c["scopes"], c["grant_type"])
            request.expires_in = 86400
        except (KeyError, IndexError):
            return False
        return True
    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        print("grant_type: ", grant_type, client.grant_type)
        if type(client.grant_type) is not list: client_grant_type = [ client.grant_type ]
        return grant_type in client_grant_type
    def get_default_scopes(self, client_id, request, *args, **kwargs):
        print("def_scopes")
        return request.client.scopes
    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        print("val_scopes")
        return set(scopes).issubset(client.scopes)
    def save_bearer_token(self, token, request, *args, **kwargs):
        print("save_bt: ", token, request, args, kwargs)
        return None
    #oidc
    def validate_client_id(self, client_id, request, *args, **kwargs):
        print("val_cli_id: ", client_id)
        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        print("val_red_uri: ", client_id, redirect_uri)
        return True

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        print("get def red uri")
        return "http://abcd"

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        print("valid scopes")
        # Is the client allowed to access the requested scopes?
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        print("def scopes")
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        return "bc de"

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        print("valid resp  type")
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        return True
    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        print("save auth cd", client_id, code)
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        pass

class Token(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str
    audience: str
    scope: str=None

def generate_signed_token(request):
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(seconds=request.expires_in)

    claims = {
        'iss': request.uri,
        'aud': request.client.audience,
        'sub': request.client_id,
        'scope': request.scope,
        'iat': int(now.timestamp()),
        'exp': int(round(exp.timestamp())),
        "gty": request.grant_type,
        'permissions': scope_to_list(request.scope)
    }

    claims.update(request.claims or {})
    res_bytes = json.dumps(claims).encode('utf-8')
    jwstoken = jws.JWS(res_bytes)
    jwstoken.add_signature(key, protected={"alg": "RS256", "typ": "JWT", "kid": key.thumbprint()})
    sig = jwstoken.serialize(compact=True)
    return sig

ac = AuthorizationCodeGrant(request_validator=RV())
ac2 = AuthorizationCodeGrant(request_validator=RV())
aCode_disp = AuthorizationCodeGrantDispatcher(default_grant=ac, oidc_grant=ac2)

@app.post("/token")
async def tok(t: Token, request: Request):
    g = ClientCredentialsGrant(request_validator=RV())
    e = lambda r: r.expires_in
    te = TokenEndpoint("client_credentials",
                       BearerToken(token_generator=generate_signed_token, expires_in=e),
                       {"client_credentials": g,
                        "authorization_code": aCode_disp})
    h, c, s = te.create_token_response(str(request.url), body=t.model_dump())
    return Response(c, headers=h, status_code=s)

ae = AuthorizationEndpoint("code", None, {"code": aCode_disp})

@app.get("/authorize")
async def ath(request: Request):
    try: 
        sc, ri = ae.validate_authorization_request(str(request.url))
    except FatalClientError as e:
        print(e)
    except InvalidRequestError as e:
        print(e)
    except OAuth2Error as e:
        print(e)
    a1state = secrets.token_urlsafe(64)
    print("--")
    print(sc)
    print(ri)
    h, c, s = ae.create_authorization_response(str(request.url))
    print("==")
    print(str(request.url))
    print("=***=")
    await r.setex(a1state, 30, json.dumps({}))
    # response.set_cookie(key="idSrv", value=a1state)
    # h, c, s = ae.create_authorization_response(str(request.url))
    # return Response(c, headers=h, status_code=s)
    return "/u/login?%s" % parse.urlencode({"state": a1state})

@app.get("/u/login")
def id_srv_get():
    pass

@app.get("/u/login")
def id_srv_post():
    pass


@app.get("/launch")
def launch():
    c = WebApplicationClient("cli_id_123")
    print(c.prepare_request_uri("https://localhost:8000/authorize",
                                redirect_uri="https://localhost:8000/code",
                                scope="openid profile email",
                                state="mystate"))
    return {}

@app.get("/.well-known/jwks.json")
def jwks():
    return keys.export(private_keys=False, as_dict=True)
