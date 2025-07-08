import tomllib
import json
import datetime
import secrets
from jwcrypto import jwk, jws
from contextlib import asynccontextmanager
# import redis.asyncio as redis
import redis
#from redis.asyncio.connection import ConnectionPool
from redis.exceptions import DataError
from urllib import parse
from typing import Annotated

from fastapi import FastAPI, Response, Request, Cookie, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi import Request, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse, PlainTextResponse, JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from pydantic import BaseModel, ValidationError
from oauthlib.oauth2 import FatalClientError, OAuth2Error
from oauthlib.oauth2.rfc6749.endpoints import TokenEndpoint, AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.tokens import BearerToken, signed_token_generator
from oauthlib.oauth2.rfc6749.utils import scope_to_list
from oauthlib.oauth2.rfc6749.clients import WebApplicationClient
from oauthlib.oauth2.rfc6749.grant_types import ClientCredentialsGrant
#from oauthlib.oauth2.rfc6749.request_validator import RequestValidator
from oauthlib.openid.connect.core.request_validator import RequestValidator
from oauthlib.oauth2.rfc6749.errors import FatalClientError, InvalidRequestError, OAuth2Error, LoginRequired
from oauthlib.openid.connect.core.exceptions import OpenIDClientError
from oauthlib.openid.connect.core.tokens import JWTToken
from oauthlib.openid.connect.core.grant_types import AuthorizationCodeGrant, AuthorizationCodeGrantDispatcher, AuthorizationTokenGrantDispatcher

import oauthlib.common as ocommon

# import logging
# import oauthlib
# import sys

# oauthlib.set_debug(True)
# log = logging.getLogger('oauthlib')
# log.addHandler(logging.StreamHandler(sys.stdout))
# log.setLevel(logging.DEBUG)

pool = redis.ConnectionPool.from_url(url="redis://localhost", decode_responses=True)
r = redis.Redis(connection_pool=pool)

templates = Jinja2Templates(directory="templates")

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


# @app.exception_handler(RequestValidationError)
# async def validation_exception_handler(request: Request, exc: RequestValidationError):
#     print(exc)
#     return JSONResponse(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         content={"error": "access_denied", "error_description": "Unauthorized"},
#     )

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
        #return "http://abcd"
        return None

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
        print("valid resp  type ", client_id, response_type, client)
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        return True
    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        print("save auth cd", client_id, code, request.headers)
        auth_code = AuthCode(client_id=client_id, code=code["code"],
                             redirect_uri=request.redirect_uri)
        try:
            a2 = request.headers["a2"]
            a2_db = r.get(a2)
            a2_sess = A2Session.model_validate_json(a2_db)
            r.expire(a2, int(datetime.timedelta(hours=3).total_seconds()))
            auth_code.email = a2_sess.email
            r.setex(auth_code.code, int(datetime.timedelta(minutes=10).total_seconds()),
                          auth_code.model_dump_json())
        except (DataError, ValidationError) as e:
            raise RequiresAuthentication(auth_code)
    def validate_user_match(self, id_token_hint, scopes, claims, request):
        return True
    def validate_silent_login(self, request):
        return True
    def validate_silent_authorization(self, request):
        return True

class RequiresAuthentication(Exception):
    def __init__(self, auth_code):
        self.auth_code = auth_code

class Token(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str
    audience: str
    scope: str=None

class AuthCode(BaseModel):
    client_id: str
    redirect_uri: str
    email: str=None
    scopes: list[str]=None
    code: str

class A2Session(BaseModel):
    email: str

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
aCode_disp = AuthorizationCodeGrantDispatcher(default_grant=ac, oidc_grant=ac)

def auth_session_validator(request):
    return {}
ac.custom_validators.post_auth.append(auth_session_validator)


@app.post("/token")
def tok(t: Token, request: Request):
    g = ClientCredentialsGrant(request_validator=RV())
    e = lambda r: r.expires_in
    te = TokenEndpoint("client_credentials",
                       BearerToken(token_generator=generate_signed_token, expires_in=e),
                       {"client_credentials": g,
                        "authorization_code": aCode_disp})
    h, c, s = te.create_token_response(str(request.url), body=t.model_dump())
    return Response(c, headers=h, status_code=s)

class DefaultResponseType():
    def create_authorization_response(self,_,__):
        raise FatalClientError("invalid_response_type")

ae = AuthorizationEndpoint("default", None, {"code": aCode_disp,
                                             "default": DefaultResponseType()})
@app.get("/authorize")
def ath(request: Request, a2 : Annotated[str | None, Cookie()] = None):
    auth_days = 7
    auth_secs = int(datetime.timedelta(days=auth_days).total_seconds())
    a2 = "abcd"
    try: 
        h, c, s = ae.create_authorization_response(str(request.url), headers={"a2": a2})
        return PlainTextResponse(h.get("Location"), headers=h, status_code=s)
    except RequiresAuthentication as e:
        auth_state = secrets.token_urlsafe(32)
        a2_new = secrets.token_urlsafe(32)
        r.setex(auth_state, auth_secs, json.dumps({"a2": a2_new}))
        r.setex(a2_new, auth_secs, e.auth_code.model_dump_json())
        redir = RedirectResponse(url="/u/login?state=%s" % auth_state, status_code=302)
        redir.set_cookie(key="a2", value=a2_new, max_age=auth_secs)
        return redir
    except FatalClientError as e:
        print(e)
        return PlainTextResponse("FatalClientError",400)

# import logging
# logging.getLogger().addHandler(logging.StreamHandler())
# logger = logging.getLogger('uvicorn.error')
# logging.getLogger().setLevel(logging.DEBUG)


@app.get("/authorize/resume")
def id_srv2_get(request: Request, state: str | None = None):
    print(state)
    return PlainTextResponse("ath")

@app.get("/u/login")
def id_srv_get(request: Request, state: str = None, a2 : Annotated[str | None, Cookie()] = None):
    if not (r.exists(a2) and r.exists(state)):
        #try to parse, confirm client_id
        return PlainTextResponse("FatalClientError",400)
    # a2_sess = A2Session.model_validate_json(a2_db)
    # r.expire(a2, int(datetime.timedelta(hours=3).total_seconds()))
    # auth_code.email = a2_sess.email
    # r.setex(auth_code.code, int(datetime.timedelta(minutes=10).total_seconds()),
    #         auth_code.model_dump_json())
    return templates.TemplateResponse(
        request=request, name="login.djhtml", context={"id": "id"})

@app.post("/u/login")
def id_srv_post(request: Request, state: str = None, a2 : Annotated[str | None, Cookie()] = None):
    redir = RedirectResponse(url="/u/login?state=%s" % auth_state, status_code=302)
    redir.set_cookie(key="a2", value=a2_new, max_age=auth_secs)
    return redir


@app.get("/launch")
def launch():
    state = secrets.token_urlsafe(8)
    c = WebApplicationClient("cli_id_123")
    launch_url = c.prepare_request_uri("http://localhost:8000/authorize",
                                       redirect_uri="https://localhost:8000/code",
                                       scope="openid profile email",
                                       state=state)
    return RedirectResponse(url=launch_url, status_code=302)

@app.get("/.well-known/jwks.json")
def jwks():
    return keys.export(private_keys=False, as_dict=True)
