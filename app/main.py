import tomllib
import requests
import json
from datetime import datetime, timedelta
import secrets
from jwcrypto import jwk, jws
from contextlib import asynccontextmanager
# import redis.asyncio as redis
import redis
#from redis.asyncio.connection import ConnectionPool
from redis.exceptions import DataError
from urllib import parse
from typing import Annotated, List, Optional
from requests_oauthlib import OAuth2Session

from fastapi import FastAPI, Response, Request, Cookie, status, Form
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi import Request, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse, PlainTextResponse, JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from pydantic import BaseModel, ValidationError
from oauthlib.oauth2 import FatalClientError, OAuth2Error
import oauthlib.oauth2
import oauthlib.common
#from oauthlib.common import Request as oauthlib_Request
from oauthlib.oauth2.rfc6749.endpoints import TokenEndpoint, AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.tokens import BearerToken, signed_token_generator
from oauthlib.oauth2.rfc6749.utils import scope_to_list
from oauthlib.oauth2.rfc6749.clients import WebApplicationClient
from oauthlib.oauth2.rfc6749.grant_types import ClientCredentialsGrant, AuthorizationCodeGrant
#from oauthlib.oauth2.rfc6749.request_validator import RequestValidator
from oauthlib.openid.connect.core.request_validator import RequestValidator
from oauthlib.oauth2.rfc6749.errors import FatalClientError, InvalidRequestError, OAuth2Error, LoginRequired
from oauthlib.openid.connect.core.exceptions import OpenIDClientError
from oauthlib.openid.connect.core.tokens import JWTToken
import oauthlib.openid.connect.core.grant_types as openid_grant_types


import logging
import oauthlib
import sys
import logging.handlers

# Create a SysLogHandler and formatter
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log', facility="local3")
formatter = logging.Formatter('%(name)s %(levelname)s: %(message)s')
syslog_handler.setFormatter(formatter)

oauthlib.set_debug(True)
oauthlib_log = logging.getLogger('oauthlib')
oauthlib_log.setLevel(logging.DEBUG)
oauthlib_log.addHandler(syslog_handler)

# Create a logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(syslog_handler)

# Log messages of different severity levels
# log.debug('This is a debug message')
log.info('=-=-=-  This is an info message! -=-=-=')
# log.warning('This is a warning message')
# log.error('This is an error message')
# log.critical('This is a critical message')


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
USER_CORRECT = ("a", "a")

# This must be Redis, Memcached, SQLite, KV, etc...
SESSION_DB = {}


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


# @app.get("/", dependencies=[Depends(get_auth_user)])
# async def secret():
#     return {"secret": "info"}


# @app.exception_handler(RequestValidationError)
# async def validation_exception_handler(request: Request, exc: RequestValidationError):
#     print(exc)
#     return JSONResponse(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         content={"error": "access_denied", "error_description": "Unauthorized"},
#     )

class Client():
  def __init__(self, client_id):
    self.client_id = client_id
    

class RV(RequestValidator):
    def authenticate_client(self, request, *args, **kwargs):
        log.debug("auth cli")
        client_id = request.client_id
        client_secret = request.client_secret
        try:
            c = [cl for cl in oadb["apps"]
             if cl["client_id"] == client_id and cl["client_secret"] == client_secret
                 ][0]                        
            request.client = Client(client_id)
            request.expires_in = 86400
        except (KeyError, IndexError) as e:
            log.debug("authenticate_client error: " + str(e))
            return False
        return True
    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        log.debug("validate_grant_type: " + grant_type)
        # if type(client.grant_type) is not list: client_grant_type = [ client.grant_type ]
        # return grant_type in client_grant_type
        return True
    def get_default_scopes(self, client_id, request, *args, **kwargs):
        log.debug("get_def_scopes")
        # return request.client.scopes
        return ["ab", "cd", "xy"]
    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        log.debug("validate_scopes")
        return True
        # only for client_credentials... no client in auth_code
        # need get_client from client_id method
        # return set(scopes).issubset(client.scopes)
    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        log.debug("validate_code")
        try:
            c_json = r.get(code)
            ri = RequestInfo.model_validate_json(c_json)
            if ri.client_id != client_id:
                return False
            request.user = "fred"
            request.scopes = ri.scopes
            request.claims = {"claim1": "claim_1", "email": "fred.gerson@furumichi.co.jp", "scopes": ri.scopes}
            return True
        except (DataError, ValidationError) as e:
            return False
    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        log.debug("confirm_redirect_uri")
        try:
            c_json = r.get(code)
            ri = RequestInfo.model_validate_json(c_json)
            if ri.redirect_uri != redirect_uri:
                return False
            return True
        except (DataError, ValidationError) as e:
            return False
    def save_bearer_token(self, token, request, *args, **kwargs):
        log.debug("save_bt: ")
        return None

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        log.debug("inv_auth_cd: ")
        r.delete(code)
    #oidc
    def validate_client_id(self, client_id, request, *args, **kwargs):
        log.debug("val_cli_id: "+ client_id)
        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        log.debug("val_red_uri: " + client_id + redirect_uri)
        return True

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        log.debug("get def red uri")
        #return "http://abcd"
        return None

    # def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
    #     log.debug("valid scopes")
    #     # Is the client allowed to access the requested scopes?
    #     return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        log.debug("def scopes")
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        return "bc de"

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        log.debug("valid resp  type "+ str(client_id) + str(response_type)+ str(client))
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        return response_type == "code"
    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        pass
    def validate_user_match(self, id_token_hint, scopes, claims, request):
        return True
    def validate_silent_login(self, request):
        return True
    def validate_silent_authorization(self, request):
        return True
    def get_authorization_code_scopes(self, client_id, code, redirect_uri, request):
        log.debug("auth_code_scopes")
        try:
            c_json = r.get(code)
            ri = RequestInfo.model_validate_json(c_json)
            return ri.scopes
        except (DataError, ValidationError) as e:
            return []
    def get_authorization_code_nonce(self, client_id, code, redirect_uri, request):
        return None
    def finalize_id_token(self, id_token, token, token_handler, request):
        log.debug("f_idt: " + str(id_token))
        log.debug("f_idt: " + str(token))
        log.debug("f_idt claims: " + str(request.claims))
        return generate_signed_token(request)

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
    now = datetime.utcnow()
    exp = now + timedelta(seconds=request.expires_in)

    claims = {
        'iss': request.uri,
        # 'aud': request.client.audience,
        # 'sub': request.client_id,
        'aud': request.client_id,
        'sub': request.user,
        # 'scope': " ".join(request.scopes),
        'iat': int(now.timestamp()),
        'exp': int(round(exp.timestamp())),
        "gty": request.grant_type,
        # 'permissions': scope_to_list(request.scope)
    }

    claims.update(request.claims or {})
    res_bytes = json.dumps(claims).encode('utf-8')
    jwstoken = jws.JWS(res_bytes)
    jwstoken.add_signature(key, protected={"alg": "RS256", "typ": "JWT", "kid": key.thumbprint()})
    sig = jwstoken.serialize(compact=True)
    return sig

ac = AuthorizationCodeGrant(request_validator=RV(), refresh_token=False)
o_ac = openid_grant_types.AuthorizationCodeGrant(request_validator=RV(), refresh_token=False)
aCode_disp = openid_grant_types.AuthorizationCodeGrantDispatcher(default_grant=ac, oidc_grant=ac)
aTok_disp = openid_grant_types.AuthorizationTokenGrantDispatcher(RV(),default_grant=ac, oidc_grant=o_ac)

def auth_session_validator(request):
    return {}
ac.custom_validators.post_auth.append(auth_session_validator)

g = ClientCredentialsGrant(request_validator=RV())
e = lambda r: r.expires_in
te = TokenEndpoint("client_credentials",
                   BearerToken(expires_in=e),
                   {"client_credentials": g,
                    "authorization_code": aTok_disp})

async def get_body(request: Request):
    return await request.body()

@app.post('/token')
def submit(request: Request, body = Depends(get_body)):
    h, c, s = te.create_token_response(str(request.url), body=body)
    return Response(c, headers=h, status_code=s)


client_id = "tst"
client_secret = "Zz"
c = WebApplicationClient(client_id)

@app.get("/code")
def code(request: Request, auth_state : Annotated[str, Cookie()]):
    try:
        state = r.get(auth_state)
        # code_map = c.parse_request_uri_response(str(request.url), state=state)
        # req_body = c.prepare_request_body(code=code_map["code"], redirect_uri="https://le1.hakofudo.com/code",include_client_id=True)
        # tkn_resp = requests.post("https://le1.hakofudo.com/token",body=req_body)
        # log.debug(tkn_resp)
        token_url = "https://le1.hakofudo.com/token"
        tkn_cli = OAuth2Session(client_id, state=state, redirect_uri="https://le1.hakofudo.com/code")
        tkn_resp = tkn_cli.fetch_token(token_url, authorization_response=str(request.url),
                                       include_client_id=True, client_secret=client_secret)
        r.delete(auth_state)
        response = PlainTextResponse(str(tkn_resp))
        response.delete_cookie(auth_state)
        return response
    except (oauthlib.oauth2.MismatchingStateError, oauthlib.oauth2.MissingCodeError) as e:
        return PlainTextResponse(str(e))


class DefaultResponseType():
    def validate_authorization_request(self,_):
        raise FatalClientError("invalid_response_type")

ae = AuthorizationEndpoint("default", None, {"code": aCode_disp,
                                             "default": DefaultResponseType()})

class RequiresAuthentication(Exception):
    pass

class LoginStateMismatch(Exception):
    pass

class RequestInfo(BaseModel):
    client_id: str
    redirect_uri: str
    response_type: str
    state: str
    login_state: str
    scopes: List[str] = []
    nickname: str | None = None 
    email: str | None = None 
    sub: str | None = None
    auth_code: str | None = None
    auth_code_exp: int = 0
    form_username: str = ""
    form_password: str = ""
    form_error_msg: bool = False

@app.get("/authorize")
def ath(request: Request, auth_sess : Annotated[str | None, Cookie()] = None):
    try:
        scopes, request_info = ae.validate_authorization_request(str(request.url))
        try:
            s_json = r.get(auth_sess)
            ri = RequestInfo.model_validate_json(s_json)
            log.debug("value of ri: " + str(ri))
            if request_info["client_id"] != ri.client_id or \
               request_info["redirect_uri"] != ri.redirect_uri or \
               not (ri.sub and ri.email and ri.nickname) or \
               ri.auth_code or \
               ri.scopes.sort() != ri.scopes.sort():
                raise RequiresAuthentication()
            auth_code = secrets.token_urlsafe(16)
            redirect_uri = oauthlib.common.add_params_to_uri(ri.redirect_uri, {"code": auth_code, "state": ri.state})
            response = RedirectResponse(url=redirect_uri, status_code=302)
            session_cookie_value = secrets.token_urlsafe(32)
            response.set_cookie(key="auth_sess", value=session_cookie_value,
                                max_age=int(timedelta(hours=3).total_seconds()),
                                httponly=True, secure=True)
            r.setex(session_cookie_value, int(timedelta(hours=3).total_seconds()), ri.model_dump_json())
            ri.auth_code = auth_code
            ri.auth_code_exp = int((datetime.utcnow() + timedelta(minutes=10)).timestamp())
            r.setex(auth_code, int(timedelta(minutes=10).total_seconds()), ri.model_dump_json())
            return response
        except (DataError, ValidationError, RequiresAuthentication) as e:
            ri = RequestInfo.model_validate(request_info | {"scopes": scopes, "login_state": secrets.token_urlsafe(32)})
            session_cookie_value = secrets.token_urlsafe(32)
            response = RedirectResponse(url="/u/login?state=%s" % ri.login_state, status_code=302)
            response.set_cookie(key="auth_sess", value=session_cookie_value,
                                max_age=int(timedelta(days=7).total_seconds()),
                                httponly=True, secure=True)
            r.setex(session_cookie_value, int(timedelta(days=7).total_seconds()), ri.model_dump_json())
            return response
            # raise RequiresAuthentication(auth_code)
    except oauthlib.oauth2.FatalClientError as e:
        return PlainTextResponse("FatalClientError",400)
    except oauthlib.oauth2.OAuth2Error as e:
        redirect_uri = oauthlib.common.add_params_to_uri(e.redirect_uri, e.twotuples)
        return RedirectResponse(redirect_uri, status_code=302)
    # except Exception as e:
    #     return PlainTextResponse(str(e), 200)


@app.get("/authorize/resume")
def resume_get(request: Request, state: str = None, auth_sess : Annotated[str | None, Cookie()] = None):
    try:
        s_json = r.get(auth_sess)
        ri = RequestInfo.model_validate_json(s_json)
        if ri.login_state != state:
            raise LoginStateMismatch()
        r.delete(auth_sess)
        session_cookie_value = secrets.token_urlsafe(32)
        auth_code = secrets.token_urlsafe(16)
        redirect_uri = oauthlib.common.add_params_to_uri(ri.redirect_uri, {"code": auth_code, "state": ri.state})
        response = RedirectResponse(url=redirect_uri, status_code=302)
        response.set_cookie(key="auth_sess", value=session_cookie_value,
                            max_age=int(timedelta(hours=3).total_seconds()),
                            httponly=True, secure=True)
        r.setex(session_cookie_value, int(timedelta(hours=3).total_seconds()), ri.model_dump_json())
        ri.auth_code = auth_code
        ri.auth_code_exp = int((datetime.utcnow() + timedelta(minutes=10)).timestamp())
        r.setex(auth_code, int(timedelta(minutes=10).total_seconds()), ri.model_dump_json())
        return response
    except (DataError, ValidationError, LoginStateMismatch) as e:
        response = PlainTextResponse(str(e))
        # response = RedirectResponse(url="/tenant_error_page", status_code=302)
        return response


@app.get("/u/login")
def login_form_get(request: Request, state: str = None, auth_sess : Annotated[str | None, Cookie()] = None):
    try:
        s_json = r.get(auth_sess)
        ri = RequestInfo.model_validate_json(s_json)
        if ri.login_state != state:
            raise LoginStateMismatch()
        # confirm client_id
        # display template response for client_id
        return templates.TemplateResponse(
            request=request, name="login.djhtml", context={"username": ri.form_username,
                                                           "password": ri.form_password,
                                                           "form_error": ri.form_error_msg,
                                                           "login_state": ri.login_state})
    except (DataError, ValidationError, LoginStateMismatch) as e:
        response = PlainTextResponse(str(e))
        # response = RedirectResponse(url="/tenant_error_page", status_code=302)
        return response

@app.post("/u/login")
def login_form_post(request: Request,  state: str = None,
                    username: Annotated[str, Form()] = None,
                    password: Annotated[str, Form()] = None,
                    login_state: Annotated[str, Form()] = None,
                    auth_sess : Annotated[str | None, Cookie()] = None):
    try:
        s_json = r.get(auth_sess)
        ri = RequestInfo.model_validate_json(s_json)
        if ri.login_state != state:
            raise LoginStateMismatch()
        allow = (username, password) == USER_CORRECT
        if allow is False:
            ri.form_username = username
            ri.form_password = password
            ri.form_error_msg = True
            response = RedirectResponse(url="/u/login?state=%s" % ri.login_state, status_code=302)
            r.set(auth_sess, ri.model_dump_json())
            return response
        ri.login_state = secrets.token_urlsafe(16)
        ri.sub = username
        response = RedirectResponse(url="/authorize/resume?state=%s" % ri.login_state, status_code=302)
        r.delete(auth_sess)
        session_cookie_value = secrets.token_urlsafe(16)
        r.setex(session_cookie_value, int(timedelta(minutes=10).total_seconds()), ri.model_dump_json())
        response.set_cookie(key="auth_sess", value=session_cookie_value,
                            max_age=int(timedelta(minutes=10).total_seconds()),
                            httponly=True, secure=True)
        return response
        # confirm client_id
        # display template response for client_id
    except (DataError, ValidationError, LoginStateMismatch) as e:
        response = PlainTextResponse(str(e))
        # response = RedirectResponse(url="/tenant_error_page", status_code=302)
        return response
    # auth_minutes = 7
    # auth_secs = int(timedelta(minutes=auth_minutes).total_seconds())
    # id_state = secrets.token_urlsafe(32)
    # id_a2 = secrets.token_urlsafe(32)

    # a2_sess = A2Session.model_validate_json(a2_db)
    # r.expire(a2, int(datetime.timedelta(hours=3).total_seconds()))
    # auth_code.email = a2_sess.email
    # r.setex(auth_code.code, int(datetime.timedelta(minutes=10).total_seconds()),
    #         auth_code.model_dump_json())

@app.get("/.well-known/jwks.json")
def jwks():
    return keys.export(private_keys=False, as_dict=True)


class AppUser(BaseModel):
    is_authenticated: bool = False
    email: str = None
    nickname: str = None
    user_id: str = None
    @property
    def display_name(self) -> str:
        return self.nickname

@app.get("/launch")
def launch():
    state = secrets.token_urlsafe(8)
    session_cookie_value = secrets.token_urlsafe(16)
    launch_url = c.prepare_request_uri("https://le1.hakofudo.com/authorize",
                                       redirect_uri="https://le1.hakofudo.com/code",
                                       scope="openid profile email",
                                       state=state)
    r.setex(session_cookie_value, int(timedelta(days=7).total_seconds()), state)
    response = RedirectResponse(url=launch_url, status_code=302)
    response.set_cookie(key="auth_state", value=session_cookie_value,
                        max_age=int(timedelta(days=7).total_seconds()),
                        httponly=True, secure=True)
    return response

@app.get("/")
def home(request: Request, app_sess : Annotated[str | None, Cookie()] = None):
    try:
        sess_json = r.get(app_sess)
        app_user = AppUser.model_validate_json(sess_json)
    except (DataError, ValueError) as e:
        app_user = AppUser(nickname="no_user")
    response = templates.TemplateResponse(
        request=request, name="home.djhtml", context={"user": app_user})
    return response

# @app.get("/authorize")
# def ath(request: Request, a2 : Annotated[str | None, Cookie()] = None):
#     auth_days = 7
#     auth_secs = int(datetime.timedelta(days=auth_days).total_seconds())
#     a2 = "abcd"
#     try: 
#         h, c, s = ae.create_authorization_response(str(request.url), headers={"a2": a2})
#         return PlainTextResponse(h.get("Location"), headers=h, status_code=s)
#     except RequiresAuthentication as e:
#         auth_state = secrets.token_urlsafe(32)
#         a2_new = secrets.token_urlsafe(32)
#         r.setex(auth_state, auth_secs, json.dumps({"a2": a2_new}))
#         r.setex(a2_new, auth_secs, e.auth_code.model_dump_json())
#         redir = RedirectResponse(url="/u/login?state=%s" % auth_state, status_code=302)
#         redir.set_cookie(key="a2", value=a2_new, max_age=auth_secs)
#         return redir
#     except FatalClientError as e:
#         print(e)
#         return PlainTextResponse("FatalClientError",400)

