import json
import logging
import logging.handlers
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Annotated, List

import oauthlib
import oauthlib.common
import oauthlib.openid.connect.core.grant_types as openid_grant_types
# import redis.asyncio as redis
import redis
from fastapi import (Cookie, Depends, FastAPI, Form, HTTPException, Request,
                     Response)
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from oauthlib.oauth2 import FatalClientError, OAuth2Error
from oauthlib.oauth2.rfc6749.utils import scope_to_list
from oauthlib.oauth2.rfc6749.clients import WebApplicationClient
#from oauthlib.common import Request as oauthlib_Request
from oauthlib.oauth2.rfc6749.endpoints import (AuthorizationEndpoint,
                                               TokenEndpoint)
from oauthlib.oauth2.rfc6749.errors import FatalClientError, InvalidScopeError
from oauthlib.oauth2.rfc6749.grant_types import (AuthorizationCodeGrant,
                                                 ClientCredentialsGrant)
from oauthlib.oauth2.rfc6749.tokens import BearerToken
#from oauthlib.oauth2.rfc6749.request_validator import RequestValidator
#from oauthlib.openid.connect.core.request_validator import RequestValidator
from pydantic import BaseModel, ValidationError
from redis.exceptions import DataError
from requests_oauthlib import OAuth2Session

from request_validator import RV, GrantInfo
from database import redis_pool, oadb, key, keys
from redis.exceptions import DataError

# Create a SysLogHandler and formatter
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log', facility="local3")
formatter = logging.Formatter('%(name)s %(levelname)s: %(message)s')
syslog_handler.setFormatter(formatter)

# oauthlib.set_debug(True)
# oauthlib_log = logging.getLogger('oauthlib')
# oauthlib_log.setLevel(logging.DEBUG)
# oauthlib_log.addHandler(syslog_handler)

# Create a logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(syslog_handler)


pool = redis.ConnectionPool.from_url(url="redis://localhost", decode_responses=True)
r = redis.Redis(connection_pool=pool)

templates = Jinja2Templates(directory="templates")

@asynccontextmanager
async def lifespan(_: FastAPI):
    yield

app = FastAPI(lifespan=lifespan, openapi_url=None, docs_url=None, redoc_url=None)


# this must be randomly generated
RANDON_SESSION_ID = "iskksioskassyidd"

# This must be a lookup on user database
USER_CORRECT = ("a", "a")


@app.post("/logout")
async def session_logout(response: Response):
    response.delete_cookie(key="Authorization")
    SESSION_DB.pop(RANDON_SESSION_ID, None)
    return {"status": "logged out"}

def get_grant_info(redis_conn, auth_sess, client_id):
    try: 
        grant_info_json = redis_conn.get(auth_sess)
        grant_info = GrantInfo.model_validate_json(grant_info_json)
        if grant_info.client_id != client_id:
            raise FatalClientError()
    except (DataError,ValidationError) as e:
        grant_info = GrantInfo.model_validate({"client_id": client_id})            
    return grant_info

o_ac = openid_grant_types.AuthorizationCodeGrant(request_validator=RV(), refresh_token=False,
                                                 pre_auth=[], post_auth=[])
g = ClientCredentialsGrant(request_validator=RV())
ae = AuthorizationEndpoint("code", None, {"code": o_ac})
te = TokenEndpoint("client_credentials",
                   BearerToken(expires_in=3600),
                   {"client_credentials": g,
                    "authorization_code": o_ac})

@app.exception_handler(oauthlib.oauth2.FatalClientError)
async def fce_exception_handler(request: Request, e: oauthlib.oauth2.FatalClientError):
    return PlainTextResponse(str(e),400)

@app.exception_handler(oauthlib.oauth2.OAuth2Error)
async def oa_exception_handler(request: Request, e: oauthlib.oauth2.OAuth2Error):
    redirect_uri = oauthlib.common.add_params_to_uri(e.redirect_uri, e.twotuples)
    return RedirectResponse(redirect_uri, status_code=302)

async def get_body(request: Request):
    return await request.body()

@app.post('/token')
def tok(request: Request, body = Depends(get_body)):
    h, c, s = te.create_token_response(str(request.url), body=body)
    return Response(c, headers=h, status_code=s)

@app.get("/authorize")
def ath(request: Request, scope: str = None,
        auth_sess : Annotated[str | None, Cookie()] = None):
    if not auth_sess:
        auth_sess = secrets.token_urlsafe(32)
    request_scopes, request_info = ae.validate_authorization_request(str(request.url))
    redis_conn = redis.Redis(connection_pool=redis_pool)
    grant_info = get_grant_info(redis_conn, auth_sess, request_info["client_id"])
    if grant_info.can_grant_scopes(request_scopes):
        h, c, s = ae.create_authorization_response(str(request.url),
                                                   credentials=request_info | {"auth_sess": auth_sess},
                                                   scopes=request_scopes)
        response = Response(c, headers=h, status_code=s)
    else:
        response = RedirectResponse(url="/login", status_code=302)
    response.set_cookie(key="auth_sess", value=auth_sess,
                        max_age=int(timedelta(days=7).total_seconds()),
                        httponly=True, secure=True)
    grant_info.authorization_request_uri = str(request.url)
    redis_conn.setex(auth_sess, int(timedelta(days=7).total_seconds()), grant_info.model_dump_json())
    return response        

@app.get("/login")
def login_get(request: Request, state: str = None, auth_sess : Annotated[str | None, Cookie()] = None):
    redis_conn = redis.Redis(connection_pool=redis_pool)
    try:
        s_json = redis_conn.get(auth_sess)
        grant_info = GrantInfo.model_validate_json(s_json)
        # confirm client_id
        # display template response for client_id
        return templates.TemplateResponse(
            request=request, name="login.djhtml", context={"username": grant_info.form_username,
                                                           "password": grant_info.form_password,
                                                           "form_error": grant_info.form_error_msg})
    except (DataError, ValidationError) as e:
        response = PlainTextResponse(str(e))
        # response = RedirectResponse(url="/tenant_error_page", status_code=302)
        return response

@app.post("/login")
def login_post(request: Request,  state: str = None,
                    username: Annotated[str, Form()] = None,
                    password: Annotated[str, Form()] = None,
                    auth_sess : Annotated[str | None, Cookie()] = None):
    redis_conn = redis.Redis(connection_pool=redis_pool)
    try:
        s_json = redis_conn.get(auth_sess)
        grant_info = GrantInfo.model_validate_json(s_json)
        allow = (username, password) == USER_CORRECT
        if allow is True:
            new_auth_sess = secrets.token_urlsafe(32)
            grant_info.sub = username
            grant_info.email = "a@b.c"
            grant_info.nickname = "fr"
            response = RedirectResponse(url=grant_info.authorization_request_uri, status_code=302)
            redis_conn.setex(new_auth_sess, int(timedelta(hours=3).total_seconds()), grant_info.model_dump_json())
            redis_conn.delete(auth_sess)
            response.set_cookie(key="auth_sess", value=new_auth_sess,
                                max_age=int(timedelta(hours=3).total_seconds()),
                                httponly=True, secure=True)
            return response
        else:
            response = templates.TemplateResponse(
                request=request, name="login.djhtml", context={"username": username,
                                                               "password": password,
                                                               "form_error": True})
            return response
    except (DataError, ValidationError) as e:
        response = PlainTextResponse(str(e))
        return response

@app.get("/logout")
def logout(request: Request,  state: str = None,
                    return_to: str = None,
                    auth_sess : Annotated[str | None, Cookie()] = None):
    redis_conn = redis.Redis(connection_pool=redis_pool)
    try:
        s_json = redis_conn.get(auth_sess)
        GrantInfo.model_validate_json(s_json)
        redis_conn.delete(auth_sess)
    except (DataError, ValidationError) as e:
        pass
    response = RedirectResponse(url=return_to, status_code=302) #default return_to
    return response
    
    
@app.get("/.well-known/jwks.json")
def jwks():
    return keys.export(private_keys=False, as_dict=True)

