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

from .request_validator import RV
from .database import redis_pool, oadb, key, keys
from redis.exceptions import DataError
import requests

from .routers import pw_reset

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
app.include_router(pw_reset.router)

# this must be randomly generated
RANDON_SESSION_ID = "iskksioskassyidd"

# This must be a lookup on user database
USER_CORRECT = ("a", "a")

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

import os
from dotenv import load_dotenv
load_dotenv()

COUCH_DB_URL=os.environ["COUCH_DB_URL"]
COUCH_AUTH_VIEW_URL=os.environ["COUCH_AUTH_VIEW_URL"]
COUCH_USR_VIEW_URL=os.environ["COUCH_USR_VIEW_URL"]
COUCH_INVALIDATE_URL=os.environ["COUCH_INVALIDATE_URL"]
COUCH_TIMESTAMP_URL=os.environ["COUCH_TIMESTAMP_URL"]
COUCH_DB_AUTH=(os.environ["COUCH_DB_USER"],os.environ["COUCH_DB_PASS"])
COUCH_VIEW_PARAMS={"include_docs": True, "reduce": False}

# session_duration = int(timedelta(seconds=5).total_seconds())
auth_request_duration = int(timedelta(hours=3).total_seconds())
session_duration = int(timedelta(days=7).total_seconds())

@app.get("/authorize")
def ath(request: Request, scope: str = None,
        # auth_k : Annotated[str | None, Cookie()] = None):
        auth_k : Annotated[str, Cookie()] = secrets.token_urlsafe(32)):
    request_scopes, request_info = ae.validate_authorization_request(str(request.url))
    now_utc = int(datetime.now().timestamp())
    try:
        r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "start_key": json.dumps(["authentication_success",auth_k, now_utc - session_duration]),
                                 "end_key": json.dumps(["authentication_success",auth_k,{}])})
        authentication_success = r.json()["rows"][-1]["doc"]
        h, c, s = ae.create_authorization_response(str(request.url),
                                                   credentials=request_info | {"auth_k": auth_k},
                                                   scopes=request_scopes)
        requests.put(COUCH_TIMESTAMP_URL + "/" + authentication_success["_id"], auth=COUCH_DB_AUTH)
        requests.post(COUCH_DB_URL, auth=COUCH_DB_AUTH,
                      json={"type": "authentication_session", "auth_k": auth_k,
                            "sid": secrets.token_urlsafe(16), "timestamp": now_utc})
        response = Response(c, headers=h, status_code=s)
    except (IndexError, KeyError, requests.exceptions.HTTPError) as e:
        requests.post(COUCH_DB_URL, auth=COUCH_DB_AUTH,
                      json={"type": "authentication_request",
                            "req_scopes": request_scopes, "req_info":
                            {key: value for key, value in request_info.items() if key not in ['request','prompt']},
                            "auth_k": auth_k, "req_url": str(request.url),
                            "timestamp": now_utc})
        response = RedirectResponse(url="/login", status_code=302)
    response.set_cookie(key="auth_k", value=auth_k,
                        max_age=session_duration,
                        httponly=True, secure=True)
    return response        

@app.get("/login")
def login_get(request: Request, auth_k : Annotated[str | None, Cookie()] = None):
    now_utc = int(datetime.now().timestamp())
    try:
        r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "start_key": json.dumps(["authentication_request",auth_k,now_utc - auth_request_duration]),
                                 "end_key": json.dumps(["authentication_request",auth_k,{}])})
        r.json()["rows"][-1]["doc"]["auth_k"]
        return templates.TemplateResponse(
            request=request, name="login.djhtml", context={})
    
    except (IndexError, KeyError, requests.exceptions.HTTPError) as e:
        response = PlainTextResponse(str(e))
        # response = RedirectResponse(url="/tenant_error_page", status_code=302)
        return response

@app.post("/login")
def login_post(request: Request,  state: str = None,
                    username: Annotated[str, Form()] = None,
                    password: Annotated[str, Form()] = None,
                    auth_k : Annotated[str | None, Cookie()] = None):
    now_utc = int(datetime.now().timestamp())
    try:
        r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params=COUCH_VIEW_PARAMS | {"start_key": json.dumps(["authentication_request",auth_k,now_utc - auth_request_duration]),
                                                     "end_key": json.dumps(["authentication_request",auth_k,{}])})
        authentication_request = r.json()["rows"][-1]["doc"]
        try:
            r = requests.get(COUCH_USR_VIEW_URL, auth=COUCH_DB_AUTH,
                             params={"include_docs": True, "reduce": False,
                                     "key": json.dumps(["email",username])}).json()["rows"]
            assert r
            user = r[-1]["doc"]
            assert user["password"] == password
        except AssertionError as e:
            response = templates.TemplateResponse(
                request=request, name="login.djhtml", context={"username": username,
                                                               "password": password,
                                                               "form_error": True})
            return response
        new_auth_k = secrets.token_urlsafe(32)
        requests.post(COUCH_DB_URL, auth=COUCH_DB_AUTH,
                      json=authentication_request | {"type": "authentication_success",
                                                     "id_claims": {"uid": user["uid"],
                                                                   "email": user["email"],
                                                                   "email_verified": user["email_verified"],
                                                                   "first_name": user["first_name"],
                                                                   "last_name": user["last_name"],
                                                                   "nickname": user["nickname"]},
                                                    "auth_k": new_auth_k, "timestamp": now_utc})
        response = RedirectResponse(url=authentication_request["req_url"], status_code=302)
        response.set_cookie(key="auth_k", value=new_auth_k,
                            max_age=session_duration,
                            httponly=True, secure=True)
        return response
    except (IndexError, KeyError, requests.exceptions.HTTPError) as e:
        response = PlainTextResponse(str(e))
        return response    

class Sess(BaseModel):
    sid: str

@app.post("/logout")
async def session_logout(request: Request, sess: Sess):
    try:
        r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "start_key": json.dumps(["authentication_session",sess.sid,0]),
                                 "end_key": json.dumps(["authentication_session",sess.sid,{}])})
        auth_k = r.json()["rows"][-1]["doc"]["auth_k"]
        r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "start_key": json.dumps(["authentication_success",auth_k,0]),
                                 "end_key": json.dumps(["authentication_success",auth_k,{}])})
        authentication_success = r.json()["rows"][-1]["doc"]
        r = requests.put(COUCH_INVALIDATE_URL + "/" + authentication_success["_id"], auth=COUCH_DB_AUTH)
        return {"status": "logged out"}
    except (IndexError, KeyError, requests.exceptions.HTTPError) as e:
        print(e)
        return {"status": "error"}
    
@app.get("/.well-known/jwks.json")
def jwks():
    return keys.export(private_keys=False, as_dict=True)

