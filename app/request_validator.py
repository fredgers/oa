import json
import logging
import logging.handlers
from datetime import datetime, timedelta
from pydantic import BaseModel, ValidationError
from typing import Annotated, List
#from oauthlib.oauth2.rfc6749.request_validator import RequestValidator
from oauthlib.openid.connect.core.request_validator import RequestValidator

import redis
from database import redis_pool, oadb, key, keys
from jwcrypto import jws
import requests

from redis.exceptions import DataError

# Create a SysLogHandler and formatter
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log', facility="local3")
formatter = logging.Formatter('%(name)s %(levelname)s: %(message)s')
syslog_handler.setFormatter(formatter)

# Create a logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(syslog_handler)

import os
from dotenv import load_dotenv
load_dotenv()

COUCH_DB_URL=os.environ["COUCH_DB_URL"]
COUCH_AUTH_VIEW_URL=os.environ["COUCH_AUTH_VIEW_URL"]
COUCH_DB_AUTH=(os.environ["COUCH_DB_USER"],os.environ["COUCH_DB_PASS"])
COUCH_VIEW_PARAMS={"include_docs": True, "reduce": False}


    # def can_grant_scopes(self, scopes):
    #     if {"openid"}.issubset(scopes) and not isinstance(self.sub, str):
    #         return False
    #     if {"email"}.issubset(scopes) and not isinstance(self.email, str):
    #         return False
    #     if {"profile"}.issubset(scopes) and not isinstance(self.nickname, str):
    #         return False
    #     return True

class Client(BaseModel):
    client_id: str
    iss: str
    valid_redirect_uris: List[str]
    valid_scopes: List[str]
    valid_grant_types: List[str]
        
r = redis.Redis(connection_pool=redis_pool)

class RV(RequestValidator):
    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        return request.req_info["redirect_uri"] == redirect_uri
    def save_bearer_token(self, token, request, *args, **kwargs):
        log.debug("save_bt: ")
        return None

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        redis_conn = redis.Redis(connection_pool=redis_pool)
        log.debug("inv_auth_cd: " + str(code))
        # r.delete(code)

    def get_authorization_code_scopes(self, client_id, code, redirect_uri, request):
        return request.grant_info.scopes

    #oidc authorization code
    def validate_client_id(self, client_id, request, *args, **kwargs):
        log.debug("val_cli_id: "+ client_id)
        try:
            client = Client.model_validate(
                [cl for cl in oadb["apps"]
             if cl["client_id"] == client_id 
                 ][0])
            request.client = client
        except IndexError as e:
            log.debug("validate_client_id error: " + str(e))
            return False
        except ValidationError as e:
            log.debug("validate_client_id error: " + str(e))
            return False
        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        log.debug("val_red_uri: " + redirect_uri)
        return {redirect_uri}.issubset(request.client.valid_redirect_uris)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return None

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        log.debug("valid resp  type "+ str(client_id) + str(response_type)+ str(client))
        return response_type == "code"

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):        
        log.debug("validate_scopes: " + str({"openid"}.issubset(scopes) and set(scopes).issubset(request.client.valid_scopes)))
        return {"openid"}.issubset(scopes) and set(scopes).issubset(request.client.valid_scopes)

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        log.debug("def scopes")
        return []

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        log.debug("sv_auth_code")
        now_utc = int(datetime.now().timestamp())
        requests.post(COUCH_DB_URL, auth=COUCH_DB_AUTH,
                      json={"type": "authorization_code", "authorization_code": code["code"],
                            "auth_k": request.auth_k, "timestamp": now_utc})

    def authenticate_client(self, request, *args, **kwargs):
        log.debug("auth cli")
        try:
            client = Client.model_validate(
                [cl for cl in oadb["apps"]
             if cl["client_id"] == request.client_id and cl["client_secret"] == request.client_secret 
                 ][0])
            request.client = client
            return True
        except (KeyError, IndexError) as e:
            log.debug("authenticate_client error: " + str(e))
            return False
    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        log.debug("validate_grant_type: " + grant_type)
        return {grant_type}.issubset(client.valid_grant_types)
    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        log.debug("validate_code   " + code)
        now_utc = int(datetime.now().timestamp())
        auth_code_duration = int(timedelta(minutes=10).total_seconds())
        try:
            r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "start_key": json.dumps(["authorization_code",code,
                                                          now_utc - auth_code_duration]),
                                 "end_key": json.dumps(["authorization_code",code,{}])})
            # authorization_code = r.json()["rows"][-1]["doc"]["auth_k"]
            auth_k = r.json()["rows"][-1]["doc"]["auth_k"]
            r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "start_key": json.dumps(["authentication_success",auth_k,0]),
                                 "end_key": json.dumps(["authentication_success",auth_k,{}])})
            authentication_success = r.json()["rows"][-1]["doc"]
            r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "start_key": json.dumps(["authentication_session",auth_k,0]),
                                 "end_key": json.dumps(["authentication_session",auth_k,{}])})
            authentication_session = r.json()["rows"][-1]["doc"]
            request.id_claims = authentication_success["id_claims"]
            request.scopes = authentication_success["req_scopes"]
            request.req_info = authentication_success["req_info"]
            request.sid = authentication_session["sid"]
            return True
        except (IndexError, KeyError, requests.exceptions.HTTPError) as e:
            return False

    def validate_silent_login(self, request):
        log.debug("val_sil_login")
        return True
    def validate_silent_authorization(self, request):
        log.debug("val_sil_auth")
        return True
    def get_authorization_code_nonce(self, client_id, code, redirect_uri, request):
        log.debug("val_auth_code_nonce")
        return None
    def finalize_id_token(self, id_token, token, token_handler, request):
        log.debug("fin_id_tok")
        # id_token["iss"] = grant_info.iss
        id_token["aud"] = request.req_info["client_id"]
        id_token["sub"] = request.id_claims["uid"]
        id_token["sid"] = request.sid
        # id_token["exp"] = id_token["iat"] + request.expires_in
        if {"email"}.issubset(request.scopes):
            id_token["email"] = request.id_claims["email"]
            id_token["email_verified"] = request.id_claims["email_verified"]
        if {"profile"}.issubset(request.scopes):
            id_token["last_name"] = request.id_claims["last_name"]
            id_token["first_name"] = request.id_claims["first_name"]
            id_token["nickname"] = request.id_claims["nickname"]
        res_bytes = json.dumps(id_token).encode('utf-8')
        jwstoken = jws.JWS(res_bytes)
        jwstoken.add_signature(key, protected={"alg": "RS256", "typ": "JWT", "kid": key.thumbprint()})
        sig = jwstoken.serialize(compact=True)
        return sig
    def validate_user_match(self, id_token_hint, scopes, claims, request):
        log.debug("val_usr_match... id_token_hint")
        return True
