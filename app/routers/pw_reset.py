import requests
import json
import secrets

from fastapi import APIRouter
from fastapi import (Cookie, Depends, FastAPI, Form, HTTPException, Request,
                     Response)
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Annotated, List
from datetime import datetime, timedelta

from ..dependencies import get_token_header

router = APIRouter()

import os
from dotenv import load_dotenv
load_dotenv()

COUCH_DB_URL=os.environ["COUCH_DB_URL"]
COUCH_AUTH_VIEW_URL=os.environ["COUCH_AUTH_VIEW_URL"]
COUCH_USR_VIEW_URL=os.environ["COUCH_USR_VIEW_URL"]
COUCH_INVALIDATE_URL=os.environ["COUCH_INVALIDATE_URL"]
COUCH_TIMESTAMP_URL=os.environ["COUCH_TIMESTAMP_URL"]
COUCH_DB_AUTH=(os.environ["COUCH_DB_USER"],os.environ["COUCH_DB_PASS"])
SMTP_LOGIN_USERNAME=os.environ["SMTP_LOGIN_USERNAME"]
SMTP_LOGIN_PASSWORD=os.environ["SMTP_LOGIN_PASSWORD"]
SMTP_SERVER=os.environ["SMTP_SERVER"]
PW_RESET_FROM_EMAIL=os.environ["PW_RESET_FROM_EMAIL"]
PW_RESET_HOST=os.environ["PW_RESET_HOST"]


templates = Jinja2Templates(directory="templates")

# @router.get("/email")
# def email_get(request: Request, auth_k : Annotated[str|None, Cookie()] = None):
#     t = templates.get_template("email/pw_reset.txt")
#     print(t)
#     print(t.render(reset_link="http://localhost:8111/link?token=abc123f"))
#     response = PlainTextResponse(str("e"))
#     return response    
    

@router.get("/start")
def start_get(request: Request, auth_k : Annotated[str|None, Cookie()] = None):
    try:
        r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "start_key": json.dumps(["authentication_request",auth_k,0]),
                                 "end_key": json.dumps(["authentication_request",auth_k,{}])})
        authentication_request = r.json()["rows"][-1]["doc"]
        return templates.TemplateResponse(
            request=request, name="pw_reset/start.djhtml", context={})
    except (IndexError, KeyError, requests.exceptions.HTTPError) as e:
        response = PlainTextResponse(str(e))
        return response    

@router.post("/start")
def start_post(request: Request, auth_k : Annotated[str|None, Cookie()] = None,
               email_address: Annotated[str, Form()] = None):

    try:
        r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "start_key": json.dumps(["authentication_request",auth_k,0]),
                                 "end_key": json.dumps(["authentication_request",auth_k,{}])})
        authentication_request = r.json()["rows"][-1]["doc"]
        r = requests.get(COUCH_USR_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "key": json.dumps(["email",email_address])}).json()["rows"]
        assert r
        user = r[-1]["doc"]
        response = templates.TemplateResponse(
            request=request, name="pw_reset/sent_thanks.djhtml", context={"email_address": email_address})
        token = secrets.token_urlsafe(32)
        send_pw_reset_email(token,"fredgers@panix.com")
        now_utc = int(datetime.now().timestamp())
        requests.post(COUCH_DB_URL, auth=COUCH_DB_AUTH,
                      json={"type": "pw_reset",
                            "uid": user["uid"],
                            "email": user["email"],
                            "pw_reset_token": token,
                            "timestamp": now_utc})
        return response    
    except AssertionError as e:
        response = templates.TemplateResponse(
            request=request, name="pw_reset/start.djhtml", context={"email_address": email_address,
                                                           "email_error": True})
        return response
    except (IndexError, KeyError, requests.exceptions.HTTPError) as e:
        response = PlainTextResponse(str(e))
        return response    

@router.get("/link")
def link_get(request: Request,token:str|None = None):
    try:
        r = requests.get(COUCH_AUTH_VIEW_URL, auth=COUCH_DB_AUTH,
                         params={"include_docs": True, "reduce": False,
                                 "key": json.dumps(["pw_reset_token",token])}).json()["rows"]
        assert r
        pw_reset = r[-1]["doc"]
        response =  templates.TemplateResponse(
            request=request, name="pw_reset/reset_form.djhtml", context={"email_address": pw_reset["email"]})
        return response
    except (IndexError, KeyError, AssertionError, requests.exceptions.HTTPError) as e:
        response = PlainTextResponse(str(e))
        return response    

@router.post("/link")
def link_post():
    return [{"username": "Rick"}, {"username": "Morty"}]

@router.get("/thanks")
def thanks_get():
    return [{"username": "Rick"}, {"username": "Morty"}]


import smtplib, ssl
from email.message import EmailMessage
from email.header import Header

def send_pw_reset_email(token, email_address):
    msg = EmailMessage()
    t = templates.get_template("email/pw_reset.txt")
    pw_reset_host = PW_RESET_HOST
    pw_reset_token = token
    reset_link=f"{pw_reset_host}/pw_reset/link?token={pw_reset_token}"
    content = t.render(reset_link=reset_link)
    msg.set_content(content)
    msg["Subject"] = Header('パスワードリセット', 'utf-8').encode()
    msg["From"] = PW_RESET_FROM_EMAIL
    msg["To"] = email_address

    context=ssl.create_default_context()

    with smtplib.SMTP("mx.furumichi.co.jp", port=587) as smtp:
        smtp.starttls(context=context)
        smtp.login(SMTP_LOGIN_USERNAME, SMTP_LOGIN_PASSWORD)
        smtp.send_message(msg)
