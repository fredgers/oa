from fastapi import APIRouter
from fastapi import (Cookie, Depends, FastAPI, Form, HTTPException, Request,
                     Response)
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Annotated, List

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
COUCH_VIEW_PARAMS={"include_docs": True, "reduce": False}

@router.get("/start")
def start_get(request: Request, auth_k : Annotated[str|None, Cookie()] = None):
    return [{"username": "Rick"}, {"username": "Morty"}]

@router.post("/start")
def start_post():
    return [{"username": "Rick"}, {"username": "Morty"}]

@router.get("/link")
def link_get():
    return [{"username": "Rick"}, {"username": "Morty"}]

@router.post("/link")
def link_post():
    return [{"username": "Rick"}, {"username": "Morty"}]

@router.get("/thanks")
def thanks_get():
    return [{"username": "Rick"}, {"username": "Morty"}]
