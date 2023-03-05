import enum
import os
from typing import Optional
import uuid

import cryptography.exceptions, cryptography.fernet
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from jinja2 import PackageLoader

import redis.asyncio as redis
from hush import crypto

app = FastAPI()

app.mount("/static", StaticFiles(packages=[(__package__, "static")]), name="static")
templates = Jinja2Templates(directory="templates", loader=PackageLoader(__package__))
redis = redis.Redis()

ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"].encode()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


class SecretType(enum.IntEnum):
    PLAINTEXT = 0
    PASSWORD_PROTECTED = 1


@app.exception_handler(KeyError)
async def handle_not_found(request: Request, _):
    return templates.TemplateResponse("404.html", {"request": request}, status_code=404)


@app.post("/submit", response_class=HTMLResponse)
async def submit(
    request: Request,
    secret: str = Form(),
    passphrase: Optional[str] = Form(None),
    ttl: int = Form(),
):
    type = SecretType.PASSWORD_PROTECTED if passphrase else SecretType.PLAINTEXT
    if passphrase:
        # FIXME: I don't know how good of an idea it is to only encrypt with passphrase
        #        It definetly needs to be part of it, but maybe only part?
        encrypted_secret, salt = crypto.encrypt_passphrase(secret, passphrase)
    else:
        encrypted_secret, salt = crypto.encrypt(secret, ENCRYPTION_KEY), b""

    id = str(uuid.uuid4())
    redis_key = f"hush:{id}"

    await redis.hset(
        redis_key,
        mapping={
            "secret": encrypted_secret,
            "salt": salt,
            "type": int(type),
        },
    )
    await redis.expire(redis_key, ttl)

    return templates.TemplateResponse("submit.html", {"request": request, "id": id})


@app.get("/view/{id}", response_class=HTMLResponse)
async def view(request: Request, id: str):
    redis_key = f"hush:{id}"
    secret = await redis.hgetall(redis_key)

    type = SecretType(int(secret[b"type"]))
    if type is SecretType.PLAINTEXT:
        decrypted_secret = crypto.decrypt(secret[b"secret"], ENCRYPTION_KEY)
        await redis.delete(redis_key)
        return templates.TemplateResponse(
            "view.html", {"request": request, "secret": decrypted_secret}
        )
    else:
        return templates.TemplateResponse("view_protected.html", {"request": request})


@app.post("/view/{id}", response_class=HTMLResponse)
async def view_protected(request: Request, id: str, passphrase=Form()):
    redis_key = f"hush:{id}"
    secret = await redis.hgetall(redis_key)

    try:
        decrypted_secret = crypto.decrypt_passphrase(
            secret[b"secret"], secret[b"salt"], passphrase
        )
        await redis.delete(redis_key)
        return templates.TemplateResponse(
            "view.html", {"request": request, "secret": decrypted_secret}
        )
    except (cryptography.exceptions.InvalidKey, cryptography.fernet.InvalidToken):
        return templates.TemplateResponse(
            "view_protected.html", {"request": request, "error": "Invalid passphrase"}
        )
