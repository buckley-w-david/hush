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
    NORMAL = 0
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
    type = SecretType.PASSWORD_PROTECTED if passphrase else SecretType.NORMAL
    key, salt = ENCRYPTION_KEY, b""
    if passphrase:
        # DANGER: This is _exactly_ what people mean when they say don't roll your own crypto
        #         I just made up this operation without any real knowledge of the security implications
        #         This XORs the passphrase generated key with the static encryption key
        #         I could just directly use the passphrase generated key, but I was worried people would use shitty passphrases.
        key, salt = crypto.merged_key(key, passphrase)
    encrypted_secret = crypto.encrypt(secret, key)

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
    type_ = await redis.hget(redis_key, "type")
    if not type_:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    type = SecretType(int(type_))
    return templates.TemplateResponse("view.html", {"request": request, "password_protected": type is SecretType.PASSWORD_PROTECTED})


@app.post("/view/{id}", response_class=HTMLResponse)
async def view_protected(request: Request, id: str, passphrase: str = Form(None)):
    redis_key = f"hush:{id}"
    secret = await redis.hgetall(redis_key)
    type = SecretType(int(secret[b"type"]))

    try:
        if type is SecretType.PASSWORD_PROTECTED:
            key, _ = crypto.merged_key(ENCRYPTION_KEY, passphrase, secret[b"salt"])
        else:
            key = ENCRYPTION_KEY

        decrypted_secret = crypto.decrypt( secret[b"secret"], key)
        await redis.delete(redis_key)
        return templates.TemplateResponse(
            "reveal.html", {"request": request, "secret": decrypted_secret}
        )
    except (cryptography.exceptions.InvalidKey, cryptography.fernet.InvalidToken):
        return templates.TemplateResponse(
            "view.html", {"request": request, "error": "Invalid passphrase"}
        )
