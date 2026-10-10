import hashlib
import hmac
import os

import stripe
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, signature, os.environ["STRIPE_WEBHOOK_SECRET"])
    except ValueError:
        raise HTTPException(status_code=400)
    return {"received": event["id"]}


@app.post("/webhooks/github")
async def github_webhook(request: Request):
    body = await request.body()
    expected = "sha256=" + hmac.new(os.environ["GITHUB_WEBHOOK_SECRET"].encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("x-hub-signature-256", "")):
        raise HTTPException(status_code=400)
    return {"ok": True}
