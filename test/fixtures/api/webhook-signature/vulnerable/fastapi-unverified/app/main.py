from fastapi import FastAPI, Request

from app.handlers import handle_pull_request

app = FastAPI()


@app.post("/webhooks/github")
async def github_webhook(request: Request):
    payload = await request.json()
    if payload.get("action") == "opened":
        handle_pull_request(payload)
    return {"ok": True}
