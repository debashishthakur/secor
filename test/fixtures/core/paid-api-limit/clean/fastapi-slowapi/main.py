from fastapi import FastAPI, Request
from openai import OpenAI
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
client = OpenAI()


@app.post("/chat")
@limiter.limit("5/minute")
async def chat(request: Request):
    body = await request.json()
    return client.chat.completions.create(model="gpt-4o-mini", messages=body["messages"])
