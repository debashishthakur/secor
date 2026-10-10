from fastapi import Depends, FastAPI
from openai import OpenAI

from auth import get_current_user

app = FastAPI()
client = OpenAI()


@app.post("/chat")
async def chat(body: dict):
    completion = client.chat.completions.create(model="gpt-4o-mini", messages=body["messages"])
    return completion


@app.post("/summaries")
async def summarize(body: dict, user=Depends(get_current_user)):
    return client.chat.completions.create(model="gpt-4o-mini", messages=body["messages"])
