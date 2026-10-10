from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

ORIGINS = ["https://app.example.com"]

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_credentials=True)

public = FastAPI()
public.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False)


@app.get("/me")
def me():
    return {}
