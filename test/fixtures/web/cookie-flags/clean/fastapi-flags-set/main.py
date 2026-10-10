from fastapi import FastAPI, Response

app = FastAPI()


@app.post("/login")
def login(response: Response):
    response.set_cookie(key="session", value="abc", httponly=True, secure=True)
    response.set_cookie("refresh_token", "t", httponly=True, secure=True, samesite="strict")
    return {"ok": True}
