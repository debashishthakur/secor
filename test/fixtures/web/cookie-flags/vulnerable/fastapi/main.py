from fastapi import FastAPI, Response

app = FastAPI()


@app.post("/login")
def login(response: Response):
    response.set_cookie(key="session", value="abc")
    response.set_cookie("access_token", "t", httponly=True, secure=False, samesite=None)
    response.set_cookie("theme", "dark")
    return {"ok": True}
