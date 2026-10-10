from fastapi import Depends, FastAPI

from app.deps import CurrentUser, get_current_user, oauth2_scheme
from app.routers import items, reports

app = FastAPI()
app.include_router(items.router)
app.include_router(reports.router, prefix="/v1", dependencies=[Depends(get_current_user)])


@app.get("/health")
def health():
    return {"ok": True}


@app.options("/items")
def items_options():
    return {}


@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    return user


@app.get("/profile")
def profile(user: CurrentUser):
    return user


@app.post("/admin/reindex", dependencies=[Depends(get_current_user)])
def reindex():
    return {"started": True}


@app.get("/token-info")
def token_info(token: str = Depends(oauth2_scheme)):
    return {"token": token}
