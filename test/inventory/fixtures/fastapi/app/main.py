from fastapi import FastAPI, Depends
from app.routers import items
from .routers.admin import router as admin_router
from app.api.deps import get_current_user

app = FastAPI()

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/me")
async def me(user = Depends(get_current_user)):
    return user

app.include_router(items.router, prefix="/api")
app.include_router(admin_router)
