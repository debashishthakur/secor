from fastapi import FastAPI

from app.routers import items

app = FastAPI()
app.include_router(items.router, prefix="/api")


@app.get("/health")
def health():
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int):
    return {"deleted": user_id}
