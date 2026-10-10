import traceback

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()


@app.get("/items/{item_id}")
async def read_item(item_id: int):
    try:
        return {"item": load(item_id)}
    except Exception:
        return {"error": "failed", "trace": traceback.format_exc()}


@app.exception_handler(Exception)
async def unhandled(request, exc):
    tb = traceback.format_exc()
    return JSONResponse(status_code=500, content={"detail": tb})


@app.post("/jobs")
async def create_job():
    try:
        return run_job()
    except Exception:
        raise HTTPException(status_code=500, detail=traceback.format_exc())
