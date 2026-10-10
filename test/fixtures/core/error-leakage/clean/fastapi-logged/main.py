import logging
import os
import traceback

from fastapi import FastAPI
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
app = FastAPI(debug=os.getenv("DEBUG") == "1")
docs_app = FastAPI(debug=False)


@app.exception_handler(Exception)
async def unhandled(request, exc):
    logger.error("unhandled: %s", traceback.format_exc())
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/x")
def x():
    try:
        return work()
    except ValueError as e:
        return {"error": str(e)}


@app.get("/y")
def y():
    try:
        return work()
    except Exception:
        if os.getenv("ENVIRONMENT") == "development":
            return {"trace": traceback.format_exc()}
        return {"error": "internal"}


def format_for_logs():
    return traceback.format_exc()
