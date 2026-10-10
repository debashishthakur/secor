from fastapi import FastAPI

app = FastAPI(debug=True, title="demo")


@app.get("/health")
def health():
    return {"ok": True}
