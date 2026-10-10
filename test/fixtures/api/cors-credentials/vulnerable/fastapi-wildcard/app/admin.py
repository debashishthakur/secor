from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware

admin = FastAPI(middleware=[Middleware(CORSMiddleware, allow_origin_regex=".*", allow_credentials=True)])
