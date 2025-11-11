from fastapi import FastAPI
from app.api import auth, files 
from fastapi.staticfiles import StaticFiles 
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Zero-Trust Collaboration Platform")

origins = [
    "http://localhost:8000", 
    "http://127.0.0.1:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)

app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(files.router, prefix="/files", tags=["Files"]) 


app.mount("/", StaticFiles(directory="static", html=True), name="static")
