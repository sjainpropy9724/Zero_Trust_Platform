from fastapi import FastAPI
from app.api import auth, files 
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Zero-Trust Collaboration Platform")

origins = [
    # In production, we would lock this down to your frontend's domain
    "*" # For development, we allow all origins
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allow all methods
    allow_headers=["*"], # Allow all headers
)

app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(files.router, prefix="/files", tags=["Files"]) # <-- Add this line


@app.get("/")
def read_root():
    return {"status": "API is running!"}