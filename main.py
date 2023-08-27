import time

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import text

from src.database.db import get_db
from src.routes import contacts, auth

app = FastAPI()

app.include_router(contacts.router, prefix='/api')
app.include_router(auth.router, prefix='/api')


@app.get("/api/healthchecker")
def healthchecker(db: Session = Depends(get_db)):
    try:
        # Make request
        result = db.execute(text("SELECT 1")).fetchone()
        if result is None:
            raise HTTPException(status_code=500, detail="Database is not configured correctly")
        return {"message": "Welcome to FastAPI!"}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Error connecting to the database")


@app.get("/", description="Main Page")
async def root(request: Request):
    return {'Hello': 'Your contacts book'}

if __name__ == '__main__':
    uvicorn.run('main:app', port=8000, reload=True)