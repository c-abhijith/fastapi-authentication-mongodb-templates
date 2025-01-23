from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from fastapi import Request
from fastapi.staticfiles import StaticFiles
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
app.mount("static/", StaticFiles(directory="static"), name="static")

MONGODB_URI = os.getenv("MONGODB_URI")
client = AsyncIOMotorClient(MONGODB_URI)
db = client.get_database()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


templates = Jinja2Templates(directory="app/templates")


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    password: str
    role: str = "user"

class UserInDB(User):
    hashed_password: str

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post("/signup", response_class=HTMLResponse)
async def signup(request: Request, user: User):
    hashed_password = pwd_context.hash(user.password)
    new_user = {**user.dict(), "hashed_password": hashed_password}
    
   
    await db.users.insert_one(new_user)

    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):

    user = await db.users.find_one({"username": form_data.username})
    if not user or not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/logout")
async def logout():
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
