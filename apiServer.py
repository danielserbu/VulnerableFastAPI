from fastapi import FastAPI, APIRouter, Request, File, UploadFile, Depends, Response, HTTPException, status, Form
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_login import LoginManager
from fastapi_login.exceptions import InvalidCredentialsException
import subprocess
from DatabaseUtils import *
from users import *
import aiohttp
import hashlib, base64
from os import path
from datetime import timedelta

# Gonna add routers in the future.
#router = APIRouter()
#app.include_router(router, prefix="/admin")

app = FastAPI(title='VulnerableFastAPI')
pth = path.dirname(__file__)
SECRET = "SEC-RET" #import os; print(os.urandom(24).hex()).
security = HTTPBasic()
app.mount("/templates", StaticFiles(directory="templates"), name="templates")
# No Jinja for now, but will add for SSTI
templates = Jinja2Templates(directory=path.join(pth, "templates"))

manager = LoginManager(SECRET,token_url="/login/",use_cookie=True)
manager.cookie_name = "Auth"

# Brute Forceable
def return_hashed_password(password):
	encoded_string = base64.b64encode(password.encode('utf8'))
	sha256_encoded_string=hashlib.sha256(encoded_string).hexdigest()
	return(sha256_encoded_string)

# Harder to brute force
def return_hashed_password_with_salt(password):
	salt = "secretSalt123"
	pw = password + salt
	encoded_string = base64.b64encode(pw.encode('utf8'))
	sha256_encoded_string=hashlib.sha256(encoded_string).hexdigest()
	return(sha256_encoded_string)

CONST_SALTED_PASSWORDS = False

def db_setup():
	if not check_if_server_databases_exist():
		create_server_databases()
	else:
		cleanup_server_databases()
		create_server_databases()
	# Create users for testing
	if CONST_SALTED_PASSWORDS:
		# Safely stored passwords
		insert_user_into_db("admin", return_hashed_password_with_salt("123456"), "admin", password_reset=0)
		insert_user_into_db("daniel", return_hashed_password_with_salt("123456"), password_reset=0)
	else:
		# Unsafely stored passwords
		insert_user_into_db("admin", return_hashed_password("123456"), "admin", password_reset=0)
		insert_user_into_db("daniel", return_hashed_password("123456"), password_reset=0)

db_setup()

@app.get("/")
async def root():
	# Return main page with input to login and links to register, reset
	#documentationPath = "http://localhost:5656" # Edit me
	#return {"message": "Hello people. You can check the documentation at " + documentationPath}
	resp = RedirectResponse(url="/loginPage",status_code=status.HTTP_302_FOUND)
	return resp

@app.get("/loginPage", response_class=HTMLResponse)
async def login_page(request:Request):
	# Return main page with input to login and links to register, reset
	with open(path.join(pth, "templates/loginPage.html")) as f:
		return HTMLResponse(content=f.read())

@app.get("/registerPage", response_class=HTMLResponse)
async def register_page(request:Request):
	# Return main page with input to login and links to register, reset
	with open(path.join(pth, "templates/registerPage.html")) as f:
		return HTMLResponse(content=f.read())

@app.get("/resetPage", response_class=HTMLResponse)
async def reset_page(request:Request):
	# Return main page with input to login and links to register, reset
	with open(path.join(pth, "templates/resetPage.html")) as f:
		return HTMLResponse(content=f.read())

@app.get("/updatePasswordPage", response_class=HTMLResponse)
async def updatepw_page(request:Request):
	# Return main page with input to login and links to register, reset
	with open(path.join(pth, "templates/updatePasswordPage.html")) as f:
		return HTMLResponse(content=f.read())

@app.get("/user")
async def logged_in(_=Depends(manager)):
	# Return logged in page with Links to upload, checkServer
	with open(path.join(pth, "templates/userPage.html")) as f:
		return HTMLResponse(content=f.read())

@app.get("/admin")
async def logged_in_admin(_=Depends(manager)):
	# Return admin logged in page with Links to downloadUpdates, checkServerIpConfig
	with open(path.join(pth, "templates/adminPage.html")) as f:
		return HTMLResponse(content=f.read())


############### Functions available to all ###############
# ----------------------------------------------
# Register
# SQL Injection (Blind, SQLITE) with Broken Authentication
@app.post("/register/")
async def register(userDetails: User):
	if CONST_SALTED_PASSWORDS:
		password = return_hashed_password_with_salt(userDetails.password)
	else:
		password = return_hashed_password(userDetails.password)
	status = insert_user_into_db(userDetails.username, password, userDetails.rights , password_reset = False)
	return (status)

# ----------------------------------------------
# Login
# SQL Injection (Blind, SQLITE)
def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    dbUsername = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "username", "username", "'" + str(credentials.username) + "'")
    try:
        is_correct_username = str(credentials.username) == dbUsername[0][0]
    except IndexError:
        return("Username doesn't exist.")
    if CONST_SALTED_PASSWORDS:
        current_password_bytes = return_hashed_password_with_salt(str(credentials.password))
    else:
        current_password_bytes = return_hashed_password(str(credentials.password))
    dbPassword = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "password", "username", "'" + str(credentials.username) + "'")
    is_correct_password = current_password_bytes == dbPassword[0][0]
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@manager.user_loader
def load_user(username:str):
    dbUsername = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "username", "username", "'" + username + "'")
    return dbUsername

@app.post("/auth/login")
def login(data: OAuth2PasswordRequestForm = Depends()):
    username = data.username
    password = data.password
    user = load_user(username)
    if reset_password_status(user) == True:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You must reset your password first, please use /updatePassword/$previous_password API POST Call"
		)
    if CONST_SALTED_PASSWORDS:
        received_password = return_hashed_password_with_salt(str(password))
    else:
        received_password = return_hashed_password(str(password))
    dbPassword = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "password", "username", "'" + str(username) + "'")
    if not user:
        raise InvalidCredentialsException
    elif received_password != dbPassword[0][0]:
        raise InvalidCredentialsException
    access_token = manager.create_access_token(
        data={"sub":username}, expires=timedelta(hours=12)
    )
	# Redirect based on user rights.
    if not is_user_allowed_to_run_admin_functions(username):
        resp = RedirectResponse(url="/user",status_code=status.HTTP_302_FOUND)
    else:
        resp = RedirectResponse(url="/admin",status_code=status.HTTP_302_FOUND)
    manager.set_cookie(resp,access_token)
    return resp

# Basic Auth
@app.get("/login/")
async def login(username: str = Depends(get_current_username)):
	if username == "Username doesn't exist.": # Username enumeration
		return{username}
	if reset_password_status(username)[0][0] == 1:
		raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You must reset your password first, please use /updatePassword/$previous_password API POST Call"
		)
	return {"username": username}

# Basic Auth from html
@app.post("/login/")
async def login(username: str = Form(), password: str = Form()):
	try:
		get_current_username()
		if reset_password_status(username)[0][0] == 1:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail="You must reset your password first, please use /updatePassword/$previous_password API POST Call"
			)
	except:
		raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Basic"},
        )
	return {"username": username}

# ----------------------------------------------
# Reset password
# SQL Injection (Blind, SQLITE)
@app.post("/resetPassword/")
async def reset_password(data: OAuth2PasswordRequestForm = Depends()):
	username = data.username
	password = data.password
	user = load_user(username)
	if CONST_SALTED_PASSWORDS:
		old_password = return_hashed_password_with_salt(password)
	else:
		old_password = return_hashed_password(password)
	dbPassword = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "password", "username", "'" + username + "'")
	is_correct_password = old_password == dbPassword[0][0]
	if is_correct_password:
		output = set_reset_password_to(username, 1)
		resp = RedirectResponse(url="/updatePasswordPage",status_code=status.HTTP_302_FOUND)
		return resp
	return{"Wrong old password."}
	

# ----------------------------------------------
# Update user password
# SQL Injection (Blind, SQLITE)
@app.post("/updatePassword/")
async def update_password(data: OAuth2PasswordRequestForm = Depends()):
	username = data.username
	password = data.password
	user = load_user(username)
	if reset_password_status(username)[0][0] == 0:
		raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Password reset hasn't been requested."
		)
	if CONST_SALTED_PASSWORDS:
		new_password = return_hashed_password_with_salt(password)
	else:
		new_password = return_hashed_password(password)
	output = update_user_password(username, new_password)
	set_reset_password_to(username, 0)
	resp = RedirectResponse(url="/loginPage",status_code=status.HTTP_302_FOUND)
	return resp
############### Functions available to all ###############

############### Functions available to users ###############	
# ----------------------------------------------
# File Upload
# Uploads to ./uploads folder
@app.post("/uploadFile/")
async def upload_file(file: UploadFile = File(...), username: str = Depends(get_current_username)):
	file_location = f"uploads/{file.filename}"
	with open(file_location, "wb+") as file_object:
		file_object.write(file.file.read())
	return {"info": f"file '{file.filename}' saved at '{file_location}'"}

# ----------------------------------------------
# Server Side Request Forgery (SSRF)
@app.get("/CheckIfRemoteServerIsOnline/")
async def checkIfRemoteServerIsOnline(path: str = "http://localhost:badport", username: str = Depends(get_current_username)):
    print(path)
    async with aiohttp.ClientSession() as session:
        async with session.get(path) as resp:
            data = await resp.text()
            return(data)
############### Functions available to users ###############	


############### Functions available to admins ###############	
def is_user_allowed_to_run_admin_functions(username):
	userRights = return_user_rights(username)
	print(userRights)
	return userRights == "admin"
# ----------------------------------------------
# Remote Command Execution (RCE)
# Not all commands are working, just as real life.
# ipconfig (default)
# whoami works
# dir works
@app.get("/admin/checkServerIpConfig/{command}")
def checkServer(command, username: str = Depends(get_current_username)):
	if not is_user_allowed_to_run_admin_functions(username):
		return {"You're required to have admin access."}
	process = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
	stderroutput = ''
	stdoutput = ''
	while True:
		stderroutput += process.stderr.read()
		stdoutput += process.stdout.read()
		if process.stderr.read() == '' and process.poll() != None:
			break
	return {"output: " + stdoutput + "\nerror: " + stderroutput}

# ----------------------------------------------
# Local File Inclusion (LFI)
# Currently not vulnerable to path traversal
@app.get("/admin/downloadUpdates/{fileName}")
async def readFile(fileName, username: str = Depends(get_current_username)):
	if not is_user_allowed_to_run_admin_functions(username):
		return {"You're required to have admin access."}
	return FileResponse(path=fileName, filename=fileName)
############### Functions available to admins ###############	
















# Future To Do
# ----------------------------------------------
# Security Misconfiguration - Stack trace in response
# ----------------------------------------------
# Mass Assignment, Hidden Attributes Manipulation
# ----------------------------------------------
# BFLA (Broken Function Level Authroization) https://docs.pynt.io/documentation/broken-function-level-authorization
# Insecure Direct Object References (IDOR) https://docs.pynt.io/documentation/security-tests/broken-object-level-authorization
# BOLA AND BFLA
# ----------------------------------------------
# Lack of resources & Rate Limiting
# ----------------------------------------------
# Not vulnerable versions for all vulns
# ----------------------------------------------
# Remote File Inclusion
# ----------------------------------------------
# OpenRedirect
# ----------------------------------------------
# SSTI
# ----------------------------------------------
# CORS
# ----------------------------------------------
# SQLi
# ----------------------------------------------
# CRLF
# ----------------------------------------------
# CSTI
# ----------------------------------------------
# CSV Injection
# ----------------------------------------------
# Parameter Pollution
# ----------------------------------------------
# XSLT Injection
# ----------------------------------------------
# XPath Injection
# ----------------------------------------------
# CSRF
# ----------------------------------------------
# XSS
# ----------------------------------------------
# XXE
# ----------------------------------------------
# HTTP Request Smuggling
