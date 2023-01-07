from fastapi import FastAPI, APIRouter, Request, File, UploadFile, Depends, Response, HTTPException, status, Form
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import subprocess
from DatabaseUtils import *
from users import *
import aiohttp
import hashlib, base64
from os import path

pth = path.dirname(__file__)

# Gonna add routers in the future.
#router = APIRouter()
app = FastAPI(title='VulnerableFastAPI')
#app.include_router(router, prefix="/admin")
security = HTTPBasic()
#port = 5151 # Useless
app.mount("/templates", StaticFiles(directory="templates"), name="templates")
templates = Jinja2Templates(directory="templates")

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
		insert_user_into_db("daniel", return_hashed_password_with_salt("abcd1234"), password_reset=0)
	else:
		# Unsafely stored passwords
		insert_user_into_db("admin", return_hashed_password("123456"), "admin", password_reset=0)
		insert_user_into_db("daniel", return_hashed_password("abcd1234"), password_reset=0)

db_setup()

@app.get("/")
async def root():
	# redirects to login
	# Return main page with input to login and links to register, reset
	documentationPath = "http://localhost:5656" # Edit me
	return {"message": "Hello people. You can check the documentation at " + documentationPath}

@app.get("/loginPage", response_class=HTMLResponse)
async def login_page(request:Request):
	# Return main page with input to login and links to register, reset
	with open(path.join(pth, "templates/loginPage.html")) as f:
		return HTMLResponse(content=f.read())


@app.get("/user")
async def logged_in():
	# Return logged in page with Links to upload, checkServer
	documentationPath = "http://localhost:5656" # Edit me
	return HTMLResponse("""
				<!DOCTYPE html>
<html>
<body>

<h1>My First Heading</h1>
<p>My first paragraph.</p>

</body>
</html>
		""")

@app.get("/admin")
async def logged_in_admin():
	# Return admin logged in page with Links to downloadUpdates, checkServerIpConfig
	documentationPath = "http://localhost:5656" # Edit me
	return HTMLResponse("""
				<!DOCTYPE html>
<html>
<body>

<h1>My First Heading</h1>
<p>My first paragraph.</p>

</body>
</html>
		""")


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

# From html
@app.post("/login/")
async def login(username: str = Form(), password: str = Form()):
	if reset_password_status(username)[0][0] == 1:
		raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You must reset your password first, please use /updatePassword/$previous_password API POST Call"
		)
	return {"username": username}

# ----------------------------------------------
# Reset password
# SQL Injection (Blind, SQLITE)
@app.get("/resetPassword/{username}/{oldPassword}")
async def reset_password(username, oldPassword):
	if CONST_SALTED_PASSWORDS:
		old_password = return_hashed_password_with_salt(oldPassword)
	else:
		old_password = return_hashed_password(oldPassword)
	dbPassword = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "password", "username", "'" + username + "'")
	is_correct_password = old_password == dbPassword[0][0]
	if is_correct_password:
		output = set_reset_password_to(username, 1)
		return(output)
	return{"Wrong old password."}
	

# ----------------------------------------------
# Update user password
# SQL Injection (Blind, SQLITE)
@app.post("/updatePassword/")
async def update_password(pwUpdate: PasswordUpdate):
	if reset_password_status(pwUpdate.username)[0][0] == 0:
		raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Password reset hasn't been requested."
		)
	if CONST_SALTED_PASSWORDS:
		old_password = return_hashed_password_with_salt(pwUpdate.old_password)
		new_password = return_hashed_password_with_salt(pwUpdate.new_password)
	else:
		old_password = return_hashed_password(pwUpdate.old_password)
		new_password = return_hashed_password(pwUpdate.new_password)
	dbPassword = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "password", "username", "'" + pwUpdate.username + "'")
	is_correct_password = old_password == dbPassword[0][0]
	if is_correct_password:
		output = update_user_password(pwUpdate.username, new_password)
		set_reset_password_to(pwUpdate.username, 0)
		return{output}
	else:
		return{"Wrong previous password."}
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
