from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse
import subprocess
from .DatabaseUtils import *
import aiohttp
import sqlite3
import bcrypt
from pydantic import BaseModel

app = FastAPI()
port = 5151

class User(BaseModel):
    username: str
    password: str
	# Note: Adds posibility to reset password in Login Request via mass enumeration.
    password_reset: bool

# Brute Forceable
def return_hashed_password(password):
	hashed_password = bcrypt.hashpw(password)
	return(hashed_password)

# Much harder to brute force
def return_hashed_password_with_salt(password):
	salt = bcrypt.gensalt()
	# bcrypt.gensalt() is cool, but let's use a constant salt set up in the code.
	hashed_password = bcrypt.hashpw(password, salt)
	return(hashed_password)

CONST_SALTED_PASSWORDS = False

# Db Setup
def setup():
	if not check_if_server_databases_exist():
		create_server_databases()
	else:
		cleanup_server_databases()
		create_server_databases()
	# Create users
	if CONST_SALTED_PASSWORDS:
		# Mock users for testing
		# Safely stored passwords
		insert_user_into_db("admin", return_hashed_password_with_salt("123456"), password_reset=0)
		insert_user_into_db("daniel", return_hashed_password_with_salt("abcd1234"), password_reset=0)
	else:
		# Mock users for testing
		# Unsafely stored passwords
		insert_user_into_db("admin", return_hashed_password("123456"), password_reset=0)
		insert_user_into_db("daniel", return_hashed_password("abcd1234"), password_reset=0)
	
@app.get("/")
async def root():
    return {"message": "Hello people"}

# ----------------------------------------------
# Server Side Request Forgery (SSRF)
@app.get("/CheckIfRemoteServerIsOnline/")
async def checkIfRemoteServerIsOnline(path: str = "http://localhost:badport"):
    print(path)
    async with aiohttp.ClientSession() as session:
        async with session.get(path) as resp:
            data = await resp.text()
            return(data)

# ----------------------------------------------
# Remote Command Execution (RCE)
# Not all commands are working, just as real life.
# ipconfig (default)
# whoami works
# dir works
@app.get("/checkServerIpConfig/{command}")
def checkServer(command):
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
# Register
# SQL Injection (Blind, SQLITE) with Broken Authentication
@app.post("/register/")
async def register(userDetails: User):
	if CONST_SALTED_PASSWORDS:
		password = return_hashed_password_with_salt(userDetails.password)
	else:
		password = return_hashed_password(userDetails.password)
	status = insert_user_into_db(userDetails.username, password, password_reset = False)
	if status == True:
		return {userDetails.username + " successfully created."}
	elif status == False:
		return("Failed to create user.")
	else:
		# Username already registered->Username Enumeration.
		return(status)

# ----------------------------------------------
# Login
# SQL Injection (Blind, SQLITE)
# Should be vulnerable to mass enumeration too (be able to reset_password).
@app.post("/login/")
async def login(userDetails: User):
	if is_reset_password_true(userDetails.username):
		return("You must reset your password first, please use /updatePassword/$previous_password API POST Call")
	if CONST_SALTED_PASSWORDS:
		password = return_hashed_password_with_salt(userDetails.password)
	else:
		password = return_hashed_password(userDetails.password)
	validation = validate_user_with_password_in_db(userDetails.username, password)
	if validation:
		# ToDo: return BASIC Auth
		return("Token")
	else:
		# Login failed (brute forcing)
		return("Login failed.")


# ----------------------------------------------
# Reset password
# SQL Injection (Blind, SQLITE)
# ToDo: Not cool, make sure to ask for old password.
@app.get("/resetPassword/{username}")
async def reset_password(username):
	output = set_reset_password_to_true(username)
	return(output)

# ----------------------------------------------
# Update user password
# SQL Injection (Blind, SQLITE)
# ToDo: Not cool, make sure to ask for old password.
@app.post("/updatePassword/{previous_password}")
async def update_user_password(userDetails: User, previous_password):
	if CONST_SALTED_PASSWORDS:
		old_password = return_hashed_password_with_salt(previous_password)
		new_password = return_hashed_password_with_salt(userDetails.password)
	else:
		old_password = return_hashed_password(previous_password)
		new_password = return_hashed_password(userDetails.password)
	dbPassword = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "username", "password", old_password)
	if dbPassword == "":
		return("Wrong previous password.")
	output = update_user_password(userDetails.username, new_password)
	return(output)

# ----------------------------------------------
# File Upload
# Uploads to ./uploads folder
@app.post("/uploadFile/")
async def create_upload_file(file: UploadFile = File(...)):
	file_location = f"uploads/{file.filename}"
	with open(file_location, "wb+") as file_object:
		file_object.write(file.file.read())
	return {"info": f"file '{file.filename}' saved at '{file_location}'"}

# ----------------------------------------------
# Local File Inclusion (LFI)
# Currently not vulnerable to path traversal
@app.get("/downloadUpdates/{fileName}")
async def readFile(fileName):
	return FileResponse(path=fileName, filename=fileName)

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
# Not vulnerable versions for all vulns
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
