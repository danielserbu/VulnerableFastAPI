from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse
import subprocess
import aiohttp

app = FastAPI()
port = 5151

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
# Not vulnerable versions for all vulns
# ----------------------------------------------
# Remote File Inclusion
# ----------------------------------------------
# Insecure Direct Object References (IDOR) 
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
