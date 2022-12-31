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
# SSRF
@app.get("/test/")
async def slow_route(path: str = "http://localhost:badport"):
    print(path)
    async with aiohttp.ClientSession() as session:
        async with session.get(path) as resp:
            data = await resp.text()
            return(data)

# ----------------------------------------------
# Command Execution
@app.get("/checkServer/{command}")
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
@app.post("/upload/file/")
async def create_upload_file(file: UploadFile = File(...)):
	file_location = f"uploads/{file.filename}"
	with open(file_location, "wb+") as file_object:
		file_object.write(file.file.read())
	return {"info": f"file '{file.filename}' saved at '{file_location}'"}

# ----------------------------------------------
# LFI
# Currently not vulnerable to path traversal
@app.get("/readFile/{fileName}")
async def readFile(fileName):
	return FileResponse(path=fileName, filename=fileName)
	