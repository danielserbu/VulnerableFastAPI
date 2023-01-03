# VulnerableFastAPI

## Description:
### VulnerableFastAPI Python program developed for learning AppSec and Pynt (https://docs.pynt.io/documentation/intro/overview)
### To Do:
### 1. Add more vulnerabilities
### 2. Add secure functions (as counter example for the vulnerable functions)
### How to run
1. Install prerequisites "pip install -r requirements.txt"
2. Start API Server with following command "uvicorn apiServer:app --reload --host=127.0.0.1 --port=5151"
3. Notes: --reload is for debugging purposes in FastAPI, and set up the port as you wish.
4. Start local webserver for SSRF testing: "python3 -m http.server 5656" (In parallel with the API Server)
5. Import Postman Collection from  here https://github.com/danielserbu/VulnerableFastAPI/tree/main/postmanCollection
6. Have Fun.
