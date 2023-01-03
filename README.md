# VulnerableFastAPI

## Description:
### VulnerableFastAPI Python program developed for learning AppSec and Pynt
### To Do:
### 1. Add more vulnerabilities
### 2. Add secure functions (as counter example for the vulnerable functions)
### How to run
1. Install prerequisites "pip install -r requirements.txt"
2. Start API Server on receiving end (your attacker machine) with following command "uvicorn apiServer:app --reload --host=127.0.0.1 --port=5151"
3. Notes: --reload is for debugging purposes in FastAPI, and set up the port as you wish.
4. Start local webserver for SSRF testing: "python3 -m http.server 5656"
5. Have fun.
