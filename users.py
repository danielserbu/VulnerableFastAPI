from pydantic import BaseModel

class User(BaseModel):
    username: str
    password: str
    rights: str
    password_reset: bool

rightsDict = [
              {
                "right": "admin",
                "functions": "all"
              }
              ,
              {
                "right": "user",
                "functions": "upload_file, CheckIfRemoteServerIsOnline"
              }
             ]