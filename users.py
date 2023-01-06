from pydantic import BaseModel

class User(BaseModel):
    username: str
    password: str
    rights: str
    password_reset: bool

class PasswordUpdate(BaseModel):
    username: str
    old_password: str
    new_password: str

rightsDictList = [
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