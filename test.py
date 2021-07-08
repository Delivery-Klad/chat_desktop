import requests

# dbx = dropbox.Dropbox('eCp2HTOUrNUAAAAAAAAAASLGV_nwg-uK-KcCXkZTWnT66l2rg9-W6CAGKZnMTiLI')

# result = dbx.sharing_create_shared_link_with_settings('/test.txt')

# print(result.url)
# import yadisk
# y = yadisk.YaDisk(token="AgAAAABITC7sAAav1g3D_G43akSwv85Xg-yPrCY")
# y.upload("test.txt", "/destination.txt")
# print(y.get_download_link('/destination.txt'))
# print(y.get_disk_info())

"""class Userbb(BaseModel):
    log: str
    passw: str


class Settings(BaseModel):
    authjwt_secret_key: str = "secret"


@AuthJWT.load_config
def get_config():
    return Settings()


@app.post('/login')
def login(user: Userbb, Authorize: AuthJWT = Depends()):
    access_token = Authorize.create_access_token(subject=user.log)
    refresh_token = Authorize.create_refresh_token(subject=user.log)
    return {"access_token": access_token, "refresh_token": refresh_token}


@app.post('/refresh')
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()
    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


@app.get('/hello')
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    return {"hello": "world"}"""

"""rez = requests.post("http://127.0.0.1:8000/login", json={"log": "aboba", "passw": "123"})
print(rez.json())

res = requests.get("http://127.0.0.1:8000/hello", headers={'Authorization': f"Bearer {rez.json()['access_token']}"})
print(res.json())"""

"""import json

with open('test.json', 'w') as file:
    theme_dict = {}
    theme_dict.update({"text_color": "entry_text.get()",
                       "entry": "entry_entry.get()",
                       "relief": "relief.get()"})
    json.dump(theme_dict, file, indent=2)

with open('test.json', 'a') as file:
    theme_dict = {}
    theme_dict.update({"frame_relief": "frames_relief.get()",
                       "bg": "entry_bg.get()",
                       "font_main": "entry_font.get()"})
    json.dump(theme_dict, file, indent=2)  theme  """
