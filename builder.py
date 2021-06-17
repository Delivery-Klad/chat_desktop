import sys
from cx_Freeze import setup, Executable

base = None
if sys.platform == "win32":
    base = "Win32GUI"
elif sys.platform == "win64":
    base = "Win64GUI"

packages = ["idna", "_cffi_backend", "bcrypt", "rsa", "os", "keyring", "keyring.backends",
            "win32ctypes", "shutil", "PIL", "qrcode"]
options = {'build_exe': {'packages': packages, }, }

setup(name="main",
      options=options,
      version="1.0.02",
      description='description',
      executables=[Executable("main.py", base=base)])
