import sys
from cx_Freeze import setup, Executable

base = None
if sys.platform == "win32":
    base = "Win32GUI"
elif sys.platform == "win64":
    base = "Win64GUI"

executables = [Executable("main.py", base=base)]
packages = ["idna", "_cffi_backend", "bcrypt", "rsa", "psycopg2", "os", "PIL", "base64", "keyring", "keyring.backends",
            "smtplib", 'win32ctypes', 'dropbox']
options = {'build_exe': {'packages': packages, }, }

setup(name="main", options=options, version="1.0",
      description='description', executables=executables)
