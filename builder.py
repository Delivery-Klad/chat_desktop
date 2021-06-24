import sys
from cx_Freeze import setup, Executable

base = None
if sys.platform == "win32":
    base = "Win32GUI"
elif sys.platform == "win64":
    base = "Win64GUI"

excludes = ['PyQt5', 'colorama', 'logging']

packages = ["idna", "_cffi_backend", "bcrypt", "rsa", "os", "keyring", "keyring.backends",
            "win32ctypes", "shutil", "PIL", "qrcode"]

zip_include_packages = ['collections', 'encodings', 'importlib', 'json']

options = {'build_exe': {
    'packages': packages,
    'excludes': excludes,
    'zip_include_packages': zip_include_packages, }
}

setup(name="main",
      options=options,
      version="1.0.2",
      description='description',
      executables=[Executable("main.py", base=base)])
