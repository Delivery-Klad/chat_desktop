import sys
from cx_Freeze import setup, Executable

base = None
if sys.platform == "win32":
    base = "Win32GUI"
elif sys.platform == "win64":
    base = "Win64GUI"

excludes = ['PyQt5', 'colorama', 'pandas', 'sqlalchemy', 'numpy', 'notebook', 'Django', 'schedule']

packages = ["idna", "_cffi_backend", "bcrypt", "rsa", "os", "keyring", "keyring.backends",
            "win32ctypes", "shutil", "PIL", "qrcode", "pyminizip", "pathlib"]

zip_include_packages = ['collections', 'encodings', 'importlib']

options = {'build_exe': {
    'packages': packages,
    'excludes': excludes,
    'zip_include_packages': zip_include_packages, }
}

executables = [Executable("main.py", base=base)]

setup(name="Chat",                              # bdist_msi, bdist_mac
      author="Delivery Klad",
      options=options,
      version="3.6",
      description='Encrypted chat',
      executables=executables)
