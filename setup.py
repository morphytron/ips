import sys, os
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need fine tuning.
build_exe_options = {"packages": ["plyer","tkinter", "os", "sys", "subprocess", "threading", "socket", "re", "datetime"], "optimize": 2, "include_files": [
'C:/Users/dapat/AppData/Local/Programs/Python/Python37/tcl/tix8.4.3',
"C:/Users/dapat/AppData/Local/Programs/Python/Python37/DLLs/tcl86t.dll",
'C:/Users/dapat/AppData/Local/Programs/Python/Python37/tcl/tcl8.6',
"C:/Users/dapat/AppData/Local/Programs/Python/Python37/DLLs/tk86t.dll",
'C:/Users/dapat/AppData/Local/Programs/Python/Python37/tcl/tk8.6',
        "server_connect.conf", "IPS.conf", "log.lg", "log2.lg"]}

# GUI applications require a different base on Windows (the default is for a
# console application).
base = None
if sys.platform == "win32":
    base = "Win32GUI"


os.environ['TCL_LIBRARY'] = 'C:/Users/dapat/AppData/Local/Programs/Python/Python37/tcl/tcl8.6'
os.environ['TK_LIBRARY'] = 'C:/Users/dapat/AppData/Local/Programs/Python/Python37/tcl/tk8.6'


setup(  name = "Intrusion Prevention System",
        author_email="atomhid@gmail.com",
        author = "Daniel Alexander Apatiga",
        version = "1.3.0",
        description = "Atomhid Ideal Intrusion Prevention System",
        long_description = "The most intuitive intrusion prevention system for small or large businesses.",
        options = {"build_exe": build_exe_options},
        executables = [Executable(script="IPS.py", copyright="2017", trademarks="Atomhid", base=base, shortcutName="IPS",  shortcutDir="DesktopFolder",  icon="ips_ico.ico"),
                       Executable(script="IPS_Logger.py", copyright="2017", trademarks="Atomhid", base=base, shortcutName="IPS Monitor Station", shortcutDir="DesktopFolder", icon="ips_servlet.ico")]
        )