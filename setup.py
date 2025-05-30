from cx_Freeze import setup, Executable
import sys
import os

# Dependencies are auto-detected, but you can tweak as needed
build_exe_options = {
    "packages": ["tkinter", "requests", "random", "threading"],
    "excludes": [],
    "include_files": [
        ("assets/app_icon.ico", "assets/app_icon.ico")
    ]
}

# Use "Win32GUI" base for GUI apps (prevents a console window)
base = "Win32GUI"

setup(
    name="ProxyCheckerTool",
    version="1.0",
    description="Proxy Checker Tool built with Tkinter and cx_Freeze",
    options={"build_exe": build_exe_options},
    executables=[
        Executable(
            "checker.py",
            base=base,
            icon="assets/app_icon.ico",
            target_name="ProxyChecker.exe"
        )
    ]
)
