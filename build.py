"""
Accounting & Tax Analysis System - Windows 11 Standalone Build Script
====================================================================
This script compiles `main.py` and its frontend UI assets into a standalone
Windows 11 executable (.exe) using PyInstaller.

Key Windows 11 Configurations:
- Mode: --onefile (single portable .exe) or --onedir (faster cold start)
- Window: --noconsole (hides the background terminal window)
- Pywebview Backend: Includes hidden imports for Windows Edge WebView2 & WinForms
- Data files: Bundles index.html and .env into the application payload
"""

import os
import sys
import subprocess
import shutil

def build_windows_executable():
    print("=" * 70)
    print("Building Windows 11 Standalone Executable (.exe)")
    print("Accounting & Tax Analysis System - Data Entry Portal")
    print("Developer: Eng. Mahmoud Mohamed | mahmoud.m@sdi.ae")
    print("=" * 70)

    # 1. Verify PyInstaller installation
    try:
        import PyInstaller
        print(f"[INFO] PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("[ERROR] PyInstaller is not installed.")
        print("[ACTION] Run: pip install pyinstaller pywebview python-dotenv supabase")
        sys.exit(1)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(base_dir, "dist")
    build_dir = os.path.join(base_dir, "build")

    # 2. Define OS-specific path separator for --add-data
    # Windows uses semicolon (;), Unix uses colon (:)
    data_sep = ";" if sys.platform.startswith("win") else ":"

    # 3. Assemble PyInstaller arguments
    # Crucial hidden imports for pywebview on Windows 11:
    # - clr & pythonnet: Required for WinForms and Edge Chromium WebView2
    # - webview.platforms.winforms & webview.platforms.edgechromium
    # - supabase, postgrest, gotrue, realtime: Database client modules
    pyinstaller_cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=TaxDataEntry_App",
        "--onefile",                    # Bundle into a single standalone .exe
        "--noconsole",                  # Hide command prompt window on launch
        "--clean",                      # Clean PyInstaller cache before building
        f"--add-data=index.html{data_sep}.",
        "--hidden-import=webview",
        "--hidden-import=webview.platforms.winforms",
        "--hidden-import=webview.platforms.edgechromium",
        "--hidden-import=clr",
        "--hidden-import=pythonnet",
        "--hidden-import=dotenv",
        "--hidden-import=supabase",
        "--hidden-import=postgrest",
        "--hidden-import=gotrue",
        "--hidden-import=realtime",
        "--hidden-import=storage3",
        "--hidden-import=supafunc",
        "--hidden-import=decimal",
        os.path.join(base_dir, "main.py")
    ]

    # Include .env if present
    env_path = os.path.join(base_dir, ".env")
    if os.path.exists(env_path):
        pyinstaller_cmd.insert(8, f"--add-data=.env{data_sep}.")

    print("\n[CMD] Executing PyInstaller build command:")
    print(" ".join(pyinstaller_cmd))
    print("\n[INFO] Compiling... (this may take 1-2 minutes)")

    # 4. Run PyInstaller
    result = subprocess.run(pyinstaller_cmd)

    if result.returncode == 0:
        exe_ext = ".exe" if sys.platform.startswith("win") else ""
        output_exe = os.path.join(dist_dir, f"TaxDataEntry_App{exe_ext}")
        print("\n" + "=" * 70)
        print("[SUCCESS] Build completed successfully!")
        print(f"[OUTPUT] Standalone Executable: {output_exe}")
        print("[DEPLOYMENT NOTE] Users can run this executable directly on Windows 11.")
        print("Optional: Place a custom .env file in the same directory as the .exe to override credentials.")
        print("=" * 70)
    else:
        print("\n[ERROR] PyInstaller compilation failed. Check logs above.")
        sys.exit(result.returncode)

if __name__ == "__main__":
    build_windows_executable()
