@echo off
echo Building NightShadow Launcher...

REM Install dependencies
pip install -r requirements.txt

REM Build executable
pyinstaller --onefile --windowed --name "NightShadow Launcher" --icon=icon.ico launcher.py 2>nul || pyinstaller --onefile --windowed --name "NightShadow Launcher" launcher.py

echo.
echo Build complete! Executable is in dist/
pause
