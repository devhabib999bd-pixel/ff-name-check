@echo off
cd /d "%~dp0"
if not exist .env copy .env.example .env >nul
pip install -r requirements.txt -q
echo.
echo Panel: http://127.0.0.1:5000/admin
echo.
python app.py
pause
