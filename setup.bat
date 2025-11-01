@echo off
echo Creating Password Strength Analyzer project...

mkdir password-strength-analyzer 2>nul
cd password-strength-analyzer

echo Creating requirements.txt...
echo requests==2.31.0 > requirements.txt

echo Creating .gitignore...
(
echo # Python
echo __pycache__/
echo *.py[cod]
echo venv/
echo .venv
) > .gitignore

echo.
echo Files created! Now you need to:
echo 1. Copy password_analyzer.py code manually
echo 2. Copy common_passwords.txt content manually
echo 3. Copy README.md content manually
echo.
echo Then run: pip install -r requirements.txt
echo Then run: python password_analyzer.py
pause