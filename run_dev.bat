@echo off
echo Starting VULNERA-MAP Backend...
c:\Users\ijgam\OneDrive\Documents\jules2\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
