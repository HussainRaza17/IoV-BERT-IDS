@echo off
echo Starting IoV-BERT-IDS Live Monitor...
call venv\Scripts\activate.bat
python run_live_monitor.py
pause
