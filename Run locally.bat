@echo off
cd /d "%~dp0"
where python >nul 2>nul || set "PATH=%USERPROFILE%\anaconda3;%USERPROFILE%\anaconda3\Scripts;%USERPROFILE%\anaconda3\Library\bin;%PATH%"
if not exist ".streamlit\secrets.toml" (
  copy ".streamlit\secrets.toml.example" ".streamlit\secrets.toml" >nul
  echo Fill in your YoLink UAID and Secret Key and the two passwords, save, close Notepad, then run this again.
  notepad ".streamlit\secrets.toml"
  pause
  exit /b
)
python -m pip install -q -r requirements.txt
python -m streamlit run streamlit_app.py
pause
