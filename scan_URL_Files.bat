@echo off
chcp 65001 >nul
pushd %~dp0
if not exist hack_report mkdir hack_report
python launcher.py
pause
