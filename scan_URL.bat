@echo off
echo input url
set /p url=""
cmd /k python hack_scanner.py -u %url%