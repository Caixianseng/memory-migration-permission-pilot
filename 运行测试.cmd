@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -B run_pilot.py %*
if errorlevel 1 (
  echo 测试未完成，请查看上方错误和 results 下的 run_manifest.json。
)
pause
