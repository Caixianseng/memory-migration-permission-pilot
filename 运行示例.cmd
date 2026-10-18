@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -B run_pilot.py --data-root examples/data --dataset synthetic %*
if errorlevel 1 (
  echo 示例未完成，请查看上方错误和 results 下的 run_manifest.json。
)
pause
