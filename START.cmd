@echo off
cd /d "%~dp0"
echo TRIDENT panel: http://127.0.0.1:8787
echo Requires Node.js 24. Keep this window open while using the panel.
node src/server.mjs
pause
