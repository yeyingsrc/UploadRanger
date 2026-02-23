@echo off
chcp 936 >nul
title UploadRanger
echo ==========================================
echo   UploadRanger v1.0.0
echo   by bae
echo ==========================================
echo.

D:\Miniconda3\miniconda3\envs\reptile_base\python.exe main.py

if errorlevel 1 (
    echo.
    echo start failed, please install python and requirements
    echo run: pip install -r requirements.txt
    pause
)
