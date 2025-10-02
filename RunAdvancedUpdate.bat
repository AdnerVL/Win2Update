@echo off

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { Start-Process powershell.exe \"-NoProfile -ExecutionPolicy Bypass -File .\AdvancedRemoteUpdate.ps1 %*\" -Verb RunAs -Wait }"
