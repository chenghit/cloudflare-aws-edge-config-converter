@echo off
setlocal

set "SKILLS_DIR=%USERPROFILE%\.kiro\skills\cloudflare-aws-converter"
set "AGENTS_DIR=%USERPROFILE%\.kiro\agents"

echo Uninstalling Cloudflare to AWS Converter Skills...

:: Remove skills
if exist "%SKILLS_DIR%" (
    echo Removing skills from %SKILLS_DIR%...
    rmdir /s /q "%SKILLS_DIR%"
    echo   Skills removed
) else (
    echo   Skills directory not found (already uninstalled?)
)

:: Remove subagent configurations
set REMOVED=0
for %%F in (cf-waf-converter.json cf-functions-converter.json cf-cdn-analyzer.json) do (
    if exist "%AGENTS_DIR%\%%F" (
        del /q "%AGENTS_DIR%\%%F"
        set /a REMOVED+=1
    )
)

if %REMOVED% gtr 0 (
    echo Removing subagent configurations from %AGENTS_DIR%...
    echo   %REMOVED% subagent(s) removed
) else (
    echo   Subagent configurations not found (already uninstalled?)
)

echo.
echo Uninstallation complete!

endlocal
