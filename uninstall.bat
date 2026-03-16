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

:: Remove subagent configurations (including deprecated cf-waf-converter)
set REMOVED=0
for %%F in (cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter cf-waf-summary-scanner cf-functions-converter cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator) do (
    if exist "%AGENTS_DIR%\%%F.json" (
        del /q "%AGENTS_DIR%\%%F.json"
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
