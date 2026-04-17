@echo off
setlocal

set "SKILLS_DIR=%USERPROFILE%\.kiro\skills\cloudflare-aws-converter"
set "AGENTS_DIR=%USERPROFILE%\.kiro\agents"

echo Uninstalling Cloudflare to AWS Converter...

if exist "%SKILLS_DIR%" (
    echo Removing skills from %SKILLS_DIR%...
    rmdir /s /q "%SKILLS_DIR%"
    echo   Skills removed
) else (
    echo   Skills directory not found (already uninstalled?)
)

:: Remove old agent configs (from previous versions that used subagents)
if exist "%AGENTS_DIR%" (
    for %%F in (cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter cf-functions-converter cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator cloudflare-aws-converter) do (
        if exist "%AGENTS_DIR%\%%F.json" del /q "%AGENTS_DIR%\%%F.json"
    )
)

echo.
echo Uninstallation complete!

endlocal
