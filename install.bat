@echo off
setlocal

set "SKILLS_DIR=%USERPROFILE%\.kiro\skills\cloudflare-aws-converter"

echo Installing Cloudflare to AWS Converter Skills...

:: Create directories
if not exist "%SKILLS_DIR%" mkdir "%SKILLS_DIR%"

:: Clean up old subagent installations
echo Cleaning up old installations...
for %%D in (cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter cf-functions-converter cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator) do (
    if exist "%SKILLS_DIR%\%%D" rmdir /s /q "%SKILLS_DIR%\%%D"
)

:: Remove old agent configs
set "AGENTS_DIR=%USERPROFILE%\.kiro\agents"
if exist "%AGENTS_DIR%" (
    for %%F in (cf-waf-converter cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-functions-converter cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator cloudflare-aws-converter) do (
        if exist "%AGENTS_DIR%\%%F.json" del /q "%AGENTS_DIR%\%%F.json"
    )
)

:: Copy skill files
echo Copying skills to %SKILLS_DIR%...
copy /y "cloudflare-aws-converter\SKILL.md" "%SKILLS_DIR%\" >nul
xcopy /s /y /i "cloudflare-aws-converter\references" "%SKILLS_DIR%\references" >nul
xcopy /s /y /i "cloudflare-aws-converter\scripts" "%SKILLS_DIR%\scripts" >nul

echo.
echo Installation complete!
echo.
echo To start a conversion:
echo   kiro-cli chat

endlocal
