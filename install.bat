@echo off
setlocal

set "SKILLS_DIR=%USERPROFILE%\.kiro\skills\cloudflare-aws-converter"
set "AGENTS_DIR=%USERPROFILE%\.kiro\agents"

echo Installing Cloudflare to AWS Converter Skills...

:: Create directories
if not exist "%SKILLS_DIR%" mkdir "%SKILLS_DIR%"
if not exist "%AGENTS_DIR%" mkdir "%AGENTS_DIR%"

:: Clean old skills (including deprecated cf-waf-converter)
echo Cleaning old skills...
for %%D in (cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter cf-functions-converter cf-cdn-analyzer cf-cdn-analyzer-validator) do (
    if exist "%SKILLS_DIR%\%%D" rmdir /s /q "%SKILLS_DIR%\%%D"
)
if exist "%SKILLS_DIR%\SKILL.md" del /q "%SKILLS_DIR%\SKILL.md"

:: Remove deprecated subagent
if exist "%AGENTS_DIR%\cf-waf-converter.json" del /q "%AGENTS_DIR%\cf-waf-converter.json"

:: Copy skills
echo Copying skills to %SKILLS_DIR%...
for %%D in (cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-functions-converter cf-cdn-analyzer cf-cdn-analyzer-validator) do (
    xcopy /e /i /q "%%D" "%SKILLS_DIR%\%%D"
)
copy /y "cloudflare-aws-converter\SKILL.md" "%SKILLS_DIR%\SKILL.md"

:: Copy subagent configurations
echo Copying subagent configurations to %AGENTS_DIR%...
for %%F in (cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-functions-converter cf-cdn-analyzer cf-cdn-analyzer-validator) do (
    copy /y "subagents\%%F.json" "%AGENTS_DIR%\"
)

echo.
echo Installation complete!
echo.
echo Installed skills:
echo   - Orchestrator: %SKILLS_DIR%\SKILL.md
echo   - WAF Analyzer: %SKILLS_DIR%\cf-waf-analyzer\
echo   - WAF Analyzer Validator: %SKILLS_DIR%\cf-waf-analyzer-validator\
echo   - WAF Terraform Generator: %SKILLS_DIR%\cf-waf-terraform-generator\
echo   - Functions Converter: %SKILLS_DIR%\cf-functions-converter\
echo   - CDN Analyzer: %SKILLS_DIR%\cf-cdn-analyzer\
echo   - CDN Analyzer Validator: %SKILLS_DIR%\cf-cdn-analyzer-validator\
echo.
echo Installed subagents:
echo   - cf-waf-analyzer
echo   - cf-waf-analyzer-validator
echo   - cf-waf-terraform-generator
echo   - cf-functions-converter
echo   - cf-cdn-analyzer
echo   - cf-cdn-analyzer-validator

endlocal
