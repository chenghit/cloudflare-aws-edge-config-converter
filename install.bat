@echo off
setlocal

set "SKILLS_DIR=%USERPROFILE%\.kiro\skills\cloudflare-aws-converter"
set "AGENTS_DIR=%USERPROFILE%\.kiro\agents"

echo Installing Cloudflare to AWS Converter Skills...

:: Create directories
if not exist "%SKILLS_DIR%" mkdir "%SKILLS_DIR%"
if not exist "%AGENTS_DIR%" mkdir "%AGENTS_DIR%"

:: Clean old skills
echo Copying skills to %SKILLS_DIR%...
if exist "%SKILLS_DIR%\cf-waf-converter" rmdir /s /q "%SKILLS_DIR%\cf-waf-converter"
if exist "%SKILLS_DIR%\cf-functions-converter" rmdir /s /q "%SKILLS_DIR%\cf-functions-converter"
if exist "%SKILLS_DIR%\cf-cdn-analyzer" rmdir /s /q "%SKILLS_DIR%\cf-cdn-analyzer"
if exist "%SKILLS_DIR%\SKILL.md" del /q "%SKILLS_DIR%\SKILL.md"

:: Copy skills
xcopy /e /i /q "cf-waf-converter" "%SKILLS_DIR%\cf-waf-converter"
xcopy /e /i /q "cf-functions-converter" "%SKILLS_DIR%\cf-functions-converter"
xcopy /e /i /q "cf-cdn-analyzer" "%SKILLS_DIR%\cf-cdn-analyzer"
copy /y "cloudflare-aws-converter\SKILL.md" "%SKILLS_DIR%\SKILL.md"

:: Copy subagent configurations
echo Copying subagent configurations to %AGENTS_DIR%...
copy /y "subagents\cf-waf-converter.json" "%AGENTS_DIR%\"
copy /y "subagents\cf-functions-converter.json" "%AGENTS_DIR%\"
copy /y "subagents\cf-cdn-analyzer.json" "%AGENTS_DIR%\"

echo.
echo Installation complete!
echo.
echo Installed skills:
echo   - Orchestrator: %SKILLS_DIR%\SKILL.md
echo   - WAF Converter: %SKILLS_DIR%\cf-waf-converter\
echo   - Functions Converter: %SKILLS_DIR%\cf-functions-converter\
echo   - CDN Analyzer: %SKILLS_DIR%\cf-cdn-analyzer\
echo.
echo Installed subagents:
echo   - cf-waf-converter
echo   - cf-functions-converter
echo   - cf-cdn-analyzer

endlocal
