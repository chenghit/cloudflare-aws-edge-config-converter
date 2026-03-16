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
for %%D in (cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter cf-functions-converter cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator) do (
    if exist "%SKILLS_DIR%\%%D" rmdir /s /q "%SKILLS_DIR%\%%D"
)
if exist "%SKILLS_DIR%\SKILL.md" del /q "%SKILLS_DIR%\SKILL.md"
if exist "%SKILLS_DIR%\scripts" rmdir /s /q "%SKILLS_DIR%\scripts"

:: Remove deprecated subagent
if exist "%AGENTS_DIR%\cf-waf-converter.json" del /q "%AGENTS_DIR%\cf-waf-converter.json"
if exist "%AGENTS_DIR%\cf-functions-converter.json" del /q "%AGENTS_DIR%\cf-functions-converter.json"

:: Copy skills
echo Copying skills to %SKILLS_DIR%...
for %%D in (cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator) do (
    xcopy /e /i /q "%%D" "%SKILLS_DIR%\%%D"
)
copy /y "cloudflare-aws-converter\SKILL.md" "%SKILLS_DIR%\SKILL.md"
xcopy /e /i /q "cloudflare-aws-converter\scripts" "%SKILLS_DIR%\scripts"

:: Copy subagent configurations
echo Copying subagent configurations to %AGENTS_DIR%...
for %%F in (cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator) do (
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
echo   - CDN DNS Parser: %SKILLS_DIR%\cf-cdn-dns-parser\
echo   - CDN Input Validator: %SKILLS_DIR%\cf-cdn-input-validator\
echo   - CDN Per-Domain Processor: %SKILLS_DIR%\cf-cdn-per-domain-processor\
echo   - CDN IR Chunk Validator: %SKILLS_DIR%\cf-cdn-ir-chunk-validator\
echo   - CDN IR Finalizer: %SKILLS_DIR%\cf-cdn-ir-finalizer\
echo   - CDN IR Final Validator: %SKILLS_DIR%\cf-cdn-ir-final-validator\
echo   - CDN TF Shared Policies: %SKILLS_DIR%\cf-cdn-tf-shared-policies\
echo   - CDN TF Domain: %SKILLS_DIR%\cf-cdn-tf-domain\
echo   - CDN JS Validator: %SKILLS_DIR%\cf-cdn-js-validator\
echo.
echo Installed subagents:
echo   - cf-waf-analyzer
echo   - cf-waf-analyzer-validator
echo   - cf-waf-terraform-generator
echo   - cf-cdn-dns-parser
echo   - cf-cdn-input-validator
echo   - cf-cdn-per-domain-processor
echo   - cf-cdn-ir-chunk-validator
echo   - cf-cdn-ir-finalizer
echo   - cf-cdn-ir-final-validator
echo   - cf-cdn-tf-shared-policies
echo   - cf-cdn-tf-domain
echo   - cf-cdn-js-validator

endlocal
