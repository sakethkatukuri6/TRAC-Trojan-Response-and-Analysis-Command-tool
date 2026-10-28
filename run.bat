@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: TRAC: Trojan Response and Analysis Command Platform
:: Master Windows Automation & Development Script
:: ============================================================================

cd /d "%~dp0"

:: Detect Python executable: prefer local virtualenv if present
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_CMD=.venv\Scripts\python.exe"
    set "UVICORN_CMD=.venv\Scripts\uvicorn.exe"
    set "PYTEST_CMD=.venv\Scripts\pytest.exe"
) else if exist "venv\Scripts\python.exe" (
    set "PYTHON_CMD=venv\Scripts\python.exe"
    set "UVICORN_CMD=venv\Scripts\uvicorn.exe"
    set "PYTEST_CMD=venv\Scripts\pytest.exe"
) else (
    set "PYTHON_CMD=python"
    set "UVICORN_CMD=uvicorn"
    set "PYTEST_CMD=pytest"
)

:: Handle command-line arguments if provided
if not "%~1"=="" (
    set "ACTION=%~1"
    goto :DISPATCH
)

:: ============================================================================
:: Interactive Menu
:: ============================================================================
:MENU
cls
echo ============================================================================
echo   TRAC: Trojan Response and Analysis Command Platform
echo ============================================================================
echo   Using Python: !PYTHON_CMD!
echo ============================================================================
echo.
echo   [1] Run Full CI Gate Check (All Committed Modules)
echo   [2] Run Contract Unit Test Suite (21 contract tests)
echo   [3] Run Pytest on Available Modules (M4, M5, M6)
echo   [4] Check M4 (IOC Extraction) Contract Compliance
echo   [5] Check M5 (Detection and Scoring) Contract Compliance
echo   [6] Check M6 (Response Engine) Contract Compliance
echo   [7] Check M7 (Core Orchestration) Contract Compliance
echo   [8] Run CLIs to Regenerate Outputs (M4, M5, M6, M7)
echo   [9] Generate / Refresh Contract Stubs (M1 - M8)
echo   [10] Start M7 Core REST API Server (Uvicorn port 8000)
echo   [11] Launch SOC Analyst Web Dashboard (Port 8088 / Auto)
echo   [12] Install Dependencies
echo   [0] Exit
echo.
set /p "CHOICE=Enter choice [0-12]: "

if "%CHOICE%"=="1" goto :CMD_GATE
if "%CHOICE%"=="2" goto :CMD_CONTRACT_TEST
if "%CHOICE%"=="3" goto :CMD_TEST_ALL
if "%CHOICE%"=="4" goto :CMD_CHECK_M4
if "%CHOICE%"=="5" goto :CMD_CHECK_M5
if "%CHOICE%"=="6" goto :CMD_CHECK_M6
if "%CHOICE%"=="7" goto :CMD_CHECK_M7
if "%CHOICE%"=="8" goto :CMD_RUN_CLIS
if "%CHOICE%"=="9" goto :CMD_STUBS
if "%CHOICE%"=="10" goto :CMD_SERVER
if "%CHOICE%"=="11" goto :CMD_UI
if "%CHOICE%"=="12" goto :CMD_INSTALL
if "%CHOICE%"=="0" goto :EOF

echo Invalid selection. Please try again.
pause
goto :MENU

:: ============================================================================
:: CLI Command Dispatcher
:: ============================================================================
:DISPATCH
if /i "%ACTION%"=="gate" goto :CMD_GATE
if /i "%ACTION%"=="gate-strict" goto :CMD_GATE_STRICT
if /i "%ACTION%"=="contract-test" goto :CMD_CONTRACT_TEST
if /i "%ACTION%"=="test-contract" goto :CMD_CONTRACT_TEST
if /i "%ACTION%"=="test" goto :CMD_TEST_ALL
if /i "%ACTION%"=="test-all" goto :CMD_TEST_ALL
if /i "%ACTION%"=="check-m4" goto :CMD_CHECK_M4
if /i "%ACTION%"=="check-m5" goto :CMD_CHECK_M5
if /i "%ACTION%"=="check-m6" goto :CMD_CHECK_M6
if /i "%ACTION%"=="check-m7" goto :CMD_CHECK_M7
if /i "%ACTION%"=="run-clis" goto :CMD_RUN_CLIS
if /i "%ACTION%"=="stubs" goto :CMD_STUBS
if /i "%ACTION%"=="api" goto :CMD_SERVER
if /i "%ACTION%"=="server" goto :CMD_SERVER
if /i "%ACTION%"=="ui" goto :CMD_UI
if /i "%ACTION%"=="dashboard" goto :CMD_UI
if /i "%ACTION%"=="install" goto :CMD_INSTALL
if /i "%ACTION%"=="help" goto :CMD_HELP
if /i "%ACTION%"=="--help" goto :CMD_HELP
if /i "%ACTION%"=="-h" goto :CMD_HELP

echo [!] Unknown command: %ACTION%
goto :CMD_HELP

:: ============================================================================
:: Action Implementations
:: ============================================================================

:CMD_GATE
echo.
echo [*] Running Platform CI Gate across all modules...
"%PYTHON_CMD%" contract\tools\check_all.py --repo-root .
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [-] CI Gate: FAILED
    if "%~1"=="" pause & goto :MENU
    exit /b 1
)
echo.
echo [+] CI Gate: PASSED
if "%~1"=="" pause & goto :MENU
exit /b 0

:CMD_GATE_STRICT
echo.
echo [*] Running Strict CI Gate (all M1-M8 outputs required)...
"%PYTHON_CMD%" contract\tools\check_all.py --repo-root . --require-all
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [-] Strict CI Gate: FAILED
    if "%~1"=="" pause & goto :MENU
    exit /b 1
)
echo.
echo [+] Strict CI Gate: PASSED
if "%~1"=="" pause & goto :MENU
exit /b 0

:CMD_CONTRACT_TEST
echo.
echo [*] Running Contract Unit Test Suite...
"%PYTHON_CMD%" -m unittest discover -s contract\tests -v
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [-] Contract Tests: FAILED
    if "%~1"=="" pause & goto :MENU
    exit /b 1
)
echo.
echo [+] Contract Tests: PASSED
if "%~1"=="" pause & goto :MENU
exit /b 0

:CMD_TEST_ALL
echo.
echo [*] Running Pytest across active modules...
set "OVERALL_ERR=0"

echo --- Testing M4 (IOC Extraction) ---
"%PYTEST_CMD%" -v m4_ioc\tests
if %ERRORLEVEL% NEQ 0 set "OVERALL_ERR=1"

echo.
echo --- Testing M5 (Detection and Scoring) ---
"%PYTEST_CMD%" -v m5_detection\tests
if %ERRORLEVEL% NEQ 0 set "OVERALL_ERR=1"

echo.
echo --- Testing M6 (Response Engine Unit Tests) ---
"%PYTEST_CMD%" -v m6_response\tests\test_approval_gate.py m6_response\tests\test_audit_chain.py m6_response\tests\test_cli.py m6_response\tests\test_exports.py m6_response\tests\test_planner.py
if %ERRORLEVEL% NEQ 0 set "OVERALL_ERR=1"

echo.
echo --- Testing M7 (Core Persistence and CLI) ---
"%PYTEST_CMD%" -v m7_core\tests\test_cli.py m7_core\tests\test_persistence.py
if %ERRORLEVEL% NEQ 0 set "OVERALL_ERR=1"

echo.
if %OVERALL_ERR% NEQ 0 (
    echo [-] Module Pytests encountered failures.
    if "%~1"=="" pause & goto :MENU
    exit /b 1
)
echo [+] All Module Pytests: PASSED
if "%~1"=="" pause & goto :MENU
exit /b 0

:CMD_CHECK_M4
echo.
echo [*] Checking M4 Contract Compliance...
"%PYTHON_CMD%" contract\tools\check_module.py --module M4 --file m4_ioc\contract_out\iocs.json
"%PYTHON_CMD%" contract\tools\check_module.py --module M4 --event m4_ioc\contract_events\iocs_done.json
if "%~1"=="" pause & goto :MENU
exit /b %ERRORLEVEL%

:CMD_CHECK_M5
echo.
echo [*] Checking M5 Contract Compliance...
"%PYTHON_CMD%" contract\tools\check_module.py --module M5 --file m5_detection\contract_out\scoring.json
"%PYTHON_CMD%" contract\tools\check_module.py --module M5 --event m5_detection\contract_events\scoring_done.json
if "%~1"=="" pause & goto :MENU
exit /b %ERRORLEVEL%

:CMD_CHECK_M6
echo.
echo [*] Checking M6 Contract Compliance...
"%PYTHON_CMD%" contract\tools\check_module.py --module M6 --file m6_response\contract_out\response_actions.json
"%PYTHON_CMD%" contract\tools\check_module.py --module M6 --event m6_response\contract_events\response_done.json
if "%~1"=="" pause & goto :MENU
exit /b %ERRORLEVEL%

:CMD_CHECK_M7
echo.
echo [*] Checking M7 Contract Compliance...
"%PYTHON_CMD%" contract\tools\check_module.py --module M7 --file m7_core\contract_out\pipeline.json
if "%~1"=="" pause & goto :MENU
exit /b %ERRORLEVEL%

:CMD_RUN_CLIS
echo.
echo [*] Executing CLIs to regenerate contract outputs...
set "SAMPLE_AID=00000003-0000-4000-8000-000000000003"
set "SAMPLE_VID=00000003-0000-4000-8000-000000000003"

echo [*] Running M4 CLI...
"%PYTHON_CMD%" -m m4_ioc.cli --analysis-id !SAMPLE_AID! --out m4_ioc\contract_out\iocs.json

echo [*] Running M5 CLI...
"%PYTHON_CMD%" -m m5_detection.cli --analysis-id !SAMPLE_AID! --out m5_detection\contract_out\scoring.json

echo [*] Running M6 CLI...
"%PYTHON_CMD%" -m m6_response.cli --analysis-id !SAMPLE_AID! --vault-id !SAMPLE_VID! --out m6_response\contract_out\response_actions.json

echo [*] Running M7 CLI...
"%PYTHON_CMD%" -m m7_core.cli --analysis-id !SAMPLE_AID! --vault-id !SAMPLE_VID! --out m7_core\contract_out\pipeline.json

echo.
echo [+] CLIs executed. Re-running gate check:
"%PYTHON_CMD%" contract\tools\check_all.py --repo-root .
if "%~1"=="" pause & goto :MENU
exit /b 0

:CMD_STUBS
echo.
echo [*] Generating / refreshing contract stubs for all modules...
for %%M in (M1 M2 M3 M4 M5 M6 M7 M8) do (
    echo [+] Generating stub for %%M...
    "%PYTHON_CMD%" contract\tools\stub_module.py %%M
)
echo.
echo [+] Stubs refreshed.
if "%~1"=="" pause & goto :MENU
exit /b 0

:CMD_SERVER
echo.
echo [*] Starting M7 Core REST API server on http://localhost:8000 ...
echo [*] OpenAPI Docs available at http://localhost:8000/docs
echo [*] Press Ctrl+C to stop.
echo.
"%UVICORN_CMD%" m7_core.api.app:app --host 0.0.0.0 --port 8000 --reload
if "%~1"=="" pause & goto :MENU
exit /b 0

:CMD_UI
echo.
echo [*] Launching TRAC SOC Command Center Web Dashboard on http://127.0.0.1:8088 ...
echo [*] Press Ctrl+C to stop the web server.
echo.
"%PYTHON_CMD%" -m m8_ui_devops.cli --serve-ui --port 8088 --open-browser
if "%~1"=="" pause & goto :MENU
exit /b 0

:CMD_INSTALL
echo.
echo [*] Installing dependencies from requirements files...
"%PYTHON_CMD%" -m pip install -r contract\requirements.txt
if exist "m6_response\requirements.txt" "%PYTHON_CMD%" -m pip install -r m6_response\requirements.txt
if exist "m7_core\requirements.txt" "%PYTHON_CMD%" -m pip install -r m7_core\requirements.txt
echo.
echo [+] Dependencies installed.
if "%~1"=="" pause & goto :MENU
exit /b 0

:CMD_HELP
echo.
echo Usage: run.bat [command]
echo.
echo Commands:
echo   gate          Run CI gate across all committed modules (default CI check)
echo   gate-strict   Run strict CI gate requiring all M1-M8 outputs
echo   contract-test Run contract unit test suite (21 schema and rule tests)
echo   test          Run pytest across all active modules (M4, M5, M6, M7)
echo   check-m4      Validate M4 output and event against contract
echo   check-m5      Validate M5 output and event against contract
echo   check-m6      Validate M6 output and event against contract
echo   check-m7      Validate M7 output against contract
echo   run-clis      Execute module CLIs to produce contract outputs
echo   stubs         Regenerate valid contract stubs for all modules
echo   server, api   Start M7 FastAPI core server on port 8000
echo   ui, dashboard Launch SOC Analyst web console on port 8088
echo   install       Install module requirements via pip
echo   help          Show this help message
echo.
echo If run without arguments, launches an interactive menu.
echo.
exit /b 0
