@echo off
:: Step 1: Change to user profile
cd /d "%USERPROFILE%"

:: Step 2: Ensure pip is updated and install dependencies
py -m ensurepip --upgrade
py -m pip install fabric paramiko

:: Step 3: Setup SSH directory and keys
if not exist ".ssh" mkdir ".ssh"
cd .ssh
ssh-keygen -t ed25519 -f id_conduit -N ""

:: Step 4: Conditional Directory Change
:: If the folder exists, move there. Otherwise, echo a notice.
if exist "C:\Conduit" (
    cd /d "C:\Conduit"
) else (
    echo.
    echo [NOTICE] C:\Conduit not found. Staying in %CD%
)

:: Step 5: Hand over control to the user
cmd /k
