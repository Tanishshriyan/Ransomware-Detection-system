$ErrorActionPreference = "Stop"

# Allow this file to be launched from any working directory.
Set-Location -LiteralPath $PSScriptRoot

$python = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $python) {
    $python = Get-Command py -ErrorAction SilentlyContinue
}

if ($null -eq $python) {
    Write-Error "Python was not found. Install Python 3.12 and retry."
    exit 1
}

Write-Host "Starting RansomGuard. The launcher will create .venv and install dependencies if needed..." -ForegroundColor Cyan
& $python.Source (Join-Path $PSScriptRoot "run.py") @args
exit $LASTEXITCODE
