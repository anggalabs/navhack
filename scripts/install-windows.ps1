# Windows installer: per-user venv, no admin required.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$python = if ($env:PYTHON) { $env:PYTHON } else { "py" }
if ($python -eq "py") {
    & py -3 --version | Out-Null
} else {
    & $python --version | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "python 3.9+ not found" }

Write-Host "creating venv..."
if ($python -eq "py") { & py -3 -m venv .venv } else { & $python -m venv .venv }

$venvPy = Join-Path (Get-Location) ".venv\Scripts\python.exe"
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install .

Write-Host ""
Write-Host "installed."
Write-Host "activate:  .\.venv\Scripts\Activate.ps1"
Write-Host "then:      navhack doctor"
