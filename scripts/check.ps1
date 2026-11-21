# Local gate for Windows; mirror of scripts/check.sh.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$python = if ($env:PYTHON) { $env:PYTHON } else { "python" }

Write-Host "== python =="
& $python --version
if ($LASTEXITCODE -ne 0) { throw "python not found" }

Write-Host "== doctor =="
& $python navhack.py doctor
if ($LASTEXITCODE -ne 0) { throw "doctor failed" }

Write-Host "== unit tests =="
$env:NAVHACK_HOME = if ($env:NAVHACK_HOME) { $env:NAVHACK_HOME } else { Join-Path (Get-Location) ".navhack" }
$env:PYTHONPATH = "src"
& $python -m unittest discover -s tests -t . -v
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Write-Host "== selftest =="
& $python navhack.py selftest
if ($LASTEXITCODE -ne 0) { throw "selftest failed" }

Write-Host "OK"
