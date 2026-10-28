param([string]$Exe = "$PSScriptRoot\..\build\DLLExplorer.exe")
$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$scratch = Join-Path $PSScriptRoot '..\build\integration'
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$scratch = (Resolve-Path -LiteralPath $scratch).Path
$unicodeFile = Join-Path $scratch 'Türkçe test.dll'
Copy-Item -LiteralPath "$env:WINDIR\System32\version.dll" -Destination $unicodeFile -Force
$report = Join-Path $scratch 'sonuç raporu.json'
function Inspect([string]$InputFile,[string]$ReportFile,[int]$ExpectedCode) {
  $arguments = '--inspect "' + $InputFile + '" "' + $ReportFile + '"'
  $process = Start-Process -FilePath $Exe -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
  if ($process.ExitCode -ne $ExpectedCode) { throw "Expected exit $ExpectedCode, got $($process.ExitCode)." }
}
Inspect $unicodeFile $report 0
$data = Get-Content -LiteralPath $report -Raw -Encoding UTF8 | ConvertFrom-Json
if ($data.path -ne $unicodeFile) { throw 'Unicode file path did not round-trip.' }
if ($data.architecture -ne 'x64' -or $data.exports.Count -lt 1) { throw 'version.dll metadata mismatch.' }
if ($data.application -ne 'DLL Explorer 1.1.0') { throw 'Application version mismatch.' }
if ($data.dependencies.Count -ne $data.library_count) { throw 'Dependency report mismatch.' }
$expectedHash = (Get-FileHash -LiteralPath $unicodeFile -Algorithm SHA256).Hash.ToLowerInvariant()
if ($data.sha256 -ne $expectedHash) { throw 'SHA-256 does not match Windows.' }
$bad = Join-Path $scratch 'invalid.dll'
[System.IO.File]::WriteAllText($bad, 'This is not a Portable Executable.')
Inspect $bad (Join-Path $scratch 'invalid.json') 2
$badReport = Get-Content -LiteralPath (Join-Path $scratch 'invalid.json') -Raw | ConvertFrom-Json
if (!$badReport.error) { throw 'Invalid file did not produce an error report.' }
Inspect (Join-Path $scratch 'missing.dll') (Join-Path $scratch 'missing.json') 2
Inspect $unicodeFile (Join-Path $scratch 'nonexistent\report.json') 3
Inspect $unicodeFile $unicodeFile 3
if ((Get-FileHash -LiteralPath $unicodeFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
  throw 'Report export altered the input binary.'
}
$lockedReport = Join-Path $scratch 'locked-report.json'
[System.IO.File]::WriteAllText($lockedReport, 'existing report')
$lock = [System.IO.File]::Open($lockedReport, [System.IO.FileMode]::Open,
                             [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
try { Inspect $unicodeFile $lockedReport 3 } finally { $lock.Dispose() }
if ([System.IO.File]::ReadAllText($lockedReport) -ne 'existing report') {
  throw 'Failed save altered the existing report.'
}
if (Get-ChildItem -LiteralPath $scratch -Filter '.dllexplorer-*.tmp' -Force) {
  throw 'A failed export left a temporary file behind.'
}
$lock = [System.IO.File]::Open($unicodeFile, [System.IO.FileMode]::Open,
                             [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
try { Inspect $unicodeFile (Join-Path $scratch 'locked-input.json') 2 } finally { $lock.Dispose() }
Inspect $Exe (Join-Path $scratch 'self.json') 0
$self = Get-Content -LiteralPath (Join-Path $scratch 'self.json') -Raw | ConvertFrom-Json
if ($self.warnings.Count -ne 0) { throw 'Self inspection produced warnings.' }
if ($self.imports.library | Where-Object { $_ -match '(?i)^(msvcp|vcruntime|ucrtbase)' }) { throw 'A C++ runtime dependency was found.' }
$process = Start-Process -FilePath $Exe -ArgumentList '--invalid-option' -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 64) { throw 'Invalid CLI arguments were not rejected.' }
Write-Output 'PASS: Unicode paths, JSON, SHA-256, locked/missing/invalid files, atomic writes, input protection, temporary cleanup, CLI validation and static runtime.'
