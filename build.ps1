param(
    [string]$OutputDirectory = "$PSScriptRoot\build",
    [switch]$Tests,
    [switch]$Analyze,
    [switch]$Sanitize
)
$ErrorActionPreference = 'Stop'
$pf86 = [Environment]::GetFolderPath('ProgramFilesX86')
$vswhere = "$pf86\Microsoft Visual Studio\Installer\vswhere.exe"
if (!(Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio Build Tools with Desktop development with C++.' }
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'A Visual C++ x64 toolchain was not found.' }
$vc = (Get-ChildItem -LiteralPath "$vs\VC\Tools\MSVC" -Directory | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1).FullName
$sdkRoot = "$pf86\Windows Kits\10"
$sdk = (Get-ChildItem -LiteralPath "$sdkRoot\Include" -Directory | Where-Object { Test-Path -LiteralPath "$sdkRoot\Lib\$($_.Name)\um\x64\kernel32.lib" } | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1).Name
if (!$sdk) { throw 'A Windows 10 or 11 SDK was not found.' }
$savedInclude = $env:INCLUDE
$savedLib = $env:LIB
$savedPath = $env:PATH
try {
    $env:INCLUDE = "$vc\include;$sdkRoot\Include\$sdk\ucrt;$sdkRoot\Include\$sdk\shared;$sdkRoot\Include\$sdk\um;$sdkRoot\Include\$sdk\winrt"
    $env:LIB = "$vc\lib\x64;$sdkRoot\Lib\$sdk\ucrt\x64;$sdkRoot\Lib\$sdk\um\x64"
    $compiler = "$vc\bin\Hostx64\x64\cl.exe"
    $resourceCompiler = "$sdkRoot\bin\$sdk\x64\rc.exe"
    $env:PATH = "$vc\bin\Hostx64\x64;$env:PATH"
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    Push-Location "$PSScriptRoot\assets"
    try { & $resourceCompiler /nologo /fo "$OutputDirectory\app.res" app.rc; if ($LASTEXITCODE) { throw 'Resource compilation failed.' } } finally { Pop-Location }
    $flags = @('/nologo','/std:c++17','/O2','/MT','/W4','/WX','/utf-8','/EHsc','/permissive-','/guard:cf','/sdl',
               '/D_WIN32_WINNT=0x0A00','/DUNICODE','/D_UNICODE','/DWIN32_LEAN_AND_MEAN','/DNOMINMAX')
    if ($Analyze) { $flags += '/analyze' }
    if ($Sanitize) { $flags += @('/fsanitize=address','/Zi') }
    $core = @("$PSScriptRoot\src\core\io.cpp","$PSScriptRoot\src\core\parser.cpp","$PSScriptRoot\src\core\report.cpp")
    $sources = $core + @("$PSScriptRoot\src\ui\model.cpp","$PSScriptRoot\src\ui\window.cpp","$PSScriptRoot\src\main.cpp")
    & $compiler @flags @sources "/Fo$OutputDirectory\" "/Fd$OutputDirectory\compile.pdb" "/Fe$OutputDirectory\DLLExplorer.exe" /link "$OutputDirectory\app.res" user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib uxtheme.lib bcrypt.lib /SUBSYSTEM:WINDOWS /MANIFEST:NO /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /OPT:REF /OPT:ICF /INCREMENTAL:NO
    if ($LASTEXITCODE) { throw 'C++ compilation failed.' }
    if ($Tests) {
      & $compiler @flags "$PSScriptRoot\tests\parser_tests.cpp" "/Fo$OutputDirectory\tests.obj" "/Fe$OutputDirectory\parser_tests.exe" /link "$OutputDirectory\io.obj" "$OutputDirectory\parser.obj" "$OutputDirectory\report.obj" bcrypt.lib
      if ($LASTEXITCODE) { throw 'Test compilation failed.' }
      & "$OutputDirectory\parser_tests.exe"
      if ($LASTEXITCODE) { throw 'Parser tests failed.' }
      if (Test-Path -LiteralPath "$PSScriptRoot\tests\model_tests.cpp") {
        & $compiler @flags "$PSScriptRoot\tests\model_tests.cpp" "/Fo$OutputDirectory\model_tests.obj" "/Fe$OutputDirectory\model_tests.exe" /link "$OutputDirectory\model.obj" "$OutputDirectory\io.obj" "$OutputDirectory\parser.obj" "$OutputDirectory\report.obj" bcrypt.lib user32.lib
        if ($LASTEXITCODE) { throw 'Model test compilation failed.' }
        & "$OutputDirectory\model_tests.exe"
        if ($LASTEXITCODE) { throw 'Model tests failed.' }
      }
    }
    Write-Output "Built: $OutputDirectory\DLLExplorer.exe"
} finally {
    $env:INCLUDE = $savedInclude
    $env:LIB = $savedLib
    $env:PATH = $savedPath
}
