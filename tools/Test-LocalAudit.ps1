param([ValidateRange(30, 3600)][int]$TimeoutSeconds = 600)
$ErrorActionPreference = 'Stop'
trap {
    if ($runRoot -and (Test-Path -LiteralPath $runRoot)) {
        $_ | Out-String | Set-Content -LiteralPath (Join-Path $runRoot 'validation-error.txt') -Encoding UTF8
    }
    Write-Error $_ -ErrorAction Continue
    exit 1
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this development helper from elevated PowerShell.'
}
$repoRoot = Split-Path $PSScriptRoot -Parent
$source = Join-Path $repoRoot 'WinUsersAudit.vbs'
$runRoot = Join-Path $repoRoot ('.local-validation/' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $runRoot | Out-Null
$copy = Join-Path $runRoot 'WinUsersAudit.vbs'
Copy-Item -LiteralPath $source -Destination $copy
$sourceHash = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash
$bytes = [IO.File]::ReadAllBytes($copy)
if ($bytes.Length -lt 2 -or $bytes[0] -ne 255 -or $bytes[1] -ne 254) { throw 'Collector must be UTF-16 LE with BOM.' }
$process = Start-Process -FilePath "$env:SystemRoot\System32\cscript.exe" -ArgumentList @('//nologo', ('"' + $copy + '"')) -WorkingDirectory $runRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runRoot 'console.txt') -RedirectStandardError (Join-Path $runRoot 'stderr.txt') -PassThru
$null = $process.Handle
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F | Out-Null
    throw "Audit timed out. Inspect $runRoot"
}
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw "Audit exit code $($process.ExitCode). Inspect $runRoot" }
$expected = @{ user = 26; int = 15; route = 7; netstat = 11; software = 12 }
Add-Type -AssemblyName Microsoft.VisualBasic
foreach ($entry in $expected.GetEnumerator()) {
    $path = Join-Path $runRoot ($env:COMPUTERNAME + '_' + $entry.Key + '.csv')
    $payload = [IO.File]::ReadAllBytes($path)
    if ($payload.Length -lt 2 -or $payload[0] -ne 255 -or $payload[1] -ne 254) { throw "Invalid BOM: $path" }
    $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($path, [Text.Encoding]::Unicode)
    try {
        $parser.SetDelimiters(';')
        $parser.HasFieldsEnclosedInQuotes = $true
        $header = $parser.ReadFields()
        if ($header.Count -ne $entry.Value) { throw "Unexpected header width: $path" }
        while (-not $parser.EndOfData) {
            if ($parser.ReadFields().Count -ne $header.Count) { throw "Invalid row width: $path" }
        }
    } finally { $parser.Close() }
}
$diag = Join-Path $runRoot ($env:COMPUTERNAME + '_diag.log')
if (-not (Test-Path -LiteralPath $diag)) { throw 'Diagnostic log missing.' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead((Join-Path $runRoot ($env:COMPUTERNAME + '.zip')))
try {
    $names = @($expected.Keys | ForEach-Object { $env:COMPUTERNAME + '_' + $_ + '.csv' }) + @($env:COMPUTERNAME + '_diag.log')
    foreach ($name in $names) {
        $item = $zip.GetEntry($name)
        if ($null -eq $item) { throw "ZIP entry missing: $name" }
        $inputStream = $item.Open()
        $memory = [IO.MemoryStream]::new()
        try {
            $inputStream.CopyTo($memory)
            $actual = $memory.ToArray()
            $original = [IO.File]::ReadAllBytes((Join-Path $runRoot $name))
            if ($name.EndsWith('.csv') -and [Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($original)) { throw "ZIP content differs: $name" }
            if ($actual.Length -eq 0) { throw "Empty ZIP entry: $name" }
        } finally { $inputStream.Dispose(); $memory.Dispose() }
    }
} finally { $zip.Dispose() }
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $sourceHash) { throw 'Collector changed during validation; run again.' }
[pscustomobject]@{ CollectorSHA256 = $sourceHash; ExitCode = $process.ExitCode; StructuralChecks = 'PASS'; DiagnosticReview = 'REQUIRED'; Directory = $runRoot } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runRoot 'validation.json') -Encoding UTF8
Write-Output "Structural checks passed. Review diagnostics before commit/push: $runRoot"
