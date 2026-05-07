param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TracePath
)

if (-not (Test-Path $TracePath)) {
    Write-Error "Trace file not found: $TracePath"
    exit 1
}

$events = New-Object System.Collections.Generic.List[object]
Get-Content $TracePath | ForEach-Object {
    $line = $_.Trim()
    if (-not $line.StartsWith("{")) {
        return
    }
    try {
        $events.Add(($line | ConvertFrom-Json))
    } catch {
    }
}

function Require($Condition, [string]$Message) {
    if (-not $Condition) {
        Write-Error "Private-access trace check failed: $Message"
        exit 1
    }
}

function Has-Event {
    param(
        [string]$Plugin,
        [string]$Call,
        [string]$PathContains
    )

    foreach ($event in $events) {
        if ($Plugin -and $event.plugin -ne $Plugin) {
            continue
        }
        if ($Call -and $event.Call -ne $Call) {
            continue
        }
        $eventPath = [string]$event.Path
        if ($PathContains -and [string]::IsNullOrEmpty($eventPath)) {
            continue
        }
        if ($PathContains -and ($eventPath.IndexOf($PathContains, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) {
            continue
        }
        return $true
    }
    return $false
}

Require ($events.Count -gt 0) "no JSONL events were parsed from emulator output"
Require (
    Has-Event -Plugin "filemon" -Call "open" -PathContains "/Users/analyst/Library/Application Support/Binance/app-store.json"
) "sample did not attempt to open Binance wallet data"
Require (
    Has-Event -Plugin "filemon" -Call "read"
) "sample did not perform any file reads"
Require (
    Has-Event -Plugin "filemon" -Call "open" -PathContains "/Users/analyst/Library/Application Support/Firefox/Profiles/"
) "sample did not attempt to open Firefox profile data"
Require (
    Has-Event -Plugin "filemon" -Call "open" -PathContains "/Users/analyst/.electrum/wallets/"
) "sample did not attempt to open Electrum wallet data"
Require (
    Has-Event -Plugin "filemon" -Call "open" -PathContains "/Users/analyst/Library/Application Support/Coinomi/wallets/"
) "sample did not attempt to open Coinomi wallet data"
Require (
    Has-Event -Plugin "filemon" -Call "_lstat" -PathContains "/Users/analyst/Library/Application Support/Google/Chrome/"
) "sample did not probe Chrome profile roots"

Write-Output "Private-access trace check passed"
