param(
    [switch]$SkipPaperBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ProjectDir = Get-ChildItem -Path $Root -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName "zoom-\security") } |
    Select-Object -First 1

if ($null -eq $ProjectDir) {
    throw "Could not find zoom- project directory."
}

$ZoomRoot = Join-Path $ProjectDir.FullName "zoom-"
$SecureServerPy = Join-Path $ZoomRoot "client\secure_static_server.py"
$SecurityRoot = Join-Path $ZoomRoot "security"

$PythonFiles = @(
    (Join-Path $Root "tools\build_figures.py"),
    (Join-Path $Root "tools\build_paper_docx.py"),
    (Join-Path $Root "tools\build_vsc_paper.py"),
    $SecureServerPy,
    (Join-Path $SecurityRoot "encryption\encryption.py"),
    (Join-Path $SecurityRoot "session_management\session_security.py"),
    (Join-Path $SecurityRoot "data_leak_prevention\data_protection.py"),
    (Join-Path $SecurityRoot "buffer_overflow\buffer_protection.py"),
    (Join-Path $SecurityRoot "assessment\threat_zap_comparison.py")
)

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Command
}

Push-Location $Root
try {
    Invoke-Step "pyright" {
        $pyrightArgs = @(
            "--yes",
            "pyright",
            ".\tools",
            $SecureServerPy,
            $SecurityRoot
        )
        npx @pyrightArgs
    }

    Invoke-Step "markdownlint" {
        $markdownlintArgs = @(
            "--yes",
            "markdownlint-cli2",
            "*.md",
            "docs/**/*.md",
            "paper/**/*.md",
            "tools/**/*.md",
            "*/zoom-/**/*.md",
            "#jitsi-meet",
            "#reports"
        )
        npx @markdownlintArgs
    }

    Invoke-Step "python syntax" {
        python -m py_compile @PythonFiles
    }

    Invoke-Step "stride-zap comparison" {
        $comparisonArgs = @(
            (Join-Path $SecurityRoot "assessment\threat_zap_comparison.py"),
            "--stride-json",
            ".\reports\stride\stride_findings.json",
            "--zap-json",
            ".\reports\zap\secure\zap-secure-report.json",
            "--stride-minutes",
            "75",
            "--zap-minutes",
            "5",
            "--output-md",
            ".\reports\comparison\stride_zap_comparison.md",
            "--output-json",
            ".\reports\comparison\stride_zap_summary.json"
        )
        python @comparisonArgs | Out-Null
        python ".\tools\build_figures.py"
    }

    if (-not $SkipPaperBuild) {
        Invoke-Step "paper build" {
            python ".\tools\build_vsc_paper.py"
            python ".\tools\build_paper_docx.py"
        }
    }

    Write-Host "All validation steps passed." -ForegroundColor Green
}
finally {
    Pop-Location
}
