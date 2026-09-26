# scripts/install_hooks.ps1
# Copies hooks/pre-commit to .git/hooks/pre-commit and marks it executable.
# Run from the repo root: ./scripts/install_hooks.ps1

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$source   = Join-Path $repoRoot "hooks\pre-commit"
$dest     = Join-Path $repoRoot ".git\hooks\pre-commit"

Copy-Item -Path $source -Destination $dest -Force

# Record the +x bit in the Git index so it survives on Unix clones.
Push-Location $repoRoot
try {
    git add --chmod=+x hooks/pre-commit
    if ($LASTEXITCODE -ne 0) {
        Write-Error "git add --chmod=+x failed (exit $LASTEXITCODE)"
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host "Hook installed: $dest"
Write-Host "Every 'git commit' will now run: python countersign.py run"
