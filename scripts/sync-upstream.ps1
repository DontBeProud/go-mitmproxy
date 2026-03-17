# sync-upstream.ps1
#
# Merges the latest changes from github.com/lqqyt2423/go-mitmproxy into this
# fork (github.com/DontBeProud/go-mitmproxy) while automatically rewriting
# the module path so that only real logic conflicts need manual resolution.
#
# Usage (from repo root):
#   .\scripts\sync-upstream.ps1 [-UpstreamBranch main]

param(
    [string]$UpstreamBranch = "main"
)

$ErrorActionPreference = "Stop"

$UpstreamRemote  = "upstream"
$RewriteBranch   = "upstream-rewritten"
$OldModule       = "github.com/lqqyt2423/go-mitmproxy"
$NewModule       = "github.com/DontBeProud/go-mitmproxy"

Write-Host "==> Fetching ${UpstreamRemote}/${UpstreamBranch}..."
git fetch $UpstreamRemote $UpstreamBranch

Write-Host "==> Creating/resetting rewrite branch '$RewriteBranch'..."
git branch -f $RewriteBranch "${UpstreamRemote}/${UpstreamBranch}"
git checkout $RewriteBranch

Write-Host "==> Rewriting module path in all Go/mod/md files..."
Get-ChildItem -Path . -Recurse -Include "*.go","go.mod","*.md" |
    Where-Object { $_.FullName -notmatch '\\.git\\' } |
    ForEach-Object {
        $content = Get-Content $_.FullName -Raw
        $updated = $content -replace [regex]::Escape($OldModule), $NewModule
        if ($content -ne $updated) {
            Set-Content -Path $_.FullName -Value $updated -NoNewline
            Write-Host "  rewritten: $($_.Name)"
        }
    }

Write-Host "==> Committing rewritten upstream..."
git add -A
$diff = git diff --cached --name-only
if ($diff) {
    git commit -m "chore: rewrite module path for upstream sync"
} else {
    Write-Host "  (nothing changed)"
}

Write-Host "==> Switching back and merging..."
git checkout -
git merge $RewriteBranch --no-ff -m "chore: sync upstream ${UpstreamRemote}/${UpstreamBranch}"

Write-Host ""
Write-Host "Done. If there are conflicts, resolve them then run: git merge --continue"
Write-Host "Afterwards clean up with: git branch -d $RewriteBranch"

