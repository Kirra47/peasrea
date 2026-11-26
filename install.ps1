# 把 PeasRea 安装成 agent 技能（默认 %USERPROFILE%\.agents\skills\peasrea）
param(
    [string]$Dest = (Join-Path $env:USERPROFILE ".agents\skills\peasrea")
)
$ErrorActionPreference = "Stop"
$src = $PSScriptRoot
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

foreach ($item in @("SKILL.md", "README.md", "LICENSE", "references", "scripts", "assets", "kb")) {
    $p = Join-Path $src $item
    if (Test-Path $p) { Copy-Item $p -Destination $Dest -Recurse -Force }
}
Get-ChildItem $Dest -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "installed -> $Dest"
Write-Host "query:  python `"$Dest\scripts\kb_query.py`" --stats"
