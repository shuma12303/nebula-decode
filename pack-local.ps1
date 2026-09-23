# =====================================================================
# pack-local.ps1 — 仅本地验证 + 打包 Pages 部署包（绝不碰 GitHub）
# 用法:  .\pack-local.ps1 [-Version v2.1]
# 顺序: node --check 语法检查 → 单元测试 → 打 zip 到项目根目录
# =====================================================================
param(
    [string]$Version = 'v2.1'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------- 0. 前置检查 ----------
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw '未找到 node，请先安装 Node.js'
}

# ---------- 1. 语法检查 ----------
Write-Host '[1/4] 语法检查 (node --check) ...' -ForegroundColor Cyan
& node --check "$Root\public\_worker.js"
if ($LASTEXITCODE -ne 0) { throw '语法检查失败' }
Write-Host '      语法 OK' -ForegroundColor Green

# ---------- 2. 单元测试 ----------
Write-Host '[2/4] 单元测试 (test/verify.mjs) ...' -ForegroundColor Cyan
& node "$Root\test\verify.mjs"
if ($LASTEXITCODE -ne 0) { throw '单元测试失败' }
Write-Host '      单元测试全绿' -ForegroundColor Green

# ---------- 3. 关键改动复核 ----------
Write-Host '[3/4] 关键改动复核 ...' -ForegroundColor Cyan
$src = Get-Content "$Root\public\_worker.js" -Raw
$checks = @{
    "版本号 $Version"       = ($src -match [regex]::Escape(">" + $Version + "<"))
    'Telegram 群组链接'     = ($src -match 't\.me/\+tVg48WK48tlkNGVl')
    'TG 胶囊样式 .tg'      = ($src -match '\.tg\{')
}
foreach ($k in $checks.Keys) {
    if ($checks[$k]) { Write-Host ("      √ {0}" -f $k) -ForegroundColor Green }
    else { Write-Host ("      × {0} 未找到" -f $k) -ForegroundColor Red; throw "复核失败: $k" }
}

# ---------- 4. 打包（zip 根目录只含 _worker.js） ----------
Write-Host '[4/4] 打包 ...' -ForegroundColor Cyan
$ZipName = "Pages-$Version.zip"
$Stage = Join-Path $env:TEMP 'nebula-pack-stage'
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Path $Stage | Out-Null
Copy-Item "$Root\public\_worker.js" "$Stage\_worker.js"
$ZipPath = Join-Path $Root $ZipName
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
Compress-Archive -Path "$Stage\_worker.js" -DestinationPath $ZipPath
$ZipSize = [math]::Round((Get-Item $ZipPath).Length / 1KB, 1)
Write-Host "      已生成 $ZipName ($ZipSize KB)" -ForegroundColor Green

Write-Host ''
Write-Host "完成! 部署包在: $ZipPath" -ForegroundColor Cyan
Write-Host '说明: 本脚本只做本地验证与打包, 不会推送 GitHub。' -ForegroundColor DarkGray
