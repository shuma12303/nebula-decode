# =====================================================================
# create-release.ps1 — 通过 GitHub API 发布 Release 并上传 Pages 部署包
# 用法:
#   .\create-release.ps1 -UserName smzxtv -Token <你的PAT> [-Version v1.6]
# =====================================================================
param(
    [Parameter(Mandatory = $true)][string]$UserName,
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$Version = 'v1.6',
    [string]$RepoName = 'nebula-decode'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

$Headers = @{
    Authorization          = "Bearer $Token"
    Accept                 = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent'           = 'release-script'
}
$Base = "https://api.github.com/repos/$UserName/$RepoName"

# ---------- 1. 打包 Pages 部署包 (zip 根目录只含 _worker.js) ----------
$ZipName = "Pages-$Version.zip"
$Stage = Join-Path $env:TEMP "nebula-release-stage"
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Path $Stage | Out-Null
Copy-Item "$Root\public\_worker.js" "$Stage\_worker.js"
$ZipPath = Join-Path $Root $ZipName
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
Compress-Archive -Path "$Stage\_worker.js" -DestinationPath $ZipPath
$ZipSize = [math]::Round((Get-Item $ZipPath).Length / 1KB, 1)
Write-Host "[1/3] 已打包 $ZipName ($ZipSize KB)" -ForegroundColor Green

# ---------- 2. 创建 Release (带中文说明) ----------
$Body = @"
## Nebula-Decode $Version

Cloudflare Pages/Workers 单文件终端 · 作者：**数码解码**

### Pages 一键部署（推荐新手）

1. 下载下方的 ``Pages-$Version.zip``
2. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers 和 Pages** → **创建** → **Pages** → **上传资产** → 选择这个 zip
3. 部署完成后绑定 KV：项目 → 设置 → 函数 → KV 命名空间绑定 → 变量名 ``KV``
4. 访问 ``https://项目名.pages.dev/24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d`` 进入管理面板
5. **第一时间在面板里点「随机生成 UUID」修改凭据 / Trojan 密码 / 自定义路径**

### 功能特性

- VLESS-WS-TLS / Trojan-WS-TLS 双协议，同一入口自动识别
- Web 图形化管理面板（面板内一键随机生成 UUID），配置存 KV 立即生效
- 订阅生成（base64 / Clash / Sing-box，自动识别 UA；`?target=` 可强制）
- 每条订阅可一键生成 SVG 二维码（零依赖，手机扫码导入）
- 优选 IP 管理 + REST API
- 内置 Cloudflare 优选 IP 池（HK/SG/JP/US/EU 共 28 个），订阅自动合并批量生成节点
- ProxyIP 智能回落

### 源码部署

也可以直接 clone 本仓库，用 ``npx wrangler pages deploy`` 部署，详见 README。

---
> ✦ 由 **数码解码** 出品 · 使用请遵守所在地区法律法规及 Cloudflare 服务条款
"@

$Payload = @{
    tag_name         = $Version
    target_commitish = 'main'
    name             = "Nebula-Decode $Version"
    body             = $Body
    draft            = $false
    prerelease       = $false
} | ConvertTo-Json

try {
    # PS5.1 的 -Body 字符串默认按 Latin-1 发送, 中文会变成非法 JSON, 必须显式转 UTF-8 字节
    $Release = Invoke-RestMethod -Uri "$Base/releases" -Method Post -Headers $Headers -Body ([Text.Encoding]::UTF8.GetBytes($Payload)) -ContentType 'application/json'
    Write-Host "[2/3] Release 已创建: $($Release.html_url)" -ForegroundColor Green
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 422) {
        Write-Host "[2/3] Release 已存在, 获取现有 Release..." -ForegroundColor Yellow
        $Release = Invoke-RestMethod -Uri "$Base/releases/tags/$Version" -Headers $Headers
    } else { throw }
}

# ---------- 3. 上传压缩包 ----------
$UploadUrl = ($Release.upload_url -split '\{')[0]
$AssetUri = "$UploadUrl`?name=$ZipName"
$Existing = $Release.assets | Where-Object { $_.name -eq $ZipName }
if ($Existing) {
    Invoke-RestMethod -Uri "$Base/releases/assets/$($Existing.id)" -Method Delete -Headers $Headers | Out-Null
    Write-Host "[3/3] 删除旧附件后重新上传..." -ForegroundColor Yellow
}
Invoke-RestMethod -Uri $AssetUri -Method Post -Headers $Headers -ContentType 'application/zip' -InFile $ZipPath | Out-Null
Write-Host "[3/3] 附件已上传: $ZipName ($ZipSize KB)" -ForegroundColor Green

Write-Host ""
Write-Host "完成! 发布页: $($Release.html_url)" -ForegroundColor Cyan