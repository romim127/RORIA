param(
    [string]$BaseUrl = "https://sistema-inhibidor-skyeye.onrender.com",
    [string]$Username = $env:SKYEYE_SMOKE_USER,
    [string]$UserSecret = $env:SKYEYE_SMOKE_SECRET
)

$ErrorActionPreference = "Stop"

$base = $BaseUrl.TrimEnd("/")
$results = [System.Collections.Generic.List[object]]::new()
$token = ""

function Get-StatusCodeFromError {
    param([Parameter(Mandatory = $true)]$ErrorRecord)
    try {
        if ($null -ne $ErrorRecord.Exception.Response -and $null -ne $ErrorRecord.Exception.Response.StatusCode) {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
    }
    catch {
    }
    return 0
}

function Add-CheckResult {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Detail
    )

    $results.Add([PSCustomObject]@{
        Check  = $Name
        Status = $(if ($Passed) { "PASS" } else { "FAIL" })
        Detail = $Detail
    }) | Out-Null
}

Write-Host "== Smoke Test Post Deploy ==" -ForegroundColor Cyan
Write-Host "Base URL: $base" -ForegroundColor DarkCyan

# 1) Health check
try {
    $health = Invoke-RestMethod -Method GET -Uri "$base/api/health" -TimeoutSec 30
    $ok = ($health.status -eq "ok")
    Add-CheckResult -Name "Health endpoint" -Passed $ok -Detail "status=$($health.status)"
}
catch {
    Add-CheckResult -Name "Health endpoint" -Passed $false -Detail $_.Exception.Message
}

# 2) Protected endpoint without token should return 401
try {
    Invoke-RestMethod -Method GET -Uri "$base/api/users" -TimeoutSec 30 | Out-Null
    Add-CheckResult -Name "Auth guard /api/users" -Passed $false -Detail "Expected 401 but request succeeded"
}
catch {
    $code = Get-StatusCodeFromError -ErrorRecord $_
    Add-CheckResult -Name "Auth guard /api/users" -Passed ($code -eq 401) -Detail "http_status=$code"
}

# 3) Login
try {
    if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($UserSecret)) {
        throw "SKYEYE_SMOKE_USER/SKYEYE_SMOKE_SECRET no configuradas; login omitido"
    }
    $loginBody = @{ username = $Username; password = $UserSecret } | ConvertTo-Json
    $login = Invoke-RestMethod -Method POST -Uri "$base/api/auth/login" -ContentType "application/json" -Body $loginBody -TimeoutSec 30
    $token = [string]$login.token
    $ok = -not [string]::IsNullOrWhiteSpace($token)
    Add-CheckResult -Name "Login" -Passed $ok -Detail $(if ($ok) { "token_ok" } else { "token_missing" })
}
catch {
    Add-CheckResult -Name "Login" -Passed $false -Detail $_.Exception.Message
}

$headers = @{}
if (-not [string]::IsNullOrWhiteSpace($token)) {
    $headers["Authorization"] = "Bearer $token"
}

# 4) Auth me
try {
    if (-not $headers.ContainsKey("Authorization")) {
        throw "No token available"
    }
    $me = Invoke-RestMethod -Method GET -Uri "$base/api/auth/me" -Headers $headers -TimeoutSec 30
    $ok = -not [string]::IsNullOrWhiteSpace([string]$me.user.username)
    Add-CheckResult -Name "Auth me" -Passed $ok -Detail "user=$($me.user.username)"
}
catch {
    Add-CheckResult -Name "Auth me" -Passed $false -Detail $_.Exception.Message
}

# 5) Heatmap base endpoint
try {
    if (-not $headers.ContainsKey("Authorization")) {
        throw "No token available"
    }
    $heatmap = Invoke-RestMethod -Method GET -Uri "$base/api/heatmap" -Headers $headers -TimeoutSec 30
    $hasShape = ($null -ne $heatmap.points -and $null -ne $heatmap.stats -and $null -ne $heatmap.filters)
    Add-CheckResult -Name "Heatmap base" -Passed $hasShape -Detail "total=$($heatmap.total)"
}
catch {
    Add-CheckResult -Name "Heatmap base" -Passed $false -Detail $_.Exception.Message
}

# 6) Heatmap combined endpoint
try {
    if (-not $headers.ContainsKey("Authorization")) {
        throw "No token available"
    }
    $combined = Invoke-RestMethod -Method GET -Uri "$base/api/heatmap/combined?show_skyeye=true&show_guardian=true&show_backpack=true" -Headers $headers -TimeoutSec 30
    $hasShape = ($null -ne $combined.points -and $null -ne $combined.by_source)
    Add-CheckResult -Name "Heatmap combined" -Passed $hasShape -Detail "total=$($combined.total)"
}
catch {
    Add-CheckResult -Name "Heatmap combined" -Passed $false -Detail $_.Exception.Message
}

# 7) Combined with filters
try {
    if (-not $headers.ContainsKey("Authorization")) {
        throw "No token available"
    }
    $dateTo = (Get-Date).ToString("yyyy-MM-dd")
    $dateFrom = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
    $uri = "$base/api/heatmap/combined?date_from=$dateFrom&date_to=$dateTo&model=&show_skyeye=true&show_guardian=true&show_backpack=true"
    $combinedFiltered = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -TimeoutSec 30
    $hasShape = ($null -ne $combinedFiltered.points -and $null -ne $combinedFiltered.by_source)
    Add-CheckResult -Name "Heatmap combined filtered" -Passed $hasShape -Detail "total=$($combinedFiltered.total)"
}
catch {
    Add-CheckResult -Name "Heatmap combined filtered" -Passed $false -Detail $_.Exception.Message
}

# 8) Septier files list
try {
    if (-not $headers.ContainsKey("Authorization")) {
        throw "No token available"
    }
    $septierFiles = Invoke-RestMethod -Method GET -Uri "$base/api/septier/files" -Headers $headers -TimeoutSec 30
    $ok = ($null -ne $septierFiles.guardian -and $null -ne $septierFiles.backpack)
    Add-CheckResult -Name "Septier files" -Passed $ok -Detail "guardian_count=$($septierFiles.guardian.Count); backpack_count=$($septierFiles.backpack.Count)"
}
catch {
    Add-CheckResult -Name "Septier files" -Passed $false -Detail $_.Exception.Message
}

# 9) Delete endpoint route safety check (expect 404 on fake file)
try {
    if (-not $headers.ContainsKey("Authorization")) {
        throw "No token available"
    }
    Invoke-RestMethod -Method DELETE -Uri "$base/api/septier/delete/guardian/archivo_que_no_existe_123456.csv" -Headers $headers -TimeoutSec 30 | Out-Null
    Add-CheckResult -Name "Septier delete route" -Passed $false -Detail "Expected 404 but request succeeded"
}
catch {
    $code = Get-StatusCodeFromError -ErrorRecord $_
    Add-CheckResult -Name "Septier delete route" -Passed ($code -eq 404) -Detail "http_status=$code"
}

# Print report
Write-Host ""
Write-Host "== Results ==" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$failed = @($results | Where-Object { $_.Status -eq "FAIL" })
Write-Host ""
if ($failed.Count -gt 0) {
    Write-Host "Smoke test FAILED: $($failed.Count) check(s) failed." -ForegroundColor Red
    exit 1
}

Write-Host "Smoke test PASSED: all checks OK." -ForegroundColor Green
exit 0
