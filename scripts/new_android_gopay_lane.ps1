param(
  [Parameter(Mandatory = $true)]
  [string]$Lane,

  [Parameter(Mandatory = $true)]
  [string]$ServerBaseUrl,

  [Parameter(Mandatory = $true)]
  [string]$RelayToken,

  [Parameter(Mandatory = $true)]
  [string]$AdbSerial,

  [int]$AppiumPort = 4723,
  [int]$SystemPort = 8201,
  [int]$MjpegServerPort = 9201,
  [int]$ChromedriverPort = 9511,

  [string]$BaseConfig = "CTF-pay\config.android-gopay.local.json",
  [string]$FallbackBaseConfig = "CTF-pay\config.android-gopay.example.json",
  [string]$OutConfig = "",

  [string]$CountryCode = "",
  [string]$GoPayPhoneNumber = "",
  [string]$GoPayPin = ""
)

$ErrorActionPreference = "Stop"

function Get-LaneId {
  param([string]$Value)
  $raw = ($Value -as [string]).Trim()
  if ($raw -match '^\d+$') {
    return ("lane-{0:D2}" -f [int]$raw)
  }
  if ($raw -match '^lane-(\d+)$') {
    return ("lane-{0:D2}" -f [int]$Matches[1])
  }
  return $raw
}

function Set-JsonProp {
  param(
    [Parameter(Mandatory = $true)]$Object,
    [Parameter(Mandatory = $true)][string]$Name,
    $Value
  )
  if ($Object.PSObject.Properties.Name -contains $Name) {
    $Object.$Name = $Value
  } else {
    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
  }
}

function Ensure-JsonObject {
  param(
    [Parameter(Mandatory = $true)]$Object,
    [Parameter(Mandatory = $true)][string]$Name
  )
  $existing = $Object.PSObject.Properties[$Name]
  if ($null -eq $existing -or $null -eq $existing.Value -or $existing.Value -isnot [pscustomobject]) {
    Set-JsonProp -Object $Object -Name $Name -Value ([pscustomobject]@{})
  }
  return $Object.$Name
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$laneId = Get-LaneId $Lane

$basePath = Join-Path $repoRoot $BaseConfig
if (-not (Test-Path -LiteralPath $basePath)) {
  $basePath = Join-Path $repoRoot $FallbackBaseConfig
}
if (-not (Test-Path -LiteralPath $basePath)) {
  throw "Base config not found: $BaseConfig or $FallbackBaseConfig"
}

if (-not $OutConfig.Trim()) {
  $OutConfig = "CTF-pay\config.android-gopay.$laneId.local.json"
}
$outPath = Join-Path $repoRoot $OutConfig
$outRelative = $OutConfig -replace '\\', '/'

$cfg = Get-Content -Raw -LiteralPath $basePath | ConvertFrom-Json

$phoneWorker = Ensure-JsonObject -Object $cfg -Name "phone_worker"
Set-JsonProp -Object $phoneWorker -Name "instance_id" -Value $laneId
Set-JsonProp -Object $phoneWorker -Name "server_base_url" -Value $ServerBaseUrl.TrimEnd("/")
Set-JsonProp -Object $phoneWorker -Name "relay_token" -Value $RelayToken
Set-JsonProp -Object $phoneWorker -Name "state_file" -Value "output/$laneId/android-phone-worker-state.json"

$workerUnlink = Ensure-JsonObject -Object $phoneWorker -Name "gopay_unlink"
Set-JsonProp -Object $workerUnlink -Name "out_dir" -Value "output/$laneId/android-gopay-unlink"

$auto = Ensure-JsonObject -Object $cfg -Name "android_automation"
Set-JsonProp -Object $auto -Name "instance_id" -Value $laneId
Set-JsonProp -Object $auto -Name "adb_serial" -Value $AdbSerial
Set-JsonProp -Object $auto -Name "adb_connect_serials" -Value @($AdbSerial)
Set-JsonProp -Object $auto -Name "appium_server_url" -Value "http://127.0.0.1:$AppiumPort"
Set-JsonProp -Object $auto -Name "device_name" -Value "Android $laneId"

$caps = Ensure-JsonObject -Object $auto -Name "capabilities"
Set-JsonProp -Object $caps -Name "systemPort" -Value $SystemPort
Set-JsonProp -Object $caps -Name "mjpegServerPort" -Value $MjpegServerPort
Set-JsonProp -Object $caps -Name "chromedriverPort" -Value $ChromedriverPort

$gopay = Ensure-JsonObject -Object $cfg -Name "gopay"
if ($CountryCode.Trim()) {
  Set-JsonProp -Object $gopay -Name "country_code" -Value $CountryCode.Trim()
}
if ($GoPayPhoneNumber.Trim()) {
  Set-JsonProp -Object $gopay -Name "phone_number" -Value $GoPayPhoneNumber.Trim()
}
if ($GoPayPin.Trim()) {
  Set-JsonProp -Object $gopay -Name "pin" -Value $GoPayPin.Trim()
}

$otp = Ensure-JsonObject -Object $gopay -Name "otp"
Set-JsonProp -Object $otp -Name "source" -Value "command"
Set-JsonProp -Object $otp -Name "command" -Value @(
  "python",
  "CTF-pay/android_gopay_automation.py",
  "--config",
  $outRelative,
  "otp"
)

$outDir = Split-Path -Parent $outPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
  New-Item -ItemType Directory -Path $outDir | Out-Null
}

$cfg | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $outPath -Encoding UTF8

Write-Host "[lane] wrote $OutConfig"
Write-Host "[lane] id=$laneId webui=$($ServerBaseUrl.TrimEnd('/')) adb=$AdbSerial appium=http://127.0.0.1:$AppiumPort systemPort=$SystemPort"
Write-Host "[lane] start worker:"
Write-Host "python CTF-pay/android_phone_worker.py --config $OutConfig"
