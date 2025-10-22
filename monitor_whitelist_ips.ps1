# IP Monitoring and Blocking Script with Whitelist
# Requires Administrator privileges for firewall rules

# Load configuration from JSON
$configPath = Join-Path $PSScriptRoot "config.json"
$config = Get-Content $configPath | ConvertFrom-Json

$check_interval = $config.check_interval
$tg_token = $config.tg_token
$tg_chat_id = $config.tg_chat_id
$whitelist_IP_ranges = $config.whitelist_IP_ranges
$notifications_only = $config.notifications_only
$enable_telegram_notifications = $config.enable_telegram_notifications

$script:monitoring = $true
$firewallRuleName = "Block Non-Whitelist IPs"
$ipsBlocked = $false

# Function to get current public IP
function Get-CurrentIP {
    try {
        Write-Host "Getting public IP information..." -ForegroundColor Gray

        # Refresh ServicePoint for api.ipify.org,
        # to avoid caching by connection change (VPN on/off)
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint("https://api.ipify.org")
        if ($servicePoint) {
            $servicePoint.CloseConnectionGroup("") | Out-Null
            $servicePoint.ConnectionLeaseTimeout = 0  # Turn off keep-alive
        }

        $publicIP = Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10
        Write-Host "Public IP: $publicIP" -ForegroundColor Cyan

        return @{
            IP = $publicIP
        }
    }
    catch {
        Write-Host "Error getting public IP: $_" -ForegroundColor Red
        return $null
    }
}
# Function to check if IP is in whitelist
function Test-IsWhitelistedIP {
    param([string]$IP)

    # Если whitelist пуст, блокируем все IP
    if ($whitelist_IP_ranges.Count -eq 0) {
        return $false
    }

    foreach ($range in $whitelist_IP_ranges) {
        if (Test-IPInRange -IP $IP -Range $range) {
            return $true
        }
    }
    return $false
}

# Function to check if IP is in specific range
function Test-IPInRange {
    param([string]$IP, [string]$Range)

    try {
        $ipParts = $IP -split '\.'
        $rangeParts = $Range -split '/'
        $network = $rangeParts[0]
        $cidr = [int]$rangeParts[1]

        $networkParts = $network -split '\.'
        $ipNumber = ([uint32]$ipParts[0] -shl 24) -bor ([uint32]$ipParts[1] -shl 16) -bor ([uint32]$ipParts[2] -shl 8) -bor [uint32]$ipParts[3]
        $networkNumber = ([uint32]$networkParts[0] -shl 24) -bor ([uint32]$networkParts[1] -shl 16) -bor ([uint32]$networkParts[2] -shl 8) -bor [uint32]$networkParts[3]
        $mask = (-1 -shl (32 - $cidr))

        return ($ipNumber -band $mask) -eq ($networkNumber -band $mask)
    }
    catch {
        return $false
    }
}

# Function to show popup notification
function Show-Notification {
    param([string]$Message)

    try {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show($Message, "IP Monitor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    catch {
        Write-Host "Notification error: $_"
    }
}

# Function to block all internet traffic
function Enable-InternetBlock {
    try {
        $firewallRule = Get-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue

        if (-not $firewallRule) {
            # Create new firewall rule to block all outbound traffic
            New-NetFirewallRule -DisplayName $firewallRuleName `
                -Direction Outbound `
                -Action Block `
                -Enabled True `
                -Profile Any | Out-Null
            Write-Host "Internet traffic blocked." -ForegroundColor Red
        }
        else {
            # Enable existing rule
            Set-NetFirewallRule -DisplayName $firewallRuleName -Enabled True
            Write-Host "Internet traffic blocked." -ForegroundColor Red
        }
        $script:ipsBlocked = $true
        return $true
    }
    catch {
        Write-Host "Error enabling firewall rule: $_" -ForegroundColor Red
        Show-Notification "Error enabling firewall rule. Run script as Administrator!"
        return $false
    }
}

# Function to enable internet traffic
function Disable-InternetBlock {
    try {
        Set-NetFirewallRule -DisplayName $firewallRuleName -Enabled False
        Write-Host "Internet traffic enabled." -ForegroundColor Green
        $script:ipsBlocked = $false
        return $true
    }
    catch {
        Write-Host "Error disabling firewall rule: $_" -ForegroundColor Red
        return $false
    }
}

# Function to send Telegram notification
function Send-TelegramNotification {
    param([string]$messageText)

    # Проверяем, включены ли телеграм уведомления
    if (-not $enable_telegram_notifications) {
        Write-Host "Telegram notifications are disabled in config" -ForegroundColor Gray
        return
    }

    if ($tg_token -eq "YOUR_BOT_TOKEN" -or $tg_chat_id -eq "YOUR_CHAT_ID") {
        Write-Host "Telegram not configured. Please set token and chat ID." -ForegroundColor Yellow
        return
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $url = "https://api.telegram.org/bot$($tg_token)/sendMessage"
        $body = @{
            chat_id = $tg_chat_id
            text = $messageText
            parse_mode = "HTML"
        }

        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body
        Write-Host "Telegram notification sent." -ForegroundColor Green
    }
    catch {
        Write-Host "Error sending Telegram notification: $_" -ForegroundColor Red
    }
}

# Function to handle user choice when non-whitelisted IP is detected
function Invoke-UserChoice {
    param([string]$CurrentIP)

    $choice = [System.Windows.Forms.MessageBox]::Show(
            "Обнаружено подключение через Неразрешенный IP!`nIP: $CurrentIP`n`nЗаблокировать интернет-соединение?`n'Нет' - временно разрешить работу",
            "Обнаружен Неразрешенный IP",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($choice -eq 'No') {
        # User chose to temporarily allow
        Disable-InternetBlock | Out-Null
        return $true
    }
    else {
        # User chose to block
        Enable-InternetBlock | Out-Null
        return $false
    }
}

# Function to display script status
function Show-ScriptStatus {
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "    IP MONITORING SCRIPT (WHITELIST)" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Status: RUNNING" -ForegroundColor Green
    Write-Host "Mode: $(if ($notifications_only) {'NOTIFICATIONS ONLY'} else {'BLOCKING'})" -ForegroundColor $(if ($notifications_only) {'Yellow'} else {'Blue'})
    Write-Host "Telegram: $(if ($enable_telegram_notifications) {'ENABLED'} else {'DISABLED'})" -ForegroundColor $(if ($enable_telegram_notifications) {'Green'} else {'Gray'})
    Write-Host "Whitelist Entries: $($whitelistIPRanges.Count)" -ForegroundColor Yellow
    Write-Host "Check Interval: $checkInterval seconds" -ForegroundColor Yellow
    Write-Host "Firewall Block: $(if ($ipsBlocked) {'ACTIVE'} else {'INACTIVE'})" -ForegroundColor $(if ($ipsBlocked) {'Red'} else {'Green'})
    Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Gray
    Write-Host "=========================================" -ForegroundColor Cyan
}
# Main monitoring function
function Start-IPMonitoring {
    Write-Host "Starting IP monitoring with whitelist..." -ForegroundColor Green
    Write-Host "Only whitelisted IPs will be allowed..." -ForegroundColor Yellow

    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host "Warning: Not running as Administrator. Firewall operations may fail." -ForegroundColor Red
    }
    
    $checkCount = 0
    
    while ($script:monitoring) {
        $checkCount++
        Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Check #$checkCount" -ForegroundColor Gray
        
        # Get current IP information
        $ipInfo = Get-CurrentIP

        if ($ipInfo) {
            $isWhitelisted = Test-IsWhitelistedIP -IP $ipInfo.IP

            Write-Host "Whitelisted: $isWhitelisted" -ForegroundColor $(if ($isWhitelisted) {'Green'} else {'Red'})

            if (-not $isWhitelisted) {
                Write-Host "NON-WHITELISTED IP DETECTED!" -ForegroundColor Red -BackgroundColor White

                # 1. Send Telegram notification
                $tgMessage = "🚨 NON-WHITELISTED IP DETECTED: $($ipInfo.IP)`nTime: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`nStatus: $(if ($notifications_only) {'NOTIFICATIONS ONLY'} else {'BLOCKED'})"
                Send-TelegramNotification -messageText $tgMessage

                # 2. Show popup notification
                Show-Notification "NON-WHITELISTED IP DETECTED!`nIP: $($ipInfo.IP)`nMode: $(if ($notifications_only) {'NOTIFICATIONS ONLY'} else {'BLOCKING ACTIVE'})"

                # 3. Если режим "только уведомления" - не блокируем и не показываем выбор
                if (-not $notifications_only) {
                    # Enable firewall block and ask user (старая логика)
                    if ($isAdmin) {
                        Enable-InternetBlock | Out-Null
                        Invoke-UserChoice -CurrentIP $ipInfo.IP | Out-Null
                    }
                } else {
                    Write-Host "Notifications-only mode: Internet NOT blocked" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "Failed to get IP information" -ForegroundColor Yellow
        }

        # Wait for interval
        Write-Host "Waiting $check_interval seconds until next check..." -ForegroundColor Gray
        Start-Sleep -Seconds $check_interval
    }
}

# Script startup
Clear-Host
Write-Host "IP Monitoring Script with Whitelist Starting..." -ForegroundColor Cyan
Write-Host "Mode: Block all non-whitelisted IP addresses" -ForegroundColor Blue
Write-Host "Whitelist entries: $($whitelist_IP_ranges.Count)" -ForegroundColor Yellow
Write-Host "Check Interval: $check_interval seconds" -ForegroundColor Yellow

if ($whitelist_IP_ranges.Count -eq 0) {
    Write-Host "WARNING: Whitelist is empty! All IPs will be blocked!" -ForegroundColor Red
}

try {
    # Start monitoring
    Show-ScriptStatus
    Start-IPMonitoring
}
finally {
    Write-Host "`nPerforming final cleanup..." -ForegroundColor Yellow
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($isAdmin) {
        try {
            Disable-InternetBlock
            Write-Host "Firewall rules completely removed." -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Some firewall cleanup operations failed: $_" -ForegroundColor Yellow
        }
    }
    Write-Host "Script execution completed." -ForegroundColor Green
}
