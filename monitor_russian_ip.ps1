# Russian IP Monitoring and Blocking Script
# Requires Administrator privileges for firewall rules

# Configuration Section
$checkInterval = 10            # Check interval in seconds
$tg_token = "5916664980:AAG_kfjbd7550xvwEjey-7_2aPyXvmTUWp0"   # Telegram Bot Token
$tg_chat_id = "759265022"   # Your Chat ID from @my_id_bot

$script:monitoring = $true
$firewallRuleName = "Block Russian IPs"
$russianIPsBlocked = $false

$russianIPRanges = @(
    "2.56.0.0/14",
    "2.60.0.0/14",
    "5.136.0.0/13",
    "5.144.0.0/12",
    "31.128.0.0/11",
    "37.0.0.0/11",
    "45.10.0.0/15",
    "46.0.0.0/16",
    "77.0.0.0/8",
    "78.0.0.0/7",
    "79.0.0.0/7",
    "80.0.0.0/7",
    "83.0.0.0/8",
    "84.0.0.0/8",
    "87.0.0.0/8",
    "89.0.0.0/8",
    "90.0.0.0/8",
    "93.0.0.0/8",
    "94.0.0.0/8",
    "95.0.0.0/8",
    "109.0.0.0/8",
    "128.0.0.0/8",
    "130.0.0.0/8",
    "176.0.0.0/8",
    "178.0.0.0/8",
    "185.0.0.0/8",
    "188.0.0.0/8",
    "193.0.0.0/8",
    "195.0.0.0/8",
    "217.0.0.0/8"
)

# Function to get current public IP and location
function Get-CurrentIPInfo {
    try {
        # Method 1: Get public IP from external service
        Write-Host "Getting public IP information..." -ForegroundColor Gray
        $publicIP = Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10
        Write-Host "Public IP: $publicIP" -ForegroundColor Cyan
        
        # Method 2: Get geolocation information
        try {
            $geoInfo = Invoke-RestMethod -Uri "http://ip-api.com/json/$publicIP" -TimeoutSec 10
            return @{
                IP = $publicIP
                Country = $geoInfo.country
                CountryCode = $geoInfo.countryCode
                Region = $geoInfo.region
                City = $geoInfo.city
                ISP = $geoInfo.isp
            }
        }
        catch {
            Write-Host "Geolocation service unavailable, using IP analysis" -ForegroundColor Yellow
            return @{
                IP = $publicIP
                Country = "Unknown"
                CountryCode = "XX"
                Region = "Unknown"
                City = "Unknown"
                ISP = "Unknown"
            }
        }
    }
    catch {
        Write-Host "Error getting public IP: $_" -ForegroundColor Red
        return $null
    }
}

# Function to check if IP is Russian
function Test-IsRussianIP {
    param([string]$IP)
    
    foreach ($range in $russianIPRanges) {
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
        [System.Windows.Forms.MessageBox]::Show($Message, "Russian IP Monitor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
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
        $script:russianIPsBlocked = $true
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
        $script:russianIPsBlocked = $false
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

# Function to handle user choice when Russian IP is detected
function Invoke-UserChoice {
    param([string]$CurrentIP, [string]$Country)
    
    $choice = [System.Windows.Forms.MessageBox]::Show(
        "Обнаружено подключение через Российский IP!`nIP: $CurrentIP`nСтрана: $Country`n`nЗаблокировать интернет-соединение?`n'Нет' - временно разрешить работу", 
        "Обнаружен Российский IP", 
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
    Write-Host "    RUSSIAN IP MONITORING SCRIPT" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Status: RUNNING" -ForegroundColor Green
    Write-Host "Target: Block Russian IPs" -ForegroundColor Red
    Write-Host "Check Interval: $checkInterval seconds" -ForegroundColor Yellow
    Write-Host "Firewall Block: $(if ($russianIPsBlocked) {'ACTIVE'} else {'INACTIVE'})" -ForegroundColor $(if ($russianIPsBlocked) {'Red'} else {'Green'})
    Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Gray
    Write-Host "=========================================" -ForegroundColor Cyan
}

# Main monitoring function
function Start-RussianIPMonitoring {
    Write-Host "Starting Russian IP monitoring..." -ForegroundColor Green
    Write-Host "Monitoring for Russian IP addresses..." -ForegroundColor Yellow
    
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
        $ipInfo = Get-CurrentIPInfo
        
        if ($ipInfo) {
            $isRussianByRange = Test-IsRussianIP -IP $ipInfo.IP
            $isRussianByGeo = $ipInfo.CountryCode -eq "RU"
            $isRussian = $isRussianByGeo -or $isRussianByRange
            
            Write-Host "IP: $($ipInfo.IP)" -ForegroundColor $(if ($isRussian) {'Red'} else {'Green'})
            Write-Host "Country: $($ipInfo.Country)" -ForegroundColor $(if ($isRussian) {'Red'} else {'Green'})
            Write-Host "City: $($ipInfo.City)" -ForegroundColor Cyan
            
            if ($isRussian) {
                Write-Host "RUSSIAN IP DETECTED!" -ForegroundColor Red -BackgroundColor White

                # 1. Send Telegram notification
                $tgMessage = "🚨 RUSSIAN IP DETECTED: $($ipInfo.IP)`nCountry: $($ipInfo.Country)`nCity: $($ipInfo.City)`nISP: $($ipInfo.ISP)`nTime: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                Send-TelegramNotification -messageText $tgMessage
                
                # 2. Show popup notification
                Show-Notification "Russian IP detected!`nIP: $($ipInfo.IP)`nCountry: $($ipInfo.Country)`nCity: $($ipInfo.City)"
                
                # 3. Enable firewall block and ask user
                if ($isAdmin) {
                    Enable-InternetBlock | Out-Null
                    Invoke-UserChoice -CurrentIP $ipInfo.IP -Country $ipInfo.Country | Out-Null
                }
            }
        }
        else {
            Write-Host "Failed to get IP information" -ForegroundColor Yellow
        }
        
        # Wait for interval
        Write-Host "Waiting $checkInterval seconds until next check..." -ForegroundColor Gray
        Start-Sleep -Seconds $checkInterval
    }
    
    # Cleanup
    Write-Host "`nStopping Russian IP monitor..." -ForegroundColor Yellow
    if ($isAdmin) {
        Disable-InternetBlock
        Write-Host "Internet access restored." -ForegroundColor Green
    }
    Write-Host "Monitoring stopped." -ForegroundColor Green
}

# Script startup
Clear-Host
Write-Host "Russian IP Monitoring Script Starting..." -ForegroundColor Cyan
Write-Host "Target: Detect and block Russian IP addresses" -ForegroundColor Red
Write-Host "Check Interval: $checkInterval seconds" -ForegroundColor Yellow

try {
    # Start monitoring
    Show-ScriptStatus
    Start-RussianIPMonitoring
}
finally {
    Write-Host "`nPerforming final cleanup..." -ForegroundColor Yellow
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($isAdmin) {
        try {
            Set-NetFirewallRule -DisplayName $firewallRuleName -Enabled False -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue
            Write-Host "Firewall rules completely removed." -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Some firewall cleanup operations failed: $_" -ForegroundColor Yellow
        }
    }
    Write-Host "Script execution completed." -ForegroundColor Green
}
