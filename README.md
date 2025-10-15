# Whitelist-ip-access
Whitelist IP Monitor & Blocker
PowerShell script for monitoring and automactic block of web-traffic when IP is not in whitelist.

# 📋 Functionality
Traffic block: Automatic creation and management of rules of the Windows firewall

Notifications:
System popup-notifications

Telegram-notifications (опционально)

# 🔧 Setting
1. Base setting
Edit env variables in config.json

powershell
checkInterval = 30                    # Check interval
tg_token = "YOUR_BOT_TOKEN"           # Telegram bot token (You can create your own bot or use existing which already defined in the script)
tg_chat_id = "YOUR_CHAT_ID"           # Telegram chat id
notifications_only                    # No blocking mode, only notifications

2. Telegram setting

2.1 Telegram bot setting (optional)
Create bot with @BotFather
Receive bot token
Insert it into tg_token in config.json

2.2 Telegram chat id receiving
Find out your Chat ID via @my_id_bot
Insert that value into chat_id env variable in .json

# 🚀 Launch

Launch PowerShell as an administrator:

powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser - with default ExecutionPolicy Powershell doesn't allow to launch custom scripts

Launch script:

powershell
.\monitor_russian_ip.ps1

# 🛡️ Security
Script requires adminstrator rights for:

Create Windows firewall rule

Network connection management

Network setting modification


# ⚠️ Important notes
Automatic recovery: When the script is ended correctly traffic blocking is automatically disabled

Manual management: When the script is ended incorrectly you mignt need to delete firewall rule manually

Performance: Script is optimized to work in the background mode

Compatibility: Script tested on Windows 11, should work on Windows 7/8/10

# 🔄 Restore connection
When the script is ended incorrectly and you have no network connection launch script - unlock_net.ps1.

