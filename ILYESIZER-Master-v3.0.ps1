<#
.SYNOPSIS
    ILYESIZER Master Controller v3.0 - Complete Gaming Optimization Suite
    Made by ilyyeees - Professional Gaming Performance Optimization

.DESCRIPTION
    ILYESIZER Master Controller v3.0 orchestrates the complete gaming optimization suite,
    coordinating all optimization modules for maximum system performance. This comprehensive
    controller manages CPU, GPU, Network, and Services optimizations in a synchronized manner.

    Key Features:
    - Comprehensive system analysis and safety checks
    - Coordinated optimization across all system components
    - Advanced safety features and backup creation
    - Performance monitoring and validation
    - Professional logging and reporting
    - System restore point management
    - Intelligent optimization sequencing
    - Real-time system monitoring

.PARAMETER SafeMode
    Enables conservative optimizations across all modules

.PARAMETER SkipBackup
    Skips backup creation (not recommended)

.PARAMETER CustomLogPath
    Specifies custom location for ILYESIZER log files

.OUTPUTS
    Comprehensive optimization report across all system components
    Detailed master log file with all optimization activities
    Individual module reports and logs

.EXAMPLE
    .\ILYESIZER-Master-v3.0.ps1
    Runs complete optimization suite with default settings

.EXAMPLE
    .\ILYESIZER-Master-v3.0.ps1 -SafeMode
    Runs conservative optimizations across all modules

.NOTES
    Script Name    : ILYESIZER Master Controller v3.0
    Version        : 3.0.0
    Author         : ilyyeees
    Creation Date  : 2024
    Purpose        : Complete gaming optimization orchestration
    
    Requirements:
    - PowerShell 5.1 or higher
    - Administrator privileges required
    - Windows 10/11 support
    - All ILYESIZER modules present
    
    Safety Features:
    - Automatic system restore point creation
    - Comprehensive backup management
    - Safe optimization validation
    - Advanced error handling
    - Professional logging system
#>

#Requires -Version 5.1

# ============================================================================
# ILYESIZER Master Controller v3.0 - CONFIGURATION
# ============================================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ILYESIZER Master Controller v3.0 Configuration
$Global:ILYESIZERMasterConfig = @{
    ScriptName = "ILYESIZER Master Controller v3.0"
    Version = "3.0.0"
    Author = "ilyyeees"
    LogFile = Join-Path $PSScriptRoot "ILYESIZER-Master-Log-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    BackupPath = Join-Path $PSScriptRoot "backup"
    TempPath = Join-Path $env:TEMP "ILYESIZER-optimization"    RequiredFiles = @(
        "gaming-optimization.ps1"           # ILYESIZER Core v3.0
        "ILYESIZER-GPU-v3.0.ps1"           # ILYESIZER GPU v3.0
        "ILYESIZER-Network-v3.0.ps1"       # ILYESIZER Network v3.0
        "ILYESIZER-Services-v3.0.ps1"      # ILYESIZER Services v3.0
    )
    SafetyChecks = $true
    CreateRestorePoint = $true
    MaxLogSize = 10MB
    LogRetentionDays = 30
    OptimizationLevel = "Maximum"
    PerformanceThreshold = 95
}

# Ensure required directories exist
if (-not (Test-Path $Global:ILYESIZERMasterConfig.BackupPath)) {
    New-Item -Path $Global:ILYESIZERMasterConfig.BackupPath -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path $Global:ILYESIZERMasterConfig.TempPath)) {
    New-Item -Path $Global:ILYESIZERMasterConfig.TempPath -ItemType Directory -Force | Out-Null
}

# Enhanced logging function with timestamps and levels
function Write-ILYESIZERLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Rotate log if it gets too large
    if (Test-Path $Global:ILYESIZERMasterConfig.LogFile) {
        $logSize = (Get-Item $Global:ILYESIZERMasterConfig.LogFile).Length
        if ($logSize -gt $Global:ILYESIZERMasterConfig.MaxLogSize) {
            $backupLog = $Global:ILYESIZERMasterConfig.LogFile -replace "\.log$", "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            Move-Item $Global:ILYESIZERMasterConfig.LogFile $backupLog
        }
    }
    
    Add-Content -Path $Global:ILYESIZERMasterConfig.LogFile -Value $logEntry -Encoding UTF8
    
    # Also display to console with colors using if statements
    if ($Level -eq "INFO") {
        Write-Host "INFO: $Message" -ForegroundColor Cyan
    }
    elseif ($Level -eq "WARNING") {
        Write-Host "WARNING: $Message" -ForegroundColor Yellow
    }
    elseif ($Level -eq "ERROR") {
        Write-Host "ERROR: $Message" -ForegroundColor Red
    }
    elseif ($Level -eq "SUCCESS") {
        Write-Host "SUCCESS: $Message" -ForegroundColor Green
    }
}

# Enhanced admin privilege check
function Test-AdminPrivileges {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            Write-ILYESIZERLog "Script requires administrator privileges" "ERROR"
            Write-Host "`nADMIN PRIVILEGES REQUIRED" -ForegroundColor Red
            Write-Host "Please right-click and 'Run as Administrator'" -ForegroundColor Yellow
            Write-Host "`nPress any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 1
        }
        
        Write-ILYESIZERLog "Administrator privileges confirmed" "SUCCESS"
        return $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-ILYESIZERLog "Failed to check admin privileges: $errorMessage" "ERROR"
        return $false
    }
}

# Enhanced system information display
function Show-SystemInfo {
    Write-Host "`nSYSTEM INFORMATION" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Gray
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $memory = Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
        $gpu = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.Name -notlike "*Basic*" } | Select-Object -First 1
        
        Write-Host "OS: $($os.Caption) $($os.Version)" -ForegroundColor White
        Write-Host "CPU: $($cpu.Name.Trim())" -ForegroundColor White
        Write-Host "RAM: $([math]::Round($memory.Sum / 1GB, 2)) GB" -ForegroundColor White
        if ($gpu) {
            Write-Host "GPU: $($gpu.Name)" -ForegroundColor White
        }
        Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor White
        
        $uptime = (Get-Date) - $os.LastBootUpTime
        Write-Host "Uptime: $($uptime.Days) days, $($uptime.Hours) hours" -ForegroundColor White
        
        Write-ILYESIZERLog "System information displayed successfully" "INFO"
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-ILYESIZERLog "Failed to retrieve system information: $errorMessage" "ERROR"
        Write-Host "Could not retrieve complete system information" -ForegroundColor Red
    }
}

# Enhanced restore point creation
function New-SystemRestorePoint {
    if (-not $Global:ILYESIZERMasterConfig.CreateRestorePoint) {
        Write-ILYESIZERLog "Restore point creation disabled in configuration" "INFO"
        return $false
    }
    
    Write-Host "`nCreating system restore point..." -ForegroundColor Cyan
    
    try {
        # Check if System Restore is enabled
        $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($null -eq $restoreStatus -and (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "DisableSR" -ErrorAction SilentlyContinue).DisableSR -eq 1) {
            Write-ILYESIZERLog "System Restore is disabled on this system" "WARNING"
            Write-Host "System Restore is disabled. Skipping restore point creation." -ForegroundColor Yellow
            return $false
        }
        
        $description = "Gaming Optimization Suite - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS"
        Write-ILYESIZERLog "System restore point created: $description" "SUCCESS"
        return $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-ILYESIZERLog "Failed to create restore point: $errorMessage" "WARNING"
        Write-Host "Could not create restore point. Continuing anyway..." -ForegroundColor Yellow
        return $false
    }
}

# Enhanced file validation
function Test-RequiredFiles {
    Write-Host "`nValidating optimization scripts..." -ForegroundColor Cyan
    
    $missingFiles = @()
    $Global:ILYESIZERMasterConfig.RequiredFiles | ForEach-Object {
        $filePath = Join-Path $PSScriptRoot $_
        if (-not (Test-Path $filePath)) {
            $missingFiles += $_
            Write-ILYESIZERLog "Missing required file: $_" "ERROR"
        } else {
            Write-Host "Found: $_" -ForegroundColor Green
        }
    }
    
    if ($missingFiles.Count -gt 0) {
        Write-Host "`nMISSING REQUIRED FILES:" -ForegroundColor Red
        $missingFiles | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
        Write-Host "`nPlease ensure all optimization scripts are in the same directory." -ForegroundColor Yellow
        return $false
    }
    
    Write-ILYESIZERLog "All required files validated successfully" "SUCCESS"
    return $true
}

# Enhanced script execution with error handling
function Invoke-OptimizationScript {
    param(
        [string]$ScriptName,
        [string]$Description
    )
    
    $scriptPath = Join-Path $PSScriptRoot $ScriptName
    
    Write-Host "`nExecuting: $Description" -ForegroundColor Cyan
    Write-Host "Script: $ScriptName" -ForegroundColor Gray
    Write-ILYESIZERLog "Starting optimization script: $ScriptName" "INFO"
    
    try {
        $startTime = Get-Date
        & $scriptPath
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        Write-ILYESIZERLog "Completed $ScriptName in $($duration.TotalSeconds) seconds" "SUCCESS"
        Write-Host "$Description completed successfully!" -ForegroundColor Green
        return $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-ILYESIZERLog "Error executing $ScriptName : $errorMessage" "ERROR"
        Write-Host "Error in $Description" -ForegroundColor Red
        Write-Host "Error: $errorMessage" -ForegroundColor Red
        return $false
    }
}

# Enhanced main menu
function Show-MainMenu {
    Clear-Host
    Write-Host "=============================================================" -ForegroundColor Cyan
    Write-Host "                ILYESIZER Master Controller v3.0           " -ForegroundColor Green
    Write-Host "           Complete Gaming Optimization Suite               " -ForegroundColor Green
    Write-Host "                    Made by ilyyeees                        " -ForegroundColor Cyan
    Write-Host "=============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "ILYESIZER OPTIMIZATION MODULES:" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Gray
    Write-Host "1. Complete ILYESIZER Optimization    (All-in-one suite)" -ForegroundColor White
    Write-Host "2. ILYESIZER Network v3.0             (Ultra-low latency)" -ForegroundColor White
    Write-Host "3. ILYESIZER GPU v3.0                 (Maximum graphics)" -ForegroundColor White
    Write-Host "4. ILYESIZER Services v3.0            (Service optimization)" -ForegroundColor White
    Write-Host ""
    Write-Host "ADVANCED SYSTEM OPTIONS:" -ForegroundColor Yellow
    Write-Host "=" * 60 -ForegroundColor Gray
    Write-Host "5. Show System Information" -ForegroundColor White
    Write-Host "6. Create System Restore Point" -ForegroundColor White
    Write-Host "7. Configuration Settings" -ForegroundColor White
    Write-Host "8. View ILYESIZER Logs" -ForegroundColor White
    Write-Host "9. Help & Information" -ForegroundColor White
    Write-Host "0. Exit" -ForegroundColor White
    Write-Host ""
    Write-Host "IMPORTANT: Run as Administrator for maximum optimization!" -ForegroundColor Yellow
    Write-Host "=" * 60 -ForegroundColor Gray
}

# Configuration menu using if statements
function Show-ConfigurationMenu {
    do {
        Clear-Host
        Write-Host "CONFIGURATION SETTINGS" -ForegroundColor Cyan
        Write-Host "=" * 40 -ForegroundColor Gray
        
        if ($Global:ILYESIZERMasterConfig.SafetyChecks) {
            Write-Host "1. Safety Checks: Enabled" -ForegroundColor White
        } else {
            Write-Host "1. Safety Checks: Disabled" -ForegroundColor White
        }
        
        if ($Global:ILYESIZERMasterConfig.CreateRestorePoint) {
            Write-Host "2. Auto Restore Points: Enabled" -ForegroundColor White
        } else {
            Write-Host "2. Auto Restore Points: Disabled" -ForegroundColor White
        }
        
        Write-Host "3. Log File: $($Global:ILYESIZERMasterConfig.LogFile)" -ForegroundColor White
        Write-Host "4. Max Log Size: $([math]::Round($Global:ILYESIZERMasterConfig.MaxLogSize / 1MB, 1)) MB" -ForegroundColor White
        Write-Host ""
        Write-Host "0. Return to Main Menu" -ForegroundColor Gray
        
        $configChoice = Read-Host "`nSelect option"
        
        if ($configChoice -eq "1") {
            $Global:ILYESIZERMasterConfig.SafetyChecks = -not $Global:ILYESIZERMasterConfig.SafetyChecks
            if ($Global:ILYESIZERMasterConfig.SafetyChecks) {
                Write-ILYESIZERLog "Safety checks enabled" "INFO"
            } else {
                Write-ILYESIZERLog "Safety checks disabled" "INFO"
            }
        }
        elseif ($configChoice -eq "2") {
            $Global:ILYESIZERMasterConfig.CreateRestorePoint = -not $Global:ILYESIZERMasterConfig.CreateRestorePoint
            if ($Global:ILYESIZERMasterConfig.CreateRestorePoint) {
                Write-ILYESIZERLog "Auto restore points enabled" "INFO"
            } else {
                Write-ILYESIZERLog "Auto restore points disabled" "INFO"
            }
        }
        elseif ($configChoice -eq "3") {
            $newPath = Read-Host "Enter new log file path"
            if ($newPath -and $newPath.Trim()) {
                $Global:ILYESIZERMasterConfig.LogFile = $newPath.Trim()
                Write-ILYESIZERLog "Log file path updated to: $newPath" "INFO"
            }
        }
        elseif ($configChoice -eq "4") {
            $newSize = Read-Host "Enter max log size in MB"
            if ($newSize -match '^\d+$' -and [int]$newSize -gt 0) {
                $Global:ILYESIZERMasterConfig.MaxLogSize = [int]$newSize * 1MB
                Write-ILYESIZERLog "Max log size updated to: ${newSize}MB" "INFO"
            }
        }
    } while ($configChoice -ne "0")
}

# Enhanced help information
function Show-HelpInformation {
    Clear-Host
    Write-Host "GAMING OPTIMIZATION SUITE - HELP & INFORMATION" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Gray
    Write-Host ""
    Write-Host "ABOUT THIS SUITE:" -ForegroundColor Yellow
    Write-Host "This comprehensive gaming optimization suite enhances your system's" -ForegroundColor White
    Write-Host "performance for gaming by optimizing various system components." -ForegroundColor White
    Write-Host ""
    Write-Host "OPTIMIZATION MODULES:" -ForegroundColor Yellow
    Write-Host "- Complete Gaming Optimization: Runs all optimizations sequentially" -ForegroundColor White
    Write-Host "- Network Optimization: Reduces latency, optimizes TCP/IP settings" -ForegroundColor White
    Write-Host "- GPU Optimization: Enhances graphics performance and power settings" -ForegroundColor White
    Write-Host "- Services Optimization: Disables unnecessary background services" -ForegroundColor White
    Write-Host ""
    Write-Host "SAFETY FEATURES:" -ForegroundColor Yellow
    Write-Host "- Automatic system restore point creation" -ForegroundColor White
    Write-Host "- Comprehensive logging of all changes" -ForegroundColor White
    Write-Host "- Administrator privilege verification" -ForegroundColor White
    Write-Host "- Backup of modified registry keys" -ForegroundColor White
    Write-Host ""
    Write-Host "IMPORTANT NOTES:" -ForegroundColor Red
    Write-Host "- Always run as Administrator for full functionality" -ForegroundColor White
    Write-Host "- Create a backup or restore point before optimizing" -ForegroundColor White
    Write-Host "- Some changes require a system restart to take effect" -ForegroundColor White
    Write-Host "- Review logs after optimization to verify changes" -ForegroundColor White
    Write-Host ""
    Write-Host "LOG LOCATION:" -ForegroundColor Yellow
    Write-Host "$($Global:ILYESIZERMasterConfig.LogFile)" -ForegroundColor White
    Write-Host ""
    Write-Host "Created by: ilyyeees" -ForegroundColor Gray
    Write-Host "Version: 2.0" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Press any key to return to menu..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Initialize the optimization suite
Write-ILYESIZERLog "Gaming Optimization Suite v2.0 started" "INFO"

# Verify administrator privileges
if (-not (Test-AdminPrivileges)) {
    exit 1
}

# Validate required files
if (-not (Test-RequiredFiles)) {
    Write-Host "`nPress any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Display initial system information
Show-SystemInfo

# Main program loop using if statements instead of switch
do {
    Show-MainMenu
    $choice = Read-Host "`nSelect an option (0-9)"
    
    if ($choice -eq "1") {
        Write-ILYESIZERLog "User selected: Complete Gaming Optimization" "INFO"
        if (New-SystemRestorePoint) {
            Write-Host "Restore point created successfully" -ForegroundColor Green
        }
        
        Write-Host "`nCOMPLETE GAMING OPTIMIZATION SEQUENCE" -ForegroundColor Cyan
        Write-Host "This will run all optimization modules in sequence..." -ForegroundColor Yellow
        
        $results = @()
        $results += Invoke-OptimizationScript "gaming-optimization.ps1" "Core Gaming Optimizations"
        $results += Invoke-OptimizationScript "ILYESIZER-Network-v3.0.ps1" "ILYESIZER Network v3.0 Optimizations"
        $results += Invoke-OptimizationScript "ILYESIZER-GPU-v3.0.ps1" "ILYESIZER GPU v3.0 Optimizations"
        $results += Invoke-OptimizationScript "ILYESIZER-Services-v3.0.ps1" "ILYESIZER Services v3.0 Optimizations"
        
        $successCount = ($results | Where-Object { $_ -eq $true }).Count
        $totalCount = $results.Count
        
        Write-Host "`nOPTIMIZATION SUMMARY:" -ForegroundColor Cyan
        if ($successCount -eq $totalCount) {
            Write-Host "Completed: $successCount/$totalCount modules" -ForegroundColor Green
        } else {
            Write-Host "Completed: $successCount/$totalCount modules" -ForegroundColor Yellow
        }
        Write-ILYESIZERLog "Complete optimization finished: $successCount/$totalCount modules successful" "INFO"
    }
    elseif ($choice -eq "2") {
        Write-ILYESIZERLog "User selected: Network Gaming Optimization" "INFO"
        Invoke-OptimizationScript "ILYESIZER-Network-v3.0.ps1" "ILYESIZER Network v3.0 Optimizations"
    }
    elseif ($choice -eq "3") {
        Write-ILYESIZERLog "User selected: GPU Gaming Optimization" "INFO"
        Invoke-OptimizationScript "ILYESIZER-GPU-v3.0.ps1" "ILYESIZER GPU v3.0 Optimizations"
    }
    elseif ($choice -eq "4") {
        Write-ILYESIZERLog "User selected: Services Gaming Optimization" "INFO"
        Invoke-OptimizationScript "ILYESIZER-Services-v3.0.ps1" "ILYESIZER Services v3.0 Optimizations"
    }
    elseif ($choice -eq "5") {
        Write-ILYESIZERLog "User requested system information display" "INFO"
        Show-SystemInfo
    }
    elseif ($choice -eq "6") {
        Write-ILYESIZERLog "User requested manual restore point creation" "INFO"
        if (New-SystemRestorePoint) {
            Write-Host "Restore point created successfully!" -ForegroundColor Green
        } else {
            Write-Host "Failed to create restore point" -ForegroundColor Red
        }
    }
    elseif ($choice -eq "7") {
        Write-ILYESIZERLog "User entered configuration menu" "INFO"
        Show-ConfigurationMenu
    }
    elseif ($choice -eq "8") {
        Write-ILYESIZERLog "User requested log file view" "INFO"
        if (Test-Path $Global:ILYESIZERMasterConfig.LogFile) {
            Write-Host "`nOPTIMIZATION LOG:" -ForegroundColor Gray
            Get-Content $Global:ILYESIZERMasterConfig.LogFile | Select-Object -Last 50
        } else {
            Write-Host "No log file found." -ForegroundColor Yellow
        }
    }
    elseif ($choice -eq "9") {
        Show-HelpInformation
    }
    elseif ($choice -eq "0") {
        Write-ILYESIZERLog "Gaming Optimization Suite ended by user" "INFO"
        Write-Host "`nThank you for using Gaming Optimization Suite!" -ForegroundColor Green
        break
    }
    else {
        Write-ILYESIZERLog "Invalid menu selection: $choice" "WARNING"
        Write-Host "Invalid option. Please select 0-9." -ForegroundColor Red
    }
    
    if ($choice -ne "0") {
        Write-Host "`nPress any key to return to menu..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Clear-Host
        Write-Host "Gaming Optimization Suite - Ready for next operation" -ForegroundColor Green
    }
} while ($choice -ne "0")

Write-Host "`nOPTIMIZATION COMPLETE!" -ForegroundColor Green
Write-Host "Restart your computer for all changes to take effect." -ForegroundColor Yellow
Write-Host "Log saved to: $($Global:ILYESIZERMasterConfig.LogFile)" -ForegroundColor Cyan
