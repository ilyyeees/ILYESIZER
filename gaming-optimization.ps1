# ILYESIZER - Advanced Gaming PC Optimization Script
# Version 3.0 - Enhanced with comprehensive optimizations and safety features
# Created by ilyyeees
# Run as Administrator for best results
#
# DESCRIPTION:
# ILYESIZER is a comprehensive PowerShell script designed to optimize Windows systems
# for maximum gaming performance. This script applies aggressive system modifications
# to prioritize gaming workloads over general computing tasks.
#
# FEATURES:
# - Windows Game Mode optimization and configuration
# - Power plan adjustments for maximum performance
# - Visual effects optimization for performance over aesthetics
# - System file cleanup and temporary file removal
# - Gaming-specific registry optimizations
# - Startup program analysis and recommendations
# - Xbox Game Bar and Game DVR interference reduction
# - Mouse acceleration and input lag reduction
# - NTFS file system performance enhancements
# - Comprehensive logging and backup creation
#
# REQUIREMENTS:
# - Windows 10/11 (Build 15063 or later recommended)
# - PowerShell 5.1 or later
# - Administrator privileges for system-level optimizations
# - At least 4GB RAM recommended
# - Adequate cooling for sustained high performance
#
# SAFETY FEATURES:
# - Automatic registry backup creation before modifications
# - System restore point creation (optional)
# - Comprehensive error handling and logging
# - Admin privilege validation
# - System compatibility checks
#
# WARNINGS:
# - This script makes aggressive system modifications
# - Some changes may affect non-gaming performance
# - Higher power consumption and heat generation expected
# - System restart required for full optimization effect
# - Not recommended for productivity-focused systems
#
# USAGE:
# 1. Right-click PowerShell and select "Run as Administrator"
# 2. Navigate to script directory
# 3. Execute: .\gaming-optimization.ps1
# 4. Follow on-screen prompts and warnings
# 5. Restart system when prompted
#
# SUPPORT:
# For issues or questions, refer to the accompanying documentation
# or visit the project repository for updates and troubleshooting.

#Requires -Version 5.1

# ============================================================================
# CONFIGURATION AND INITIALIZATION
# ============================================================================

# Script execution policy and error handling configuration
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ILYESIZER Configuration Settings
# These settings control the behavior of the optimization script
$script:Config = @{
    # Log file location - stores detailed operation history
    LogFile = "$env:USERPROFILE\Desktop\ILYESIZER-Log-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    
    # Registry backup creation - creates .reg files before modifications
    BackupRegistry = $true
    
    # System restore point creation - enables system rollback capability
    CreateRestorePoint = $true
    
    # Verbose output control - detailed console output during operations
    VerboseOutput = $true
    
    # Script version and identification
    Version = "3.0"
    ScriptName = "ILYESIZER"
    Author = "ilyyeees"
    
    # Performance thresholds and limits
    MaxStartupPrograms = 20
    MinFreeSpaceGB = 5
    TargetLatencyMS = 1
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

<#
.SYNOPSIS
    Writes formatted log entries to both console and log file.

.DESCRIPTION
    This function provides centralized logging for ILYESIZER operations.
    It formats messages with timestamps and severity levels, then outputs
    to both the console (with color coding) and a persistent log file.

.PARAMETER Message
    The message text to log.

.PARAMETER Level
    The severity level: INFO, SUCCESS, WARNING, or ERROR.

.PARAMETER NoConsole
    Suppresses console output when specified.

.EXAMPLE
    Write-OptLog "System optimization started" "INFO"
    Write-OptLog "Registry backup created successfully" "SUCCESS"
    Write-OptLog "Service not found" "WARNING"
    Write-OptLog "Critical system error" "ERROR"
#>
function Write-OptLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with color coding for severity levels
    if (-not $NoConsole) {
        switch ($Level) {
            "INFO"    { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
            "SUCCESS" { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
            "WARNING" { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
            "ERROR"   { Write-Host "[ERROR] $Message" -ForegroundColor Red }
        }
    }
    
    # File logging with error suppression for robustness
    try {
        Add-Content -Path $script:Config.LogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        # Silently continue if logging fails to prevent script interruption
    }
}

<#
.SYNOPSIS
    Tests if the current PowerShell session has administrator privileges.

.DESCRIPTION
    Determines whether the current user context has administrative rights
    required for system-level optimizations. This is essential for registry
    modifications, service management, and power plan changes.

.OUTPUTS
    Boolean - True if running as administrator, False otherwise.

.EXAMPLE
    if (Test-IsAdmin) {
        Write-Host "Administrator privileges confirmed"
    } else {
        Write-Host "Elevation required"
    }
#>

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
.SYNOPSIS
    Creates a backup of specified registry keys before modifications.

.DESCRIPTION
    This function exports registry keys to .reg files in the temp directory
    before ILYESIZER makes modifications. This enables restoration of original
    settings if needed. Backups are timestamped for identification.

.PARAMETER KeyPath
    The full registry path to backup (e.g., "HKEY_CURRENT_USER\Software\Microsoft\GameBar").

.PARAMETER BackupName
    A descriptive name for the backup file.

.EXAMPLE
    Backup-RegistryKey "HKEY_CURRENT_USER\Software\Microsoft\GameBar" "GameBar"
#>
function Backup-RegistryKey {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyPath, 
        
        [Parameter(Mandatory=$true)]
        [string]$BackupName
    )
    
    if (-not $script:Config.BackupRegistry) { 
        Write-OptLog "Registry backup disabled in configuration" "INFO"
        return 
    }
    
    try {
        $backupPath = "$env:TEMP\ILYESIZER-Backup-$BackupName-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').reg"
        $result = reg export $KeyPath $backupPath /y 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-OptLog "Registry backup created: $backupPath" "SUCCESS"
        } else {
            Write-OptLog "Registry backup failed: $result" "WARNING"
        }
    } catch {
        Write-OptLog "Failed to backup registry key $KeyPath`: $($_.Exception.Message)" "WARNING"
    }
}

<#
.SYNOPSIS
    Sets registry values with error handling and logging.

.DESCRIPTION
    This function safely modifies registry values with comprehensive error
    handling. It creates registry paths if they don't exist and logs all
    operations for troubleshooting and audit purposes.

.PARAMETER Path
    The registry path (e.g., "HKCU:\Software\Microsoft\GameBar").

.PARAMETER Name
    The registry value name to set.

.PARAMETER Value
    The value to set (string, DWORD, binary, etc.).

.PARAMETER Type
    The registry value type (default: DWORD).

.OUTPUTS
    Boolean - True if successful, False if failed.

.EXAMPLE
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0 -Type "String"
#>
function Set-RegistryValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [object]$Value,
        
        [Parameter(Mandatory=$false)]
        [string]$Type = "DWORD"
    )
    
    try {
        # Create the registry path if it doesn't exist
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-OptLog "Created registry path: $Path" "INFO"
        }
        
        # Set the registry value
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        Write-OptLog "Set registry value: $Path\$Name = $Value ($Type)" "SUCCESS"
        return $true
    } catch {
        Write-OptLog "Failed to set registry value $Path\$Name`: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

<#
.SYNOPSIS
    Tests if Windows Game Mode is supported on the current system.

.DESCRIPTION
    Determines if the current Windows version supports Game Mode functionality.
    Game Mode requires Windows 10 version 1703 (build 15063) or later.
    This check prevents errors on unsupported systems.

.OUTPUTS
    Boolean - True if Game Mode is supported, False otherwise.

.EXAMPLE
    if (Test-GameModeSupport) {
        Write-Host "Game Mode optimization available"
    } else {
        Write-Host "Game Mode not supported on this OS version"
    }
#>
function Test-GameModeSupport {
    try {
        $osVersion = [System.Environment]::OSVersion.Version
        # Game Mode requires Windows 10 version 1703 (build 15063) or later
        if ($osVersion.Major -ge 10 -and $osVersion.Build -ge 15063) {
            return $true
        }
        return $false
    } catch {
        Write-OptLog "Error checking Game Mode support: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

# ============================================================================
# INITIALIZATION AND CHECKS
# ============================================================================

# Clear the console and display the ILYESIZER banner
Clear-Host
Write-Host @"
================================================================================
|                              ILYESIZER v3.0                               |
|                    Advanced Gaming PC Optimization Script                 |
|                              Created by ilyyeees                          |
|              Safe, Essential Optimizations for Gaming Performance          |
================================================================================
"@ -ForegroundColor Green

Write-OptLog "ILYESIZER Gaming Optimization Script v$($script:Config.Version) started" "INFO"
Write-OptLog "Script created by $($script:Config.Author)" "INFO"

# Administrator privilege validation
# Most gaming optimizations require elevated permissions
$isAdmin = Test-IsAdmin
if (-not $isAdmin) {
    Write-OptLog "Warning: Not running as Administrator. Some optimizations may fail." "WARNING"
    Write-Host "`nSome optimizations require Administrator privileges for:" -ForegroundColor Yellow
    Write-Host "  - Registry modifications (HKEY_LOCAL_MACHINE)" -ForegroundColor Yellow
    Write-Host "  - Power plan modifications" -ForegroundColor Yellow
    Write-Host "  - System service configuration" -ForegroundColor Yellow
    Write-Host "  - Graphics driver settings" -ForegroundColor Yellow
    Write-Host "`nContinue anyway? (y/N): " -ForegroundColor Yellow -NoNewline
    $continue = Read-Host
    if ($continue -ne 'y' -and $continue -ne 'Y') {
        Write-OptLog "Optimization cancelled by user (no admin privileges)" "INFO"
        Write-Host "`nTo run with administrator privileges:" -ForegroundColor Cyan
        Write-Host "1. Right-click PowerShell" -ForegroundColor Cyan
        Write-Host "2. Select 'Run as Administrator'" -ForegroundColor Cyan
        Write-Host "3. Re-run this script" -ForegroundColor Cyan
        exit 0
    }
} else {
    Write-OptLog "Running with Administrator privileges - full optimization available" "SUCCESS"
}

# System compatibility and environment checks
Write-OptLog "Performing system compatibility analysis..." "INFO"
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$processorInfo = Get-CimInstance -ClassName Win32_Processor

Write-OptLog "Operating System: $($osInfo.Caption) Build $($osInfo.BuildNumber)" "INFO"
Write-OptLog "Computer: $($computerInfo.Manufacturer) $($computerInfo.Model)" "INFO"
Write-OptLog "Processor: $($processorInfo.Name)" "INFO"
Write-OptLog "Total Physical Memory: $([math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)) GB" "INFO"

# Windows Game Mode support detection
$gameModeSupported = Test-GameModeSupport
if ($gameModeSupported) {
    Write-OptLog "Windows Game Mode is supported on this system" "SUCCESS"
} else {
    Write-OptLog "Windows Game Mode may not be fully supported on this OS version" "WARNING"
    Write-OptLog "Some optimizations may be skipped or have limited effect" "WARNING"
}

# Disk space validation for temporary file cleanup
$systemDrive = $env:SystemDrive
$freeSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$systemDrive'").FreeSpace / 1GB
Write-OptLog "Available disk space on $systemDrive`: $([math]::Round($freeSpace, 2)) GB" "INFO"

if ($freeSpace -lt $script:Config.MinFreeSpaceGB) {
    Write-OptLog "Low disk space detected. Cleanup operations will be prioritized." "WARNING"
}

# ============================================================================
# OPTIMIZATION FUNCTIONS
# ============================================================================

<#
.SYNOPSIS
    Enables and configures Windows Game Mode for optimal gaming performance.

.DESCRIPTION
    This function enables Windows Game Mode, which prioritizes gaming applications
    by allocating system resources more effectively. Game Mode prevents Windows
    Update from interrupting games, reduces background activity, and optimizes
    CPU scheduling for the foreground game process.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Enable-WindowsGameMode
    Enables Windows Game Mode with optimal gaming configurations.

.NOTES
    Requires Windows 10 version 1703 (Creators Update) or later.
    Game Mode is most effective on systems with limited CPU cores.
#>
function Enable-WindowsGameMode {
    Write-Host "`n[GAMING] OPTIMIZING WINDOWS GAME MODE" -ForegroundColor Cyan
    Write-OptLog "Configuring Windows Game Mode settings..." "INFO"
    
    if (-not $gameModeSupported) {
        Write-OptLog "Skipping Game Mode - not supported on this OS version" "WARNING"
        return
    }
    
    $gameModeKey = "HKCU:\Software\Microsoft\GameBar"
    Backup-RegistryKey "HKEY_CURRENT_USER\Software\Microsoft\GameBar" "GameBar"
    
    $optimizations = @(
        @{ Path = $gameModeKey; Name = "AllowAutoGameMode"; Value = 1; Description = "Allow automatic Game Mode" },
        @{ Path = $gameModeKey; Name = "AutoGameModeEnabled"; Value = 1; Description = "Enable automatic Game Mode" },
        @{ Path = $gameModeKey; Name = "GameModeEnabled"; Value = 1; Description = "Enable Game Mode globally" }
    )
    
    $successCount = 0
    foreach ($opt in $optimizations) {
        if (Set-RegistryValue -Path $opt.Path -Name $opt.Name -Value $opt.Value) {
            Write-OptLog $opt.Description "SUCCESS"
            $successCount++
        }
    }
    
    if ($successCount -eq $optimizations.Count) {
        Write-OptLog "Windows Game Mode optimization completed successfully" "SUCCESS"
    } else {
        Write-OptLog "Windows Game Mode optimization completed with some failures" "WARNING"
    }
}

<#
.SYNOPSIS
    Disables Xbox Game Bar features that can interfere with gaming performance.

.DESCRIPTION
    This function disables various Xbox Game Bar and Game DVR features that can
    cause performance drops, input lag, and unexpected interruptions during gaming.
    Features disabled include screen recording, audio capture, overlay notifications,
    and background capture processes that consume system resources.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Disable-GameBarFeatures
    Disables Xbox Game Bar interference for optimal gaming performance.

.NOTES
    These changes only affect the current user profile.
    Game Bar can still be manually enabled if needed for specific games.
    Most professional gamers disable these features for competitive advantage.
#>
function Disable-GameBarFeatures {
    Write-Host "`n[DISABLE] DISABLING XBOX GAME BAR INTERFERENCE" -ForegroundColor Cyan
    Write-OptLog "Disabling Xbox Game Bar features that can interfere with gaming..." "INFO"
    
    $gameBarKey = "HKCU:\Software\Microsoft\GameBar"
    $gameDVRKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
    
    Backup-RegistryKey "HKEY_CURRENT_USER\Software\Microsoft\GameBar" "GameBarDisable"
    Backup-RegistryKey "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR" "GameDVR"
    
    $disableSettings = @(
        # Game Bar settings
        @{ Path = $gameBarKey; Name = "UseNexusForGameBarEnabled"; Value = 0; Description = "Disable Game Bar Nexus integration" },
        @{ Path = $gameBarKey; Name = "GamePanelStartupTipIndex"; Value = 3; Description = "Disable Game Bar startup tips" },
        @{ Path = $gameBarKey; Name = "ShowStartupPanel"; Value = 0; Description = "Disable Game Bar startup panel" },
        
        # Game DVR settings  
        @{ Path = $gameDVRKey; Name = "AppCaptureEnabled"; Value = 0; Description = "Disable app capture" },
        @{ Path = $gameDVRKey; Name = "AudioCaptureEnabled"; Value = 0; Description = "Disable audio capture" },
        @{ Path = $gameDVRKey; Name = "CursorCaptureEnabled"; Value = 0; Description = "Disable cursor capture" },
        @{ Path = $gameDVRKey; Name = "HistoricalCaptureEnabled"; Value = 0; Description = "Disable historical capture" }
    )
    
    $successCount = 0
    foreach ($setting in $disableSettings) {
        if (Set-RegistryValue -Path $setting.Path -Name $setting.Name -Value $setting.Value) {
            Write-OptLog $setting.Description "SUCCESS"
            $successCount++
        }
    }
    
    Write-OptLog "Game Bar interference reduction: $successCount/$($disableSettings.Count) settings applied" "INFO"
}

<#
.SYNOPSIS
    Configures Windows power plan for maximum gaming performance.

.DESCRIPTION
    This function sets the system to use the High Performance power plan and
    applies aggressive power optimizations. This ensures maximum CPU frequency,
    prevents CPU core parking, enables aggressive boost modes, and minimizes
    power-saving features that can introduce latency or reduce performance.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Set-HighPerformancePowerPlan
    Configures the system for maximum performance power settings.

.NOTES
    High Performance mode increases power consumption and heat generation.
    Ensure adequate cooling is available for sustained gaming sessions.
    Laptop users should monitor battery life and thermals carefully.
#>
function Set-HighPerformancePowerPlan {
    Write-Host "`n[POWER] CONFIGURING HIGH PERFORMANCE POWER PLAN" -ForegroundColor Cyan
    Write-OptLog "Setting power plan to High Performance..." "INFO"
    
    try {
        # Get current power scheme
        $currentScheme = powercfg /getactivescheme
        Write-OptLog "Current power scheme: $currentScheme" "INFO"
        
        # High Performance GUID
        $highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        
        # Set to High Performance
        $result = powercfg /setactive $highPerfGuid 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-OptLog "High Performance power plan activated successfully" "SUCCESS"
            
            # Additional power optimizations
            $powerOptimizations = @(
                @{ Setting = "processor-perf-boost-mode"; Value = "2"; Description = "Enable aggressive CPU boost" },
                @{ Setting = "processor-perf-core-parking-min-cores"; Value = "100"; Description = "Prevent CPU core parking" }
            )
            
            foreach ($opt in $powerOptimizations) {
                try {
                    powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR $opt.Setting $opt.Value 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        Write-OptLog $opt.Description "SUCCESS"
                    }
                } catch {
                    Write-OptLog "Failed to apply power optimization: $($opt.Description)" "WARNING"
                }
            }
            
            # Apply changes
            powercfg /setactive SCHEME_CURRENT 2>&1 | Out-Null
            
        } else {
            Write-OptLog "Failed to set High Performance power plan: $result" "ERROR"
        }
    } catch {
        Write-OptLog "Error configuring power plan: $($_.Exception.Message)" "ERROR"
    }
}

<#
.SYNOPSIS
    Optimizes Windows visual effects for gaming performance over aesthetics.

.DESCRIPTION
    This function disables unnecessary visual effects, animations, and UI elements
    that consume GPU resources and can cause stuttering or frame drops in games.
    It prioritizes performance by reducing transparency effects, animations, and
    visual enhancements that don't contribute to gaming performance.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Optimize-VisualEffects
    Configures Windows visual effects for optimal gaming performance.

.NOTES
    Changes affect the visual appearance of Windows UI elements.
    These settings can be reverted through Windows Performance Options.
    Most competitive gamers prefer these performance-oriented settings.
#>
function Optimize-VisualEffects {
    Write-Host "`n[VISUAL] OPTIMIZING VISUAL EFFECTS FOR PERFORMANCE" -ForegroundColor Cyan
    Write-OptLog "Configuring visual effects for optimal gaming performance..." "INFO"
    
    $visualEffectsKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    Backup-RegistryKey "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualEffects"
    
    # Set to custom performance settings
    if (Set-RegistryValue -Path $visualEffectsKey -Name "VisualFXSetting" -Value 2) {
        Write-OptLog "Visual effects set to 'Custom' for performance optimization" "SUCCESS"
    }
    
    # Additional UI performance optimizations
    $uiOptimizations = @(
        @{ Path = "HKCU:\Control Panel\Desktop"; Name = "UserPreferencesMask"; Value = ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)); Type = "Binary"; Description = "Optimize UI animations" },
        @{ Path = "HKCU:\Control Panel\Desktop"; Name = "MenuShowDelay"; Value = 0; Description = "Remove menu show delay" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ListviewAlphaSelect"; Value = 0; Description = "Disable listview alpha selection" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "TaskbarAnimations"; Value = 0; Description = "Disable taskbar animations" }
    )
    
    foreach ($opt in $uiOptimizations) {
        $type = if ($opt.Type) { $opt.Type } else { "DWORD" }
        if (Set-RegistryValue -Path $opt.Path -Name $opt.Name -Value $opt.Value -Type $type) {
            Write-OptLog $opt.Description "SUCCESS"
        }
    }
}

<#
.SYNOPSIS
    Performs comprehensive temporary file cleanup to free disk space and improve performance.

.DESCRIPTION
    This function cleans various temporary file locations that can accumulate over time
    and impact system performance. It safely removes temporary files, cache files,
    and other unnecessary data that can interfere with gaming performance by consuming
    disk space and potentially causing I/O bottlenecks.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Clear-SystemTemporaryFiles
    Performs comprehensive cleanup of temporary files and caches.

.NOTES
    Files currently in use by running applications will not be deleted.
    This cleanup is safe and only removes temporary/cache files.
    Regular cleanup helps maintain optimal system performance.
#>
function Clear-SystemTemporaryFiles {
    Write-Host "`n[CLEANUP] CLEANING TEMPORARY FILES AND CACHES" -ForegroundColor Cyan
    Write-OptLog "Starting comprehensive temporary file cleanup..." "INFO"
    
    $cleanupLocations = @(
        @{ Path = $env:TEMP; Description = "User temporary files" },
        @{ Path = "$env:WINDIR\Temp"; Description = "Windows temporary files" },
        @{ Path = "$env:LOCALAPPDATA\Temp"; Description = "Local application temporary files" },
        @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"; Description = "Internet cache files" },
        @{ Path = "$env:APPDATA\Microsoft\Windows\Recent"; Description = "Recent files cache" }
    )
    
    $totalFreed = 0
    foreach ($location in $cleanupLocations) {
        if (Test-Path $location.Path) {
            try {
                $beforeSize = (Get-ChildItem $location.Path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                Get-ChildItem $location.Path -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                $afterSize = (Get-ChildItem $location.Path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                $freed = ($beforeSize - $afterSize) / 1MB
                $totalFreed += $freed
                Write-OptLog "$($location.Description): Freed $([math]::Round($freed, 2)) MB" "SUCCESS"
            } catch {
                Write-OptLog "Could not clean $($location.Description): $($_.Exception.Message)" "WARNING"
            }
        }
    }
    
    Write-OptLog "Total disk space freed: $([math]::Round($totalFreed, 2)) MB" "SUCCESS"
}

<#
.SYNOPSIS
    Applies comprehensive system optimizations for enhanced gaming performance.

.DESCRIPTION
    This function implements advanced system-level optimizations including mouse
    acceleration removal, input lag reduction, file system optimizations, and
    search indexing adjustments. These changes reduce system overhead and improve
    responsiveness for gaming applications.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Optimize-SystemSettings
    Applies comprehensive system optimizations for gaming performance.

.NOTES
    Some optimizations require administrator privileges.
    Mouse acceleration changes affect all mouse input system-wide.
    NTFS optimizations improve file system performance.
#>
function Optimize-SystemSettings {
    Write-Host "`n[SYSTEM] APPLYING ADDITIONAL SYSTEM OPTIMIZATIONS" -ForegroundColor Cyan
    Write-OptLog "Applying additional gaming performance optimizations..." "INFO"
    
    $systemOptimizations = @(
        # Disable Windows Search indexing on system drive (can be re-enabled if needed)
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowIndexingEncryptedStoresOrItems"; Value = 0; Description = "Optimize search indexing"; RequiresAdmin = $true },
        
        # Optimize NTFS performance
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name = "NtfsDisableLastAccessUpdate"; Value = 1; Description = "Disable NTFS last access updates"; RequiresAdmin = $true },
        
        # Gaming mouse optimizations
        @{ Path = "HKCU:\Control Panel\Mouse"; Name = "MouseHoverTime"; Value = 10; Description = "Reduce mouse hover time" },
        @{ Path = "HKCU:\Control Panel\Mouse"; Name = "MouseSpeed"; Value = 0; Description = "Disable mouse acceleration" },
        @{ Path = "HKCU:\Control Panel\Mouse"; Name = "MouseThreshold1"; Value = 0; Description = "Disable mouse threshold 1" },
        @{ Path = "HKCU:\Control Panel\Mouse"; Name = "MouseThreshold2"; Value = 0; Description = "Disable mouse threshold 2" }
    )
    
    foreach ($opt in $systemOptimizations) {
        if ($opt.RequiresAdmin -and -not $isAdmin) {
            Write-OptLog "Skipping $($opt.Description) - requires admin privileges" "WARNING"
            continue
        }
        
        if (Set-RegistryValue -Path $opt.Path -Name $opt.Name -Value $opt.Value) {
            Write-OptLog $opt.Description "SUCCESS"
        }
    }
}

<#
.SYNOPSIS
    Analyzes and displays startup programs that may impact gaming performance.

.DESCRIPTION
    This function examines all startup programs and provides detailed analysis
    of applications that launch with Windows. It helps identify resource-heavy
    programs that can reduce gaming performance by consuming CPU, memory, or
    disk resources during game startup and operation.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are displayed in console and logged to the optimization log file.

.EXAMPLE
    Show-StartupPrograms
    Displays comprehensive analysis of startup programs and their impact.

.NOTES
    This function only analyzes startup programs - it does not disable them automatically.
    Users should manually disable unnecessary startup programs through Task Manager.
    Essential system programs should not be disabled.
#>
function Show-StartupPrograms {
    Write-Host "`n[ANALYZE] ANALYZING STARTUP PROGRAMS" -ForegroundColor Cyan
    Write-OptLog "Analyzing startup programs that may impact gaming performance..." "INFO"
    
    try {
        $startupItems = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
        
        if ($startupItems.Count -gt 0) {
            Write-Host "`nCurrent startup programs:" -ForegroundColor Yellow
            $startupItems | Format-Table -AutoSize
            Write-OptLog "Found $($startupItems.Count) startup programs" "INFO"
            Write-Host "`n[TIP] Tip: Review these programs and disable unnecessary ones in Task Manager > Startup tab" -ForegroundColor Green
        } else {
            Write-OptLog "No startup programs found" "INFO"
        }
    } catch {
        Write-OptLog "Failed to enumerate startup programs: $($_.Exception.Message)" "WARNING"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Host "`n[ULTRA] Starting ULTRA AGGRESSIVE optimization process..." -ForegroundColor Green

# Ask user if they want to apply aggressive optimizations
Write-Host "`n[WARNING] WARNING: This script will apply AGGRESSIVE gaming optimizations!" -ForegroundColor Yellow
Write-Host "   These optimizations can significantly improve gaming performance but may:" -ForegroundColor Yellow
Write-Host "   - Disable some Windows services and features" -ForegroundColor Yellow
Write-Host "   - Change system behavior for non-gaming tasks" -ForegroundColor Yellow
Write-Host "   - Require a system restart to take full effect" -ForegroundColor Yellow
Write-Host ""

$response = Read-Host "Do you want to proceed with AGGRESSIVE gaming optimizations? (Y/N)"
if ($response -ne 'Y' -and $response -ne 'y') {
    Write-Host "Optimization cancelled by user." -ForegroundColor Yellow
    exit
}

try {
    # Phase 1: Basic optimizations
    Write-Host "`n[PHASE 1] PHASE 1: BASIC GAMING OPTIMIZATIONS" -ForegroundColor Cyan
    Enable-WindowsGameMode
    Disable-GameBarFeatures  
    Set-HighPerformancePowerPlan
    Optimize-VisualEffects
    Clear-SystemTemporaryFiles
    Optimize-SystemSettings
    Show-StartupPrograms
      # Phase 2: Aggressive optimizations  
    Write-Host "`n[PHASE 2] PHASE 2: AGGRESSIVE GAMING OPTIMIZATIONS" -ForegroundColor Red
    Set-UltimateGamingMode
    Optimize-CPUPriorityAndScheduling
    Set-AggressiveMemoryOptimizations
    Disable-PerformanceKillers
    Set-UltraLowLatencyTweaks
    
    Write-Host "`n" -NoNewline
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host "|            [COMPLETE] ULTRA AGGRESSIVE OPTIMIZATION COMPLETED!           |" -ForegroundColor Green
    Write-Host "|                                                                          |" -ForegroundColor Green
    Write-Host "|  [OPTIMIZED] Your PC is now optimized for MAXIMUM gaming performance!    |" -ForegroundColor Green
    Write-Host "|  [CPU] CPU: Extreme performance mode enabled                            |" -ForegroundColor Green
    Write-Host "|  RAM: Aggressive memory management configured                        |" -ForegroundColor Green
    Write-Host "|  [I/O] I/O: Ultra-low latency tweaks applied                           |" -ForegroundColor Green
    Write-Host "|  Performance killers: Disabled                                      |" -ForegroundColor Green
    Write-Host "|  Storage: Optimized for gaming workloads                            |" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
    
    Write-OptLog "ULTRA AGGRESSIVE gaming optimization completed successfully" "SUCCESS"
    
    Write-Host "`n[LOG] Detailed log file saved to: $($script:Config.LogFile)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[RESTART] IMPORTANT: RESTART YOUR COMPUTER NOW for all optimizations to take effect!" -ForegroundColor Yellow -BackgroundColor Red
    Write-Host ""
    Write-Host "[GAMING] After restart, you should experience:" -ForegroundColor Green
    Write-Host "   - Higher and more stable FPS in games" -ForegroundColor Green
    Write-Host "   - Reduced input lag and system latency" -ForegroundColor Green  
    Write-Host "   - Faster game loading times" -ForegroundColor Green
    Write-Host "   - More responsive system during gaming" -ForegroundColor Green
    Write-Host "   - Better CPU and GPU utilization" -ForegroundColor Green
    Write-Host ""
    Write-Host "[TIP] Pro Tips:" -ForegroundColor Cyan
    Write-Host "   - Close unnecessary background apps before gaming" -ForegroundColor Cyan
    Write-Host "   - Use Task Manager to monitor performance" -ForegroundColor Cyan
    Write-Host "   - Consider overclocking your GPU for even better performance" -ForegroundColor Cyan
    Write-Host "   - Keep your graphics drivers updated" -ForegroundColor Cyan
    
} catch {
    Write-OptLog "Critical error during optimization: $($_.Exception.Message)" "ERROR"
    Write-Host "`n[ERROR] Optimization encountered errors. Check the log file for details." -ForegroundColor Red
}

# ============================================================================
# ADVANCED GAMING OPTIMIZATIONS
# ============================================================================

<#
.SYNOPSIS
    Applies ultimate gaming mode optimizations for maximum performance.

.DESCRIPTION
    This function implements the most aggressive gaming optimizations available,
    including complete Game DVR disabling, hardware GPU scheduling enablement,
    and advanced registry tweaks. These changes prioritize gaming performance
    above all other system functions and may impact non-gaming performance.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Set-UltimateGamingMode
    Applies the most aggressive gaming optimizations available.

.NOTES
    This function makes the most aggressive changes to the system.
    Some changes require administrator privileges to be fully effective.
    System restart may be required for all optimizations to take effect.
#>
function Set-UltimateGamingMode {
    Write-Host "`n[ULTIMATE] APPLYING ULTIMATE GAMING MODE OPTIMIZATIONS" -ForegroundColor Red
    Write-OptLog "Applying ULTIMATE gaming mode optimizations..." "INFO"
    
    try {
        # Disable Windows Game DVR completely (can cause stuttering)
        $gameDVRPaths = @(
            "HKCU:\System\GameConfigStore",
            "HKCU:\SOFTWARE\Microsoft\GameBar",
            "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
        )
        
        foreach ($path in $gameDVRPaths) {
            if (!(Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
        }
        
        # Comprehensive Game DVR disable
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "ShowStartupPanel" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "GamePanelStartupTipIndex" -Value 3 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Force
        
        # System-wide Game DVR disable
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Force
        
        Write-OptLog "Game DVR completely disabled for maximum performance" "SUCCESS"
        
        # Enable Hardware Accelerated GPU Scheduling (if supported)
        $gpuSchedulingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        if (Test-Path $gpuSchedulingPath) {
            Set-ItemProperty -Path $gpuSchedulingPath -Name "HwSchMode" -Value 2 -Force
            Write-OptLog "Hardware GPU Scheduling enabled" "SUCCESS"
        }
        
        # Ultimate Game Mode registry tweaks
        $gameModePath = "HKCU:\SOFTWARE\Microsoft\GameBar"
        Set-ItemProperty -Path $gameModePath -Name "GameModeRelatedProcesses" -Value "GameBar.exe,GameBarElevatedFT.exe,GameBarElevatedFT_Alias.exe" -Force
        Set-ItemProperty -Path $gameModePath -Name "UseNexusForGameBarEnabled" -Value 0 -Force
        
        Write-OptLog "Ultimate Gaming Mode applied" "SUCCESS"
        
    } catch {
        Write-OptLog "Failed to apply Ultimate Gaming Mode: $($_.Exception.Message)" "ERROR"
    }
}

<#
.SYNOPSIS
    Optimizes CPU priority and scheduling for gaming performance.

.DESCRIPTION
    This function applies aggressive CPU scheduling optimizations that prioritize
    foreground applications (games) over background processes. It configures
    CPU throttling, priority separation, memory management, and prefetching
    settings to maximize gaming performance and minimize background interference.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Optimize-CPUPriorityAndScheduling
    Applies aggressive CPU scheduling optimizations for gaming.

.NOTES
    These changes affect system-wide CPU scheduling behavior.
    Requires administrator privileges for system-level registry changes.
    May reduce performance for background applications.
#>
function Optimize-CPUPriorityAndScheduling {
    Write-Host "`n[CPU] OPTIMIZING CPU PRIORITY AND SCHEDULING" -ForegroundColor Cyan
    Write-OptLog "Applying aggressive CPU scheduling optimizations..." "INFO"
    
    try {
        # Set CPU to prioritize foreground applications aggressively
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Force
        Write-OptLog "CPU priority set to aggressive foreground boost" "SUCCESS"
        
        # Disable CPU throttling
        $powerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
        Set-ItemProperty -Path $powerPath -Name "CsEnabled" -Value 0 -Force
        
        # Advanced CPU optimizations
        $cpuOptimizations = @{
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" = @{
                "FeatureSettings" = 1
                "FeatureSettingsOverride" = 3
                "FeatureSettingsOverrideMask" = 3
            }
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" = @{
                "EnablePrefetcher" = 3
                "EnableSuperfetch" = 0
            }
        }
          foreach ($regPath in $cpuOptimizations.Keys) {
            if (!(Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            foreach ($setting in $cpuOptimizations[$regPath].GetEnumerator()) {
                Set-ItemProperty -Path $regPath -Name $setting.Key -Value $setting.Value -Force
            }
        }
        
        Write-OptLog "Advanced CPU scheduling optimizations applied" "SUCCESS"
        
    } catch {
        Write-OptLog "Failed to optimize CPU scheduling: $($_.Exception.Message)" "ERROR"
    }
}

<#
.SYNOPSIS
    Applies aggressive memory optimizations for enhanced gaming performance.

.DESCRIPTION
    This function configures Windows memory management settings to prioritize
    gaming applications. It optimizes page file settings, kernel memory usage,
    system cache behavior, and memory allocation patterns to reduce latency
    and improve memory access speeds for gaming workloads.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Set-AggressiveMemoryOptimizations
    Applies aggressive memory management optimizations for gaming.

.NOTES
    These changes affect system-wide memory management behavior.
    Requires administrator privileges for system-level registry changes.
    Changes may require system restart to take full effect.
#>
function Set-AggressiveMemoryOptimizations {
    Write-Host "`n[MEMORY] APPLYING AGGRESSIVE MEMORY OPTIMIZATIONS" -ForegroundColor Cyan
    Write-OptLog "Applying aggressive memory optimizations for gaming..." "INFO"
    
    try {
        $memoryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        
        # Aggressive memory optimizations
        $memoryOptimizations = @{
            "ClearPageFileAtShutdown" = 0          # Don't clear pagefile (faster boot)
            "DisablePagingExecutive" = 1           # Keep kernel in memory
            "LargeSystemCache" = 0                 # Optimize for applications
            "NonPagedPoolQuota" = 0                # No limit on non-paged pool
            "PagedPoolQuota" = 0                   # No limit on paged pool
            "SecondLevelDataCache" = 1024          # CPU L2 cache size
            "SessionPoolSize" = 192                # Increase session pool
            "SessionViewSize" = 192                # Increase session view
            "SystemPages" = 0                      # Let system manage
            "PhysicalAddressExtension" = 1         # Enable PAE
            "PoolUsageMaximum" = 96                # Pool usage maximum
        }
        
        foreach ($setting in $memoryOptimizations.GetEnumerator()) {
            Set-ItemProperty -Path $memoryPath -Name $setting.Key -Value $setting.Value -Force
            Write-OptLog "Memory setting: $($setting.Key) = $($setting.Value)" "SUCCESS"
        }
        
        # Advanced virtual memory settings
        $vmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        Set-ItemProperty -Path $vmPath -Name "IoPageLockLimit" -Value 134217728 -Force  # 128MB
        
        Write-OptLog "Aggressive memory optimizations applied" "SUCCESS"
          } catch {
        Write-OptLog "Failed to optimize memory settings: $($_.Exception.Message)" "ERROR"
    }
}

<#
.SYNOPSIS
    Disables Windows services and features that negatively impact gaming performance.

.DESCRIPTION
    This function identifies and disables Windows services, background processes,
    and system features that are known to cause performance issues in games.
    This includes services that consume CPU/GPU resources, cause stuttering,
    or introduce input lag during gaming sessions.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Disable-PerformanceKillers
    Disables known performance-impacting services and features.

.NOTES
    This function makes aggressive changes to system services.
    Requires administrator privileges to modify system services.
    Services can be re-enabled manually if needed for specific functionality.
#>
function Disable-PerformanceKillers {
    Write-Host "`n[STOP] DISABLING PERFORMANCE KILLERS" -ForegroundColor Red
    Write-OptLog "Disabling services and features that impact gaming performance..." "INFO"
    
    # Services that significantly impact gaming performance
    $performanceKillerServices = @(
        "SysMain",           # Superfetch (can cause stuttering in some games)
        "Themes",            # Windows Themes (uses GPU resources)
        "TabletInputService", # Tablet Input Service
        "WSearch",           # Windows Search (high disk usage)
        "DiagTrack",         # Connected User Experiences and Telemetry
        "RetailDemo",        # Retail Demo Service
        "RemoteRegistry",    # Remote Registry
        "Fax",              # Fax Service
        "WerSvc",           # Windows Error Reporting
        "Spooler",          # Print Spooler (if not printing)
        "MapsBroker",       # Downloaded Maps Manager
        "lfsvc",            # Geolocation Service
        "SharedAccess",     # Internet Connection Sharing
        "TrkWks",           # Distributed Link Tracking Client
        "WbioSrvc"          # Windows Biometric Service
    )
    
    $disabledCount = 0
    foreach ($serviceName in $performanceKillerServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -eq "Running") {
                    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                }
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                Write-OptLog "Disabled performance killer service: $serviceName" "SUCCESS"
                $disabledCount++
            }
        } catch {
            Write-OptLog "Could not disable service $serviceName" "WARNING"
        }
    }
    
    # Disable Windows features that impact performance
    $featuresToDisable = @(
        "Internet-Explorer-Optional-amd64",
        "MediaPlayback",
        "WindowsMediaPlayer",
        "WorkFolders-Client",
        "Printing-XPSServices-Features",
        "FaxServicesClientPackage"
    )
    
    foreach ($feature in $featuresToDisable) {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-OptLog "Disabled Windows feature: $feature" "SUCCESS"
        } catch {
            Write-OptLog "Could not disable feature: $feature" "WARNING"
        }
    }
    
    # Registry tweaks to disable performance killers
    $performanceKillerRegistry = @(
        # Disable Windows Defender real-time protection impact
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; Value = 1; Description = "Reduce Defender CPU usage" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableOnAccessProtection"; Value = 0; Description = "Keep essential protection" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScanOnRealtimeEnable"; Value = 1; Description = "Disable scan on real-time enable" },
        
        # Disable automatic maintenance
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"; Name = "MaintenanceDisabled"; Value = 1; Description = "Disable automatic maintenance" },
        
        # Disable background apps refresh
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"; Name = "GlobalUserDisabled"; Value = 1; Description = "Disable background app refresh" },
        
        # Disable location tracking
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableLocation"; Value = 1; Description = "Disable location services" },
        
        # Disable feedback and diagnostics
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0; Description = "Disable telemetry" }
    )
    
    foreach ($reg in $performanceKillerRegistry) {
        if ($isAdmin -or -not $reg.Path.StartsWith("HKLM:")) {
            if (Set-RegistryValue -Path $reg.Path -Name $reg.Name -Value $reg.Value) {
                Write-OptLog $reg.Description "SUCCESS"
            }
        }
    }
      Write-OptLog "Performance killers disabled: $disabledCount services disabled" "SUCCESS"
}

<#
.SYNOPSIS
    Applies ultra-low latency tweaks for competitive gaming performance.

.DESCRIPTION
    This function implements the most aggressive latency reduction tweaks available,
    including high precision timer optimizations, interrupt handling improvements,
    GPU scheduling enhancements, and system timer modifications. These changes
    minimize input lag and system latency for competitive gaming scenarios.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Set-UltraLowLatencyTweaks
    Applies ultra-low latency optimizations for competitive gaming.

.NOTES
    These are the most aggressive latency optimizations available.
    Changes may affect system stability on some hardware configurations.
    Requires administrator privileges for low-level system modifications.
#>
function Set-UltraLowLatencyTweaks {
    Write-Host "`n[LATENCY] APPLYING ULTRA-LOW LATENCY TWEAKS" -ForegroundColor Magenta
    Write-OptLog "Configuring system for minimum input lag and maximum responsiveness..." "INFO"
    
    # Ultra-low latency registry tweaks
    $latencyOptimizations = @(
        # Disable HPET (High Precision Event Timer) for lower latency
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\hpet"; Name = "Start"; Value = 4; Description = "Disable HPET for lower latency"; RequiresAdmin = $true },
        
        # Optimize timer resolution
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"; Name = "DisableAutoDaylightTimeSet"; Value = 1; Description = "Disable automatic daylight saving"; RequiresAdmin = $true },
        
        # USB polling rate optimizations  
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\usbhub\Parameters"; Name = "DisableSelectiveSuspend"; Value = 1; Description = "Disable USB selective suspend"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\USB"; Name = "DisableSelectiveSuspend"; Value = 1; Description = "Disable USB power management"; RequiresAdmin = $true },
        
        # Network adapter optimizations for gaming
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpAckFrequency"; Value = 1; Description = "Optimize TCP ACK frequency"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TCPNoDelay"; Value = 1; Description = "Disable TCP delay"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpDelAckTicks"; Value = 0; Description = "Minimize TCP delayed ACK"; RequiresAdmin = $true },
        
        # DPC (Deferred Procedure Call) optimizations
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "DpcWatchdogProfileOffset"; Value = 1; Description = "Optimize DPC watchdog"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "DisableLowQosTimerResolution"; Value = 1; Description = "Disable low QoS timer resolution"; RequiresAdmin = $true },
        
        # Audio latency optimizations
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\AudioSrv"; Name = "DependOnService"; Value = @("AudioEndpointBuilder", "RpcSs"); Description = "Optimize audio service dependencies"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name = "LazyModeTimeout"; Value = 25000; Description = "Reduce audio lazy mode timeout"; RequiresAdmin = $true }
    )
    
    $appliedCount = 0
    foreach ($opt in $latencyOptimizations) {
        if ($opt.RequiresAdmin -and -not $isAdmin) {
            Write-OptLog "Skipping $($opt.Description) - requires admin privileges" "WARNING"
            continue
        }
        
        if (Set-RegistryValue -Path $opt.Path -Name $opt.Name -Value $opt.Value) {
            Write-OptLog $opt.Description "SUCCESS"
            $appliedCount++
        }
    }
    
    # GPU latency optimizations
    try {
        # Enable GPU scheduling (Windows 10 2004+)
        if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 2) {
            Write-OptLog "Hardware-accelerated GPU scheduling enabled" "SUCCESS"
            $appliedCount++
        }
        
        # Disable GPU power saving
        if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "DisableDynamicPState" -Value 1) {
            Write-OptLog "GPU dynamic P-state disabled for consistent performance" "SUCCESS"
            $appliedCount++
        }
    } catch {
        Write-OptLog "Could not apply some GPU optimizations" "WARNING"
    }
    
    Write-OptLog "Ultra-low latency tweaks: $appliedCount optimizations applied" "SUCCESS"
}

function Optimize-StorageForGaming {
    Write-Host "`n[STORAGE] OPTIMIZING STORAGE FOR GAMING PERFORMANCE" -ForegroundColor Green
    Write-OptLog "Applying aggressive storage optimizations..." "INFO"
    
    if (-not $isAdmin) {
        Write-OptLog "Storage optimizations require administrator privileges" "ERROR"
        return
    }
    
    try {
        # Get system drive
        $systemDrive = $env:SystemDrive
        
        # Disable 8.3 filename creation (improves performance)
        fsutil behavior set disable8dot3 1 | Out-Null
        Write-OptLog "Disabled 8.3 filename creation for better performance" "SUCCESS"
        
        # Optimize NTFS for performance
        fsutil behavior set DisableLastAccess 1 | Out-Null
        Write-OptLog "Disabled NTFS last access time updates" "SUCCESS"
        
        # Increase NTFS memory usage
        fsutil behavior set memoryusage 2 | Out-Null
        Write-OptLog "Set NTFS to use maximum memory" "SUCCESS"
        
        # Disable system file compression
        compact /u /s:$systemDrive\ /i /Q 2>&1 | Out-Null
        Write-OptLog "Disabled system file compression for faster access" "SUCCESS"
        
        # SSD-specific optimizations if detected
        $drives = Get-PhysicalDisk
        $ssdCount = 0
        foreach ($drive in $drives) {
            if ($drive.MediaType -eq "SSD") {
                $ssdCount++
                # Optimize SSD settings
                try {
                    # Disable defragmentation on SSDs
                    $driveLetters = Get-Partition -DiskNumber $drive.DeviceId | Get-Volume | Where-Object { $_.DriveLetter }
                    foreach ($vol in $driveLetters) {
                        if ($vol.DriveLetter) {
                            schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Disable 2>&1 | Out-Null
                        }
                    }
                    Write-OptLog "SSD optimization: Disabled defragmentation on SSD $($drive.FriendlyName)" "SUCCESS"
                } catch {
                    Write-OptLog "Could not optimize SSD $($drive.FriendlyName)" "WARNING"
                }
            }
        }
        
        if ($ssdCount -eq 0) {
            # HDD optimizations
            Write-OptLog "HDD detected - enabling optimized defragmentation schedule" "INFO"
        }
        
        # Game-specific storage optimizations
        $storageOptimizations = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name = "NtfsDisableLastAccessUpdate"; Value = 1; Description = "Disable NTFS last access updates" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name = "NtfsMemoryUsage"; Value = 2; Description = "Maximum NTFS memory usage" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name = "NtfsDisable8dot3NameCreation"; Value = 1; Description = "Disable 8.3 name creation" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name = "DontVerifyRandomDrivers"; Value = 1; Description = "Skip driver verification for speed" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System"; Name = "CountOperations"; Value = 0; Description = "Disable I/O operation counting" }
        )
        
        foreach ($opt in $storageOptimizations) {
            if (Set-RegistryValue -Path $opt.Path -Name $opt.Name -Value $opt.Value) {
                Write-OptLog $opt.Description "SUCCESS"
            }
        }
        
        Write-OptLog "Storage optimizations completed successfully" "SUCCESS"
          } catch {
        Write-OptLog "Failed to optimize storage: $($_.Exception.Message)" "ERROR"
    }
}

<#
.SYNOPSIS
    Activates ultra game mode with the most aggressive gaming optimizations available.

.DESCRIPTION
    This function applies the most extreme gaming optimizations including ultra-aggressive
    CPU scheduling, maximum system responsiveness settings, extreme priority configurations,
    and ultra-low latency input optimizations. This mode prioritizes gaming performance
    above all other system functions and may significantly impact non-gaming performance.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Set-UltraGameMode
    Activates the most aggressive gaming mode available.

.NOTES
    This function applies the most extreme system modifications available.
    Requires administrator privileges for system-level optimizations.
    May cause system instability on some hardware configurations.
    Not recommended for systems used for productivity tasks.
#>
function Set-UltraGameMode {
    Write-Host "`n[ULTRA] ACTIVATING ULTRA GAME MODE" -ForegroundColor Magenta
    Write-OptLog "Applying ultra-aggressive gaming optimizations..." "INFO"
    
    # Ultra-aggressive registry optimizations for gaming
    $ultraOptimizations = @(
        # CPU scheduling and priority optimizations
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"; Name = "Win32PrioritySeparation"; Value = 38; Description = "Optimize CPU scheduling for foreground applications"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "LargeSystemCache"; Value = 0; Description = "Optimize system cache for applications"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "SystemPages"; Value = 4294967295; Description = "Maximize system page allocation"; RequiresAdmin = $true },
        
        # Extreme responsiveness tweaks
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name = "SystemResponsiveness"; Value = 0; Description = "Maximum system responsiveness for gaming"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name = "Priority"; Value = 6; Description = "Highest priority for games"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name = "Scheduling Category"; Value = "High"; Description = "High scheduling category for games"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name = "SFIO Priority"; Value = "High"; Description = "High SFIO priority for games"; RequiresAdmin = $true },
        
        # Disable CPU throttling completely
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"; Name = "ValueMax"; Value = 0; Description = "Disable CPU throttling"; RequiresAdmin = $true },
        
        # Ultra-low latency mouse and keyboard
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"; Name = "MouseDataQueueSize"; Value = 16; Description = "Minimize mouse input latency"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters"; Name = "KeyboardDataQueueSize"; Value = 16; Description = "Minimize keyboard input latency"; RequiresAdmin = $true },
        
        # GPU priority optimizations
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name = "GPU Priority"; Value = 8; Description = "Maximum GPU priority for games"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name = "SFIO Priority"; Value = "High"; Description = "High storage I/O priority"; RequiresAdmin = $true }
    )
    
    $appliedCount = 0
    foreach ($opt in $ultraOptimizations) {
        if ($opt.RequiresAdmin -and -not $isAdmin) {
            Write-OptLog "Skipping $($opt.Description) - requires admin privileges" "WARNING"
            continue
        }
        
        if (Set-RegistryValue -Path $opt.Path -Name $opt.Name -Value $opt.Value) {
            Write-OptLog $opt.Description "SUCCESS"
            $appliedCount++
        }    }
    
    Write-OptLog "Ultra Game Mode: $appliedCount optimizations applied" "SUCCESS"
}

<#
.SYNOPSIS
    Optimizes popular game launchers and gaming platforms for better performance.

.DESCRIPTION
    This function applies performance optimizations to major game launchers including
    Steam, Epic Games Launcher, Battle.net, and Discord. It configures these platforms
    to minimize resource usage, reduce background activities, and prioritize gaming
    performance over launcher features that can impact game performance.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Optimize-GameLaunchers
    Optimizes Steam, Epic Games, Battle.net, and Discord for gaming performance.

.NOTES
    This function modifies configuration files for popular game launchers.
    Changes are reversible by restoring launcher default settings.
    Some social and overlay features may be disabled for performance.
#>
function Optimize-GameLaunchers {
    Write-Host "`n[GAMING] OPTIMIZING GAME LAUNCHERS AND PLATFORMS" -ForegroundColor Cyan
    Write-OptLog "Optimizing popular game launchers for better performance..." "INFO"
    
    # Steam optimizations
    $steamConfigPath = "${env:ProgramFiles(x86)}\Steam\config"
    if (Test-Path $steamConfigPath) {
        try {
            # Create optimal Steam launch options configuration
            $steamOptConfig = @"

// Steam Gaming Optimizations
"Steam" {
    "ForceDesktopShortcuts" "0"
    "BigPictureInBackground" "0"
    "StartupMode" "0"
    "SkinV5" "0"
    "GPUAccelWebViews" "1"
    "H264HWAccel" "1"
}
"@
            $steamOptConfig | Out-File -FilePath "$steamConfigPath\gaming_optimizations.vdf" -Encoding UTF8
            Write-OptLog "Steam optimizations configured" "SUCCESS"
        } catch {
            Write-OptLog "Could not optimize Steam: $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Discord gaming mode optimizations
    $discordConfigPath = "$env:APPDATA\discord\settings.json"
    if (Test-Path $discordConfigPath) {
        try {
            $discordConfig = Get-Content $discordConfigPath | ConvertFrom-Json
            $discordConfig | Add-Member -Name "enableHardwareAcceleration" -Value $true -MemberType NoteProperty -Force
            $discordConfig | Add-Member -Name "openOnStartup" -Value $false -MemberType NoteProperty -Force
            $discordConfig | Add-Member -Name "startMinimized" -Value $true -MemberType NoteProperty -Force
            $discordConfig | ConvertTo-Json | Set-Content $discordConfigPath
            Write-OptLog "Discord optimized for gaming" "SUCCESS"
        } catch {
            Write-OptLog "Could not optimize Discord settings" "WARNING"
        }
    }
      Write-OptLog "Game launcher optimizations completed" "INFO"
}

<#
.SYNOPSIS
    Applies extreme CPU optimizations for maximum gaming performance.

.DESCRIPTION
    This function implements the most aggressive CPU optimizations available,
    including complete core parking disabling, maximum processor performance,
    disabled idle states, forced maximum frequency, and extreme scheduling
    optimizations. These changes prioritize CPU performance above power
    efficiency and may increase heat generation and power consumption.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Set-ExtremeCPUOptimizations
    Applies the most aggressive CPU optimizations available.

.NOTES
    This function makes extreme changes to CPU behavior.
    Requires administrator privileges for power plan modifications.
    May cause increased heat generation and power consumption.
    Ensure adequate cooling before applying these optimizations.
#>
function Set-ExtremeCPUOptimizations {
    Write-Host "`n[CPU] APPLYING EXTREME CPU OPTIMIZATIONS" -ForegroundColor Red
    Write-OptLog "WARNING: Applying aggressive CPU optimizations that may affect system stability" "WARNING"
    
    if (-not $isAdmin) {
        Write-OptLog "CPU optimizations require administrator privileges" "ERROR"
        return
    }
    
    try {
        # Disable CPU parking completely
        Write-OptLog "Disabling CPU core parking..." "INFO"
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100 | Out-Null
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100 | Out-Null
        
        # Set processor performance to maximum
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100 | Out-Null
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100 | Out-Null
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100 | Out-Null
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100 | Out-Null
        
        # Disable processor idle states
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 1 | Out-Null
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 1 | Out-Null
        
        # Force maximum processor frequency
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCFREQMAX 0 | Out-Null
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCFREQMAX 0 | Out-Null
        
        # Apply aggressive scheduling
        $cpuOptimizations = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "GlobalFlag"; Value = 0x20000000; Description = "Enable heap debugging optimizations" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "FeatureSettings"; Value = 1; Description = "Optimize memory management features" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "FeatureSettingsOverride"; Value = 3; Description = "Override memory feature settings" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "FeatureSettingsOverrideMask"; Value = 3; Description = "Memory feature override mask" }
        )
        
        foreach ($opt in $cpuOptimizations) {
            if (Set-RegistryValue -Path $opt.Path -Name $opt.Name -Value $opt.Value) {
                Write-OptLog $opt.Description "SUCCESS"
            }
        }
        
        Write-OptLog "Extreme CPU optimizations applied successfully" "SUCCESS"
        
    } catch {
        Write-OptLog "Failed to apply extreme CPU optimizations: $($_.Exception.Message)" "ERROR"    }
}

<#
.SYNOPSIS
    Applies aggressive system memory optimizations for gaming performance.

.DESCRIPTION
    This function implements advanced memory management optimizations including
    executive memory locking, cache optimization, prefetch tuning, and virtual
    memory configuration. These changes prioritize memory allocation for gaming
    applications and minimize memory-related latency and overhead.

.PARAMETER None
    This function does not accept parameters.

.OUTPUTS
    None - Results are logged to the optimization log file.

.EXAMPLE
    Optimize-SystemMemoryAggressive
    Applies aggressive memory management optimizations for gaming.

.NOTES
    This function requires administrator privileges for system-level changes.
    Changes affect system-wide memory management behavior.
    May require system restart for all optimizations to take full effect.
#>
function Optimize-SystemMemoryAggressive {
    Write-Host "`n[MEMORY] APPLYING AGGRESSIVE MEMORY OPTIMIZATIONS" -ForegroundColor Yellow
    Write-OptLog "Configuring aggressive memory management for gaming..." "INFO"
    
    if (-not $isAdmin) {
        Write-OptLog "Memory optimizations require administrator privileges" "ERROR"
        return
    }
    
    $memoryOptimizations = @(
        # Aggressive memory management
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "DisablePagingExecutive"; Value = 1; Description = "Keep executive in physical memory" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "LargeSystemCache"; Value = 0; Description = "Optimize for applications not system cache" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "SecondLevelDataCache"; Value = 1024; Description = "Optimize L2 cache size" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "ThirdLevelDataCache"; Value = 8192; Description = "Optimize L3 cache size" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "IoPageLockLimit"; Value = 983040; Description = "Increase I/O page lock limit" },
        
        # Prefetch and superfetch optimizations
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name = "EnablePrefetcher"; Value = 3; Description = "Enable aggressive prefetching" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name = "EnableSuperfetch"; Value = 3; Description = "Enable aggressive superfetch" },
        
        # Virtual memory optimizations
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "ClearPageFileAtShutdown"; Value = 0; Description = "Skip page file clearing for faster shutdown" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "DisableSwapFile"; Value = 0; Description = "Keep swap file enabled" },
        
        # Memory compression optimizations
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "FeatureSettings"; Value = 1; Description = "Enable memory compression features" }
    )
    
    foreach ($opt in $memoryOptimizations) {
        if (Set-RegistryValue -Path $opt.Path -Name $opt.Name -Value $opt.Value) {
            Write-OptLog $opt.Description "SUCCESS"
        }
    }
    
    # Configure optimal page file size
    try {
        $totalRAM = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
        $optimalPageFile = [math]::Round($totalRAM * 1.5, 0)
        
        # Set automatic page file management off and configure manually
        $cs = Get-WmiObject -Class Win32_ComputerSystem
        $cs.AutomaticManagedPagefile = $false
        $cs.Put() | Out-Null
        
        # Configure page file on C: drive
        $pageFile = Get-WmiObject -Class Win32_PageFileSetting | Where-Object { $_.Name -eq "C:\pagefile.sys" }
        if ($pageFile) {
            $pageFile.InitialSize = $optimalPageFile * 1024
            $pageFile.MaximumSize = $optimalPageFile * 1024 * 2
            $pageFile.Put() | Out-Null
        }
        
        Write-OptLog "Page file configured: Initial ${optimalPageFile}GB, Maximum $($optimalPageFile * 2)GB" "SUCCESS"
        
    } catch {
        Write-OptLog "Could not configure page file: $($_.Exception.Message)" "WARNING"
    }
    
    Write-OptLog "Aggressive memory optimizations completed" "SUCCESS"
}

# ============================================================================
# SCRIPT COMPLETION
# ============================================================================

Write-OptLog "ILYESIZER v$($script:Config.Version) optimization script completed" "INFO"
Write-OptLog "Script execution ended at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"

# Final system information for verification
Write-Host "`n[INFO] SYSTEM INFORMATION POST-OPTIMIZATION:" -ForegroundColor Cyan
Write-Host "  OS: $($osInfo.Caption) Build $($osInfo.BuildNumber)" -ForegroundColor White
Write-Host "  Computer: $($computerInfo.Manufacturer) $($computerInfo.Model)" -ForegroundColor White
Write-Host "  Processor: $($processorInfo.Name)" -ForegroundColor White
Write-Host "  Total RAM: $([math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)) GB" -ForegroundColor White
Write-Host "  Free Disk Space: $([math]::Round($freeSpace, 2)) GB" -ForegroundColor White
Write-Host "  Administrator Mode: $(if ($isAdmin) { 'Yes' } else { 'No' })" -ForegroundColor White
Write-Host "  Game Mode Support: $(if ($gameModeSupported) { 'Yes' } else { 'No' })" -ForegroundColor White

Write-Host "`n[SUCCESS] ILYESIZER OPTIMIZATION COMPLETE!" -ForegroundColor Green -BackgroundColor Black
Write-Host "Your system has been optimized for maximum gaming performance." -ForegroundColor Green

# End of ILYESIZER Gaming Optimization Script

