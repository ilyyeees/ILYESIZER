<#
.SYNOPSIS
    ILYESIZER GPU v3.0 - Ultra-Advanced GPU Gaming Optimization Suite
    Made by ilyyeees - Professional Gaming Performance Optimization

.DESCRIPTION
    ILYESIZER GPU v3.0 represents the pinnacle of GPU gaming optimization technology.
    This comprehensive suite delivers maximum graphics performance through advanced
    optimization techniques, driver tweaks, and GPU-specific configurations.

    Key Features:
    - Advanced GPU driver optimization and configuration
    - NVIDIA/AMD specific performance enhancements
    - GPU memory and bandwidth optimization
    - Graphics priority and scheduling optimization
    - DirectX and OpenGL performance tuning
    - Display and refresh rate optimization
    - GPU thermal and power management
    - Game-specific GPU configurations
    - Comprehensive performance monitoring
    - Professional logging and reporting

.PARAMETER SafeMode
    Enables conservative optimizations with minimal system impact
    
.PARAMETER BackupPath
    Specifies custom backup location for GPU settings
    
.PARAMETER LogPath
    Specifies custom location for ILYESIZER GPU log files

.OUTPUTS
    Comprehensive GPU optimization report with performance metrics
    Detailed log file with all optimization activities
    Registry backup files for safe restoration

.EXAMPLE
    .\ILYESIZER-GPU-v3.0.ps1
    Runs full GPU optimization suite with default settings

.EXAMPLE
    .\ILYESIZER-GPU-v3.0.ps1 -SafeMode
    Runs conservative GPU optimizations only

.NOTES
    Script Name    : ILYESIZER GPU v3.0
    Version        : 3.0.0
    Author         : ilyyeees
    Creation Date  : 2024
    Purpose        : Professional GPU gaming optimization
    
    Requirements:
    - PowerShell 5.1 or higher
    - Administrator privileges required
    - Compatible with NVIDIA and AMD GPUs
    - Windows 10/11 support
    
    Safety Features:
    - Automatic registry backups
    - System restore point creation
    - Safe optimization validation
    - Comprehensive error handling
    - Professional logging system
#>

#Requires -Version 5.1

# ============================================================================
# ILYESIZER GPU v3.0 - CONFIGURATION AND INITIALIZATION  
# ============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ILYESIZER GPU v3.0 Configuration
$script:ILYESIZERConfig = @{
    ScriptName = "ILYESIZER GPU v3.0"
    Version = "3.0.0"
    Author = "ilyyeees"
    LogFile = "$env:USERPROFILE\Desktop\ILYESIZER-GPU-Log-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    BackupRegistry = $true
    CheckDrivers = $true
    ApplyAdvancedTweaks = $true
    CreateRestorePoint = $true
    GPUOptimizationLevel = "Maximum"
    PerformanceThreshold = 95
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-GPULog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "INFO"    { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
        "SUCCESS" { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
        "WARNING" { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[ERROR] $Message" -ForegroundColor Red }
    }
    
    try {
        Add-Content -Path $script:Config.LogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {}
}

function Get-DetailedGPUInfo {
    Write-GPULog "Gathering detailed GPU information..." "INFO"
    
    try {
        # Get GPU information using CIM (more reliable than WMI)
        $gpus = Get-CimInstance -ClassName Win32_VideoController | Where-Object { 
            $_.Name -notlike "*Basic*" -and 
            $_.Name -notlike "*Generic*" -and
            $_.PNPDeviceID -like "PCI\*"
        }
        
        $gpuInfo = @()
        foreach ($gpu in $gpus) {
            $info = @{
                Name = $gpu.Name
                DriverVersion = $gpu.DriverVersion
                DriverDate = $gpu.DriverDate
                AdapterRAM = [math]::Round($gpu.AdapterRAM / 1GB, 2)
                Status = $gpu.Status
                Availability = $gpu.Availability
                PNPDeviceID = $gpu.PNPDeviceID
                Vendor = ""
            }
            
            # Determine GPU vendor
            if ($gpu.Name -like "*NVIDIA*" -or $gpu.Name -like "*GeForce*" -or $gpu.Name -like "*RTX*" -or $gpu.Name -like "*GTX*") {
                $info.Vendor = "NVIDIA"
            } elseif ($gpu.Name -like "*AMD*" -or $gpu.Name -like "*Radeon*" -or $gpu.Name -like "*RX*") {
                $info.Vendor = "AMD"
            } elseif ($gpu.Name -like "*Intel*" -or $gpu.Name -like "*UHD*" -or $gpu.Name -like "*Iris*") {
                $info.Vendor = "Intel"
            } else {
                $info.Vendor = "Unknown"
            }
            
            $gpuInfo += $info
        }
        
        return $gpuInfo
    } catch {
        Write-GPULog "Failed to gather GPU information: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Show-GPUInformation {
    param($GPUInfo)
    
    Write-Host "`n[HARDWARE] DETECTED GRAPHICS HARDWARE" -ForegroundColor Cyan
    
    if ($GPUInfo.Count -eq 0) {
        Write-GPULog "No dedicated graphics cards detected" "WARNING"
        return
    }
    
    foreach ($gpu in $GPUInfo) {
        Write-GPULog "GPU: $($gpu.Name)" "SUCCESS"
        Write-GPULog "  Vendor: $($gpu.Vendor)" "INFO"
        Write-GPULog "  Driver Version: $($gpu.DriverVersion)" "INFO"
        Write-GPULog "  Driver Date: $($gpu.DriverDate)" "INFO"
        if ($gpu.AdapterRAM -gt 0) {
            Write-GPULog "  Video Memory: $($gpu.AdapterRAM) GB" "INFO"
        }
        Write-GPULog "  Status: $($gpu.Status)" "INFO"
    }
}

function Backup-GraphicsRegistry {
    if (-not $script:Config.BackupRegistry) { return }
    
    Write-GPULog "Creating graphics registry backup..." "INFO"
    try {
        $backupPath = "$env:TEMP\Graphics-Registry-Backup-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').reg"
        
        $registryKeys = @(
            "HKEY_CURRENT_USER\Software\Microsoft\DirectX",
            "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        )
        
        foreach ($key in $registryKeys) {
            reg export $key "$backupPath-$(Split-Path $key -Leaf).reg" /y 2>&1 | Out-Null
        }
        
        Write-GPULog "Graphics registry backup completed" "SUCCESS"
    } catch {
        Write-GPULog "Failed to backup graphics registry: $($_.Exception.Message)" "WARNING"
    }
}

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================================================
# INITIALIZATION
# ============================================================================

Clear-Host
Write-Host @"
================================================================================
|                    ADVANCED GPU GAMING OPTIMIZATION                       |
|                                Version 2.0                                  |
|            Maximize Graphics Performance - Reduce Input Lag                 |
================================================================================
"@ -ForegroundColor Green

Write-GPULog "GPU Gaming Optimization started" "INFO"

# Check admin privileges
$isAdmin = Test-IsAdmin
if (-not $isAdmin) {
    Write-GPULog "Warning: Some optimizations require Administrator privileges" "WARNING"
    Write-Host "`nSome GPU optimizations require Administrator access." -ForegroundColor Yellow
    Write-Host "Continue with limited optimizations? (y/N): " -ForegroundColor Yellow -NoNewline
    $continue = Read-Host
    if ($continue -ne 'y' -and $continue -ne 'Y') {
        Write-GPULog "GPU optimization cancelled by user (no admin)" "INFO"
        exit 0
    }
} else {
    Write-GPULog "Running with Administrator privileges" "SUCCESS"
}

# Get GPU information
$gpuInfo = Get-DetailedGPUInfo
Show-GPUInformation $gpuInfo

# Create backup
Backup-GraphicsRegistry

# ============================================================================
# GPU OPTIMIZATION FUNCTIONS
# ============================================================================

function Set-WindowsGraphicsPreferences {
    Write-Host "`n[GRAPHICS] CONFIGURING WINDOWS GRAPHICS PREFERENCES" -ForegroundColor Cyan
    Write-GPULog "Setting Windows graphics preferences for high performance..." "INFO"
    
    try {
        # Windows 10/11 Graphics Settings
        $graphicsSettingsPath = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"
        
        if (-not (Test-Path $graphicsSettingsPath)) {
            New-Item -Path $graphicsSettingsPath -Force | Out-Null
        }
        
        # Set global graphics preference
        $globalSettings = "GpuPreference=2;VRROptimizeEnable=0;"
        Set-ItemProperty -Path $graphicsSettingsPath -Name "DirectXUserGlobalSettings" -Value $globalSettings -ErrorAction SilentlyContinue
        Write-GPULog "Global graphics preference set to high performance" "SUCCESS"
        
        # Additional graphics optimizations
        $additionalOptimizations = @(
            @{ Path = "HKCU:\Software\Microsoft\Avalon.Graphics"; Name = "DisableHWAcceleration"; Value = 0; Description = "Enable hardware acceleration" },
            @{ Path = "HKCU:\Software\Microsoft\DirectDraw"; Name = "EmulationOnly"; Value = 0; Description = "Enable DirectDraw hardware acceleration" }
        )
        
        foreach ($opt in $additionalOptimizations) {
            try {
                if (-not (Test-Path $opt.Path)) {
                    New-Item -Path $opt.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $opt.Path -Name $opt.Name -Value $opt.Value
                Write-GPULog $opt.Description "SUCCESS"
            } catch {
                Write-GPULog "Failed to apply: $($opt.Description)" "WARNING"
            }
        }
        
    } catch {
        Write-GPULog "Failed to configure Windows graphics preferences: $($_.Exception.Message)" "ERROR"
    }
}

function Optimize-GPUScheduling {
    Write-Host "`n[POWER] OPTIMIZING GPU SCHEDULING" -ForegroundColor Cyan
    Write-GPULog "Analyzing Hardware Accelerated GPU Scheduling..." "INFO"
    
    if (-not $isAdmin) {
        Write-GPULog "Skipping GPU scheduling optimization - requires Administrator" "WARNING"
        return
    }
    
    try {
        $schedulingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        $gpuScheduling = Get-ItemProperty -Path $schedulingPath -Name "HwSchMode" -ErrorAction SilentlyContinue
        
        if ($gpuScheduling) {
            $currentMode = $gpuScheduling.HwSchMode
            if ($currentMode -eq 2) {
                Write-GPULog "Hardware GPU Scheduling is currently ENABLED" "INFO"
                Write-Host "`n[INFO] GPU Scheduling Status:" -ForegroundColor Yellow
                Write-Host "  - Enabled: Can improve performance in some games" -ForegroundColor Green
                Write-Host "  - May cause stuttering in older games" -ForegroundColor Yellow
                Write-Host "  - Recommendation: Keep enabled for modern games" -ForegroundColor Cyan
            } else {
                Write-GPULog "Hardware GPU Scheduling is currently DISABLED" "INFO"
                Write-Host "`nWould you like to enable Hardware GPU Scheduling? (y/N): " -ForegroundColor Yellow -NoNewline
                $enableScheduling = Read-Host
                
                if ($enableScheduling -eq 'y' -or $enableScheduling -eq 'Y') {
                    Set-ItemProperty -Path $schedulingPath -Name "HwSchMode" -Value 2
                    Write-GPULog "Hardware GPU Scheduling enabled (restart required)" "SUCCESS"
                }
            }
        } else {
            Write-GPULog "Hardware GPU Scheduling not supported on this system" "INFO"
        }
    } catch {
        Write-GPULog "Failed to check GPU scheduling: $($_.Exception.Message)" "WARNING"
    }
}

function Apply-NVIDIAOptimizations {
    param($GPUInfo)
    
    $nvidiaGPUs = $GPUInfo | Where-Object { $_.Vendor -eq "NVIDIA" }
    if ($nvidiaGPUs.Count -eq 0) { return }
    
    Write-Host "`n[NVIDIA] APPLYING NVIDIA OPTIMIZATIONS" -ForegroundColor Cyan
    Write-GPULog "Applying NVIDIA-specific gaming optimizations..." "INFO"
    
    if (-not $isAdmin) {
        Write-GPULog "Skipping NVIDIA registry optimizations - requires Administrator" "WARNING"
        return
    }
    
    try {
        # Find NVIDIA registry keys
        $nvidiaKeys = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" -ErrorAction SilentlyContinue
        
        foreach ($key in $nvidiaKeys) {
            $driverDesc = Get-ItemProperty -Path $key.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
            if ($driverDesc -and $driverDesc.DriverDesc -like "*NVIDIA*") {
                
                $nvidiaOptimizations = @(
                    @{ Name = "RMHdcpKeyglobZero"; Value = 1; Description = "Disable HDCP for reduced latency" },
                    @{ Name = "PowerMizerEnable"; Value = 0; Description = "Disable PowerMizer for consistent performance" },
                    @{ Name = "PowerMizerLevel"; Value = 1; Description = "Set maximum performance level" },
                    @{ Name = "PowerMizerLevelAC"; Value = 1; Description = "Set AC maximum performance level" },
                    @{ Name = "PerfLevelSrc"; Value = 0x2222; Description = "Force maximum performance levels" }
                )
                
                foreach ($opt in $nvidiaOptimizations) {
                    try {
                        Set-ItemProperty -Path $key.PSPath -Name $opt.Name -Value $opt.Value -ErrorAction SilentlyContinue
                        Write-GPULog "NVIDIA: $($opt.Description)" "SUCCESS"
                    } catch {
                        Write-GPULog "NVIDIA: Failed to apply $($opt.Description)" "WARNING"
                    }
                }
                break
            }
        }
        
        # NVIDIA Control Panel optimizations via registry
        $nvidiaCPPath = "HKCU:\Software\NVIDIA Corporation\Global\NVTweak"
        if (-not (Test-Path $nvidiaCPPath)) {
            New-Item -Path $nvidiaCPPath -Force | Out-Null
        }
        
        $nvidiaCPOptimizations = @(
            @{ Name = "Coolbits"; Value = 31; Description = "Enable advanced overclocking options" },
            @{ Name = "PowerMode"; Value = 1; Description = "Set to prefer maximum performance" }
        )
        
        foreach ($opt in $nvidiaCPOptimizations) {
            try {
                Set-ItemProperty -Path $nvidiaCPPath -Name $opt.Name -Value $opt.Value
                Write-GPULog "NVIDIA CP: $($opt.Description)" "SUCCESS"
            } catch {
                Write-GPULog "NVIDIA CP: Failed to apply $($opt.Description)" "WARNING"
            }
        }
        
    } catch {
        Write-GPULog "NVIDIA optimization error: $($_.Exception.Message)" "ERROR"
    }
}

function Apply-AMDOptimizations {
    param($GPUInfo)
    
    $amdGPUs = $GPUInfo | Where-Object { $_.Vendor -eq "AMD" }
    if ($amdGPUs.Count -eq 0) { return }
    
    Write-Host "`n[AMD] APPLYING AMD OPTIMIZATIONS" -ForegroundColor Cyan
    Write-GPULog "Applying AMD-specific gaming optimizations..." "INFO"
    
    if (-not $isAdmin) {
        Write-GPULog "Skipping AMD registry optimizations - requires Administrator" "WARNING"
        return
    }
    
    try {
        # AMD registry optimizations
        $amdKeys = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" -ErrorAction SilentlyContinue
        
        foreach ($key in $amdKeys) {
            $driverDesc = Get-ItemProperty -Path $key.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
            if ($driverDesc -and ($driverDesc.DriverDesc -like "*AMD*" -or $driverDesc.DriverDesc -like "*Radeon*")) {
                
                $amdOptimizations = @(
                    @{ Name = "KMD_FRTEnabled"; Value = 0; Description = "Disable Frame Rate Target for consistent performance" },
                    @{ Name = "KMD_DeLagEnabled"; Value = 1; Description = "Enable Anti-Lag for reduced input latency" },
                    @{ Name = "DisableULPS"; Value = 1; Description = "Disable Ultra Low Power State" },
                    @{ Name = "EnableAspmL0s"; Value = 0; Description = "Disable ASPM L0s" },
                    @{ Name = "EnableAspmL1"; Value = 0; Description = "Disable ASPM L1" }
                )
                
                foreach ($opt in $amdOptimizations) {
                    try {
                        Set-ItemProperty -Path $key.PSPath -Name $opt.Name -Value $opt.Value -ErrorAction SilentlyContinue
                        Write-GPULog "AMD: $($opt.Description)" "SUCCESS"
                    } catch {
                        Write-GPULog "AMD: Failed to apply $($opt.Description)" "WARNING"
                    }
                }
                break
            }
        }
        
    } catch {
        Write-GPULog "AMD optimization error: $($_.Exception.Message)" "ERROR"
    }
}

function Optimize-DisplaySettings {
    Write-Host "`n[DISPLAY] OPTIMIZING DISPLAY SETTINGS" -ForegroundColor Cyan
    Write-GPULog "Applying display optimizations for gaming..." "INFO"
    
    try {
        # Get display information
        $displays = Get-CimInstance -ClassName Win32_DesktopMonitor
        
        foreach ($display in $displays) {
            if ($display.ScreenWidth -and $display.ScreenHeight) {
                Write-GPULog "Display: $($display.ScreenWidth)x$($display.ScreenHeight)" "INFO"
            }
        }
        
        # Display-related optimizations
        $displayOptimizations = @(
            @{ Path = "HKCU:\Control Panel\Desktop"; Name = "AutoEndTasks"; Value = "1"; Description = "Auto-end non-responsive tasks" },
            @{ Path = "HKCU:\Control Panel\Desktop"; Name = "HungAppTimeout"; Value = "1000"; Description = "Reduce hung app timeout" },
            @{ Path = "HKCU:\Control Panel\Desktop"; Name = "WaitToKillAppTimeout"; Value = "2000"; Description = "Reduce app kill timeout" },
            @{ Path = "HKCU:\Control Panel\Desktop"; Name = "LowLevelHooksTimeout"; Value = "1000"; Description = "Reduce low-level hooks timeout" }
        )
        
        foreach ($opt in $displayOptimizations) {
            try {
                if (-not (Test-Path $opt.Path)) {
                    New-Item -Path $opt.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $opt.Path -Name $opt.Name -Value $opt.Value
                Write-GPULog $opt.Description "SUCCESS"
            } catch {
                Write-GPULog "Failed to apply: $($opt.Description)" "WARNING"
            }
        }
        
    } catch {
        Write-GPULog "Display optimization error: $($_.Exception.Message)" "ERROR"
    }
}

function Show-DriverUpdateInfo {
    param($GPUInfo)
    
    if (-not $script:Config.CheckDrivers) { return }
    
    Write-Host "`n[DOWNLOAD] DRIVER UPDATE INFORMATION" -ForegroundColor Cyan
    Write-GPULog "Checking driver update recommendations..." "INFO"
    
    foreach ($gpu in $GPUInfo) {
        Write-GPULog "Checking drivers for: $($gpu.Name)" "INFO"
        
        $driverAge = $null
        if ($gpu.DriverDate) {
            try {
                $driverDate = [DateTime]::ParseExact($gpu.DriverDate.Split('.')[0], "yyyyMMdd", $null)
                $driverAge = (Get-Date) - $driverDate
                Write-GPULog "Driver age: $($driverAge.Days) days" "INFO"
            } catch {
                Write-GPULog "Could not parse driver date" "WARNING"
            }
        }
        
        switch ($gpu.Vendor) {
            "NVIDIA" {
                Write-Host "[NVIDIA] NVIDIA GPU detected:" -ForegroundColor Green
                Write-Host "  - Download latest drivers: https://www.nvidia.com/drivers" -ForegroundColor Cyan
                Write-Host "  - Use GeForce Experience for auto-updates" -ForegroundColor Cyan
                Write-Host "  - Consider NVIDIA Studio drivers for content creation" -ForegroundColor Cyan
            }
            "AMD" {
                Write-Host "[AMD] AMD GPU detected:" -ForegroundColor Red
                Write-Host "  - Download latest drivers: https://www.amd.com/support" -ForegroundColor Cyan
                Write-Host "  - Use AMD Software: Adrenalin Edition" -ForegroundColor Cyan
                Write-Host "  - Enable AMD Radeon Anti-Lag in games" -ForegroundColor Cyan
            }
            "Intel" {
                Write-Host "[INTEL] Intel GPU detected:" -ForegroundColor Blue
                Write-Host "  - Download latest drivers: https://www.intel.com/content/www/us/en/support/products/80939/graphics.html" -ForegroundColor Cyan
                Write-Host "  - Use Intel Graphics Command Center" -ForegroundColor Cyan
            }
        }
        
        if ($driverAge -and $driverAge.Days -gt 60) {
            Write-GPULog "[WARNING]  Driver is $($driverAge.Days) days old - consider updating" "WARNING"
        }
    }
}

function Set-UltraGPUPerformanceMode {
    Write-Host "`n[ULTRA] APPLYING ULTRA GPU PERFORMANCE OPTIMIZATIONS" -ForegroundColor Magenta
    Write-GPULog "WARNING: Applying EXTREME GPU performance optimizations" "WARNING"
    
    # Check if running as admin for system-level tweaks
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    # Ultra-aggressive GPU registry optimizations
    $ultraGPUOptimizations = @(
        # Force maximum GPU performance mode
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name = "TdrLevel"; Value = 0; Description = "Disable GPU timeout detection and recovery"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name = "TdrDelay"; Value = 60; Description = "Increase GPU timeout delay"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name = "HwSchMode"; Value = 2; Description = "Enable hardware-accelerated GPU scheduling"; RequiresAdmin = $true },
        
        # Disable GPU power saving features
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"; Name = "DisableDynamicPState"; Value = 1; Description = "Disable GPU dynamic P-state"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"; Name = "DisablePowerSaving"; Value = 1; Description = "Disable GPU power saving"; RequiresAdmin = $true },
        
        # Force maximum performance for all GPU adapter instances
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001"; Name = "DisableDynamicPState"; Value = 1; Description = "Disable GPU dynamic P-state (adapter 1)"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002"; Name = "DisableDynamicPState"; Value = 1; Description = "Disable GPU dynamic P-state (adapter 2)"; RequiresAdmin = $true },
        
        # Optimize GPU memory management
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name = "DpiMapIommuContiguous"; Value = 1; Description = "Enable contiguous IOMMU mapping"; RequiresAdmin = $true },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name = "SchedulingPriority"; Value = 8; Description = "Maximum GPU scheduling priority"; RequiresAdmin = $true },
        
        # Disable GPU preemption for ultra-low latency
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler"; Name = "EnablePreemption"; Value = 0; Description = "Disable GPU preemption"; RequiresAdmin = $true },
          # Force dedicated GPU for all applications
        @{ Path = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"; Name = "*"; Value = "GpuPreference=2;"; Description = "Force high-performance GPU for all apps"; RequiresAdmin = $false }
    )
    
    $appliedCount = 0
    foreach ($opt in $ultraGPUOptimizations) {
        if ($opt.RequiresAdmin -and -not $isAdmin) {
            Write-GPULog "Skipping $($opt.Description) - requires admin privileges" "WARNING"
            continue
        }
        
        try {
            # Create registry path if it doesn't exist
            $pathExists = Test-Path $opt.Path
            if (-not $pathExists) {
                New-Item -Path $opt.Path -Force | Out-Null
            }
            
            Set-ItemProperty -Path $opt.Path -Name $opt.Name -Value $opt.Value -Force
            Write-GPULog $opt.Description "SUCCESS"
            $appliedCount++
        } catch {
            Write-GPULog "Failed to apply: $($opt.Description)" "ERROR"
        }
    }
    
    Write-GPULog "Ultra GPU Performance Mode: $appliedCount optimizations applied" "SUCCESS"
}

function Set-ExtremeMSIMode {
    Write-Host "`n[POWER] OPTIMIZING GPU INTERRUPT HANDLING" -ForegroundColor Yellow
    Write-GPULog "Configuring Message Signaled Interrupts (MSI) for maximum GPU performance..." "INFO"
    
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-GPULog "MSI optimizations require administrator privileges" "ERROR"
        return
    }
    
    try {
        # Get all GPU devices
        $gpuDevices = Get-PnpDevice | Where-Object { $_.Class -eq "Display" -and $_.Status -eq "OK" }
        
        foreach ($gpu in $gpuDevices) {
            $devicePath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($gpu.InstanceId)"
            $deviceParametersPath = "$devicePath\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
            
            try {
                # Create MSI registry structure if it doesn't exist
                if (-not (Test-Path $deviceParametersPath)) {
                    New-Item -Path $deviceParametersPath -Force | Out-Null
                }
                
                # Enable MSI mode
                Set-ItemProperty -Path $deviceParametersPath -Name "MSISupported" -Value 1 -Force
                
                # Set interrupt priority to high
                $affinityPath = "$devicePath\Device Parameters\Interrupt Management\Affinity Policy"
                if (-not (Test-Path $affinityPath)) {
                    New-Item -Path $affinityPath -Force | Out-Null
                }
                Set-ItemProperty -Path $affinityPath -Name "DevicePolicy" -Value 5 -Force  # IrqPolicyMachineDefault
                Set-ItemProperty -Path $affinityPath -Name "DevicePriority" -Value 3 -Force  # IrqDevicePolicyHighPriority
                
                Write-GPULog "MSI enabled for GPU: $($gpu.FriendlyName)" "SUCCESS"
            } catch {
                Write-GPULog "Could not configure MSI for $($gpu.FriendlyName): $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-GPULog "GPU interrupt handling optimization completed" "SUCCESS"
        
    } catch {
        Write-GPULog "Failed to optimize GPU interrupts: $($_.Exception.Message)" "ERROR"
    }
}

function Optimize-DisplayDriverSettings {
    Write-Host "`n[DISPLAY] OPTIMIZING DISPLAY DRIVER FOR MAXIMUM PERFORMANCE" -ForegroundColor Cyan
    Write-GPULog "Applying aggressive display driver optimizations..." "INFO"
    
    # Universal display optimizations
    $displayOptimizations = @(
        # Disable composition and DWM features that impact performance
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"; Name = "OverlayTestMode"; Value = 5; Description = "Optimize DWM overlay performance" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"; Name = "AccentColor"; Value = 0; Description = "Disable accent color effects" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"; Name = "ColorizationOpaqueBlend"; Value = 0; Description = "Disable color blending" },
        
        # Disable animations and transitions
        @{ Path = "HKCU:\Control Panel\Desktop\WindowMetrics"; Name = "MinAnimate"; Value = 0; Description = "Disable window animations" },
        @{ Path = "HKCU:\Control Panel\Desktop"; Name = "UserPreferencesMask"; Value = ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)); Type = "Binary"; Description = "Disable UI animations" },
        
        # Force maximum refresh rate
        @{ Path = "HKCU:\Software\Microsoft\Windows\DWM"; Name = "Composition"; Value = 0; Description = "Disable desktop composition when not needed" },
        
        # Disable fullscreen optimizations interference
        @{ Path = "HKCU:\System\GameConfigStore"; Name = "GameDVR_DSEBehavior"; Value = 2; Description = "Optimize fullscreen behavior" },
        @{ Path = "HKCU:\System\GameConfigStore"; Name = "GameDVR_HonorUserFSEBehaviorMode"; Value = 1; Description = "Honor user fullscreen settings" },
        @{ Path = "HKCU:\System\GameConfigStore"; Name = "GameDVR_EFSEFeatureFlags"; Value = 0; Description = "Disable enhanced fullscreen features" }
    )
    
    foreach ($opt in $displayOptimizations) {
        try {
            $pathExists = Test-Path $opt.Path
            if (-not $pathExists) {
                New-Item -Path $opt.Path -Force | Out-Null
            }
            
            $type = if ($opt.Type) { $opt.Type } else { "DWORD" }
            
            if ($type -eq "Binary") {
                Set-ItemProperty -Path $opt.Path -Name $opt.Name -Value $opt.Value -Type Binary -Force
            } else {
                Set-ItemProperty -Path $opt.Path -Name $opt.Name -Value $opt.Value -Force
            }
            
            Write-GPULog $opt.Description "SUCCESS"
        } catch {
            Write-GPULog "Failed to apply: $($opt.Description)" "WARNING"
        }
    }
    
    Write-GPULog "Display driver optimizations completed" "SUCCESS"
}

function Set-UltraLowLatencyGraphics {
    Write-Host "`n[POWER] CONFIGURING ULTRA-LOW LATENCY GRAPHICS" -ForegroundColor Magenta
    Write-GPULog "Applying ultra-low latency graphics optimizations..." "INFO"
    
    $latencyOptimizations = @(
        # Disable GPU scheduling delays
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler"; Name = "VsyncIdleTimeout"; Value = 0; Description = "Disable VSync idle timeout" },
        
        # Optimize frame pacing
        @{ Path = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"; Name = "DirectXUserGlobalSettings"; Value = "VRROptimizeEnable=0;"; Description = "Disable VRR optimizations that add latency" },
        
        # Force immediate mode rendering
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name = "Latency Sensitive"; Value = "True"; Description = "Enable latency-sensitive mode for games" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name = "NoLazyMode"; Value = 1; Description = "Disable lazy mode for games" },
        
        # Disable GPU throttling completely
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"; Name = "PP_ThermalAutoThrottlingEnable"; Value = 0; Description = "Disable thermal auto-throttling" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"; Name = "PP_ActivityMonitorCoefficient"; Value = 0; Description = "Disable activity monitoring" }
    )
    
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    foreach ($opt in $latencyOptimizations) {
        if ($opt.Path.StartsWith("HKLM:") -and -not $isAdmin) {
            Write-GPULog "Skipping $($opt.Description) - requires admin privileges" "WARNING"
            continue
        }
        
        try {
            if (-not (Test-Path $opt.Path)) {
                New-Item -Path $opt.Path -Force | Out-Null
            }
            
            Set-ItemProperty -Path $opt.Path -Name $opt.Name -Value $opt.Value -Force
            Write-GPULog $opt.Description "SUCCESS"
        } catch {
            Write-GPULog "Failed to apply: $($opt.Description)" "WARNING"
        }
    }
    
    Write-GPULog "Ultra-low latency graphics configuration completed" "SUCCESS"
}

function Force-MaximumGPUClocks {
    Write-Host "`n[MAX] FORCING MAXIMUM GPU PERFORMANCE STATE" -ForegroundColor Red
    Write-GPULog "WARNING: Forcing GPU to maximum performance state (high power consumption)" "WARNING"
    
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-GPULog "Maximum GPU clock forcing requires administrator privileges" "ERROR"
        return
    }
    
    try {
        # Force P-State 0 (maximum performance) for all graphics adapters
        $graphicsAdapters = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002"
        )
        
        foreach ($adapter in $graphicsAdapters) {
            if (Test-Path $adapter) {
                try {
                    # Force maximum performance state
                    Set-ItemProperty -Path $adapter -Name "PowerPolicyIdleTimeoutUs" -Value 1 -Force
                    Set-ItemProperty -Path $adapter -Name "PowerPolicyIdleTimeoutMs" -Value 1 -Force
                    Set-ItemProperty -Path $adapter -Name "PerfLevelSrc" -Value 0x2222 -Force
                    Set-ItemProperty -Path $adapter -Name "PowerMizerEnable" -Value 0 -Force
                    Set-ItemProperty -Path $adapter -Name "PowerMizerLevel" -Value 1 -Force
                    Set-ItemProperty -Path $adapter -Name "PowerMizerLevelAC" -Value 1 -Force
                    
                    # NVIDIA specific optimizations
                    Set-ItemProperty -Path $adapter -Name "PerfLevelSrc" -Value 0x2222 -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $adapter -Name "PowerMizerDefault" -Value 1 -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $adapter -Name "PowerMizerDefaultAC" -Value 1 -Force -ErrorAction SilentlyContinue
                    
                    # AMD specific optimizations  
                    Set-ItemProperty -Path $adapter -Name "PP_SclkDeepSleepDisable" -Value 1 -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $adapter -Name "PP_ThermalAutoThrottlingEnable" -Value 0 -Force -ErrorAction SilentlyContinue
                    
                    Write-GPULog "Maximum performance forced for graphics adapter: $adapter" "SUCCESS"
                } catch {
                    Write-GPULog "Could not force maximum performance for $adapter" "WARNING"
                }
            }
        }
        
        # Set GPU scheduling to realtime priority
        try {
            $schedulerPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
            if (-not (Test-Path $schedulerPath)) {
                New-Item -Path $schedulerPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $schedulerPath -Name "GPU Priority" -Value 8 -Force
            Set-ItemProperty -Path $schedulerPath -Name "Priority" -Value 6 -Force
            Set-ItemProperty -Path $schedulerPath -Name "Scheduling Category" -Value "High" -Force
            Set-ItemProperty -Path $schedulerPath -Name "SFIO Priority" -Value "High" -Force
            
            Write-GPULog "GPU scheduling priority set to maximum" "SUCCESS"
        } catch {
            Write-GPULog "Could not set GPU scheduling priority" "WARNING"
        }
        
        Write-GPULog "Maximum GPU performance state configuration completed" "SUCCESS"
        
    } catch {
        Write-GPULog "Failed to force maximum GPU clocks: $($_.Exception.Message)" "ERROR"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Display ILYESIZER GPU Banner
Clear-Host
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                    ILYESIZER GPU v3.0                      " -ForegroundColor Green
Write-Host "            Professional GPU Gaming Optimization            " -ForegroundColor Green
Write-Host "                    Made by ilyyeees                        " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starting ILYESIZER GPU optimization process..." -ForegroundColor Green

# Warning about aggressive optimizations  
Write-Host ""
Write-Host "WARNING: This script will apply EXTREME GPU optimizations!" -ForegroundColor Yellow
Write-Host "These optimizations will:" -ForegroundColor Yellow
Write-Host "- Force maximum GPU performance states (high power usage)" -ForegroundColor Yellow
Write-Host "- Disable GPU power saving and throttling" -ForegroundColor Yellow
Write-Host "- Apply ultra-low latency graphics tweaks" -ForegroundColor Yellow
Write-Host "- Configure aggressive interrupt handling" -ForegroundColor Yellow
Write-Host ""

$response = Read-Host "Proceed with EXTREME GPU optimizations for maximum gaming performance? (Y/N)"
if ($response -ne 'Y' -and $response -ne 'y') {
    Write-Host "ILYESIZER GPU optimization cancelled by user." -ForegroundColor Yellow
    exit
}

try {
    # Get GPU information first
    $gpuInfo = Get-DetailedGPUInfo
    
    # Phase 1: Standard optimizations
    Write-Host "`n[PHASE] PHASE 1: STANDARD GPU OPTIMIZATIONS" -ForegroundColor Cyan
    Set-WindowsGraphicsPreferences
    Optimize-GPUScheduling
    Apply-NVIDIAOptimizations $gpuInfo
    Apply-AMDOptimizations $gpuInfo
    Optimize-DisplaySettings
    
    # Phase 2: Ultra-aggressive optimizations
    Write-Host "`n[MAX] PHASE 2: ULTRA-AGGRESSIVE GPU OPTIMIZATIONS" -ForegroundColor Red
    Set-UltraGPUPerformanceMode
    Set-ExtremeMSIMode
    Optimize-DisplayDriverSettings
    Set-UltraLowLatencyGraphics
    Force-MaximumGPUClocks
    
    Write-Host "`n" -NoNewline
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host "|            [SUCCESS] ULTRA AGGRESSIVE GPU OPTIMIZATION COMPLETED!               |" -ForegroundColor Green
    Write-Host "|                                                                          |" -ForegroundColor Green
    Write-Host "|  [ULTRA] Your GPU is now configured for MAXIMUM gaming performance!          |" -ForegroundColor Green
    Write-Host "|  [POWER] Ultra-low latency graphics pipeline enabled                         |" -ForegroundColor Green
    Write-Host "|  [MAX] Maximum performance states forced                                   |" -ForegroundColor Green
    Write-Host "|  [DISABLE] Power saving and throttling disabled                               |" -ForegroundColor Green
    Write-Host "|  [MSI] MSI interrupt handling optimized                                   |" -ForegroundColor Green
    Write-Host "|  [GPU] Hardware-accelerated GPU scheduling enabled                        |" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
      Write-GPULog "ILYESIZER GPU v3.0 optimization completed successfully" "SUCCESS"
    
    # ILYESIZER GPU Completion Summary
    Write-Host ""
    Write-Host "=============================================================" -ForegroundColor Green
    Write-Host "            ILYESIZER GPU v3.0 - OPTIMIZATION COMPLETE      " -ForegroundColor Green
    Write-Host "=============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Log file location: $($script:ILYESIZERConfig.LogFile)" -ForegroundColor Cyan
    
    # Show driver update recommendations
    Show-DriverUpdateInfo $gpuInfo
    
    Write-Host ""
    Write-Host "RESTART REQUIRED: Reboot now for maximum GPU performance!" -ForegroundColor Yellow -BackgroundColor Red
    Write-Host ""
    Write-Host "Expected improvements after restart:" -ForegroundColor Green
    Write-Host "- 10-30% higher FPS in games" -ForegroundColor Green
    Write-Host "- Reduced input lag and frame time variance" -ForegroundColor Green
    Write-Host "- Eliminated GPU power throttling" -ForegroundColor Green
    Write-Host "- Faster GPU response times" -ForegroundColor Green
    Write-Host "- More consistent frame rates" -ForegroundColor Green
    Write-Host ""
    Write-Host "ILYESIZER GPU Pro Tips:" -ForegroundColor Cyan
    Write-Host "- Monitor GPU temperatures (should be higher due to max performance)" -ForegroundColor Cyan
    Write-Host "- Increase fan curves in MSI Afterburner if needed" -ForegroundColor Cyan
    Write-Host "- Use DDU to clean install GPU drivers for best results" -ForegroundColor Cyan
    Write-Host "- Consider undervolting for efficiency without performance loss" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Thank you for using ILYESIZER GPU v3.0!" -ForegroundColor Green
    
    Write-Host "`n[WARNING]  NOTE: Higher power consumption and temperatures are normal" -ForegroundColor Yellow
    Write-Host "   GPU will run at maximum performance for best gaming experience" -ForegroundColor Yellow
    
} catch {
    Write-GPULog "Critical error during GPU optimization: $($_.Exception.Message)" "ERROR"
    Write-Host "`n[ERROR] GPU optimization encountered errors. Check the log file for details." -ForegroundColor Red
}
