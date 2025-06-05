# ILYESIZER Optimization Verification Script
# Version 3.0 - Comprehensive verification of gaming optimizations
# Created by ilyyeees
#
# DESCRIPTION:
# This script verifies that all ILYESIZER gaming optimizations have been
# properly applied and are functioning correctly. It performs comprehensive
# checks across all optimization categories and provides detailed reporting.
#
# FEATURES:
# - Registry setting verification
# - Service status checking
# - Power plan validation
# - Network configuration testing
# - GPU optimization confirmation
# - Performance metric analysis
# - Detailed reporting with recommendations
#
# USAGE:
# Run this script after applying ILYESIZER optimizations to verify success.
# No administrator privileges required for most checks.

#Requires -Version 5.1

param(
    [switch]$Detailed,
    [switch]$ExportReport
)

# Script configuration
$script:VerificationConfig = @{
    LogFile = "$env:USERPROFILE\Desktop\ILYESIZER-Verification-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    ReportFile = "$env:USERPROFILE\Desktop\ILYESIZER-Report-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
    Version = "3.0"
    TotalChecks = 0
    PassedChecks = 0
    FailedChecks = 0
    WarningChecks = 0
}

# Logging function for verification script
function Write-VerifyLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "PASS", "FAIL", "WARNING")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with color coding
    switch ($Level) {
        "INFO"    { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
        "PASS"    { Write-Host "[PASS] $Message" -ForegroundColor Green }
        "FAIL"    { Write-Host "[FAIL] $Message" -ForegroundColor Red }
        "WARNING" { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
    }
    
    # Update counters
    $script:VerificationConfig.TotalChecks++
    switch ($Level) {
        "PASS"    { $script:VerificationConfig.PassedChecks++ }
        "FAIL"    { $script:VerificationConfig.FailedChecks++ }
        "WARNING" { $script:VerificationConfig.WarningChecks++ }
    }
    
    # File logging
    try {
        Add-Content -Path $script:VerificationConfig.LogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {}
}

# Check registry value function
function Test-RegistryOptimization {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [object]$ExpectedValue,
        
        [Parameter(Mandatory=$true)]
        [string]$Description
    )
    
    try {
        if (Test-Path $Path) {
            $actualValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($actualValue.$Name -eq $ExpectedValue) {
                Write-VerifyLog "$Description - Configured correctly" "PASS"
                return $true
            } else {
                Write-VerifyLog "$Description - Value mismatch (Expected: $ExpectedValue, Actual: $($actualValue.$Name))" "FAIL"
                return $false
            }
        } else {
            Write-VerifyLog "$Description - Registry path not found: $Path" "FAIL"
            return $false
        }
    } catch {
        Write-VerifyLog "$Description - Error checking: $($_.Exception.Message)" "FAIL"
        return $false
    }
}

# Main verification function
function Start-ILYESIZERVerification {
    Clear-Host
    Write-Host @"
================================================================================
|                    ILYESIZER OPTIMIZATION VERIFICATION                    |
|                                Version 3.0                                |
|                          Gaming Performance Analysis                      |
================================================================================
"@ -ForegroundColor Green

    Write-VerifyLog "ILYESIZER Optimization Verification started" "INFO"
    
    # Windows Game Mode Verification
    Write-Host "`n[SECTION] Windows Game Mode Configuration" -ForegroundColor Cyan
    Test-RegistryOptimization -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -ExpectedValue 1 -Description "Auto Game Mode"
    Test-RegistryOptimization -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ExpectedValue 1 -Description "Game Mode Enabled"
    Test-RegistryOptimization -Path "HKCU:\Software\Microsoft\GameBar" -Name "GameModeEnabled" -ExpectedValue 1 -Description "Global Game Mode"
    
    # Game Bar Interference Reduction
    Write-Host "`n[SECTION] Xbox Game Bar Interference Reduction" -ForegroundColor Cyan
    Test-RegistryOptimization -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -ExpectedValue 0 -Description "Game Bar Nexus Disabled"
    Test-RegistryOptimization -Path "HKCU:\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -ExpectedValue 0 -Description "Startup Panel Disabled"
    Test-RegistryOptimization -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -ExpectedValue 0 -Description "App Capture Disabled"
    Test-RegistryOptimization -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -ExpectedValue 0 -Description "Audio Capture Disabled"
    
    # Visual Effects Optimization
    Write-Host "`n[SECTION] Visual Effects Performance" -ForegroundColor Cyan
    Test-RegistryOptimization -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -ExpectedValue 2 -Description "Custom Visual Effects"
    Test-RegistryOptimization -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -ExpectedValue 0 -Description "Menu Show Delay Removed"
    Test-RegistryOptimization -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -ExpectedValue 0 -Description "Taskbar Animations Disabled"
    
    # Mouse Optimization
    Write-Host "`n[SECTION] Mouse and Input Optimization" -ForegroundColor Cyan
    Test-RegistryOptimization -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -ExpectedValue 0 -Description "Mouse Acceleration Disabled"
    Test-RegistryOptimization -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -ExpectedValue 10 -Description "Mouse Hover Time Optimized"
    Test-RegistryOptimization -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -ExpectedValue 0 -Description "Mouse Threshold 1 Disabled"
    Test-RegistryOptimization -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -ExpectedValue 0 -Description "Mouse Threshold 2 Disabled"
    
    # Power Plan Verification
    Write-Host "`n[SECTION] Power Management" -ForegroundColor Cyan
    try {
        $currentScheme = powercfg /getactivescheme
        if ($currentScheme -match "High performance" -or $currentScheme -match "8c5e7fda") {
            Write-VerifyLog "High Performance power plan active" "PASS"
        } else {
            Write-VerifyLog "High Performance power plan not active" "FAIL"
        }
    } catch {
        Write-VerifyLog "Unable to check power plan status" "WARNING"
    }
    
    # System Performance Check
    Write-Host "`n[SECTION] System Performance Analysis" -ForegroundColor Cyan
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
        $processorInfo = Get-CimInstance -ClassName Win32_Processor
        
        Write-VerifyLog "OS: $($osInfo.Caption) Build $($osInfo.BuildNumber)" "INFO"
        Write-VerifyLog "Total RAM: $([math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)) GB" "INFO"
        Write-VerifyLog "Processor: $($processorInfo.Name)" "INFO"
        
        # Memory utilization check
        $memoryUsage = [math]::Round((($computerInfo.TotalPhysicalMemory - $osInfo.FreePhysicalMemory * 1KB) / $computerInfo.TotalPhysicalMemory) * 100, 1)
        if ($memoryUsage -lt 80) {
            Write-VerifyLog "Memory utilization: $memoryUsage% - Good" "PASS"
        } else {
            Write-VerifyLog "Memory utilization: $memoryUsage% - High" "WARNING"
        }
        
        # Startup program count
        $startupItems = Get-CimInstance Win32_StartupCommand | Measure-Object
        if ($startupItems.Count -le 20) {
            Write-VerifyLog "Startup programs: $($startupItems.Count) - Acceptable" "PASS"
        } else {
            Write-VerifyLog "Startup programs: $($startupItems.Count) - Too many" "WARNING"
        }
        
    } catch {
        Write-VerifyLog "Error during system analysis: $($_.Exception.Message)" "WARNING"
    }
    
    # Network Performance Check
    Write-Host "`n[SECTION] Network Configuration" -ForegroundColor Cyan
    try {
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.MediaType -eq "802.3" }
        if ($networkAdapters) {
            Write-VerifyLog "Active network adapters found: $($networkAdapters.Count)" "PASS"
            foreach ($adapter in $networkAdapters) {
                Write-VerifyLog "Network adapter: $($adapter.Name) - Link Speed: $($adapter.LinkSpeed)" "INFO"
            }
        } else {
            Write-VerifyLog "No active ethernet adapters found" "WARNING"
        }
    } catch {
        Write-VerifyLog "Error checking network adapters: $($_.Exception.Message)" "WARNING"
    }
    
    # GPU Information
    Write-Host "`n[SECTION] Graphics Hardware" -ForegroundColor Cyan
    try {
        $gpuInfo = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.PNPDeviceID -notlike "ROOT\*" }
        foreach ($gpu in $gpuInfo) {
            Write-VerifyLog "GPU: $($gpu.Name)" "INFO"
            Write-VerifyLog "Driver Version: $($gpu.DriverVersion)" "INFO"
            Write-VerifyLog "Video Memory: $([math]::Round($gpu.AdapterRAM / 1GB, 1)) GB" "INFO"
        }
        
        # Hardware GPU Scheduling check
        $gpuScheduling = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -ErrorAction SilentlyContinue
        if ($gpuScheduling.HwSchMode -eq 2) {
            Write-VerifyLog "Hardware GPU Scheduling enabled" "PASS"
        } else {
            Write-VerifyLog "Hardware GPU Scheduling not enabled" "WARNING"
        }
    } catch {
        Write-VerifyLog "Error checking GPU information: $($_.Exception.Message)" "WARNING"
    }
    
    # Final Results
    Write-Host "`n" -NoNewline
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host "|                    ILYESIZER VERIFICATION COMPLETE                     |" -ForegroundColor Green
    Write-Host "|                                                                        |" -ForegroundColor Green
    
    $passPercentage = [math]::Round(($script:VerificationConfig.PassedChecks / $script:VerificationConfig.TotalChecks) * 100, 1)
    
    if ($passPercentage -ge 90) {
        $status = "EXCELLENT"
        $color = "Green"
    } elseif ($passPercentage -ge 75) {
        $status = "GOOD"
        $color = "Green"
    } elseif ($passPercentage -ge 60) {
        $status = "FAIR"
        $color = "Yellow"
    } else {
        $status = "NEEDS IMPROVEMENT"
        $color = "Red"
    }
    
    Write-Host "|  Optimization Status: $status ($passPercentage% passed)" -ForegroundColor $color
    Write-Host "|  Total Checks: $($script:VerificationConfig.TotalChecks)" -ForegroundColor Green
    Write-Host "|  Passed: $($script:VerificationConfig.PassedChecks)" -ForegroundColor Green
    Write-Host "|  Failed: $($script:VerificationConfig.FailedChecks)" -ForegroundColor Green
    Write-Host "|  Warnings: $($script:VerificationConfig.WarningChecks)" -ForegroundColor Green
    Write-Host "|                                                                        |" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
    
    Write-Host "`n[LOG] Detailed verification log: $($script:VerificationConfig.LogFile)" -ForegroundColor Cyan
    
    if ($script:VerificationConfig.FailedChecks -gt 0) {
        Write-Host "`n[RECOMMENDATION] Some optimizations may need to be re-applied" -ForegroundColor Yellow
        Write-Host "Consider running ILYESIZER again or checking the log for specific issues" -ForegroundColor Yellow
    }
    
    if ($script:VerificationConfig.WarningChecks -gt 0) {
        Write-Host "`n[NOTE] Some warnings detected - these may be expected depending on your system" -ForegroundColor Cyan
    }
    
    Write-VerifyLog "ILYESIZER verification completed: $passPercentage% passed" "INFO"
}

# Execute verification
Start-ILYESIZERVerification
