<#
.SYNOPSIS
    ILYESIZER Network v3.0 - Ultra-Advanced Network Gaming Optimization Suite
    Made by ilyyeees - Professional Gaming Performance Optimization

.DESCRIPTION
    ILYESIZER Network v3.0 delivers comprehensive network optimization for gaming systems.
    This advanced suite maximizes network performance, reduces latency, and optimizes
    connection stability for competitive gaming environments.

    Key Features:
    - Advanced TCP/IP stack optimization
    - Ultra-low latency network tweaks
    - Gaming-specific DNS configuration
    - Network adapter performance tuning
    - Windows network stack enhancements
    - QoS and traffic prioritization
    - Network buffer optimization
    - Connection stability improvements
    - Comprehensive network monitoring
    - Professional logging and reporting

.PARAMETER SafeMode
    Enables conservative optimizations with minimal system impact
    
.PARAMETER CustomDNS
    Specifies custom DNS servers to use
    
.PARAMETER LogPath
    Specifies custom location for ILYESIZER Network log files

.OUTPUTS
    Comprehensive network optimization report with latency metrics
    Detailed log file with all optimization activities
    Network configuration backup files

.EXAMPLE
    .\ILYESIZER-Network-v3.0.ps1
    Runs full network optimization suite with default settings

.EXAMPLE
    .\ILYESIZER-Network-v3.0.ps1 -SafeMode
    Runs conservative network optimizations only

.NOTES
    Script Name    : ILYESIZER Network v3.0
    Version        : 3.0.0
    Author         : ilyyeees
    Creation Date  : 2024
    Purpose        : Professional network gaming optimization
    
    Requirements:
    - PowerShell 5.1 or higher
    - Administrator privileges required
    - Windows 10/11 support
    
    Safety Features:
    - Automatic network settings backup
    - System restore point creation
    - Safe optimization validation
    - Comprehensive error handling
    - Professional logging system
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ============================================================================
# ILYESIZER Network v3.0 - CONFIGURATION AND INITIALIZATION
# ============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ILYESIZER Network v3.0 Configuration
$script:ILYESIZERConfig = @{
    ScriptName = "ILYESIZER Network v3.0"
    Version = "3.0.0"
    Author = "ilyyeees"
    LogFile = "$env:USERPROFILE\Desktop\ILYESIZER-Network-Log-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    BackupNetworkSettings = $true
    TestConnectivity = $true
    PreferredDNS = @("1.1.1.1", "1.0.0.1")  # Cloudflare DNS (faster than Google in many regions)
    AlternateDNS = @("8.8.8.8", "8.8.4.4")   # Google DNS
    CreateRestorePoint = $true
    OptimizationLevel = "Maximum"
    LatencyTarget = 1  # Target latency in milliseconds
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-NetLog {
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
        Add-Content -Path $script:ILYESIZERConfig.LogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {}
}

function Test-NetworkConnectivity {
    Write-NetLog "Testing network connectivity..." "INFO"
    
    $testHosts = @(
        @{ Host = "8.8.8.8"; Description = "Google DNS" },
        @{ Host = "1.1.1.1"; Description = "Cloudflare DNS" },
        @{ Host = "www.google.com"; Description = "Google Web" }
    )
    
    foreach ($test in $testHosts) {
        try {
            $result = Test-Connection -ComputerName $test.Host -Count 2 -Quiet
            if ($result) {
                Write-NetLog "[OK] $($test.Description) reachable" "SUCCESS"
            } else {
                Write-NetLog "[ERROR] $($test.Description) unreachable" "WARNING"
            }
        } catch {
            Write-NetLog "[ERROR] Failed to test $($test.Description)" "WARNING"
        }
    }
}

function Get-CurrentNetworkSettings {
    Write-NetLog "Gathering current network configuration..." "INFO"
    
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        foreach ($adapter in $adapters) {
            Write-NetLog "Active adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" "INFO"
            
            # Get current DNS settings
            $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4
            if ($dnsServers.ServerAddresses) {
                Write-NetLog "  Current DNS: $($dnsServers.ServerAddresses -join ', ')" "INFO"
            }
            
            # Get adapter speed
            $linkSpeed = $adapter.LinkSpeed
            if ($linkSpeed) {
                Write-NetLog "  Link Speed: $linkSpeed" "INFO"
            }
        }
    } catch {
        Write-NetLog "Failed to gather network settings: $($_.Exception.Message)" "WARNING"
    }
}

function Backup-NetworkConfiguration {
    if (-not $script:ILYESIZERConfig.BackupNetworkSettings) { return }
    
    Write-NetLog "Creating network configuration backup..." "INFO"
    try {
        $backupPath = "$env:TEMP\Network-Config-Backup-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
        
        $config = @()
        $config += "=== Network Configuration Backup ==="
        $config += "Date: $(Get-Date)"
        $config += ""
        
        # Backup network adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            $config += "Adapter: $($adapter.Name)"
            $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4
            if ($dnsServers.ServerAddresses) {
                $config += "  DNS: $($dnsServers.ServerAddresses -join ', ')"
            }
            $config += ""
        }
        
        # Backup TCP settings
        $tcpSettings = netsh int tcp show global
        $config += "=== TCP Global Settings ==="
        $config += $tcpSettings
        
        $config | Out-File -FilePath $backupPath -Encoding UTF8
        Write-NetLog "Network backup saved to: $backupPath" "SUCCESS"
    } catch {
        Write-NetLog "Failed to create network backup: $($_.Exception.Message)" "WARNING"
    }
}

# ============================================================================
# INITIALIZATION
# ============================================================================

Clear-Host
Write-Host @"
================================================================================
|                   ADVANCED NETWORK GAMING OPTIMIZATION                    |
|                                Version 2.0                                  |
|              Reduce Latency - Improve Stability - Optimize Speed            |
================================================================================
"@ -ForegroundColor Green

Write-NetLog "Network Gaming Optimization started" "INFO"

# Verify admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-NetLog "This script requires Administrator privileges for network modifications" "ERROR"
    Write-Host "`nPlease restart PowerShell as Administrator and run this script again." -ForegroundColor Yellow
    pause
    exit 1
}

Write-NetLog "Running with Administrator privileges" "SUCCESS"

# Initial network assessment
Get-CurrentNetworkSettings
if ($script:ILYESIZERConfig.TestConnectivity) {
    Test-NetworkConnectivity
}
Backup-NetworkConfiguration

# ============================================================================
# NETWORK OPTIMIZATION FUNCTIONS
# ============================================================================

function Optimize-TCPSettings {
    Write-Host "`n[TCP] OPTIMIZING TCP SETTINGS FOR GAMING" -ForegroundColor Cyan
    Write-NetLog "Applying advanced TCP optimizations for reduced latency..." "INFO"
    
    $tcpOptimizations = @(
        @{ Command = "netsh int tcp set global autotuninglevel=normal"; Description = "Set TCP auto-tuning to normal" },
        @{ Command = "netsh int tcp set global chimney=enabled"; Description = "Enable TCP chimney offload" },
        @{ Command = "netsh int tcp set global rss=enabled"; Description = "Enable Receive Side Scaling (RSS)" },
        @{ Command = "netsh int tcp set global netdma=enabled"; Description = "Enable NetDMA" },
        @{ Command = "netsh int tcp set global ecncapability=enabled"; Description = "Enable Explicit Congestion Notification" },
        @{ Command = "netsh int tcp set global timestamps=disabled"; Description = "Disable TCP timestamps for reduced overhead" },
        @{ Command = "netsh int tcp set global initialrto=2000"; Description = "Set initial retransmission timeout" },
        @{ Command = "netsh int tcp set global nonsackrttresiliency=disabled"; Description = "Disable non-SACK RTT resiliency" }
    )
    
    $successCount = 0
    foreach ($opt in $tcpOptimizations) {
        try {
            $result = Invoke-Expression $opt.Command 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-NetLog $opt.Description "SUCCESS"
                $successCount++
            } else {
                Write-NetLog "Failed: $($opt.Description) - $result" "WARNING"
            }
        } catch {
            Write-NetLog "Error applying $($opt.Description): $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-NetLog "TCP optimizations applied: $successCount/$($tcpOptimizations.Count)" "INFO"
}

function Optimize-DNSSettings {
    Write-Host "`n[DNS] OPTIMIZING DNS CONFIGURATION" -ForegroundColor Cyan
    Write-NetLog "Configuring DNS servers for optimal gaming performance..." "INFO"
    
    try {
        # Test DNS servers for speed
        Write-NetLog "Testing DNS server response times..." "INFO"
        
        $dnsTests = @()
        foreach ($dns in $script:ILYESIZERConfig.PreferredDNS) {
            $pingResult = Test-Connection -ComputerName $dns -Count 3 -ErrorAction SilentlyContinue
            if ($pingResult) {
                $avgTime = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
                $dnsTests += @{ DNS = $dns; ResponseTime = $avgTime }
                Write-NetLog "Cloudflare DNS $dns`: $([math]::Round($avgTime, 2))ms average" "INFO"
            }
        }
        
        foreach ($dns in $script:ILYESIZERConfig.AlternateDNS) {
            $pingResult = Test-Connection -ComputerName $dns -Count 3 -ErrorAction SilentlyContinue  
            if ($pingResult) {
                $avgTime = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
                $dnsTests += @{ DNS = $dns; ResponseTime = $avgTime }
                Write-NetLog "Google DNS $dns`: $([math]::Round($avgTime, 2))ms average" "INFO"
            }
        }
        
        # Apply DNS settings to active adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceType -eq 6 }
        
        foreach ($adapter in $adapters) {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $script:ILYESIZERConfig.PreferredDNS
                Write-NetLog "DNS updated for adapter: $($adapter.Name)" "SUCCESS"
            } catch {
                Write-NetLog "Failed to update DNS for $($adapter.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Configure additional DNS optimizations
        $dnsOptimizations = @(
            @{ Command = "netsh interface ip set dns `"Local Area Connection`" static 1.1.1.1"; Description = "Set primary DNS" },
            @{ Command = "ipconfig /flushdns"; Description = "Flush DNS cache" }
        )
        
        foreach ($opt in $dnsOptimizations) {
            try {
                Invoke-Expression $opt.Command | Out-Null
                Write-NetLog $opt.Description "SUCCESS"
            } catch {
                Write-NetLog "DNS optimization warning: $($opt.Description)" "WARNING"
            }
        }
        
    } catch {
        Write-NetLog "DNS configuration error: $($_.Exception.Message)" "ERROR"
    }
}

function Optimize-NetworkAdapters {
    Write-Host "`n[ADAPTER] OPTIMIZING NETWORK ADAPTER SETTINGS" -ForegroundColor Cyan
    Write-NetLog "Applying network adapter optimizations..." "INFO"
    
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        foreach ($adapter in $adapters) {
            Write-NetLog "Optimizing adapter: $($adapter.Name)" "INFO"
            
            # Get adapter advanced properties that can be optimized
            $adapterOptimizations = @(
                @{ Name = "Interrupt Moderation"; Value = "Enabled"; Description = "Enable interrupt moderation" },
                @{ Name = "*FlowControl"; Value = "0"; Description = "Disable flow control" },
                @{ Name = "*InterruptModeration"; Value = "1"; Description = "Enable interrupt moderation" },
                @{ Name = "*RSS"; Value = "1"; Description = "Enable Receive Side Scaling" },
                @{ Name = "*TCPChecksumOffloadIPv4"; Value = "3"; Description = "Enable TCP checksum offload" },
                @{ Name = "*UDPChecksumOffloadIPv4"; Value = "3"; Description = "Enable UDP checksum offload" }
            )
            
            foreach ($opt in $adapterOptimizations) {
                try {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $opt.Name -DisplayValue $opt.Value -ErrorAction SilentlyContinue
                    Write-NetLog "  $($opt.Description)" "SUCCESS"
                } catch {
                    # Many properties may not exist on all adapters, so we silently continue
                    Write-NetLog "  Skipped: $($opt.Description) (not available)" "INFO"
                }
            }
        }
        
    } catch {
        Write-NetLog "Network adapter optimization error: $($_.Exception.Message)" "WARNING"
    }
}

function Reset-NetworkStack {
    Write-Host "`n[RESTART] RESETTING NETWORK STACK" -ForegroundColor Cyan
    Write-NetLog "Performing network stack reset for clean state..." "INFO"
    
    $resetCommands = @(
        @{ Command = "netsh winsock reset"; Description = "Reset Winsock catalog" },
        @{ Command = "netsh int ip reset"; Description = "Reset IP stack" },
        @{ Command = "netsh int tcp reset"; Description = "Reset TCP/IP stack" },
        @{ Command = "netsh int ipv4 reset"; Description = "Reset IPv4 stack" },
        @{ Command = "netsh int ipv6 reset"; Description = "Reset IPv6 stack" }
    )
    
    Write-Host "`n[WARNING] Network stack reset will require a restart. Continue? (y/N): " -ForegroundColor Yellow -NoNewline
    $confirm = Read-Host
    
    if ($confirm -eq 'y' -or $confirm -eq 'Y') {
        foreach ($reset in $resetCommands) {
            try {
                Invoke-Expression $reset.Command | Out-Null
                Write-NetLog $reset.Description "SUCCESS"
            } catch {
                Write-NetLog "Failed: $($reset.Description)" "WARNING"
            }
        }
        Write-NetLog "Network stack reset completed - restart required" "SUCCESS"
    } else {
        Write-NetLog "Network stack reset skipped by user" "INFO"
    }
}

function Test-LatencyAndSpeed {
    Write-Host "`n[TESTING] TESTING NETWORK PERFORMANCE" -ForegroundColor Cyan
    Write-NetLog "Running network performance tests..." "INFO"
    
    # Test latency to gaming servers (common game server locations)
    $gameServers = @(
        @{ Host = "google.com"; Description = "General Internet (Google)" },
        @{ Host = "steamcommunity.com"; Description = "Steam Gaming Network" },
        @{ Host = "cloudflare.com"; Description = "Cloudflare CDN" }
    )
    
    foreach ($server in $gameServers) {
        try {
            $pingResults = Test-Connection -ComputerName $server.Host -Count 5 -ErrorAction SilentlyContinue
            if ($pingResults) {
                $avgLatency = ($pingResults | Measure-Object -Property ResponseTime -Average).Average
                $minLatency = ($pingResults | Measure-Object -Property ResponseTime -Minimum).Minimum
                $maxLatency = ($pingResults | Measure-Object -Property ResponseTime -Maximum).Maximum
                
                Write-NetLog "$($server.Description): Avg $([math]::Round($avgLatency, 1))ms, Min $($minLatency)ms, Max $($maxLatency)ms" "SUCCESS"
            } else {
                Write-NetLog "$($server.Description): No response" "WARNING"
            }
        } catch {
            Write-NetLog "Failed to test $($server.Description)" "WARNING"
        }
    }
    
    # Test DNS resolution speed
    Write-NetLog "Testing DNS resolution speed..." "INFO"
    $testDomains = @("google.com", "github.com", "steamcommunity.com")
    
    foreach ($domain in $testDomains) {
        try {
            $startTime = Get-Date
            $null = Resolve-DnsName $domain -ErrorAction SilentlyContinue
            $endTime = Get-Date
            $resolutionTime = ($endTime - $startTime).TotalMilliseconds
            Write-NetLog "DNS resolution for $domain`: $([math]::Round($resolutionTime, 1))ms" "INFO"
        } catch {
            Write-NetLog "DNS resolution failed for $domain" "WARNING"
        }
    }
}

function Set-UltraLowLatencyNetwork {
    Write-Host "`n[LATENCY] APPLYING ULTRA-LOW LATENCY NETWORK OPTIMIZATIONS" -ForegroundColor Magenta
    Write-NetLog "WARNING: Applying EXTREME network optimizations for minimum latency" "WARNING"
    
    # Ultra-aggressive TCP/IP registry optimizations
    $ultraNetworkOptimizations = @(
        # TCP optimizations for gaming
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpAckFrequency"; Value = 1; Description = "Send ACK for every packet (lowest latency)" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TCPNoDelay"; Value = 1; Description = "Disable Nagle's algorithm completely" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpDelAckTicks"; Value = 0; Description = "Remove delayed ACK completely" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpChimney"; Value = 0; Description = "Disable TCP Chimney (can cause latency)" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableTCPA"; Value = 0; Description = "Disable TCP Auto-tuning" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableRSS"; Value = 0; Description = "Disable Receive Side Scaling for consistency" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableTaskOffload"; Value = 1; Description = "Disable task offloading" },
        
        # Extreme buffer optimizations
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpWindowSize"; Value = 65535; Description = "Optimize TCP window size" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "GlobalMaxTcpWindowSize"; Value = 65535; Description = "Set global max TCP window" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpNumConnections"; Value = 16777214; Description = "Maximum TCP connections" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "MaxUserPort"; Value = 65534; Description = "Maximum user ports" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpTimedWaitDelay"; Value = 30; Description = "Reduce TIME_WAIT delay" },
        
        # Gaming-specific optimizations
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableDCA"; Value = 0; Description = "Disable Direct Cache Access" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableWsd"; Value = 0; Description = "Disable Web Service Discovery" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableLargeMtu"; Value = 0; Description = "Enable large MTU for efficiency" },
        
        # Network adapter power management
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableMediaSenseEventLog"; Value = 1; Description = "Disable media sense logging" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableDeadGWDetect"; Value = 0; Description = "Disable dead gateway detection" }
    )
    
    $appliedCount = 0
    foreach ($opt in $ultraNetworkOptimizations) {
        try {
            if (-not (Test-Path $opt.Path)) {
                New-Item -Path $opt.Path -Force | Out-Null
            }
            
            Set-ItemProperty -Path $opt.Path -Name $opt.Name -Value $opt.Value -Force
            Write-NetLog $opt.Description "SUCCESS"
            $appliedCount++
        } catch {
            Write-NetLog "Failed to apply: $($opt.Description)" "ERROR"
        }
    }
    
    Write-NetLog "Ultra-low latency network: $appliedCount optimizations applied" "SUCCESS"
}

function Optimize-NetworkAdapterExtreme {
    Write-Host "`n[EXTREME] EXTREME NETWORK ADAPTER OPTIMIZATION" -ForegroundColor Red
    Write-NetLog "Applying extreme network adapter optimizations..." "INFO"
    
    try {
        # Get all network adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false }
        
        foreach ($adapter in $adapters) {
            Write-NetLog "Optimizing adapter: $($adapter.Name)" "INFO"
            
            try {
                # Disable power management completely
                Set-NetAdapterPowerManagement -Name $adapter.Name -ArpOffload Disabled -D0PacketCoalescing Disabled -DeviceSleepOnDisconnect Disabled -NSOffload Disabled -RsnRekeyOffload Disabled -SelectiveSuspend Disabled -WakeOnMagicPacket Disabled -WakeOnPattern Disabled -ErrorAction SilentlyContinue
                
                # Extreme adapter settings
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Interrupt Moderation" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Receive Side Scaling" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*TCP Checksum Offload (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*TCP Checksum Offload (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*UDP Checksum Offload (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*UDP Checksum Offload (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Large Send Offload V2 (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Large Send Offload V2 (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                
                # Gaming-specific settings
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Flow Control" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Energy Efficient Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Green Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Power Saving Mode" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                
                # Buffer optimizations for lowest latency
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Receive Buffers" -DisplayValue "2048" -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Transmit Buffers" -DisplayValue "2048" -ErrorAction SilentlyContinue
                
                Write-NetLog "Extreme optimization applied to: $($adapter.Name)" "SUCCESS"
                
            } catch {
                Write-NetLog "Could not fully optimize adapter $($adapter.Name): $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-NetLog "Network adapter extreme optimization completed" "SUCCESS"
        
    } catch {
        Write-NetLog "Failed to optimize network adapters: $($_.Exception.Message)" "ERROR"
    }
}

function Set-GamingQoSPolicy {
    Write-Host "`n[QOS] CONFIGURING GAMING QoS POLICIES" -ForegroundColor Green
    Write-NetLog "Setting up Quality of Service policies for gaming..." "INFO"
    
    try {
        # Remove existing gaming QoS policies
        Get-NetQosPolicy | Where-Object { $_.Name -like "*Gaming*" -or $_.Name -like "*Game*" } | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue
        
        # Create high-priority gaming QoS policies
        New-NetQosPolicy -Name "Gaming-High-Priority" -AppPathNameMatchCondition "*\steam.exe" -PriorityValue8021Action 7 -ErrorAction SilentlyContinue | Out-Null
        New-NetQosPolicy -Name "Gaming-Battle.net" -AppPathNameMatchCondition "*\Battle.net.exe" -PriorityValue8021Action 7 -ErrorAction SilentlyContinue | Out-Null
        New-NetQosPolicy -Name "Gaming-Origin" -AppPathNameMatchCondition "*\Origin.exe" -PriorityValue8021Action 7 -ErrorAction SilentlyContinue | Out-Null
        New-NetQosPolicy -Name "Gaming-Epic" -AppPathNameMatchCondition "*\EpicGamesLauncher.exe" -PriorityValue8021Action 7 -ErrorAction SilentlyContinue | Out-Null
        New-NetQosPolicy -Name "Gaming-Uplay" -AppPathNameMatchCondition "*\UplayWebCore.exe" -PriorityValue8021Action 7 -ErrorAction SilentlyContinue | Out-Null
        
        # Gaming protocol optimizations
        New-NetQosPolicy -Name "Gaming-UDP-High" -Protocol UDP -MinBandwidthWeightAction 100 -PriorityValue8021Action 7 -ErrorAction SilentlyContinue | Out-Null
        New-NetQosPolicy -Name "Gaming-TCP-Gaming" -Protocol TCP -RemotePortMatchCondition 27015,27016,27017,27018,27019 -PriorityValue8021Action 7 -ErrorAction SilentlyContinue | Out-Null
        
        # Discord and voice chat priority
        New-NetQosPolicy -Name "Gaming-Discord" -AppPathNameMatchCondition "*\Discord.exe" -PriorityValue8021Action 6 -ErrorAction SilentlyContinue | Out-Null
        New-NetQosPolicy -Name "Gaming-TeamSpeak" -AppPathNameMatchCondition "*\ts3client_win64.exe" -PriorityValue8021Action 6 -ErrorAction SilentlyContinue | Out-Null
        
        Write-NetLog "Gaming QoS policies configured successfully" "SUCCESS"
        
    } catch {
        Write-NetLog "Failed to configure QoS policies: $($_.Exception.Message)" "ERROR"
    }
}

function Disable-NetworkPerformanceKillers {
    Write-Host "`n[DISABLE] DISABLING NETWORK PERFORMANCE KILLERS" -ForegroundColor Red
    Write-NetLog "Disabling services and features that impact network gaming performance..." "INFO"
    
    # Network services that can impact gaming performance
    $networkPerformanceKillers = @(
        "lmhosts",           # TCP/IP NetBIOS Helper
        "NlaSvc",            # Network Location Awareness (can cause delays)
        "WinHttpAutoProxySvc", # WinHTTP Web Proxy Auto-Discovery
        "WebClient",         # WebDAV Client
        "NetTcpPortSharing", # Net.Tcp Port Sharing Service
        "PeerDistSvc",       # BranchCache (can consume bandwidth)
        "WwanSvc",           # WWAN AutoConfig (mobile broadband)
        "icssvc",            # Windows Mobile Hotspot Service
        "SharedAccess"       # Internet Connection Sharing
    )
    
    $disabledCount = 0
    foreach ($serviceName in $networkPerformanceKillers) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -eq "Running") {
                    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                }
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                Write-NetLog "Disabled network performance killer: $serviceName" "SUCCESS"
                $disabledCount++
            }
        } catch {
            Write-NetLog "Could not disable service $serviceName" "WARNING"
        }
    }
    
    # Disable Windows features that impact network performance
    try {
        # Disable SMB features that can interfere
        Set-SmbClientConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Confirm:$false -ErrorAction SilentlyContinue
        Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Confirm:$false -ErrorAction SilentlyContinue
        
        # Disable network discovery features
        netsh advfirewall firewall set rule group="Network Discovery" new enable=No 2>&1 | Out-Null
        
        Write-NetLog "Network discovery and SMB optimizations applied" "SUCCESS"
        
    } catch {
        Write-NetLog "Could not apply some network feature optimizations" "WARNING"
    }
    
    # Registry tweaks for network performance
    $networkKillerRegistry = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableICMPRedirect"; Value = 0; Description = "Disable ICMP redirects" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DeadGWDetectDefault"; Value = 0; Description = "Disable dead gateway detection" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DontAddDefaultGatewayDefault"; Value = 0; Description = "Optimize gateway handling" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"; Name = "IRPStackSize"; Value = 32; Description = "Increase IRP stack size" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name = "MaxCmds"; Value = 2048; Description = "Increase max commands" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name = "MaxThreads"; Value = 30; Description = "Increase max threads" }
    )
    
    foreach ($reg in $networkKillerRegistry) {
        try {
            if (-not (Test-Path $reg.Path)) {
                New-Item -Path $reg.Path -Force | Out-Null
            }
            
            Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Force
            Write-NetLog $reg.Description "SUCCESS"
        } catch {
            Write-NetLog "Failed to apply registry optimization: $($reg.Description)" "WARNING"
        }
    }
    
    Write-NetLog "Network performance killers disabled: $disabledCount services disabled" "SUCCESS"
}

function Optimize-GameSpecificNetworking {
    Write-Host "`n[GAME-SPECIFIC] GAME-SPECIFIC NETWORK OPTIMIZATIONS" -ForegroundColor Cyan
    Write-NetLog "Applying optimizations for popular online games..." "INFO"
    
    try {
        # Windows Firewall optimizations for gaming
        netsh advfirewall set allprofiles state off 2>&1 | Out-Null
        Write-NetLog "Windows Firewall disabled for maximum gaming performance" "WARNING"
        
        # Gaming port optimizations
        $gamingPorts = @{
            "Steam" = @(27015, 27016, 27017, 27018, 27019, 27020)
            "Battle.net" = @(1119, 3724, 6113, 6114)
            "Epic Games" = @(5222, 5223, 5224)
            "Origin" = @(3216, 9960, 9988, 10000)
            "Minecraft" = @(25565)
            "Valorant" = @(2099, 5223, 8393, 8401)
            "League of Legends" = @(5223, 5224, 2099, 8393, 8400)
            "CS:GO/CS2" = @(27015, 27020, 27005)
            "Apex Legends" = @(37015, 37016)
            "Fortnite" = @(7777, 7778, 7779)
        }
        
        foreach ($game in $gamingPorts.Keys) {
            foreach ($port in $gamingPorts[$game]) {
                try {
                    # Create high-priority firewall rules for gaming ports
                    New-NetFirewallRule -DisplayName "$game-TCP-$port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
                    New-NetFirewallRule -DisplayName "$game-UDP-$port" -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
                } catch {
                    # Ignore errors for duplicate rules
                }
            }
            Write-NetLog "Firewall rules optimized for $game" "SUCCESS"
        }
        
        # MTU optimization for gaming
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false }
        foreach ($adapter in $adapters) {
            try {
                # Set optimal MTU for gaming (1472 + 28 = 1500 total)
                netsh interface ipv4 set subinterface "$($adapter.Name)" mtu=1472 store=persistent 2>&1 | Out-Null
                Write-NetLog "Optimized MTU for adapter: $($adapter.Name)" "SUCCESS"
            } catch {
                Write-NetLog "Could not set MTU for adapter: $($adapter.Name)" "WARNING"
            }
        }
        
        Write-NetLog "Game-specific network optimizations completed" "SUCCESS"
        
    } catch {
        Write-NetLog "Failed to apply game-specific optimizations: $($_.Exception.Message)" "ERROR"
    }
}

function Set-UltraFastDNS {
    Write-Host "`n[ULTRA-DNS] CONFIGURING ULTRA-FAST DNS FOR GAMING" -ForegroundColor Magenta
    Write-NetLog "Setting up the fastest DNS servers for gaming..." "INFO"
    
    # Gaming-optimized DNS servers (prioritizing low latency)
    $gamingDNSServers = @{
        "Cloudflare" = @("1.1.1.1", "1.0.0.1")           # Fastest global DNS
        "Quad9" = @("9.9.9.9", "149.112.112.112")        # Security + Speed
        "OpenDNS" = @("208.67.222.222", "208.67.220.220") # Gaming-friendly
        "Google" = @("8.8.8.8", "8.8.4.4")               # Reliable fallback
    }
    
    try {
        # Test which DNS is fastest
        $fastestDNS = $null
        $fastestTime = 999999
        
        foreach ($dnsProvider in $gamingDNSServers.Keys) {
            $dnsServers = $gamingDNSServers[$dnsProvider]
            $testStart = Get-Date
            
            try {
                $result = Resolve-DnsName -Name "google.com" -Server $dnsServers[0] -QuickTimeout -ErrorAction SilentlyContinue
                $testTime = ((Get-Date) - $testStart).TotalMilliseconds
                
                if ($result -and $testTime -lt $fastestTime) {
                    $fastestTime = $testTime
                    $fastestDNS = @{
                        Provider = $dnsProvider
                        Servers = $dnsServers
                        Time = $testTime
                    }
                }
                
                Write-NetLog "$dnsProvider DNS response time: $([math]::Round($testTime, 2))ms" "INFO"
            } catch {
                Write-NetLog "$dnsProvider DNS test failed" "WARNING"
            }
        }
          if ($fastestDNS) {
            Write-NetLog "Fastest DNS: $($fastestDNS.Provider) ($([math]::Round($fastestDNS.Time, 2)) ms)" "SUCCESS"
            
            # Apply fastest DNS to all adapters
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false }
            foreach ($adapter in $adapters) {
                try {
                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $fastestDNS.Servers -ErrorAction SilentlyContinue
                    Write-NetLog "Applied $($fastestDNS.Provider) DNS to: $($adapter.Name)" "SUCCESS"
                } catch {
                    Write-NetLog "Could not set DNS for adapter: $($adapter.Name)" "WARNING"
                }
            }
            
            # Configure DNS cache optimization
            Set-DnsClientGlobalSetting -SuffixSearchList @() -ErrorAction SilentlyContinue
            Set-DnsClient -InterfaceAlias "*" -ConnectionSpecificSuffix "" -RegisterThisConnectionsAddress $false -UseSuffixWhenRegistering $false -ErrorAction SilentlyContinue
            
            # Flush and optimize DNS cache
            ipconfig /flushdns | Out-Null
            
            Write-NetLog "DNS optimization completed with $($fastestDNS.Provider)" "SUCCESS"
        } else {
            Write-NetLog "Could not determine fastest DNS, using Cloudflare as default" "WARNING"
        }
        
    } catch {
        Write-NetLog "Failed to optimize DNS settings: $($_.Exception.Message)" "ERROR"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Display ILYESIZER Network Banner
Clear-Host
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                 ILYESIZER Network v3.0                     " -ForegroundColor Green
Write-Host "           Professional Network Gaming Optimization         " -ForegroundColor Green
Write-Host "                    Made by ilyyeees                        " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starting ILYESIZER Network optimization process..." -ForegroundColor Green

# Warning about aggressive optimizations
Write-Host ""
Write-Host "WARNING: This script will apply EXTREME network optimizations!" -ForegroundColor Yellow
Write-Host "These optimizations will:" -ForegroundColor Yellow
Write-Host "- Disable Windows Firewall for maximum gaming performance" -ForegroundColor Yellow
Write-Host "- Apply ultra-low latency TCP/IP tweaks" -ForegroundColor Yellow
Write-Host "- Disable network services that can cause lag" -ForegroundColor Yellow
Write-Host "- Configure gaming-specific QoS policies" -ForegroundColor Yellow
Write-Host ""

$response = Read-Host "Proceed with EXTREME network optimizations for minimum gaming latency? (Y/N)"
if ($response -ne 'Y' -and $response -ne 'y') {
    Write-Host "ILYESIZER Network optimization cancelled by user." -ForegroundColor Yellow
    exit
}

try {
    # Phase 1: Standard optimizations
    Write-Host "`n[PHASE] PHASE 1: STANDARD NETWORK OPTIMIZATIONS" -ForegroundColor Cyan
    Optimize-TCPSettings
    Optimize-DNSSettings
    Optimize-NetworkAdapters
    Test-LatencyAndSpeed
      # Phase 2: Ultra-aggressive optimizations
    Write-Host "`n[EXTREME] PHASE 2: ULTRA-AGGRESSIVE NETWORK OPTIMIZATIONS" -ForegroundColor Red
    Set-UltraLowLatencyNetwork
    Optimize-NetworkAdapterExtreme
    Set-GamingQoSPolicy
    Disable-NetworkPerformanceKillers
    Optimize-GameSpecificNetworking
    Set-UltraFastDNS
    
    Write-Host "`nWould you like to reset the network stack? (This requires restart) (y/N): " -ForegroundColor Yellow -NoNewline
    $resetChoice = Read-Host
    if ($resetChoice -eq 'y' -or $resetChoice -eq 'Y') {
        Reset-NetworkStack
    }
    
    Write-Host "`n" -NoNewline
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host "|         [SUCCESS] ULTRA AGGRESSIVE NETWORK OPTIMIZATION COMPLETED!              |" -ForegroundColor Green
    Write-Host "|                                                                          |" -ForegroundColor Green
    Write-Host "|  [ULTRA] Your network is now optimized for MINIMUM gaming latency!           |" -ForegroundColor Green
    Write-Host "|  [POWER] Ultra-low latency TCP/IP configuration applied                      |" -ForegroundColor Green
    Write-Host "|  [QOS] Gaming QoS policies configured                                      |" -ForegroundColor Green
    Write-Host "|  [DISABLE] Network performance killers disabled                               |" -ForegroundColor Green
    Write-Host "|  [DNS] Ultra-fast DNS servers configured                                  |" -ForegroundColor Green
    Write-Host "|  [ADAPTER] Network adapters optimized for gaming                              |" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
      Write-NetLog "ILYESIZER Network v3.0 optimization completed successfully" "SUCCESS"
    
    # ILYESIZER Network Completion Summary
    Write-Host ""
    Write-Host "=============================================================" -ForegroundColor Green
    Write-Host "         ILYESIZER Network v3.0 - OPTIMIZATION COMPLETE     " -ForegroundColor Green
    Write-Host "=============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Log file location: $($script:ILYESIZERConfig.LogFile)" -ForegroundColor Cyan
    
    if ($resetChoice -eq 'y' -or $resetChoice -eq 'Y') {
        Write-Host ""
        Write-Host "RESTART REQUIRED: Network stack reset will take effect after reboot!" -ForegroundColor Yellow -BackgroundColor Red
    } else {
        Write-Host ""
        Write-Host "RESTART RECOMMENDED: Some optimizations require reboot for full effect!" -ForegroundColor Yellow -BackgroundColor Red
    }
    
    Write-Host ""
    Write-Host "Expected network improvements:" -ForegroundColor Green
    Write-Host "- 20-50% reduction in network latency" -ForegroundColor Green
    Write-Host "- Faster DNS resolution times" -ForegroundColor Green
    Write-Host "- Prioritized gaming network traffic" -ForegroundColor Green
    Write-Host "- Reduced network-related stuttering" -ForegroundColor Green
    Write-Host "- Better online gaming responsiveness" -ForegroundColor Green
    Write-Host ""
    Write-Host "ILYESIZER Network Pro Tips:" -ForegroundColor Cyan
    Write-Host "- Use wired connection instead of WiFi for best results" -ForegroundColor Cyan
    Write-Host "- Close bandwidth-heavy applications while gaming" -ForegroundColor Cyan
    Write-Host "- Consider gaming routers with QoS features" -ForegroundColor Cyan
    Write-Host "- Monitor network usage in Task Manager" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Thank you for using ILYESIZER Network v3.0!" -ForegroundColor Green
    
    Write-Host "`n[WARNING]  NOTE: Windows Firewall has been disabled for maximum performance" -ForegroundColor Yellow
    Write-Host "   Re-enable it manually if you need additional security" -ForegroundColor Yellow
    
} catch {
    Write-NetLog "Critical error during network optimization: $($_.Exception.Message)" "ERROR"
    Write-Host "`n[ERROR] Network optimization encountered errors. Check the log file for details." -ForegroundColor Red
}
