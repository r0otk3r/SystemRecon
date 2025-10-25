<#
Full Computer Enumeration Toolkit
---------------------------------
Comprehensive system, security, network, and forensic data collection for Windows systems.

Usage: Run as Administrator for full functionality
Output: .\Computer_Enumeration_<TIMESTAMP>\
#>

#Requires -Version 5.1

param(
    [string]$OutputPath = ".\Computer_Enumeration_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$QuickMode = $false,
    [switch]$IncludeMemoryDump = $false,
    [switch]$NetworkCapture = $false,
    [int]$EventLogDays = 30,
    [switch]$SkipHashes = $false
)

# Global Variables
$Script:StartTime = Get-Date
$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"

# Colors for output
$Host.UI.RawUI.ForegroundColor = "White"

# Logging Function
function Write-EnumerationLog {
    param([string]$Message, [string]$Type = "INFO", [string]$Color = "White")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    
    switch ($Type) {
        "ERROR" { $Color = "Red" }
        "SUCCESS" { $Color = "Green" }
        "WARNING" { $Color = "Yellow" }
        "INFO" { $Color = "Cyan" }
    }
    
    Write-Host $logEntry -ForegroundColor $Color
    Add-Content -Path "$OutputPath\enumeration.log" -Value $logEntry -ErrorAction SilentlyContinue
}

# Initialize Output Directory
function Initialize-OutputDirectory {
    Write-EnumerationLog "Initializing output directory: $OutputPath" -Type "INFO"
    
    try {
        if (!(Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        # Create subdirectories
        $subDirs = @(
            "System_Info", "Network", "Processes", "Services", "Users_Groups",
            "Event_Logs", "Registry", "Filesystem", "Security", "Applications",
            "Scheduled_Tasks", "WMI", "Performance", "Forensic", "Memory"
        )
        
        foreach ($dir in $subDirs) {
            $fullPath = Join-Path $OutputPath $dir
            if (!(Test-Path $fullPath)) {
                New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
            }
        }
        
        Write-EnumerationLog "Output directory initialized successfully" -Type "SUCCESS"
        return $true
    }
    catch {
        Write-EnumerationLog "Failed to initialize output directory: $($_.Exception.Message)" -Type "ERROR"
        return $false
    }
}

# Check Administrator Privileges
function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 1. Comprehensive System Information
function Get-SystemInformation {
    Write-EnumerationLog "Collecting comprehensive system information..." -Type "INFO"
    
    try {
        $sysInfo = @()
        
        # Computer System
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $sysInfo += [PSCustomObject]@{
            Category = "Computer System"
            Property = "Name"
            Value = $computerSystem.Name
        }
        $sysInfo += [PSCustomObject]@{
            Category = "Computer System"
            Property = "Manufacturer"
            Value = $computerSystem.Manufacturer
        }
        $sysInfo += [PSCustomObject]@{
            Category = "Computer System"
            Property = "Model"
            Value = $computerSystem.Model
        }
        $sysInfo += [PSCustomObject]@{
            Category = "Computer System"
            Property = "Total Physical Memory (GB)"
            Value = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
        }
        $sysInfo += [PSCustomObject]@{
            Category = "Computer System"
            Property = "Number of Processors"
            Value = $computerSystem.NumberOfProcessors
        }
        
        # Operating System
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $sysInfo += [PSCustomObject]@{
            Category = "Operating System"
            Property = "Caption"
            Value = $osInfo.Caption
        }
        $sysInfo += [PSCustomObject]@{
            Category = "Operating System"
            Property = "Version"
            Value = $osInfo.Version
        }
        $sysInfo += [PSCustomObject]@{
            Category = "Operating System"
            Property = "Build Number"
            Value = $osInfo.BuildNumber
        }
        $sysInfo += [PSCustomObject]@{
            Category = "Operating System"
            Property = "Install Date"
            Value = $osInfo.InstallDate
        }
        $sysInfo += [PSCustomObject]@{
            Category = "Operating System"
            Property = "Last Boot Time"
            Value = $osInfo.LastBootUpTime
        }
        
        # BIOS Information
        $biosInfo = Get-CimInstance -ClassName Win32_BIOS
        $sysInfo += [PSCustomObject]@{
            Category = "BIOS"
            Property = "Version"
            Value = $biosInfo.SMBIOSBIOSVersion
        }
        $sysInfo += [PSCustomObject]@{
            Category = "BIOS"
            Property = "Manufacturer"
            Value = $biosInfo.Manufacturer
        }
        $sysInfo += [PSCustomObject]@{
            Category = "BIOS"
            Property = "Release Date"
            Value = $biosInfo.ReleaseDate
        }
        
        # Processor Information
        $processors = Get-CimInstance -ClassName Win32_Processor
        foreach ($processor in $processors) {
            $sysInfo += [PSCustomObject]@{
                Category = "Processor"
                Property = "Name"
                Value = $processor.Name
            }
            $sysInfo += [PSCustomObject]@{
                Category = "Processor"
                Property = "Cores"
                Value = $processor.NumberOfCores
            }
            $sysInfo += [PSCustomObject]@{
                Category = "Processor"
                Property = "Logical Processors"
                Value = $processor.NumberOfLogicalProcessors
            }
            $sysInfo += [PSCustomObject]@{
                Category = "Processor"
                Property = "Max Clock Speed (GHz)"
                Value = [math]::Round($processor.MaxClockSpeed / 1000, 2)
            }
        }
        
        # Memory Information
        $memory = Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
        $sysInfo += [PSCustomObject]@{
            Category = "Memory"
            Property = "Total Physical Memory (GB)"
            Value = [math]::Round($memory.Sum / 1GB, 2)
        }
        $sysInfo += [PSCustomObject]@{
            Category = "Memory"
            Property = "Memory Modules"
            Value = $memory.Count
        }
        
        # Disk Information
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk
        foreach ($disk in $disks) {
            if ($disk.Size -gt 0) {
                $sysInfo += [PSCustomObject]@{
                    Category = "Disk"
                    Property = "Drive $($disk.DeviceID)"
                    Value = "Size: $([math]::Round($disk.Size/1GB,2))GB, Free: $([math]::Round($disk.FreeSpace/1GB,2))GB"
                }
            }
        }
        
        $sysInfo | Export-Csv -Path "$OutputPath\System_Info\System_Information.csv" -NoTypeInformation
        $sysInfo | Format-Table -AutoSize | Out-File -FilePath "$OutputPath\System_Info\System_Information.txt"
        
        Write-EnumerationLog "System information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting system information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 2. Detailed Hardware Inventory
function Get-HardwareInventory {
    Write-EnumerationLog "Collecting detailed hardware inventory..." -Type "INFO"
    
    try {
        # Network Adapters
        $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true }
        $networkAdapters | Select-Object Name, AdapterType, MACAddress, Speed | 
            Export-Csv -Path "$OutputPath\System_Info\Network_Adapters.csv" -NoTypeInformation
        
        # Graphics Cards
        $graphicsCards = Get-CimInstance -ClassName Win32_VideoController
        $graphicsCards | Select-Object Name, AdapterRAM, DriverVersion | 
            Export-Csv -Path "$OutputPath\System_Info\Graphics_Cards.csv" -NoTypeInformation
        
        # USB Devices
        $usbDevices = Get-CimInstance -ClassName Win32_USBHub
        $usbDevices | Select-Object Name, DeviceID, Status | 
            Export-Csv -Path "$OutputPath\System_Info\USB_Devices.csv" -NoTypeInformation
        
        # Printers
        $printers = Get-CimInstance -ClassName Win32_Printer
        $printers | Select-Object Name, DriverName, PortName, Default | 
            Export-Csv -Path "$OutputPath\System_Info\Printers.csv" -NoTypeInformation
        
        Write-EnumerationLog "Hardware inventory collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting hardware inventory: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 3. Comprehensive Network Information
function Get-NetworkInformation {
    Write-EnumerationLog "Collecting comprehensive network information..." -Type "INFO"
    
    try {
        # IP Configuration
        $ipConfig = Get-NetIPConfiguration -All
        $ipConfig | Export-Csv -Path "$OutputPath\Network\IP_Configuration.csv" -NoTypeInformation
        
        # Network Adapters Detailed
        $netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        $netAdapters | Export-Csv -Path "$OutputPath\Network\Network_Adapters_Detailed.csv" -NoTypeInformation
        
        # Listening Ports with Process Information
        $listeningPorts = Get-NetTCPConnection -State Listen | 
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{Name='ProcessName'; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
        
        $listeningPorts | Export-Csv -Path "$OutputPath\Network\Listening_Ports.csv" -NoTypeInformation
        
        # Active Connections
        $activeConnections = Get-NetTCPConnection -State Established | 
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{Name='ProcessName'; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
        
        $activeConnections | Export-Csv -Path "$OutputPath\Network\Active_Connections.csv" -NoTypeInformation
        
        # DNS Cache
        Get-DnsClientCache | Export-Csv -Path "$OutputPath\Network\DNS_Cache.csv" -NoTypeInformation
        
        # ARP Table
        Get-NetNeighbor | Where-Object { $_.State -eq 'Reachable' } | 
            Export-Csv -Path "$OutputPath\Network\ARP_Table.csv" -NoTypeInformation
        
        # Firewall Rules
        $firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' }
        $firewallRules | Select-Object DisplayName, Direction, Action, Profile | 
            Export-Csv -Path "$OutputPath\Network\Firewall_Rules.csv" -NoTypeInformation
        
        # Firewall Profiles
        Get-NetFirewallProfile | Export-Csv -Path "$OutputPath\Network\Firewall_Profiles.csv" -NoTypeInformation
        
        # Network Shares
        Get-SmbShare | Export-Csv -Path "$OutputPath\Network\Network_Shares.csv" -NoTypeInformation
        
        Write-EnumerationLog "Network information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting network information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 4. Process and Service Enumeration
function Get-ProcessServiceInformation {
    Write-EnumerationLog "Collecting process and service information..." -Type "INFO"
    
    try {
        # All Processes with Details
        $allProcesses = Get-Process | 
            Select-Object Id, ProcessName, CPU, 
                @{Name='WorkingSetMB'; Expression={[math]::Round($_.WorkingSet / 1MB, 2)}},
                @{Name='PrivateMemoryMB'; Expression={[math]::Round($_.PrivateMemorySize / 1MB, 2)}},
                @{Name='StartTime'; Expression={$_.StartTime}},
                Path, Company, FileVersion,
                @{Name='CommandLine'; Expression={
                    try { (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine }
                    catch { "N/A" }
                }}
        
        $allProcesses | Export-Csv -Path "$OutputPath\Processes\All_Processes.csv" -NoTypeInformation
        
        # Top Processes by CPU and Memory
        $allProcesses | Sort-Object CPU -Descending | Select-Object -First 25 | 
            Export-Csv -Path "$OutputPath\Processes\Top_CPU_Processes.csv" -NoTypeInformation
        
        $allProcesses | Sort-Object WorkingSetMB -Descending | Select-Object -First 25 | 
            Export-Csv -Path "$OutputPath\Processes\Top_Memory_Processes.csv" -NoTypeInformation
        
        # Services Information
        $services = Get-CimInstance -ClassName Win32_Service | 
            Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId, StartName,
            @{Name='ServiceType'; Expression={$_.ServiceType}},
            @{Name='Description'; Expression={$_.Description}}
        
        $services | Export-Csv -Path "$OutputPath\Services\All_Services.csv" -NoTypeInformation
        
        # Running Services
        $services | Where-Object { $_.State -eq 'Running' } | 
            Export-Csv -Path "$OutputPath\Services\Running_Services.csv" -NoTypeInformation
        
        # Service Dependencies
        foreach ($service in $services) {
            try {
                $serviceObj = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
                if ($serviceObj) {
                    $dependencies = $serviceObj.DependentServices | Select-Object -ExpandProperty Name
                    if ($dependencies) {
                        [PSCustomObject]@{
                            Service = $service.Name
                            DependentServices = ($dependencies -join ', ')
                        } | Export-Csv -Path "$OutputPath\Services\Service_Dependencies.csv" -Append -NoTypeInformation
                    }
                }
            }
            catch {
                # Continue with next service
            }
        }
        
        Write-EnumerationLog "Process and service information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting process/service information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 5. User and Group Information
function Get-UserGroupInformation {
    Write-EnumerationLog "Collecting user and group information..." -Type "INFO"
    
    try {
        # Local Users
        $localUsers = Get-LocalUser | 
            Select-Object Name, SID, Enabled, PasswordRequired, 
                @{Name='LastLogon'; Expression={$_.LastLogon}},
                Description
        
        $localUsers | Export-Csv -Path "$OutputPath\Users_Groups\Local_Users.csv" -NoTypeInformation
        
        # Local Groups
        $localGroups = Get-LocalGroup | 
            Select-Object Name, SID, Description
        
        $localGroups | Export-Csv -Path "$OutputPath\Users_Groups\Local_Groups.csv" -NoTypeInformation
        
        # Group Members
        foreach ($group in $localGroups) {
            try {
                $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
                if ($members) {
                    $members | 
                        Select-Object @{Name='Group'; Expression={$group.Name}}, Name, ObjectClass, SID |
                        Export-Csv -Path "$OutputPath\Users_Groups\Group_Members.csv" -Append -NoTypeInformation
                }
            }
            catch {
                # Continue with next group
            }
        }
        
        # Logged On Users
        try {
            quser 2>$null | Out-File -FilePath "$OutputPath\Users_Groups\LoggedOn_Users.txt"
        }
        catch {
            # Alternative method
            Get-CimInstance -ClassName Win32_LoggedOnUser | 
                ForEach-Object { 
                    $antecedent = $_.Antecedent
                    $dependent = $_.Dependent
                    "$($antecedent -replace '.*Name="([^"]+)".*','$1') logged on as $($dependent -replace '.*Name="([^"]+)".*','$1')"
                } | Out-File -FilePath "$OutputPath\Users_Groups\LoggedOn_Users.txt"
        }
        
        # User Profiles
        $userProfiles = Get-CimInstance -ClassName Win32_UserProfile | 
            Select-Object SID, LocalPath, Loaded, LastUseTime, Special
        
        $userProfiles | Export-Csv -Path "$OutputPath\Users_Groups\User_Profiles.csv" -NoTypeInformation
        
        Write-EnumerationLog "User and group information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting user/group information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 6. Event Log Collection
function Get-EventLogs {
    Write-EnumerationLog "Collecting event logs..." -Type "INFO"
    
    try {
        $logNames = @("System", "Application", "Security", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational")
        $startTime = (Get-Date).AddDays(-$EventLogDays)
        
        foreach ($logName in $logNames) {
            try {
                Write-EnumerationLog "Processing event log: $logName" -Type "INFO"
                
                $events = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue -MaxEvents 1000 | 
                    Where-Object { $_.TimeCreated -ge $startTime } |
                    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, UserId, Message
                
                if ($events) {
                    $safeLogName = $logName -replace '[\\/]', '_'
                    $events | Export-Csv -Path "$OutputPath\Event_Logs\$safeLogName.csv" -NoTypeInformation
                }
            }
            catch {
                Write-EnumerationLog "Error processing event log $logName : $($_.Exception.Message)" -Type "WARNING"
            }
        }
        
        # Critical Security Events
        $securityEvents = @(
            4624,  # Successful logon
            4625,  # Failed logon
            4648,  # Logon with explicit credentials
            4672,  # Special privileges assigned
            4688,  # Process creation
            4697,  # Service installation
            4698,  # Scheduled task creation
            4702,  # Scheduled task updated
            4719,  # System audit policy changed
            4720,  # User account created
            4732,  # User added to enabled security group
            4738,  # User account changed
            4740,  # User account locked out
            4776,  # Domain controller failed to validate credentials
            5140,  # Network share accessed
            4649,  # Replay attack detected
            4768,  # Kerberos TGT requested
            4769   # Kerberos service ticket requested
        )
        
        $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[TimeCreated[timediff(@SystemTime) &lt;= 86400000 * $EventLogDays]] and 
        (EventID=$(($securityEvents -join ') or (EventID=')))]
    </Select>
  </Query>
</QueryList>
"@
        
        try {
            $criticalEvents = Get-WinEvent -FilterXml $filterXml -MaxEvents 2000 -ErrorAction SilentlyContinue
            if ($criticalEvents) {
                $criticalEvents | 
                    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, UserId, Message |
                    Export-Csv -Path "$OutputPath\Event_Logs\Critical_Security_Events.csv" -NoTypeInformation
            }
        }
        catch {
            Write-EnumerationLog "Error collecting critical security events: $($_.Exception.Message)" -Type "WARNING"
        }
        
        Write-EnumerationLog "Event logs collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting event logs: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 7. Registry Analysis
function Get-RegistryInformation {
    Write-EnumerationLog "Collecting registry information..." -Type "INFO"
    
    try {
        # Autorun Locations
        $autorunPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SYSTEM\CurrentControlSet\Services"
        )
        
        $autoruns = @()
        
        foreach ($path in $autorunPaths) {
            if (Test-Path $path) {
                try {
                    $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                    foreach ($item in $items.PSObject.Properties) {
                        if ($item.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                            $autoruns += [PSCustomObject]@{
                                Path = $path
                                Name = $item.Name
                                Value = $item.Value
                                Type = "Autorun"
                            }
                        }
                    }
                }
                catch {
                    # Continue with next path
                }
            }
        }
        
        $autoruns | Export-Csv -Path "$OutputPath\Registry\Autoruns.csv" -NoTypeInformation
        
        # Installed Software from Registry
        $softwarePaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $installedSoftware = foreach ($path in $softwarePaths) {
            Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString
        }
        
        $installedSoftware | Sort-Object DisplayName | 
            Export-Csv -Path "$OutputPath\Registry\Installed_Software.csv" -NoTypeInformation
        
        Write-EnumerationLog "Registry information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting registry information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 8. File System Analysis
function Get-FileSystemInformation {
    Write-EnumerationLog "Collecting file system information..." -Type "INFO"
    
    try {
        # Recent Files
        $recentFiles = Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue |
            Select-Object Name, LastWriteTime, Length
        
        if ($recentFiles) {
            $recentFiles | Export-Csv -Path "$OutputPath\Filesystem\Recent_Files.csv" -NoTypeInformation
        }
        
        # Startup Items
        $startupLocations = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        
        $startupItems = foreach ($location in $startupLocations) {
            if (Test-Path $location) {
                Get-ChildItem $location -Recurse -ErrorAction SilentlyContinue |
                    Select-Object @{Name='Location'; Expression={$location}}, Name, FullName, LastWriteTime
            }
        }
        
        if ($startupItems) {
            $startupItems | Export-Csv -Path "$OutputPath\Filesystem\Startup_Items.csv" -NoTypeInformation
        }
        
        # Suspicious File Locations
        $suspiciousLocations = @(
            "$env:TEMP",
            "$env:LOCALAPPDATA\Temp",
            "C:\Windows\Temp",
            "C:\Windows\Prefetch"
        )
        
        $suspiciousFiles = foreach ($location in $suspiciousLocations) {
            if (Test-Path $location) {
                Get-ChildItem $location -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -match '\.(exe|dll|ps1|bat|scr|vbs|js)$' } |
                    Select-Object @{Name='Location'; Expression={$location}}, Name, FullName, Length, LastWriteTime
            }
        }
        
        if ($suspiciousFiles) {
            $suspiciousFiles | Export-Csv -Path "$OutputPath\Filesystem\Suspicious_Files.csv" -NoTypeInformation
        }
        
        # Calculate file hashes if requested
        if (!$SkipHashes) {
            Write-EnumerationLog "Calculating file hashes for suspicious files..." -Type "INFO"
            
            $filesToHash = $suspiciousFiles | Select-Object -First 50  # Limit to prevent timeout
            $fileHashes = foreach ($file in $filesToHash) {
                try {
                    $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                    if ($hash) {
                        [PSCustomObject]@{
                            File = $file.FullName
                            SHA256 = $hash.Hash
                            Algorithm = $hash.Algorithm
                        }
                    }
                }
                catch {
                    # Continue with next file
                }
            }
            
            if ($fileHashes) {
                $fileHashes | Export-Csv -Path "$OutputPath\Filesystem\File_Hashes.csv" -NoTypeInformation
            }
        }
        
        Write-EnumerationLog "File system information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting file system information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 9. Security Configuration
function Get-SecurityInformation {
    Write-EnumerationLog "Collecting security configuration..." -Type "INFO"
    
    try {
        # Windows Defender Status
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus) {
                $defenderStatus | 
                    Select-Object AMProductVersion, AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, 
                              RealTimeProtectionEnabled, QuickScanAge, FullScanAge, LastQuickScan, LastFullScan |
                    Export-Csv -Path "$OutputPath\Security\Windows_Defender_Status.csv" -NoTypeInformation
            }
        }
        catch {
            Write-EnumerationLog "Windows Defender information not available" -Type "WARNING"
        }
        
        # Local Security Policy (basic)
        $auditPolicy = auditpol /get /category:* 2>$null
        if ($auditPolicy) {
            $auditPolicy | Out-File -FilePath "$OutputPath\Security\Audit_Policy.txt"
        }
        
        # UAC Settings
        $uacSettings = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        if ($uacSettings) {
            [PSCustomObject]@{
                EnableLUA = $uacSettings.EnableLUA
                ConsentPromptBehaviorAdmin = $uacSettings.ConsentPromptBehaviorAdmin
                PromptOnSecureDesktop = $uacSettings.PromptOnSecureDesktop
            } | Export-Csv -Path "$OutputPath\Security\UAC_Settings.csv" -NoTypeInformation
        }
        
        # BitLocker Status
        try {
            $bitlockerStatus = Manage-BDE -Status 2>$null
            if ($bitlockerStatus) {
                $bitlockerStatus | Out-File -FilePath "$OutputPath\Security\BitLocker_Status.txt"
            }
        }
        catch {
            # BitLocker not available or accessible
        }
        
        Write-EnumerationLog "Security configuration collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting security configuration: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 10. Application and Browser Information
function Get-ApplicationInformation {
    Write-EnumerationLog "Collecting application and browser information..." -Type "INFO"
    
    try {
        # Browser History (Edge/Chrome)
        $browserPaths = @(
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
        )
        
        foreach ($browserPath in $browserPaths) {
            if (Test-Path $browserPath) {
                Copy-Item $browserPath "$OutputPath\Applications\$(Split-Path $browserPath -Leaf)" -ErrorAction SilentlyContinue
            }
        }
        
        # Installed Programs from Registry (more comprehensive)
        $programs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                                     "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString |
            Sort-Object DisplayName
        
        $programs | Export-Csv -Path "$OutputPath\Applications\Installed_Programs.csv" -NoTypeInformation
        
        # Running COM Objects
        $comObjects = Get-CimInstance -ClassName Win32_COMApplication | 
            Select-Object Name, InstallDate, Description
        
        if ($comObjects) {
            $comObjects | Export-Csv -Path "$OutputPath\Applications\COM_Objects.csv" -NoTypeInformation
        }
        
        Write-EnumerationLog "Application information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting application information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 11. Scheduled Tasks
function Get-ScheduledTasks {
    Write-EnumerationLog "Collecting scheduled tasks..." -Type "INFO"
    
    try {
        $scheduledTasks = Get-ScheduledTask | 
            Select-Object TaskName, TaskPath, State, @{Name='Author'; Expression={$_.Principal.UserId}}, 
                      Description, Actions, Triggers, Date, Principal
        
        $scheduledTasks | Export-Csv -Path "$OutputPath\Scheduled_Tasks\All_Scheduled_Tasks.csv" -NoTypeInformation
        
        # Running and enabled tasks
        $scheduledTasks | Where-Object { $_.State -eq 'Running' -or $_.State -eq 'Ready' } |
            Export-Csv -Path "$OutputPath\Scheduled_Tasks\Active_Scheduled_Tasks.csv" -NoTypeInformation
        
        Write-EnumerationLog "Scheduled tasks collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting scheduled tasks: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 12. WMI Information
function Get-WMIInformation {
    Write-EnumerationLog "Collecting WMI information..." -Type "INFO"
    
    try {
        # WMI Event Consumers (Persistence)
        $wmiEventFilters = Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue
        if ($wmiEventFilters) {
            $wmiEventFilters | Select-Object Name, Query | 
                Export-Csv -Path "$OutputPath\WMI\Event_Filters.csv" -NoTypeInformation
        }
        
        $wmiEventConsumers = Get-WmiObject -Namespace root\Subscription -Class __EventConsumer -ErrorAction SilentlyContinue
        if ($wmiEventConsumers) {
            $wmiEventConsumers | Select-Object Name, CommandLineTemplate | 
                Export-Csv -Path "$OutputPath\WMI\Event_Consumers.csv" -NoTypeInformation
        }
        
        # WMI Namespaces
        $wmiNamespaces = Get-WmiObject -Namespace root -Class __Namespace | Select-Object Name
        $wmiNamespaces | Export-Csv -Path "$OutputPath\WMI\Namespaces.csv" -NoTypeInformation
        
        Write-EnumerationLog "WMI information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting WMI information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 13. Performance Information
function Get-PerformanceInformation {
    Write-EnumerationLog "Collecting performance information..." -Type "INFO"
    
    try {
        # Performance Counters
        $perfCounters = @(
            "\Memory\Available MBytes",
            "\Processor(_Total)\% Processor Time", 
            "\PhysicalDisk(_Total)\% Disk Time",
            "\Network Interface(*)\Bytes Total/sec"
        )
        
        $perfData = foreach ($counter in $perfCounters) {
            try {
                $value = (Get-Counter -Counter $counter -SampleInterval 1 -MaxSamples 1).CounterSamples.CookedValue
                [PSCustomObject]@{
                    Counter = $counter
                    Value = $value
                }
            }
            catch {
                # Counter not available
            }
        }
        
        $perfData | Export-Csv -Path "$OutputPath\Performance\Performance_Counters.csv" -NoTypeInformation
        
        # System Uptime
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $uptime = (Get-Date) - $osInfo.LastBootUpTime
        [PSCustomObject]@{
            LastBootTime = $osInfo.LastBootUpTime
            UptimeDays = [math]::Round($uptime.TotalDays, 2)
            UptimeHours = [math]::Round($uptime.TotalHours, 2)
        } | Export-Csv -Path "$OutputPath\Performance\System_Uptime.csv" -NoTypeInformation
        
        Write-EnumerationLog "Performance information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting performance information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 14. Forensic Artifacts
function Get-ForensicArtifacts {
    Write-EnumerationLog "Collecting forensic artifacts..." -Type "INFO"
    
    try {
        # Prefetch Files (if accessible)
        $prefetchFiles = Get-ChildItem "C:\Windows\Prefetch" -ErrorAction SilentlyContinue | 
            Select-Object Name, LastWriteTime, Length | Sort-Object LastWriteTime -Descending | Select-Object -First 50
        
        if ($prefetchFiles) {
            $prefetchFiles | Export-Csv -Path "$OutputPath\Forensic\Prefetch_Files.csv" -NoTypeInformation
        }
        
        # DNS Cache
        Get-DnsClientCache | Select-Object Entry, Name, Data, DataLength, TTL | 
            Export-Csv -Path "$OutputPath\Forensic\DNS_Cache.csv" -NoTypeInformation
        
        # ARP Cache
        Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias | 
            Export-Csv -Path "$OutputPath\Forensic\ARP_Cache.csv" -NoTypeInformation
        
        # Environment Variables
        Get-ChildItem Env: | Select-Object Name, Value | 
            Export-Csv -Path "$OutputPath\Forensic\Environment_Variables.csv" -NoTypeInformation
        
        Write-EnumerationLog "Forensic artifacts collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting forensic artifacts: $($_.Exception.Message)" -Type "ERROR"
    }
}

# 15. Memory Information (Optional)
function Get-MemoryInformation {
    if (!$IncludeMemoryDump) {
        Write-EnumerationLog "Skipping memory dump (not requested)" -Type "INFO"
        return
    }
    
    Write-EnumerationLog "Collecting memory information..." -Type "INFO"
    
    try {
        # Memory Statistics
        $memoryStats = Get-CimInstance -ClassName Win32_OperatingSystem |
            Select-Object @{Name='TotalVisibleMemorySizeGB'; Expression={[math]::Round($_.TotalVisibleMemorySize/1MB, 2)}},
                          @{Name='FreePhysicalMemoryGB'; Expression={[math]::Round($_.FreePhysicalMemory/1MB, 2)}},
                          @{Name='TotalVirtualMemorySizeGB'; Expression={[math]::Round($_.TotalVirtualMemorySize/1MB, 2)}},
                          @{Name='FreeVirtualMemoryGB'; Expression={[math]::Round($_.FreeVirtualMemory/1MB, 2)}}
        
        $memoryStats | Export-Csv -Path "$OutputPath\Memory\Memory_Statistics.csv" -NoTypeInformation
        
        # Process Memory Usage
        $processMemory = Get-Process | 
            Group-Object ProcessName | 
            ForEach-Object {
                [PSCustomObject]@{
                    ProcessName = $_.Name
                    InstanceCount = $_.Count
                    TotalWorkingSetMB = [math]::Round(($_.Group | Measure-Object WorkingSet -Sum).Sum / 1MB, 2)
                    AverageWorkingSetMB = [math]::Round(($_.Group | Measure-Object WorkingSet -Average).Average / 1MB, 2)
                }
            } | Sort-Object TotalWorkingSetMB -Descending | Select-Object -First 25
        
        $processMemory | Export-Csv -Path "$OutputPath\Memory\Process_Memory_Usage.csv" -NoTypeInformation
        
        Write-EnumerationLog "Memory information collected successfully" -Type "SUCCESS"
    }
    catch {
        Write-EnumerationLog "Error collecting memory information: $($_.Exception.Message)" -Type "ERROR"
    }
}

# Generate Summary Report
function New-EnumerationSummary {
    Write-EnumerationLog "Generating summary report..." -Type "INFO"
    
    try {
        $endTime = Get-Date
        $duration = $endTime - $Script:StartTime
        $fileCount = (Get-ChildItem $OutputPath -Recurse -File | Measure-Object).Count
        $dirCount = (Get-ChildItem $OutputPath -Recurse -Directory | Measure-Object).Count
        $totalSize = [math]::Round(((Get-ChildItem $OutputPath -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB), 2)
        
        $memoryCheck = if ($IncludeMemoryDump) { "[X]" } else { "[ ]" }
        
        $summary = @"
FULL COMPUTER ENUMERATION SUMMARY REPORT
=========================================

GENERATED: $endTime
HOSTNAME: $env:COMPUTERNAME
USER: $env:USERNAME
DOMAIN: $env:USERDOMAIN
ADMIN PRIVILEGES: $(if (Test-Administrator) { "Yes" } else { "No" })
SCRIPT DURATION: $($duration.ToString('hh\:mm\:ss'))

OUTPUT LOCATION: $OutputPath
TOTAL DIRECTORIES: $dirCount
TOTAL FILES: $fileCount
TOTAL SIZE: $totalSize MB

COLLECTION SUMMARY:
-------------------
[X] System Information
[X] Hardware Inventory  
[X] Network Configuration
[X] Processes & Services
[X] Users & Groups
[X] Event Logs ($EventLogDays days)
[X] Registry Analysis
[X] File System Analysis
[X] Security Configuration
[X] Applications & Browsers
[X] Scheduled Tasks
[X] WMI Information
[X] Performance Data
[X] Forensic Artifacts
$memoryCheck Memory Information

OUTPUT STRUCTURE:
-----------------
$OutputPath/
├── System_Info/           # Hardware and OS details
├── Network/               # Network configuration and connections
├── Processes/             # Running processes and details
├── Services/              # Windows services
├── Users_Groups/          # Local users and groups
├── Event_Logs/            # System and security events
├── Registry/              # Autoruns and installed software
├── Filesystem/            # File system analysis
├── Security/              # Security settings and Defender
├── Applications/          # Installed programs and browsers
├── Scheduled_Tasks/       # Automated tasks
├── WMI/                   # WMI configuration
├── Performance/           # System performance
├── Forensic/              # Forensic artifacts
├── Memory/                # Memory information
└── enumeration.log        # Execution log

IMMEDIATE INVESTIGATION POINTS:
------------------------------
1. Review suspicious files in Filesystem\Suspicious_Files.csv
2. Check unauthorized autoruns in Registry\Autoruns.csv  
3. Examine network connections in Network\Active_Connections.csv
4. Audit user accounts in Users_Groups\Local_Users.csv
5. Review security events in Event_Logs\Critical_Security_Events.csv
6. Check scheduled tasks for unknown automation
7. Verify running services match expected baseline

CRITICAL FILES FOR ANALYSIS:
----------------------------
- Network\Listening_Ports.csv
- Network\Active_Connections.csv  
- Processes\All_Processes.csv
- Services\All_Services.csv
- Registry\Autoruns.csv
- Filesystem\Suspicious_Files.csv
- Event_Logs\Critical_Security_Events.csv

NOTE: This enumeration provides comprehensive system baseline.
Use for security assessment, incident response, or system documentation.

"@
        
        $summary | Out-File -FilePath "$OutputPath\Enumeration_Summary.txt" -Encoding UTF8
        Write-EnumerationLog "Summary report generated successfully" -Type "SUCCESS"
        
        # Display summary to console
        Write-Host "`n" + "="*70 -ForegroundColor Green
        Write-Host "ENUMERATION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
        Write-Host "="*70 -ForegroundColor Green
        Write-Host "Output Location: $OutputPath" -ForegroundColor Yellow
        Write-Host "Files Generated: $fileCount" -ForegroundColor Yellow
        Write-Host "Total Size: $totalSize MB" -ForegroundColor Yellow
        Write-Host "Execution Time: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Yellow
        Write-Host "`nReview Enumeration_Summary.txt for detailed findings and next steps." -ForegroundColor Cyan
        Write-Host "="*70 -ForegroundColor Green
    }
    catch {
        Write-EnumerationLog "Error generating summary report: $($_.Exception.Message)" -Type "ERROR"
    }
}

# Main Execution Function
function Start-ComputerEnumeration {
    Write-Host "`n" + "="*70 -ForegroundColor Cyan
    Write-Host "FULL COMPUTER ENUMERATION TOOLKIT" -ForegroundColor Cyan
    Write-Host "="*70 -ForegroundColor Cyan
    Write-Host "Start Time: $($Script:StartTime)" -ForegroundColor White
    Write-Host "Output Path: $OutputPath" -ForegroundColor White
    Write-Host "Quick Mode: $QuickMode" -ForegroundColor White
    Write-Host "Event Log Days: $EventLogDays" -ForegroundColor White
    Write-Host "="*70 -ForegroundColor Cyan
    
    # Check if running as Administrator
    if (!(Test-Administrator)) {
        Write-EnumerationLog "WARNING: Not running as Administrator. Some data may not be accessible." -Type "WARNING"
    }
    
    # Initialize output directory
    if (!(Initialize-OutputDirectory)) {
        Write-EnumerationLog "Failed to initialize output directory. Exiting." -Type "ERROR"
        return
    }
    
    # Start transcript
    Start-Transcript -Path "$OutputPath\PowerShell_Transcript.log" -Append | Out-Null
    
    try {
        # Execute collection functions
        Get-SystemInformation
        Get-HardwareInventory
        Get-NetworkInformation
        Get-ProcessServiceInformation
        Get-UserGroupInformation
        Get-EventLogs
        Get-RegistryInformation
        Get-FileSystemInformation
        Get-SecurityInformation
        Get-ApplicationInformation
        Get-ScheduledTasks
        Get-WMIInformation
        Get-PerformanceInformation
        Get-ForensicArtifacts
        Get-MemoryInformation
        
        # Generate final summary
        New-EnumerationSummary
    }
    finally {
        # Stop transcript
        Stop-Transcript | Out-Null
    }
}

# Execute the enumeration
Start-ComputerEnumeration
