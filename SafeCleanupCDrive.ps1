<#
.SYNOPSIS
    Safely cleans up common temporary and update files from the C: drive.
.DESCRIPTION
    Removes Windows temp files, user temp files, C:\Temp, Windows Update leftovers, ProPatch cache, font cache, shadow copies, $PatchCache, and Recycle Bin contents.
    Stops and restarts the FontCache service and Windows Update service if needed. Logs actions and provides a summary.
    Must be run as Administrator otherwise it won't work

.AUTHOR
    Chris McMorrin

.CREATED
    2025-05-23

.LASTUPDATED
    2025-06-04

.VERSION
    1.3.0

.CHANGELOG
    2025-05-23: Initial version.
    2025-05-24: 
        - Modularised clean-up functions and improved logging.
        - Unified summary reporting with per-step size tracking.
        - Enhanced WhatIf handling and error reporting.
        - Improved user profile filtering and code readability.
    2025-05-26:
        - Added consistent parameter block formatting and comments for all functions.
        - Improved logging and error handling
        - Added detailed comments and explanations for maintainability.
        - Added countdown and user-interruptible pause before execution.
        - Enhanced Recycle Bin and shadow copy handling and reporting.
        - Added class for structured removal results.
        - General code clean-up and uniformity improvements.
    2025-06-02:
        - Added Administrator check at the start of the script

.PARAMETER CleanupWindowsTemp
    Clean Windows\Temp
.PARAMETER CleanupCTemp
    Clean Temp
.PARAMETER CleanupUserTemp
    Clean user profile temp folders
.PARAMETER CleanupWindowsUpdate
    Clean Windows Update leftovers
.PARAMETER CleanupIvantiPatchCache
    Clean the Ivanti ProPatch cache
.PARAMETER CleanupFontCache
    Clean font cache and restart FontCache service
.PARAMETER CleanupRecycleBin
    Empty Recycle Bin
.PARAMETER CleanupShadowCopies
    Delete all shadow copies -Disabled by default
.PARAMETER CleanupWindowsPrefetch
    Clean Windows Prefetch -Disabled by default
.PARAMETER CleanupRecentFiles
    Clean Recent Files - Disabled by default
.PARAMETER CleanupWindowsPatchCache
    Clean Windows\Installer\$PatchCache - Disabled by default
.PARAMETER CleanupIISLogs
    Compresses IIS Logs to an Archive subfolder and delete old archived logs - Disabled by default
.PARAMETER CleanupOrphanedProfiles
    Delete user profiles for accounts that are disabled or no longer exist in AD - Disabled by default

.NOTES
    Run as Administrator.
    Tested on Windows 10/11 and Server 2016/2019/2022.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogFilePath = $( 
        # Use $PSScriptRoot if available, otherwise fallback to current directory
        if ($PSScriptRoot) {
            Join-Path -Path $PSScriptRoot -ChildPath ("SafeCleanupCDrive_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        } else {
            Join-Path -Path (Get-Location) -ChildPath ("SafeCleanupCDrive_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        }
    ),
    [Parameter()]
    [switch]$CleanupWindowsTemp,
    [Parameter()]
    [switch]$CleanupCTemp,
    [Parameter()]
    [switch]$CleanupUserTemp,
    [Parameter()]
    [switch]$CleanupWindowsUpdate,
    [Parameter()]
    [switch]$CleanupIvantiPatchCache,
    [Parameter()]
    [switch]$CleanupFontCache,
    [Parameter()]
    [switch]$CleanupRecycleBin,
    [Parameter()]
    [switch]$CleanupShadowCopies,
    [Parameter()]
    [switch]$CleanupWindowsPrefetch,
    [Parameter()]
    [switch]$CleanupRecentFiles,
    [Parameter()]
    [switch]$CleanupWindowsPatchCache,
    [Parameter()]
    [switch]$CleanupIISLogs,
    [Parameter()]
    [switch]$CleanupOrphanedProfiles
)

# --- ADMINISTRATOR CHECK ---
# Check if the script is running with administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Configure the scheduled task to run with Administrator privileges." -ForegroundColor Yellow
    Write-Log "ERROR: Script attempted to run without Administrator privileges. Exiting."
    
    # 5-second timer before exit
    Write-Host "Exiting in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    exit 1
}

# --- DEFAULT PARAMETER HANDLING ---
# --- Set default options if not specified ---
if (-not $PSBoundParameters.ContainsKey('CleanupWindowsTemp'))      { $CleanupWindowsTemp      = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupCTemp'))            { $CleanupCTemp            = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupUserTemp'))         { $CleanupUserTemp         = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupWindowsUpdate'))    { $CleanupWindowsUpdate    = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupIvantiPatchCache')) { $CleanupIvantiPatchCache = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupFontCache'))        { $CleanupFontCache        = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupRecycleBin'))       { $CleanupRecycleBin       = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupShadowCopies'))     { $CleanupShadowCopies     = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupWindowsPrefetch'))  { $CleanupWindowsPrefetch  = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupRecentFiles'))      { $CleanupRecentFiles      = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupWindowsPatchCache')){ $CleanupWindowsPatchCache= $false }
if (-not $PSBoundParameters.ContainsKey('CleanupIISLogs'))          { $CleanupIISLogs          = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupOrphanedProfiles')) { $CleanupOrphanedProfiles = $true }


# GLOBAL VARIABLES AND CONFIG
# --- Initialise script variables ---
$scriptStartTime = Get-Date
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$startDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $script:StepSizes) { $script:StepSizes = @{} }


# --- Initialise logging ---
if ($LogFilePath) {
    # Check if the provided path is a directory or a file
    if (Test-Path $LogFilePath -PathType Container) {
        # If it's a directory, create a log file with the current date and time
        $LogFile = Join-Path $LogFilePath "SafeCleanupCDrive_$startDateTime.log"
    } else {
        # If it's a file, use it directly
        $LogFile = $LogFilePath
    }
} else {
    # Default log file path if not specified
    $LogFile = Join-Path $scriptDir "SafeCleanupCDrive_$startDateTime.log"
}
# Ensure the log file directory exists
$parentDir = Split-Path $LogFile -Parent
if (-not (Test-Path $parentDir)) {
    # Create the parent directory if it doesn't exist
    New-Item -ItemType Directory -Path $parentDir -Force -WhatIf:$false | Out-Null
}
# Write initial log entry with start time
Set-Content -Path $LogFile -Value "SafeCleanupCDrive started: $(Get-Date)`n" -WhatIf:$false
$ProgramData = [Environment]::GetFolderPath('CommonApplicationData')

# Define the configuration for each clean-up step
$CleanupConfig = @{
    WindowsTemp = @{
        Paths = @("$env:SystemRoot\Temp\*")
        Description = "Clean $env:SystemRoot\Temp"
    }
    CTemp = @{
        Paths = @("C:\Temp\*")
        Description = "Clean C:\Temp"
    }
    UserTemp = @{
        AccountTypes = @('Domain','Local')
        DynamicPaths = { param($config) Get-UserProfilePaths -AccountTypes $config.AccountTypes -SubPath 'AppData\Local\Temp\*' }
        Description = "Clean user profile temp folders"
    }
    WindowsUpdate = @{
        Paths = @(
            "$env:SystemRoot\SoftwareDistribution\Download\*",
            "$env:SystemRoot\SoftwareDistribution\Datastore\*",
            "$env:SystemRoot\Logs\CBS\*"
        )
        ServiceName = "wuauserv"
        Description = "Clean Windows Update leftovers"
    }
    IvantiPatchCache = @{
        Paths = @(
            "$env:SystemRoot\ProPatches\Patches\*",
            "C:\ProPatch\Cache\*",
            "$ProgramData\ProPatch\Cache\*"
        )
        Description = "Clean Ivanti ProPatch cache"
    }
    FontCache = @{
        Paths = @("$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\FontCache\*")
        ServiceName = "FontCache"
        Description = "Clean font cache and restart FontCache service"
    }
    RecycleBin = @{
        SpecialHandler = 'Clear-RecycleBin'
        Description = "Empty Recycle Bin"
    }
    ShadowCopies = @{
        SpecialHandler = 'Clear-ShadowCopies'
        Description = "Delete all shadow copies"
    }
    WindowsPrefetch = @{
        Paths = @("$env:SystemRoot\Prefetch\*")
        Description = "Clean Windows Prefetch"
    }
    RecentFiles = @{
        AccountTypes = @('Domain','Local')
        DynamicPaths = { param($config) Get-UserProfilePaths -AccountTypes $config.AccountTypes -SubPath 'AppData\Roaming\Microsoft\Windows\Recent\*' }
        Description = "Clean Recent Files"
    }
    WindowsPatchCache = @{
        Paths = @(
            "$env:SystemRoot\Installer\`$PatchCache`$\*",
            "$env:SystemRoot\Installer\PatchCache\*"
        )
        Description = "Clean $env:SystemRoot\Installer\$PatchCache$"
    }
    IISLogs = @{
        LogFolder = "C:\inetpub\logs\LogFiles"
        ArchiveFolderName = "Archive"
        RetentionDays = 30
        ArchiveDeletionDays = 60
        Description = "Compress IIS Logs >30 days old to an Archive subfolder and delete archived >60 days old"
    }
    OrphanedProfiles = @{
        SpecialHandler = 'Clear-OrphanedProfiles'
        AccountTypes = @('Domain')
        Description = "Delete user profiles for disabled or non-existent AD accounts"
    }
}

# --- DATA STRUCTURES ---
#--- Represents the result of a file or directory removal operation ---
class RemovalResult {
    [string]$Path
    [bool]$Success
    [string]$Error
    [long]$BytesAttempted
    RemovalResult([string]$path, [bool]$success, [string]$errorMsg, [long]$bytes) {
        $this.Path = $path
        $this.Success = $success
        $this.Error = $errorMsg
        $this.BytesAttempted = $bytes
    }
}

# --- UTILITY FUNCTIONS ---
# --- Logging function: writes messages to log file and optionally to console ---
function Write-Log {
    param(
        [Parameter()]
        [string]$Message,
        [Parameter()]
        [switch]$LogOnly,
        [Parameter()]
        [System.ConsoleColor]$Colour
    )

    # Ensure log file exists
    if (-not (Test-Path -Path $LogFile)) {
        New-Item -Path $LogFile -ItemType File -Force -WhatIf:$false | Out-Null
    }
    # Write message to log file
    Add-Content -Path $LogFile -Value $Message -WhatIf:$false
    # Optionally write to console, with colour if specified
    if (-not $LogOnly) {
        if ($PSBoundParameters.ContainsKey('Colour') -and $Colour) {
            Write-Host $Message -ForegroundColor $Colour
        } else {
            Write-Host $Message
        }
    }
}

# --- Logs detailed error information to the log file and optionally to the console ---
function Write-ErrorLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter()]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter()]
        [ValidateSet('Critical', 'Warning', 'Information')]
        [string]$Severity = 'Warning',
        [Parameter()]
        [switch]$Critical
    )

    # Default message if empty
    if (-not $Message) { $Message = "Unknown error" }

    # Build error details object for logging
    $errorDetails = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Operation = $Operation
        Message = $Message
        Severity = $Severity
        Error = if ($ErrorRecord) { $ErrorRecord.Exception.Message } else { $null }
        Category = if ($ErrorRecord) { $ErrorRecord.CategoryInfo.Category } else { $null }
        TargetObject = if ($ErrorRecord) { $ErrorRecord.TargetObject } else { $null }
        ScriptStackTrace = if ($ErrorRecord) { $ErrorRecord.ScriptStackTrace } else { $null }
    }
    $logMessage = "[$Severity] $Operation - $Message"
    Write-Log $logMessage -LogOnly
    Write-Log ("[ERROR DETAILS] " + ($errorDetails | ConvertTo-Json -Compress)) -LogOnly
    # If critical, also write to console in red
    if ($Critical -or $Severity -eq 'Critical') {
        Write-Host "CRITICAL ERROR: $Operation - $Message" -ForegroundColor Red
    }
}

function Add-StepResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StepName,
        [Parameter(Mandatory = $true)]
        [long]$BytesBefore,
        [Parameter(Mandatory = $true)]
        [long]$BytesDeleted
    )
    if (-not $script:StepSizes) { $script:StepSizes = @{} }
    $script:StepSizes[$StepName] = @{
        Before = $BytesBefore
        Deleted = $BytesDeleted
    }
}

# --- Converts a byte value to a human-readable size (e.g. GB) ---
function Convert-Size {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [double]$Bytes,
        [Parameter()]
        [ValidateSet('Bytes', 'KB', 'MB', 'GB', 'TB')]
        [string]$To = 'GB',
        [Parameter()]
        [ValidateRange(0, 15)]
        [int]$DecimalPlaces = 3
    )
    process {
        $sizes = @{
            Bytes = 1
            KB = 1KB
            MB = 1MB
            GB = 1GB
            TB = 1TB
        }
        return [math]::Round($Bytes / $sizes[$To], $DecimalPlaces)
    }
}

# --- User Filtering ---
$SystemAccounts = @('Default', 'Default User', 'Public', 'All Users', 'Administrator')
$UserAccountExcludePatterns = @(
    '^S_', '^svc', '^admin$', '^administrator$', '^admin\d+$', '^adm$', '^adm\d+$', '^sys', '^test$', '^test\d+$'
)

function Get-UserProfilePaths {
    param(
        [string[]]$AccountTypes,
        [string]$SubPath
    )
    $Global:UserProfiles | Where-Object { $_.AccountType -in $AccountTypes } | ForEach-Object {
        Join-Path $_.Path $SubPath
    }
}

function Get-UserProfileType {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName,
        [Parameter(Mandatory = $true)]
        [string]$SID,
        [Parameter(Mandatory = $true)]
        [string]$LocalSIDPrefix
    )
    if ($null -eq $SID) {
        return "Unknown"
    }
    if ($SID -like "S-1-5-80-*") {
        return "Service"
    }
    if ($SID -like "$LocalSIDPrefix*") {
        if ($SID -match '-500$') { return "DefaultAdmin" }
        if ($SID -match '-501$') { return "DefaultGuest" }
        return "Local"
    }
    if ($ProfileName -in $SystemAccounts -or ($UserAccountExcludePatterns | Where-Object { $_ -and $ProfileName -match $_ })) {
        return "System"
    }
    return "Domain"
}

function Get-UserProfiles {
    $usersPath = "$env:SystemDrive\Users"
    $localSIDPrefix = Get-LocalMachineSIDPrefix
    $profileSIDMap = Get-ProfileSIDMap
    $profiles = Get-ChildItem $usersPath -Directory
    $results = @()
    foreach ($profile in $profiles) {
        $sid = $profileSIDMap[$profile.Name]
        $accountType = Get-UserProfileType -ProfileName $profile.Name -SID $sid -LocalSIDPrefix $localSIDPrefix
        $results += [PSCustomObject]@{
            Name        = $profile.Name
            Path        = $profile.FullName
            SID         = $sid
            AccountType = $accountType
        }
    }
    return $results
}

function Get-LdapUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    try {
        $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
        if (-not $domainDN) {
            Write-Error "LDAP query failed: Could not determine defaultNamingContext (domainDN is null or empty)."
            return $null
        }
        $ldapPath = "LDAP://$domainDN"
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$ldapPath)
        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$Username))"
        $searcher.PropertiesToLoad.AddRange(@("distinguishedName","displayName","mail","userAccountControl"))
        $result = $searcher.FindOne()
        if ($null -eq $result) {
            Write-Error "LDAP query failed: No result found for user '$Username'."
            return $null
        }
        if ($null -eq $result.Properties -or $result.Properties.Count -eq 0) {
            Write-Error "LDAP query failed: No properties returned for user '$Username'."
            return $null
        }
        $user = $result.Properties
        # Defensive checks for each property
        return [PSCustomObject]@{
            DistinguishedName = if ($user.distinguishedname.Count -gt 0) { $user.distinguishedname[0] } else { $null }
            DisplayName       = if ($user.displayname.Count -gt 0) { $user.displayname[0] } else { $null }
            Email             = if ($user.mail.Count -gt 0) { $user.mail[0] } else { $null }
            UserAccountControl= if ($user.useraccountcontrol.Count -gt 0) { $user.useraccountcontrol[0] } else { $null }
        }
    } catch {
        Write-Error "LDAP query failed for user '$Username': $_"
        return $null
    }
}

function Get-LocalMachineSIDPrefix {
    # Returns the SID prefix for local accounts (e.g., S-1-5-21-xxxx-xxxx-xxxx)
    $computerSID = (Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | Select-Object -First 1).SID
    if ($computerSID) {
        # Remove the last part (RID) to get the prefix
        return ($computerSID -replace '\-\d+$','')
    }
    return $null
}

# --- User Profile SID Mapping with CIM/WMI/Hardcoded fallback ---

function Get-ProfileSIDMap {
    $map = @{}
    $usersPath = "$env:SystemDrive\Users"
    $folders = Get-ChildItem $usersPath -Directory
    # Try CIM first
    try {
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -like "$usersPath\*" }
        foreach ($profile in $profiles) {
            $folder = Split-Path $profile.LocalPath -Leaf
            $map[$folder] = $profile.SID
        }
    } catch {
        # Fallback to WMI
        try {
            $profiles = Get-WmiObject Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -like "$usersPath\*" }
            foreach ($profile in $profiles) {
                $folder = Split-Path $profile.LocalPath -Leaf
                $map[$folder] = $profile.SID
            }
        } catch {
            Write-Log "WARNING: Falling back to folder names for profile SID mapping. Orphaned profile detection may be less accurate." -Colour Yellow
        }
    }
    # Ensure every folder is mapped (even if not in Win32_UserProfile)
    foreach ($folder in $folders) {
        if (-not $map.ContainsKey($folder.Name)) {
            $map[$folder.Name] = $null
        }
    }
    return $map
}

# --- CORE CLEANUP FUNCTIONS ---
# --- Starts or stops a Windows service and waits for the operation to complete ---
function Set-ServiceState {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Running', 'Stopped')]
        [string]$State,
        [Parameter()]
        [int]$TimeoutSeconds = 30,
        [Parameter()]
        [switch]$AbortOnFailure
    )
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        if ($service.Status -eq $State) {
            Write-Log "Service $Name is already $State" -LogOnly
            return $true
        }
        if ($PSCmdlet.ShouldProcess($Name, "Set service to $State")) {
            Write-Log "Setting service $Name to $State" -LogOnly
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            if ($State -eq 'Running') { $service.Start() } else { $service.Stop() }
            do {
                Start-Sleep -Milliseconds 500
                $service.Refresh()
                if ($service.Status -eq $State) {
                    $timer.Stop()
                    Write-Log "Service $Name successfully set to $State" -LogOnly
                    return $true
                }
            } while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
            $timer.Stop()
            Write-ErrorLog -Operation "Service$State" `
                -Message "Timeout waiting for service $Name to reach status $State" `
                -Severity 'Critical'
            if ($AbortOnFailure) {
                throw "Critical: Service $Name did not reach $State in time."
            }
            return $false
        }
    } catch {
        Write-ErrorLog -Operation "Service$State" `
            -Message "Failed to set service $Name to $State" `
            -ErrorRecord $_ `
            -Severity 'Critical'
        if ($AbortOnFailure) {
            throw "Critical: Service $Name failed to change state."
        }
        return $false
    }
}

function Remove-Safe {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $results = [System.Collections.ArrayList]::new()
    $bytesBefore = 0
    $bytesDeleted = 0

    # Use Get-ChildItem for wildcards, Get-Item otherwise
    $hasWildcard = $Path.Contains('*')
    if ($hasWildcard) {
        $items = @(Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue)
    } else {
        $items = @(Get-Item -Path $Path -Force -ErrorAction SilentlyContinue)
    }

    if (-not $items) {
        return [PSCustomObject]@{
            Results = $results
            BytesBefore = 0
            BytesDeleted = 0
        }
    }

    $totalItems = $items.Count
    $currentItem = 0
    foreach ($item in $items) {
        $currentItem++
        Write-Progress -Activity "Deleting items" -Status "$currentItem of $totalItems" -PercentComplete (($currentItem / $totalItems) * 100)
        if ($item.PSIsContainer) {
            # Directory: get all files and subdirs recursively
            $allFiles = @(Get-ChildItem -Path $item.FullName -File -Recurse -Force -ErrorAction SilentlyContinue)
            $allDirs  = @(Get-ChildItem -Path $item.FullName -Directory -Recurse -Force -ErrorAction SilentlyContinue)
            # Delete files first
            foreach ($file in $allFiles) {
                $fileSize = $file.Length
                $bytesBefore += $fileSize
                if ($PSCmdlet.ShouldProcess($file.FullName, "Remove file")) {
                    try {
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        $bytesDeleted += $fileSize
                        $null = $results.Add([RemovalResult]::new($file.FullName, $true, $null, $fileSize))
                    } catch {
                        $null = $results.Add([RemovalResult]::new($file.FullName, $false, $_.Exception.Message, $fileSize))
                    }
                } else {
                    $msg = "[WhatIf] Would delete file: $($file.FullName)"
                    $null = $results.Add([RemovalResult]::new($file.FullName, $true, $msg, $fileSize))
                }
            }
            # Delete directories (deepest first)
            $allDirs = $allDirs | Sort-Object -Property FullName -Descending
            foreach ($dir in $allDirs) {
                if ($PSCmdlet.ShouldProcess($dir.FullName, "Remove directory")) {
                    try {
                        Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction Stop
                        $null = $results.Add([RemovalResult]::new($dir.FullName, $true, $null, 0))
                    } catch {
                        $null = $results.Add([RemovalResult]::new($dir.FullName, $false, $_.Exception.Message, 0))
                    }
                } else {
                    $msg = "[WhatIf] Would remove directory: $($dir.FullName)"
                    $null = $results.Add([RemovalResult]::new($dir.FullName, $true, $msg, 0))
                }
            }
            # Finally, delete the top-level directory
            if ($PSCmdlet.ShouldProcess($item.FullName, "Remove directory")) {
                try {
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                    $null = $results.Add([RemovalResult]::new($item.FullName, $true, $null, 0))
                } catch {
                    $null = $results.Add([RemovalResult]::new($item.FullName, $false, $_.Exception.Message, 0))
                }
            } else {
                $msg = "[WhatIf] Would remove directory: $($item.FullName)"
                $null = $results.Add([RemovalResult]::new($item.FullName, $true, $msg, 0))
            }
        } else {
            # Single file
            $fileSize = $item.Length
            $bytesBefore += $fileSize
            if ($PSCmdlet.ShouldProcess($item.FullName, "Remove file")) {
                try {
                    Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                    $bytesDeleted += $fileSize
                    $null = $results.Add([RemovalResult]::new($item.FullName, $true, $null, $fileSize))
                } catch {
                    $null = $results.Add([RemovalResult]::new($item.FullName, $false, $_.Exception.Message, $fileSize))
                }
            } else {
                $msg = "[WhatIf] Would delete file: $($item.FullName)"
                $null = $results.Add([RemovalResult]::new($item.FullName, $true, $msg, $fileSize))
            }
        }
    }
    Write-Progress -Activity "Deleting items" -Completed
    return [PSCustomObject]@{
        Results = $results
        BytesBefore = $bytesBefore
        BytesDeleted = $bytesDeleted
    }
}

# --- SPECIAL HANDLERS ---
# --- Archives and cleans IIS log files older than 30 days, moving them to an Archive folder ---
function Invoke-IISLogsCleanup {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $config = $CleanupConfig.IISLogs
    $IISLogRoot = $config.LogFolder
    $ArchiveFolderName = "Archive"
    $retentionDays = $config.RetentionDays
    $archiveDeletionDays = $config.ArchiveDeletionDays
    $now = Get-Date
    $bytesBefore = 0
    $bytesDeleted = 0

    if (-not (Test-Path $IISLogRoot)) {
        Write-Log "IIS log folder not found: $IISLogRoot"
        Add-StepResult -StepName "IIS Logs" -BytesBefore 0 -BytesDeleted 0
        return
    }

    $logFolders = Get-ChildItem $IISLogRoot -Directory -ErrorAction SilentlyContinue
    foreach ($folder in $logFolders) {
        $archivePath = Join-Path $folder.FullName $ArchiveFolderName
        if (-not (Test-Path $archivePath)) {
            New-Item -ItemType Directory -Path $archivePath -Force | Out-Null
        }

        # Find logs older than retention period to archive
        $logsToArchive = Get-ChildItem $folder.FullName -File -Exclude $ArchiveFolderName -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $now.AddDays(-$retentionDays) }
        # Find archives older than archive deletion period to delete
        $archivesToDelete = Get-ChildItem $archivePath -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $now.AddDays(-$archiveDeletionDays) }

        # Calculate "before" as total size of all files that would be deleted (originals + archives)
        $bytesBefore += ($logsToArchive | Measure-Object -Property Length -Sum).Sum
        $bytesBefore += ($archivesToDelete | Measure-Object -Property Length -Sum).Sum

        # Archive logs > retention days (move to archive)
        foreach ($log in $logsToArchive) {
            $dest = Join-Path $archivePath $log.Name
            if ($PSCmdlet.ShouldProcess($log.FullName, "Archive IIS log to $dest")) {
                Move-Item $log.FullName $dest -Force
                Write-Log ("[Archived] {0} -> {1}" -f $log.FullName, $dest) -LogOnly
            } else {
                Write-Log ("[WhatIf] Would archive {0} -> {1}" -f $log.FullName, $dest) -LogOnly
            }
        }

        # Delete archives > archive deletion days
        foreach ($archive in $archivesToDelete) {
            if ($PSCmdlet.ShouldProcess($archive.FullName, "Delete archived IIS log")) {
                Remove-Item $archive.FullName -Force
                Write-Log ("[Deleted Archive] {0}" -f $archive.FullName) -LogOnly
                $bytesDeleted += $archive.Length
            } else {
                Write-Log ("[WhatIf] Would delete archive {0}" -f $archive.FullName) -LogOnly
            }
        }

        # After archiving, delete any remaining logs > retention days in the original folder (should be none, but just in case)
        $logsToDelete = Get-ChildItem $folder.FullName -File -Exclude $ArchiveFolderName -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $now.AddDays(-$retentionDays) }
        foreach ($log in $logsToDelete) {
            if ($PSCmdlet.ShouldProcess($log.FullName, "Delete original IIS log")) {
                Remove-Item $log.FullName -Force
                Write-Log ("[Deleted Original] {0}" -f $log.FullName) -LogOnly
                $bytesDeleted += $log.Length
            } else {
                Write-Log ("[WhatIf] Would delete original {0}" -f $log.FullName) -LogOnly
            }
        }
    }

    # In WhatIf mode, report as if all eligible files would be deleted
    if ($WhatIfPreference -or $PSCmdlet.MyInvocation.BoundParameters['WhatIf']) {
        Add-StepResult -StepName "IIS Logs" -BytesBefore $bytesBefore -BytesDeleted $bytesBefore
    } else {
        Add-StepResult -StepName "IIS Logs" -BytesBefore $bytesBefore -BytesDeleted $bytesDeleted
    }
    Write-Log "-- FINISHED: IIS Logs cleanup --"
}

# --- Lists contents of the Recycle Bin for all users, excluding system files ---
function Show-RecycleBinContents {
    [CmdletBinding()]
    param()
    $results = @()
    try {
        # Get all recycle bins for users on C: drive
        $recycleBins = Get-ChildItem -Path 'C:\$Recycle.Bin' -Directory -Force | Where-Object { $_.Name -match '^S-1-5-' }
        foreach ($bin in $recycleBins) {
            try {
                # Attempt to translate the SID to a user name
                $sid = New-Object System.Security.Principal.SecurityIdentifier($bin.Name)
                $user = $sid.Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                $user = "Unknown"
            }
            # Exclude desktop.ini and $I*/$R* system files from count
            $files = Get-ChildItem -Path $bin.FullName -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('desktop.ini') -and $_.Name -notmatch '^\$[IR]' }
            $folders = Get-ChildItem -Path $bin.FullName -Recurse -Force -Directory -ErrorAction SilentlyContinue
            $sizeBytes = ($files | Measure-Object -Property Length -Sum).Sum
            $deletedItemsCount = $files.Count
            # Create a custom object for the recycle bin contents
            $results += [PSCustomObject]@{
                User = $user
                SID = $bin.Name
                FileCount = $deletedItemsCount
                FolderCount = $folders.Count
                SizeBytes = $sizeBytes
            }
        }

        return $results
    } catch {
        Write-ErrorLog -Operation "Show-RecycleBinContents" -Message "Failed to enumerate recycle bins" -ErrorRecord $_
        return @()
    }
}

# --- Empties the Recycle Bin on C: for all users, with logging and size tracking ---
function Clear-RecycleBin {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    # Check if the Recycle Bin is available
    $binContents = Show-RecycleBinContents
    foreach ($bin in $binContents) {
        # Convert size to GB for logging
        $sizeGB = $bin.SizeBytes | Convert-Size -To GB
        Write-Log ("Recycle Bin for user: {0} (SID: {1}) - Files: {2}, Folders: {3}, Size: {4} GB" -f $bin.User, $bin.SID, $bin.FileCount, $bin.FolderCount, $sizeGB) -LogOnly
    }
    # Check if there are any files or folders in the Recycle Bin
    $hasContent = $binContents | Where-Object { $_.FileCount -gt 0 -or $_.FolderCount -gt 0 }
    if (-not $hasContent) {
        # No files or folders found in the Recycle Bin
        Write-Log "Recycle Bin on C: is already empty (no files or folders found)"
        $script:StepSizes["Recycle Bin"] = @{ Before = 0; Deleted = 0 }
        Add-StepResult -StepName "Recycle Bin" -BytesBefore 0 -BytesDeleted 0
        Write-Log "-- FINISHED: Empty Recycle Bin --"
        return
    }
    # Calculate the total size of the Recycle Bin before emptying
    $sizeBefore = ($binContents | Measure-Object -Property SizeBytes -Sum).Sum
    if ($PSCmdlet.ShouldProcess("Recycle Bin", "Empty Recycle Bin on C: for all users")) {
        try {
            # Use the Clear-RecycleBin cmdlet to empty the Recycle Bin
            Microsoft.PowerShell.Management\Clear-RecycleBin -DriveLetter C -Force -ErrorAction Stop
            Write-Log "Emptied Recycle Bin on C: for all users" -LogOnly
            # Track the size after emptying 
            $binContents = Show-RecycleBinContents
            $sizeAfter = ($binContents | Measure-Object -Property SizeBytes -Sum).Sum
            # Add the step result with size tracking
            Add-StepResult -StepName "Recycle Bin" -BytesBefore $sizeBefore -BytesDeleted ($sizeBefore - $sizeAfter)
        } catch {
            # Log the error and add to failure list
            Write-ErrorLog -Operation "RecycleBin" -Message "Could not empty Recycle Bin" -ErrorRecord $_ -Severity 'Warning'
            $binContents = Show-RecycleBinContents
            # Track the size after emptying (even if it failed)
            $sizeAfter = ($binContents | Measure-Object -Property SizeBytes -Sum).Sum
            # Add the step result with size tracking
            Add-StepResult -StepName "Recycle Bin" -BytesBefore $sizeBefore -BytesDeleted ($sizeBefore - $sizeAfter)
        }
    } else {
        # WhatIf mode: log what would have been done
        Add-StepResult -StepName "Recycle Bin" -BytesBefore $sizeBefore -BytesDeleted 0
        Write-Log "[WhatIf] Would empty Recycle Bin on C: for all users" -LogOnly
    }
    Write-Log "-- FINISHED: Empty Recycle Bin --"
}

# --- Deletes all shadow copies on C: using vssadmin, with logging and error handling ---
function Clear-ShadowCopies {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess("Shadow Copies", "Delete all shadow copies on C:")) {
        try {
            # Check if vssadmin command is available
            if (Get-Command vssadmin -ErrorAction SilentlyContinue) {
                # Attempt to delete all shadow copies
                $vssResult = & vssadmin delete shadows /for=C: /all /quiet 2>&1
                if ($LASTEXITCODE -eq 0) {
                    # Log the successful deletion
                    Write-Log "Old shadow copies deleted."
                    # Add the step result with size tracking
                    Add-StepResult -StepName "Shadow Copies" -BytesBefore 0 -BytesDeleted 0
                } else {
                    # Log the error and add to failure list
                    Write-Log "Could not delete shadow copies. vssadmin output: $vssResult"
                }
            } else {
                # vssadmin command not found, log the error
                Write-Log "vssadmin not found. Cannot delete shadow copies."
            }
        } catch {
            # Catch any exceptions and log the error
            Write-Log "Could not delete shadow copies: $_"
        }
    } else {
        # WhatIf mode: log what would have been done
        Write-Log "[WhatIf] Would delete all shadow copies on C:"
        Add-StepResult -StepName "Shadow Copies" -BytesBefore 0 -BytesDeleted 0
    }
}

function Clear-OrphanedProfiles {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $profileSIDMap = Get-ProfileSIDMap
    $profiles = Get-ChildItem "$env:SystemDrive\Users" -Directory
    $statusList = @()
    $orphaned = @()
    $domainNetbios = (Get-WmiObject Win32_NTDomain | Where-Object { $_.DnsForestName } | Select-Object -First 1).DomainName
    $localSIDPrefix = Get-LocalMachineSIDPrefix

    foreach ($profile in $profiles) {
        $sid = $profileSIDMap[$profile.Name]
        $profileType = Get-UserProfileType -ProfileName $profile.Name -SID $sid -LocalSIDPrefix $localSIDPrefix
        $status = $profileType
        $isOrphaned = $false

        if ($profileType -eq "Domain") {
            # Extract username if folder ends with .DOMAIN
            $adUser = $profile.Name
            if ($domainNetbios -and $profile.Name -like "*.$domainNetbios") {
                $adUser = $profile.Name.Substring(0, $profile.Name.Length - $domainNetbios.Length - 1)
            }
            $userObj = Get-LdapUser -Username $adUser
            if (-not $userObj) {
                $status = "Not found in AD"
                $isOrphaned = $true
            } elseif (($userObj.UserAccountControl -band 2) -ne 0) {
                $status = "Disabled in AD"
                $isOrphaned = $true
            } else {
                $status = "Active in AD"
            }
        } elseif ($profileType -eq "Unknown") {
            $status = "No SID mapping"
            $isOrphaned = $true
        }

        $statusList += [PSCustomObject]@{
            Profile = $profile.Name
            Path    = $profile.FullName
            Status  = $status
        }

        if ($isOrphaned) {
            $orphaned += $profile
        }
    }

    # Output status list to log and console
    Write-Log "User profile status before deletion:"
    Write-Host "User profile status before deletion:"
    foreach ($entry in $statusList) {
        $msg = "{0,-20} {1,-40} {2}" -f $entry.Profile, $entry.Path, $entry.Status
        Write-Log $msg
        Write-Host $msg
    }

    # Wait for Enter before deleting orphaned profiles (console only)
    if ($orphaned.Count -gt 0) {
        Write-Host ""
        Write-Host "Press Enter to proceed with deleting orphaned profiles, or Ctrl+C to abort..." -ForegroundColor Yellow
        if ($host.Name -ne 'Windows PowerShell ISE Host') {
            [void][System.Console]::ReadLine()
        } else {
            Write-Host "(ISE detected: waiting 10 seconds instead of keypress...)" -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        }
    } else {
        Write-Log "No orphaned profiles found for deletion."
        Write-Host "No orphaned profiles found for deletion."
        return
    }

    # Proceed with deletion
    $bytesBefore = 0
    $bytesDeleted = 0
    $failedDeletions = @()
    foreach ($profile in $orphaned) {
        $result = Remove-Safe -Path $profile.FullName
        $bytesBefore += $result.BytesBefore
        $bytesDeleted += $result.BytesDeleted
        foreach ($r in $result.Results) {
            if (-not $r.Success) {
                $failedDeletions += $r.Path
            }
        }
    }
    Add-StepResult -StepName "OrphanedProfiles" -BytesBefore $bytesBefore -BytesDeleted $bytesDeleted
    if ($failedDeletions.Count -gt 0) {
        Write-Log "Failed to delete the following orphaned profiles:" -LogOnly
        $failedDeletions | ForEach-Object { Write-Log " - $_" -LogOnly }
    }
    Write-Log "-- FINISHED: Orphaned user profile cleanup --"
}

# --- SUMMARY AND REPORTING FUNCTIONS ---
# --- Returns the free space on C: in GB, or "Unknown" if it can't be determined ---
function Get-FreeSpaceGB {
    param()
    try {
        # Get the free space on C: drive in bytes and convert to GB
        $free = [math]::Round((Get-PSDrive C).Free/1GB,2)
        Write-Log "Free space on C: is $free GB"
        return $free
    } catch {
        # If there's an error getting the free space, log it and return "Unknown"
        Write-Log "Could not determine free space: $_"
        return "Unknown"
    }
}

# --- Outputs a summary of the clean-up, including space saved and any failures ---
function Show-Summary {
    param(
        [Parameter(Mandatory = $true)]
        [double]$freeBefore,
        [Parameter(Mandatory = $true)]
        [double]$freeAfter,
        [Parameter(Mandatory = $true)]
        [string]$LogFile,
        [Parameter(Mandatory = $true)]
        [datetime]$scriptStartTime,
        [Parameter(Mandatory = $true)]
        [datetime]$scriptEndTime
    )
    # Ensure free space values are valid and numeric
    if ($freeBefore -eq "Unknown" -or $freeBefore -isnot [double]) {
        Write-Log "Warning: Could not determine free space before clean-up. Reporting as 0 GB." -LogOnly
        $freeBefore = 0
    }
    if ($freeAfter -eq "Unknown" -or $freeAfter -isnot [double]) {
        Write-Log "Warning: Could not determine free space after clean-up. Reporting as 0 GB." -LogOnly
        $freeAfter = 0
    }


    Write-Log ""
    $IsWhatIf = $PSCmdlet.MyInvocation.BoundParameters['WhatIf']
    # Output the summary header
    If ($IsWhatIf) {
        Write-Log "==================== SUMMARY ===================="
        Write-Log ("{0,-30} {1,12}" -f "Action", "Est. Removal (GB)")
    } else {
        Write-Log "========================== SUMMARY ==========================="
        Write-Log ("{0,-20} {1,12} {2,14} {3,12}" -f "Action", "Before (GB)", "Deleted (GB)", "Now (GB)")
    }

    $totalBefore = 0
    $totalDeleted = 0
    $totalAfter = 0
    # Get the free space before clean-up, the free space after clean-up, and the total size of files deleted
    foreach ($step in $script:StepSizes.Keys) {
        $before = $script:StepSizes[$step].Before | Convert-Size -To GB
        $deleted = $script:StepSizes[$step].Deleted | Convert-Size -To GB
        $after = $before - $deleted
        $totalBefore += $before
        $totalDeleted += $deleted
        $totalAfter += $after
        # Log the step results into summary table
        If ($IsWhatIf) {
            Write-Log ("{0,-30} {1,17:N3}" -f $step, $before)
        } else {
            Write-Log ("{0,-20} {1,12:N3} {2,14:N3} {3,12:N3}" -f $step, $before, $deleted, $after)
        }
    }
    Write-Log ""
    # Log the total sizes
    If ($IsWhatIf) {
        Write-Log ("{0,-30} {1,17:N3}" -f "TOTAL", [math]::Round($totalBefore, 3))
        Write-Log "================================================="
    } else {
        Write-Log ("{0,-20} {1,12:N3} {2,14:N3} {3,12:N3}" -f "TOTAL", [math]::Round($totalBefore, 3), [math]::Round($totalDeleted, 3), [math]::Round($totalAfter, 3))
        Write-Log "==============================================================="
    }
    Write-Log ""

    # Log the before and after free space
    If ($IsWhatIf) {
        Write-Log ("{0,-30} {1,17:N3}" -f "Free space before (GB)", [math]::Round($freeBefore, 3))
        Write-Log ("{0,-30} {1,17:N3}" -f "Free space est. after (GB)", [math]::Round($freeBefore - $totalBefore, 3))
        Write-Log "================================================="
    } else {
        Write-Log ("{0,-30} {1,17:N3}" -f "Free space before (GB)", [math]::Round($freeBefore, 3))
        Write-Log ("{0,-30} {1,17:N3}" -f "Free space after (GB)", [math]::Round($freeAfter, 3))
        Write-Log "==============================================================="
    }

    # Log the size of files that failed to delete
    $recycleBinAfter = 0
    if ($script:StepSizes.ContainsKey("Recycle Bin")) {
        $recycleBinAfter = [math]::Round($script:StepSizes["Recycle Bin"].Before / 1GB, 3) - [math]::Round($script:StepSizes["Recycle Bin"].Deleted / 1GB, 3)
    }
    if (-not $IsWhatIf -and $recycleBinAfter -gt 0) {
        Write-Host ("NOTE: Recycle Bin failed to empty (still remaining): $recycleBinAfter GB" ) -ForegroundColor Yellow
        Write-Log ("NOTE: Recycle Bin failed to empty (still remaining): $recycleBinAfter GB") -LogOnly
    }
    If (-not $IsWhatIf -and $totalAfter -gt 0) {
        Write-Host ("NOTE: Total size of files failed to delete: {0} GB" -f [math]::Round($totalAfter, 3)) -ForegroundColor Yellow
        Write-Host "Refer to the log file for the list of files and errors" -ForegroundColor Yellow
        Write-Log ("NOTE: Total size of files failed to delete: {0} GB" -f [math]::Round($totalAfter, 3)) -LogOnly
    }
    Write-Log ""
    Write-Log ("Total time taken: {0}" -f ($scriptEndTime - $scriptStartTime))
    Write-Log ""
    Write-Log "Log file saved to: $LogFile"
    Write-Log "==============================================================="
}

# --- STEP DISPATCHER ---
# --- Runs the clean-up for a given step, including service handling and logging ---
function Invoke-Cleanup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StepName
    )
    $config = $CleanupConfig[$StepName]
    Write-Log "-- STARTED: $($config.Description) --"
    try {
        $wasRunning = $false
        # Stop service if required for this step
        if ($config.ServiceName) {
            $service = Get-Service -Name $config.ServiceName -ErrorAction Stop
            If ($service.Status -eq 'Running') {
                $wasRunning = Set-ServiceState -Name $config.ServiceName -State 'Stopped'
            }
            else {$wasRunning = $false}
        }
        # Use special handler if defined (e.g. for Recycle Bin or Shadow Copies)
        if ($config.SpecialHandler) {
            & $config.SpecialHandler
            return
        }
        # Get paths to clean (static or dynamic)
        $paths = if ($config.DynamicPaths) { & $config.DynamicPaths $config } else { $config.Paths }
        $beforeTotal = 0
        $deletedTotal = 0
        foreach ($path in $paths) {
            $output = Remove-Safe -Path $path
            # Log each result
            foreach ($result in $output.Results) {
                if ($result.Success -and -not $result.Error) {
                    Write-Log ("[Deleted] {0} ({1} bytes)" -f $result.Path, $result.BytesAttempted) -LogOnly
                } elseif ($result.Success -and $result.Error) {
                    Write-Log ("[WhatIf] {0}" -f $result.Error) -LogOnly
                } else {
                    Write-Log ("[FAILED] {0} - {1}" -f $result.Path, $result.Error) -LogOnly
                }
            }
            $beforeTotal += $output.BytesBefore
            $deletedTotal += $output.BytesDeleted
        }
        Add-StepResult -StepName $StepName -BytesBefore $beforeTotal -BytesDeleted $deletedTotal
        # Restart service if it was running before
        if ($config.ServiceName -and $wasRunning) {
            Set-ServiceState -Name $config.ServiceName -State 'Running'
        }
    } catch {
        Write-ErrorLog -Operation $StepName -Message "Failed to complete cleanup" -ErrorRecord $_
    }
    Write-Log "-- FINISHED: $($config.Description) --"
}

# --- MAIN EXECUTION BLOCK ---
try {
    $freeBefore = Get-FreeSpaceGB
    $IsWhatIf = $PSCmdlet.MyInvocation.BoundParameters['WhatIf']
    # --- Plan Output Section ---
    Write-Log "`nCleanup Plan $(if ($IsWhatIf) {'[WhatIf Mode]'} else {'[Execute Mode]'})"
    Write-Log "========================="

    # Enabled steps
    foreach ($step in $CleanupConfig.Keys) {
        try {
            $switchName = "Cleanup$step"
            $enabled = Get-Variable -Name $switchName -ValueOnly -ErrorAction SilentlyContinue
            $desc = $CleanupConfig[$step].Description
            $mode = if ($IsWhatIf) {'[Will simulate]'} else {'[Will execute]'}
            if ($enabled) {
                Write-Log ("• {0} {1}" -f $desc, $mode) -LogOnly
                Write-Host ("- {0} {1}" -f $desc, $mode)
            }
        } catch {
            $msg = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            Write-Log "Error determining enabled state for step '$step': $msg"
            Write-ErrorLog -Operation "PlanOutput" -Message $msg -ErrorRecord $_
        }
    }

    # Skipped steps
    Write-Log ""
    Write-Log "Skipped:" -Colour Yellow
    foreach ($step in $CleanupConfig.Keys) {
        try {
            $switchName = "Cleanup$step"
            $enabled = Get-Variable -Name $switchName -ValueOnly -ErrorAction SilentlyContinue
            $desc = $CleanupConfig[$step].Description
            if (-not $enabled) {
                Write-Log ("• {0}" -f $desc) -LogOnly
                Write-Host ("- {0}" -f $desc) -ForegroundColor Yellow
            }
        } catch {
            $msg = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            Write-Log "Error determining skipped state for step '$step': $msg"
            Write-ErrorLog -Operation "PlanOutputSkipped" -Message $msg -ErrorRecord $_
        }
    }
    Write-Log ""
    Write-Log "`nMode: $(if ($IsWhatIf) {'Simulation (no files will be deleted)'} else {'Live Execution (files will be deleted)'})"
    Write-Log "Output will be logged to: $LogFile`n"
    Write-Host ""
    
    # --- Countdown to give user a chance to cancel script ---
    $isISE = $host.Name -eq 'Windows PowerShell ISE Host'
    If ($isISE) {
        # In ISE it cannot accept key input, so just wait for timeout
        $timeout = 10
        Write-Host ("The selected {0} actions will begin in {1} seconds" -f ($(if ($IsWhatIf) {'simulated'} else {'clean-up'}), $timeout)) -ForegroundColor Yellow
        Write-Host "Press Ctrl+C to abort..." -ForegroundColor Yellow
    } else {
        $timeout = 30
        Write-Host ("The selected {0} actions will begin in {1} seconds" -f ($(if ($IsWhatIf) {'simulated'} else {'clean-up'}), $timeout)) -ForegroundColor Yellow
        Write-Host " Press Enter to continue immediately, or Ctrl+C to abort..." -ForegroundColor Yellow
    }
    #Wait for user input or timeout. Stopwatch object to track elapsed time.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeout) {
        $remaining = [math]::Ceiling($timeout - $sw.Elapsed.TotalSeconds)
        If ($isISE) {
            # In ISE, print each countdown on a new line
            Write-Host ("Continuing in {0} seconds..." -f $remaining)
        } else {
            # In console, updates same line with updated countdown
            Write-Host ("Continuing in {0} seconds..." -f $remaining) -NoNewline
            if ([console]::KeyAvailable) {
                $key = [console]::ReadKey($true)
                if ($key.Key -eq 'Enter') {
                    break
                }
                # Ignore other keys
            }
            Write-Host "`r" -NoNewline
        }
        Start-Sleep -Seconds 1
    }
    $sw.Stop()
    Write-Host ""
    Write-Log ("========== {0} Safe clean-up of C: drive started: {1} ==========" -f ($(if ($IsWhatIf) {'[WhatIf]'} else {''}), (Get-Date)))
    Write-Log ""
    Start-Sleep 5
    # Check if we need to get user profile information
    if ($CleanupUserTemp -or $CleanupRecentFiles -or $CleanupOrphanedProfiles) {
       $Global:UserProfiles = Get-UserProfiles
    }
    # --- Execute each cleanup step with nested try/catch ---
    foreach ($step in $CleanupConfig.Keys) {
        $switchName = "Cleanup$step"
        if (Get-Variable -Name $switchName -ValueOnly -ErrorAction SilentlyContinue) {
            try {
                Invoke-Cleanup -StepName $step
            } catch {
                $msg = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                Write-Log "Error in step '$step': $msg"
                #Write-ErrorLog -Operation $step -Message $msg -ErrorRecord $_
            }
        }
    }
    $freeAfter = Get-FreeSpaceGB
    # --- Final Summary Section ---
    Show-Summary -freeBefore $freeBefore -freeAfter $freeAfter -LogFile $LogFile `
        -ScriptStartTime $scriptStartTime -ScriptEndTime (Get-Date)
} catch {
    Write-Log "Unexpected script error: $_"
    Write-Host "A fatal error occurred. See log for details."
    $msg = if ($_.Exception.Message) { $_.Exception.Message } else { "Unknown error" }
    Write-ErrorLog -Operation "SomeOperation" -Message $msg -ErrorRecord $_
    $scriptEndTime = Get-Date
    $freeAfter = Get-FreeSpaceGB
    Show-Summary -freeBefore $freeBefore -freeAfter $freeAfter -LogFile $LogFile `
        -ScriptStartTime $scriptStartTime -ScriptEndTime $scriptEndTime
    exit 3
}