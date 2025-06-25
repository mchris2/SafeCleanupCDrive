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
    2025-06-23

.VERSION
    1.3.1

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
    Delete all shadow copies - Disabled by default
.PARAMETER CleanupWindowsPrefetch
    Clean Windows Prefetch - Disabled by default
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
if (-not $PSBoundParameters.ContainsKey('CleanupWindowsTemp'))      { $CleanupWindowsTemp      = $true }
if (-not $PSBoundParameters.ContainsKey('CleanupCTemp'))            { $CleanupCTemp            = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupUserTemp'))         { $CleanupUserTemp         = $true }
if (-not $PSBoundParameters.ContainsKey('CleanupWindowsUpdate'))    { $CleanupWindowsUpdate    = $true }
if (-not $PSBoundParameters.ContainsKey('CleanupIvantiPatchCache')) { $CleanupIvantiPatchCache = $true }
if (-not $PSBoundParameters.ContainsKey('CleanupFontCache'))        { $CleanupFontCache        = $true }
if (-not $PSBoundParameters.ContainsKey('CleanupRecycleBin'))       { $CleanupRecycleBin       = $true }
if (-not $PSBoundParameters.ContainsKey('CleanupShadowCopies'))     { $CleanupShadowCopies     = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupWindowsPrefetch'))  { $CleanupWindowsPrefetch  = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupRecentFiles'))      { $CleanupRecentFiles      = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupWindowsPatchCache')){ $CleanupWindowsPatchCache= $false }
if (-not $PSBoundParameters.ContainsKey('CleanupIISLogs'))          { $CleanupIISLogs          = $false }
if (-not $PSBoundParameters.ContainsKey('CleanupOrphanedProfiles')) { $CleanupOrphanedProfiles = $false }


# GLOBAL VARIABLES AND CONFIG
# --- Initialise script variables ---
$scriptStartTime = Get-Date
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$startDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $script:StepSizes) { $script:StepSizes = @{} }
$UserProfileRoot = "$env:SystemDrive\Users"

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

#region --- DATA STRUCTURES ---
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
#endregion


#region --- UTILITY FUNCTIONS ---
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

    $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $logLine = "[$timestamp] $Message"

    # Ensure log file exists
    if (-not (Test-Path -Path $LogFile)) {
        New-Item -Path $LogFile -ItemType File -Force -WhatIf:$false | Out-Null
    }
    # Write message to log file
    Add-Content -Path $LogFile -Value $logLine -WhatIf:$false
    # Optionally write to console, with colour if specified
    if (-not $LogOnly) {
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Colour') -and $Colour) {
            Write-Host $logLine -ForegroundColor $Colour
        } else {
            Write-Host $logLine
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
# User profile pattern matching - inclusion approach
$UserAccountIncludePatterns = @(
    # Standard AD account format: 2 letters followed by 2-7 numbers (with optional 'A' suffix)
    '^[a-zA-Z]{2}[0-9]{2,7}(A)?$',
    
    # DXC format
    '^DXC\.[a-zA-Z]+\.[a-zA-Z]+$',
    
    # Direct firstname.lastname format
    '^[a-zA-Z]+\.[a-zA-Z]+$',
    
    # Temporary profiles
    '^TEMP'
)

# Define significant size threshold (in GB)
$SignificantProfileSizeGB = 5
# Define "long time" not accessed threshold (in days)
$OldProfileThresholdDays = 180

<# Keep SystemAccounts for compatibility with other functions
$SystemAccounts = @(
    'Default', 'Default User', 'Public', 'All Users', 'Administrator',
    '.NET v4.5', '.NET v4.5 Classic', 'ASP.NET',
    'IUSR', 'NetworkService', 'LocalService', 'SYSTEM', 'TrustedInstaller',
    'MSSQL', 'SQLServer'
)
#>

# --- Retrieves user profile paths for specified account types ---
function Get-UserProfilePaths {
    param(
        [string[]]$AccountTypes,
        [string]$SubPath
    )
    $Global:UserProfiles | Where-Object { $_.AccountType -in $AccountTypes } | ForEach-Object {
        Join-Path $_.Path $SubPath
    }
}

# --- Determines the type of user profile based on name and SID ---
function Get-UserProfileType {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$SID,
        [Parameter(Mandatory = $true)]
        [string]$LocalSIDPrefix
    )
    # First check if it matches our known user patterns
    $isKnownUserPattern = $false
    foreach ($pattern in $UserAccountIncludePatterns) {
        if ($ProfileName -match $pattern) {
            $isKnownUserPattern = $true
            break
        }
    }
    
    # Special handling for empty/unknown SIDs
    if ([string]::IsNullOrEmpty($SID) -or $SID -eq "Unknown-SID") {
        # If it matches our user patterns, treat as Unknown
        # Otherwise treat as System to prevent accidental deletion
        if ($isKnownUserPattern) {
            return "Unknown"
        } else {
            return "System"
        }
    }
    
    # Handle special Windows accounts
    if ($SID -like "S-1-5-80-*") {
        return "Service"
    }
    
    # Handle local accounts
    if ($SID -like "$LocalSIDPrefix*") {
        if ($SID -match '-500$') { return "DefaultAdmin" }
        if ($SID -match '-501$') { return "DefaultGuest" }
        
        # Only consider it a normal local user if it matches our patterns
        If ($isKnownUserPattern) {
            return "Local"
        } else {
            return "System"
        }
    }
    
    # For domain accounts, only consider it a user if it matches our patterns
    If ($isKnownUserPattern) {
        return "Domain"
    } else {
        # If it doesn't match our patterns, treat as System
        return "System"
    }
}

# --- Calculate size of each profile folder and last accessed time ---
function Get-ProfileInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath
    )
    
    $size = 0
    $lastAccessed = $null
    
    try {
        # Get folder size (recursive)
        $size = (Get-ChildItem -Path $ProfilePath -Recurse -Force -ErrorAction SilentlyContinue | 
                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        
        # Get last accessed time from folder access time
        $lastAccessed = (Get-Item -Path $ProfilePath -Force -ErrorAction SilentlyContinue).LastAccessTime
    } catch {
        Write-Log "Warning: Could not get full information for profile $ProfilePath" -Colour Yellow
    }
    
    return @{
        Path = $ProfilePath
        SizeBytes = $size
        SizeGB = [math]::Round($size / 1GB, 2)
        LastAccessed = $lastAccessed
        DaysSinceAccess = if ($lastAccessed) { (New-TimeSpan -Start $lastAccessed -End (Get-Date)).Days } else { $null }
    }
}

# --- Retrieves all user profiles on the system, including SID and account type ---
function Get-UserProfiles {
    param(
        [switch]$IncludeSystemProfiles
    )
    
    Write-Log "Starting user profile analysis..." -LogOnly
    Write-Host "Scanning user profiles..." -ForegroundColor Cyan
    
    # Get computer SID prefix for local account detection
    Write-Log "Getting computer SID for local account detection..." -LogOnly
    $computerSid = (New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME + "\Administrator")).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $localSIDPrefix = $computerSid.Substring(0, $computerSid.LastIndexOf("-"))
    Write-Log "Local SID prefix: $localSIDPrefix" -LogOnly
    
    # First get a map of profile folders to SIDs
    Write-Log "Retrieving profile SID mappings..." -LogOnly
    Write-Host "  Retrieving profile SID mappings..." -ForegroundColor DarkGray
    $sidMap = Get-ProfileSIDMap
    Write-Log "Found $(($sidMap.Keys).Count) profile folders" -LogOnly
    
    $profiles = @()
    $nonMatchingProfiles = @()
    $profileCount = 0
    $userProfileCount = 0
    
    Write-Log "Processing profile folders..." -LogOnly
    Write-Host "  Processing profile folders in $UserProfileRoot" -ForegroundColor DarkGray
    
    $folderCount = (Get-ChildItem -Path $UserProfileRoot -Directory).Count
    Write-Host "  Found $folderCount profile folders to analyze" -ForegroundColor DarkGray
    
    Get-ChildItem -Path $UserProfileRoot -Directory | ForEach-Object {
        $profilePath = $_.FullName
        $profileName = $_.Name
        $profileCount++
        
        # Progress indicator
        if ($profileCount % 5 -eq 0 -or $profileCount -eq $folderCount) {
            Write-Host "  Processed $profileCount of $folderCount profiles..." -ForegroundColor DarkGray
        }
        
        Write-Log "Processing profile: $profileName" -LogOnly
        
        # Get the SID for this profile
        $sid = $sidMap[$profileName]
        if ([string]::IsNullOrEmpty($sid)) {
            $sid = "Unknown-SID"
            Write-Log "  No SID found for $profileName, using placeholder" -LogOnly
        }
        
        # Determine profile type
        Write-Log "  Determining profile type..." -LogOnly
        $profileType = Get-UserProfileType -ProfileName $profileName -SID $sid -LocalSIDPrefix $localSIDPrefix
        Write-Log "  Profile type: $profileType" -LogOnly
        
        # Get basic info about last accessed time
        try {
            $lastAccessed = (Get-Item -Path $profilePath -Force -ErrorAction SilentlyContinue).LastAccessTime
            $daysSinceAccess = (New-TimeSpan -Start $lastAccessed -End (Get-Date)).Days
            Write-Log "  Last accessed: $lastAccessed ($daysSinceAccess days ago)" -LogOnly
        } catch {
            $lastAccessed = $null
            $daysSinceAccess = $null
            Write-Log "  Warning: Could not get last access time for profile $profilePath" -Colour Yellow -LogOnly
        }
        
        # Calculate profile size (only for non-matching profiles that may need attention)
        $profileSize = $null
        $profileSizeGB = $null
        if ($profileType -eq "System" -or $profileType -eq "Unknown") {
            try {
                $profileSize = (Get-ChildItem -Path $profilePath -Recurse -Force -ErrorAction SilentlyContinue | 
                               Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                $profileSizeGB = [math]::Round($profileSize / 1GB, 2)
                Write-Log "  Profile size: $profileSizeGB GB" -LogOnly
            } catch {
                Write-Log "  Warning: Could not determine size for profile $profilePath" -Colour Yellow -LogOnly
            }
        }
        
        # Create profile object with account type based on our pattern matching
        $profileObj = [PSCustomObject]@{
            Name = $profileName
            Path = $profilePath
            SID = $sid
            Type = $profileType
            AccountType = if ($profileType -in @("Domain", "Local")) { $profileType } else { "System" }
            LastAccessed = $lastAccessed
            DaysSinceAccess = $daysSinceAccess
            SizeBytes = $profileSize
            SizeGB = $profileSizeGB
        }
        
        if ($profileType -in @("Domain", "Local")) {
            $userProfileCount++
            Write-Log "  Added as user profile: $profileName ($profileType)" -LogOnly
        }
        
        $profiles += $profileObj
        
        # Log warnings for non-matching profiles that meet certain criteria
        # Now properly using BOTH threshold variables
        if ($profileType -eq "System" -or $profileType -eq "Unknown") {
            $isOldProfile = ($daysSinceAccess -ge $OldProfileThresholdDays)
            $isLargeProfile = ($profileSizeGB -ge $SignificantProfileSizeGB)
            $matchesUserPattern = ($profileName -match ($UserAccountIncludePatterns -join '|'))
            
            if ($isOldProfile -or $isLargeProfile -or $matchesUserPattern) {
                $reasons = @()
                if ($isOldProfile) { $reasons += "not accessed for $daysSinceAccess days" }
                if ($isLargeProfile) { $reasons += "large size ($profileSizeGB GB)" }
                if ($matchesUserPattern) { $reasons += "matches user naming pattern" }
                
                Write-Log "  NOTE: Profile $profileName looks interesting: $($reasons -join ', ')" -Colour Yellow -LogOnly
                $nonMatchingProfiles += $profileObj
            }
        }
    }
    
    # Log information about non-matching profiles
    if ($nonMatchingProfiles.Count -gt 0) {
        Write-Log "Found $($nonMatchingProfiles.Count) profiles that may need attention:" -Colour Yellow
        Write-Host "  Found $($nonMatchingProfiles.Count) profiles that may need attention (see log for details)" -ForegroundColor Yellow
        foreach ($profileObj in $nonMatchingProfiles) {
            $reasons = @()
            if ($profileObj.DaysSinceAccess -ge $OldProfileThresholdDays) { 
                $reasons += "not accessed for $($profileObj.DaysSinceAccess) days" 
            }
            if ($profileObj.SizeGB -ge $SignificantProfileSizeGB) { 
                $reasons += "large size ($($profileObj.SizeGB) GB)" 
            }
            if ($profileObj.Name -match ($UserAccountIncludePatterns -join '|')) { 
                $reasons += "matches user naming pattern" 
            }
            
            Write-Log "  - $($profileObj.Name): Categorized as $($profileObj.Type), $($reasons -join ', ')" -Colour Yellow
        }
        Write-Log "These profiles were not cleaned as they don't match user profile patterns." -Colour Yellow
    }
    
    # Filter out system profiles if not requested
    if (-not $IncludeSystemProfiles) {
        $profiles = $profiles | Where-Object { $_.AccountType -in @("Domain", "Local") }
    }
    
    Write-Log "Profile analysis complete. Found $profileCount total profiles ($userProfileCount user profiles, $(($profiles | Where-Object { $_.AccountType -eq 'Domain' }).Count) domain, $(($profiles | Where-Object { $_.AccountType -eq 'Local' }).Count) local)" -LogOnly
    Write-Host "Found $profileCount total profiles ($userProfileCount user profiles)" -ForegroundColor Cyan
    
    return $profiles
}

# --- Retrieves a user object from Active Directory via LDAP ---
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

# --- Retrieves the local machine SID prefix ---
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
    $folders = Get-ChildItem $UserProfileRoot -Directory
    Write-Log "Found $($folders.Count) profile folders in $UserProfileRoot" -LogOnly
    
    # Try CIM first
    try {
        Write-Log "Trying to get profile SIDs using CIM..." -LogOnly
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -like "$UserProfileRoot\*" }
        Write-Log "Retrieved $($profiles.Count) profiles via CIM" -LogOnly
        
        foreach ($profile in $profiles) {
            $folder = Split-Path $profile.LocalPath -Leaf
            $map[$folder] = $profile.SID
            Write-Log "  Mapped $folder to SID $($profile.SID)" -LogOnly
        }
    } catch {
        # Fallback to WMI
        Write-Log "CIM failed, trying WMI: $_" -Colour Yellow -LogOnly
        try {
            Write-Log "Trying to get profile SIDs using WMI..." -LogOnly
            $profiles = Get-WmiObject Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -like "$UserProfileRoot\*" }
            Write-Log "Retrieved $($profiles.Count) profiles via WMI" -LogOnly
            
            foreach ($profile in $profiles) {
                $folder = Split-Path $profile.LocalPath -Leaf
                $map[$folder] = $profile.SID
                Write-Log "  Mapped $folder to SID $($profile.SID)" -LogOnly
            }
        } catch {
            Write-Log "WARNING: Falling back to folder names for profile SID mapping. Orphaned profile detection may be less accurate." -Colour Yellow
            Write-Log "WMI Error: $_" -Colour Yellow -LogOnly
        }
    }
    
    # Ensure every folder is mapped (even if not in Win32_UserProfile)
    $unmappedCount = 0
    foreach ($folder in $folders) {
        if (-not $map.ContainsKey($folder.Name)) {
            $map[$folder.Name] = "Unknown-SID"
            $unmappedCount++
            Write-Log "  No SID found for folder $($folder.Name), using placeholder" -LogOnly
        }
    }
    if ($unmappedCount -gt 0) {
        Write-Log "$unmappedCount profile folders had no corresponding SID information" -Colour Yellow -LogOnly
    }
    
    Write-Log "Profile SID mapping complete. Mapped $($map.Count) profiles." -LogOnly
    return $map
}

#endregion

#region --- CORE CLEANUP FUNCTIONS ---
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
    $filesDeleted = 0 # Successfully deleted files

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
                        $filesDeleted++
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
                    $filesDeleted++
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
#endregion

#region --- SPECIAL HANDLERS ---
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
            # Track the size after emptyting 
            $binContents = Show-RecycleBinContents
            $sizeAfter = ($binContents | Measure-Object -Property SizeBytes -Sum).Sum
            # Add the step result with size tracking
            Add-StepResult -StepName "Recycle Bin" -BytesBefore $sizeBefore -BytesDeleted ($sizeBefore - $sizeAfter)
        } catch {
            # Log the error and add to failure list
            Write-ErrorLog -Operation "RecycleBin" -Message "Could not empty Recycle Bin" -ErrorRecord $_ -Severity 'Warning'
            $binContents = Show-RecycleBinContents
            # Track the size after emptyting (even if it failed)
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

# --- Cleans up orphaned user profiles by checking if they still exist in Active Directory ---
function Clear-OrphanedProfiles {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    Write-Log "-- STARTING: Orphaned user profile cleanup --"
    Write-Host "`nChecking for orphaned domain user profiles..." -ForegroundColor Cyan
    
    $domainNetbios = $null
    try {
        $ntDomain = Get-WmiObject Win32_NTDomain | Where-Object { $_.DnsForestName } | Select-Object -First 1
        if ($ntDomain) {
            $domainNetbios = $ntDomain.DomainName
            Write-Log "Domain NetBIOS name: $domainNetbios" -LogOnly
        } else {
            Write-Log "Could not determine domain NetBIOS name" -Colour Yellow -LogOnly
        }
    } catch {
        Write-Log "Error getting domain information: $_" -Colour Yellow -LogOnly
    }
    
    $orphaned = @()
    $statusList = @()

    # Use the centralized user profile list
    $profiles = $Global:UserProfiles | Where-Object { $_.AccountType -eq 'Domain' }
    
    Write-Log "Checking $($profiles.Count) domain user profiles for orphaned accounts..."
    Write-Host "Found $($profiles.Count) domain user profiles to check against Active Directory"

    $checkCount = 0
    foreach ($userProfile in $profiles) {
        $checkCount++
        # Progress indicator
        if ($checkCount % 5 -eq 0 -or $checkCount -eq $profiles.Count) {
            Write-Host "  Checked $checkCount of $($profiles.Count) profiles..." -ForegroundColor DarkGray
        }
        
        # Extract username if folder ends with .DOMAIN
        $adUser = $userProfile.Name
        if ($domainNetbios -and $userProfile.Name -like "*.$domainNetbios") {
            $adUser = $userProfile.Name.Substring(0, $userProfile.Name.Length - $domainNetbios.Length - 1)
            Write-Log "Processing profile: $($userProfile.Name) (AD username: $adUser)" -LogOnly
        } else {
            Write-Log "Processing profile: $adUser" -LogOnly
        }
        
        Write-Log "  Checking AD for user: $adUser" -LogOnly
        $userObj = Get-LdapUser -Username $adUser
        
        # Suppress error output from LDAP queries to console
        $ErrorActionPreference_Original = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        $userObj = Get-LdapUser -Username $adUser 2>$null
        $ErrorActionPreference = $ErrorActionPreference_Original

        if (-not $userObj) {
            $status = "Not found in AD"
            $orphaned += $userProfile
            Write-Log "  Result: Not found in Active Directory" -LogOnly
        } elseif (($userObj.UserAccountControl -band 2) -ne 0) {
            $status = "Disabled in AD"
            $orphaned += $userProfile
            Write-Log "  Result: Account is disabled in Active Directory" -LogOnly
        } else {
            $status = "Active in AD"
            Write-Log "  Result: Active account in Active Directory" -LogOnly
        }
        $statusList += [PSCustomObject]@{
            Profile = $userProfile.Name
            Path    = $userProfile.Path
            Status  = $status
        }
    }

    # Output status list
    Write-Log "User profile status before deletion:"
    Write-Host "`nUser profile status summary:" -ForegroundColor Cyan
    $statusList | ForEach-Object {
        $colorCode = switch ($_.Status) {
            "Not found in AD" { "Red" }
            "Disabled in AD" { "Yellow" }
            "Active in AD" { "Green" }
            default { "White" }
        }
        
        $msg = "{0,-20} {1,-40} {2}" -f $_.Profile, $_.Path, $_.Status
        Write-Log $msg
        
        # In console, use colors based on status
        Write-Host $_.Profile.PadRight(20) -NoNewline
        Write-Host $_.Path.PadRight(40) -NoNewline
        Write-Host $_.Status -ForegroundColor $colorCode
    }

    if ($orphaned.Count -eq 0) {
        Write-Log "No orphaned profiles found for deletion."
        Write-Host "`nNo orphaned profiles found for deletion." -ForegroundColor Green
        Add-StepResult -StepName "OrphanedProfiles" -BytesBefore 0 -BytesDeleted 0
        Write-Log "-- FINISHED: Orphaned user profile cleanup --"
        return
    }

    Write-Host ""
    Write-Host "Found $($orphaned.Count) orphaned profiles to delete." -ForegroundColor Yellow
    Write-Host "Press Enter to proceed with deleting orphaned profiles, or Ctrl+C to abort..." -ForegroundColor Yellow
    if ($host.Name -ne 'Windows PowerShell ISE Host') {
        [void][System.Console]::ReadLine()
    } else {
        Write-Host "(ISE detected: waiting 10 seconds instead of keypress...)" -ForegroundColor Yellow
        Start-Sleep -Seconds 10
    }

    # Proceed with deletion
    $bytesBefore = 0
    $bytesDeleted = 0
    $failedDeletions = @()
    
    Write-Host "`nDeleting orphaned profiles..." -ForegroundColor Cyan
    $deleteCount = 0
    foreach ($userProfile in $orphaned) {
        $deleteCount++
        Write-Host "  Deleting profile $deleteCount of $($orphaned.Count): $($userProfile.Name)..." -ForegroundColor Yellow
        
        # Get size before deletion
        Write-Log "Calculating size of profile $($userProfile.Path) before deletion..." -LogOnly
        $profileSize = 0
        try {
            $profileSize = (Get-ChildItem -Path $userProfile.Path -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            Write-Log "Profile size: $([math]::Round($profileSize / 1MB, 2)) MB" -LogOnly
        } catch {
            Write-Log "Could not determine size of profile $($userProfile.Path): $_" -LogOnly
        }
        
        $bytesBefore += $profileSize
        
        Write-Log "Deleting profile: $($userProfile.Path)" -LogOnly
        $result = Remove-Safe -Path $userProfile.Path
        $bytesDeleted += $result.BytesDeleted
        
        foreach ($r in $result.Results) {
            if (-not $r.Success) {
                $failedDeletions += $r.Path
            }
        }
        
        if ($result.BytesDeleted -gt 0) {
            Write-Host "    Deleted $([math]::Round($result.BytesDeleted / 1MB, 2)) MB" -ForegroundColor Green
        } else {
            Write-Host "    No data deleted" -ForegroundColor DarkGray
        }
    }
    Add-StepResult -StepName "OrphanedProfiles" -BytesBefore $bytesBefore -BytesDeleted $bytesDeleted
    
    Write-Host "`nOrphaned profile cleanup complete" -ForegroundColor Cyan
    Write-Host "  Total space reclaimed: $([math]::Round($bytesDeleted / 1MB, 2)) MB" -ForegroundColor Green
    
    if ($failedDeletions.Count -gt 0) {
        Write-Log "Failed to delete the following orphaned profiles:" -Colour Yellow -LogOnly
        Write-Host "`nWARNING: Failed to delete some items:" -ForegroundColor Yellow
        $failedDeletions | ForEach-Object { 
            Write-Log " - $_" -LogOnly
            Write-Host "  - $_" -ForegroundColor Yellow
        }
    }
    Write-Log "-- FINISHED: Orphaned user profile cleanup --"
}

#endregion

#region --- SUMMARY AND REPORTING FUNCTIONS ---
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

function Write-SummaryTable {
    param(
        [hashtable]$StepSizes,
        [bool]$IsWhatIf
    )
    $totalBefore = 0
    $totalDeleted = 0
    $totalAfter = 0
    foreach ($step in $StepSizes.Keys) {
        $before = $StepSizes[$step].Before | Convert-Size -To GB
        $deleted = $StepSizes[$step].Deleted | Convert-Size -To GB
        $after = $before - $deleted
        $totalBefore += $before
        $totalDeleted += $deleted
        $totalAfter += $after
        If ($IsWhatIf) {
            Write-Log ("{0,-30} {1,17:N3}" -f $step, $before)
        } else {
            Write-Log ("{0,-20} {1,12:N3} {2,14:N3} {3,12:N3}" -f $step, $before, $deleted, $after)
        }
    }
    return @{
        TotalBefore = $totalBefore
        TotalDeleted = $totalDeleted
        TotalAfter = $totalAfter
    }
}

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
        [datetime]$scriptEndTime,
        [Parameter(Mandatory = $false)]
        [bool]$IsWhatIf = $WhatIfPreference  # Use $WhatIfPreference as default
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

    $summaryTotals = Write-SummaryTable -StepSizes $script:StepSizes -IsWhatIf $IsWhatIf
    $totalBefore = $summaryTotals.TotalBefore
    $totalDeleted = $summaryTotals.TotalDeleted
    $totalAfter = $summaryTotals.TotalAfter

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
#endregion

#region --- STEP DISPATCHER ---
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
        # If not WhatIf, report the total bytes before and deleted for this step
        if (-not $WhatIfPreference) {
            Add-StepResult -StepName $StepName -BytesBefore $beforeTotal -BytesDeleted $deletedTotal
        }
    } catch {
        Write-ErrorLog -Operation "Cleanup$StepName" `
            -Message "Failed to perform cleanup for $StepName" `
            -ErrorRecord $_ `
            -Severity 'Critical'
    } finally {
        # Ensure service is restarted if it was running before
        if ($wasRunning) {
            Set-ServiceState -Name $config.ServiceName -State 'Running' -AbortOnFailure:$false | Out-Null
        }
        Write-Log "-- FINISHED: $($config.Description) --"
    }
}

#endregion
#region --- EXECUTION START ---
Write-Log "SafeCleanupCDrive started." -LogOnly
Write-Host "SafeCleanupCDrive started. Version: 1.3.1" -ForegroundColor Green

# --- INITIAL CLEANUP CHECKS ---
# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Configure the scheduled task to run with Administrator privileges." -ForegroundColor Yellow
    Write-Log "ERROR: Script attempted to run without Administrator privileges. Exiting."
    exit 1
}

# --- Log initial parameters
Write-Log "Initial parameters:" -LogOnly
foreach ($param in $PSBoundParameters.Keys) {
    $value = $PSBoundParameters[$param]
    Write-Log ("  {0} = {1}" -f $param, $value) -LogOnly
}

# --- Check and create log file
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

# --- MAIN CLEANUP LOGIC ---
# Perform the cleanup for each requested step
$steps = @(
    'WindowsTemp',
    'CTemp',
    'UserTemp',
    'WindowsUpdate',
    'IvantiPatchCache',
    'FontCache',
    'RecycleBin',
    'ShadowCopies',
    'WindowsPrefetch',
    'RecentFiles',
    'WindowsPatchCache',
    'IISLogs',
    'OrphanedProfiles'
)

foreach ($step in $steps) {
    # Check if this step is enabled
    if ($PSBoundParameters["Cleanup$step"]) {
        Invoke-Cleanup -StepName $step
    } else {
        Write-Log "Skipping cleanup for $step (not enabled)" -LogOnly
    }
}

# --- FINAL REPORTING ---
$freeBefore = Get-FreeSpaceGB
$freeAfter = Get-FreeSpaceGB

# Write final summary
Show-Summary -freeBefore $freeBefore -freeAfter $freeAfter -LogFile $LogFile -scriptStartTime $scriptStartTime -scriptEndTime (Get-Date)

Write-Log "SafeCleanupCDrive completed." -LogOnly
Write-Host "SafeCleanupCDrive completed. Log file: $LogFile" -ForegroundColor Green

#endregion

# --- END OF SCRIPT ---