# SafeCleanupCDrive
PowerShell script for cleaning up common temporary and update files from C drive on servers

Performs the following actions:
* Clean C:\Windows\Temp
* Clean C:\Temp
* Clean user profile temp folders
* Clean Windows Update leftovers
* Clean the Ivanti ProPatch cache
* Clean font cache and restart FontCache service
* Empty Recycle Bin
* Delete all shadow copies -Disabled by default
* Clean Windows Prefetch -Disabled by default
* Clean Recent Files - Disabled by default
* Clean C:\Windows\Installer\$PatchCache - Disabled by default
* Compresses IIS Logs >30 days old to an Archive subfolder and deletes archived >60 days old - Disabled by default

Switches are available to enable and disable each of the actions. By defaul the first 7 are enabled. To disable use switches as follows:
-CleanupCTemp:false
-CleanupWindowsTemp:false
-CleanupUserTemp:false
-CleanupWindowsUpdate:false
-CleanupIvantiPatchCache:false
-CleanupFontCache:false
-CleanupRecycleBin:false
-CleanupShadowCopies
-CleanupWindowsPrefetch
-CleanupRecentFiles
-CleanupWindowsPatchCache
-CleanupIISLogs

There are additional switches for:
-LogFilePath
-WhatIf

Script needs to be run as an Administrator
