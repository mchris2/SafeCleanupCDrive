# SafeCleanupCDrive
PowerShell script for cleaning up common temporary and update files from C drive on servers

## Prerequisites
- PowerShell 5.1 or later (Windows 10/11, Server 2016/2019/2022)
- Must be run as Administrator

## Installation
Clone or download this repository:
```powershell
git clone https://github.com/mchris2/SafeCleanupCDrive.git
```

## Usage Examples
```powershell
# Basic usage (default actions)
.\SafeCleanupCDrive.ps1

# Disable Windows Update leftovers cleanup, enable WhatIf mode
.\SafeCleanupCDrive.ps1 -CleanupWindowsUpdate:$false -WhatIf

# Only clean user temp and orphaned profiles
.\SafeCleanupCDrive.ps1 -CleanupUserTemp -CleanupOrphanedProfiles
```

## Performs the following actions
* Clean C:\Windows\Temp
* Clean C:\Temp (Disabled by default)
* Clean user profile temp folders (Domain/Local accounts only)
* Clean Windows Update leftovers
* Clean the Ivanti ProPatch cache
* Clean font cache and restart FontCache service
* Empty Recycle Bin
* Delete all shadow copies (Disabled by default)
* Clean Windows Prefetch (Disabled by default)
* Clean Recent Files (Disabled by default)
* Clean C:\Windows\Installer\$PatchCache (Disabled by default)
* Compresses IIS Logs >30 days old to an Archive subfolder and deletes archived >60 days old (Disabled by default)
* Delete user profiles for accounts that are disabled or no longer exist in AD (Disabled by default)

## Switches
Switches are available to enable and disable each of the actions. By default, the following are enabled unless specified otherwise:

- `-CleanupWindowsTemp` (default: true)
- `-CleanupCTemp` (default: false)
- `-CleanupUserTemp` (default: true)
- `-CleanupWindowsUpdate` (default: true)
- `-CleanupIvantiPatchCache` (default: true)
- `-CleanupFontCache` (default: true)
- `-CleanupRecycleBin` (default: true)
- `-CleanupShadowCopies` (default: false)
- `-CleanupWindowsPrefetch` (default: false)
- `-CleanupRecentFiles` (default: false)
- `-CleanupWindowsPatchCache` (default: false)
- `-CleanupIISLogs` (default: false)
- `-CleanupOrphanedProfiles` (default: false)

Additional switches:
- `-LogFilePath` (specify custom log file location)
- `-WhatIf` (simulate actions without making changes)

## Notes
- User-profile-based cleanup steps use robust account type filtering (Domain/Local accounts only).
- Script needs to be run as an Administrator.
- See [CHANGELOG.md](CHANGELOG.md) for recent improvements and details.

## Troubleshooting / FAQ
- **Script fails with permission error:** Run PowerShell as Administrator.
- **Some files are not deleted:** Files may be locked or in use by the system. Try running after a reboot.
- **WhatIf mode does not delete files:** This is expected; WhatIf simulates actions only.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request. For details, see [CONTRIBUTING.md](CONTRIBUTING.md) if available.

## License
This project is licensed under the terms of the license found in the [LICENSE](LICENSE) file.

## Contact / Support
For questions, suggestions, or issues, please use the GitHub Issues page.
