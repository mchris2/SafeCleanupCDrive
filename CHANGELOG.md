# CHANGELOG

## [1.3.1] - 2025-06-23
- Converted `Get-UserProfileType` and `Get-UserProfiles` to inclusion approach instead of exclusion.
- Added `Get-ProfileInfo` to check for profiles over a specified size and/or not accessed in a long time. Any profiles not picked up int he inclusion approach will be reported in the console and logfile but not actioned.
- Added progress indicator to Remove-Safe and additional output to console so easier to track progress
- Minor fixes to summary output
- Added #endregion to each region for consistency

## [1.3.0] - 2025-06-04
### Added
- Centralised user profile discovery and filtering: introduced `Get-UserProfiles` and improved `Get-UserProfileType` for robust account type detection (Domain, Local, Service, System, DefaultAdmin, DefaultGuest, Unknown).
- `AccountTypes` array added to relevant steps in `$CleanupConfig` for explicit control over which user profile types are processed per cleanup step.
- Helper function `Get-UserProfilePaths` for DRY, consistent dynamic path generation based on allowed account types.
- Improved SID mapping: `Get-ProfileSIDMap` now ensures all folders in `C:\Users` are mapped, even if not registered in Win32_UserProfile.
- Enhanced LDAP lookup logic: only performed for true domain accounts, with correct username extraction for `.DOMAIN` profile folders.
- Service SIDs and built-in/renamed Administrator and Guest accounts are now reliably excluded from all user profile operations.

### Changed
- All user-profile-based cleanup steps (UserTemp, RecentFiles, OrphanedProfiles) now use the centralised user profile list and account type filtering for consistency and maintainability.
- Refactored redundant or legacy filtering functions; logic is now unified and easier to maintain.
- Updated dynamic path generation in `$CleanupConfig` to reference `AccountTypes` directly, eliminating duplication.

### Fixed
- Fixed issues where local, service, or renamed system accounts could be incorrectly processed or trigger LDAP errors.
- Improved handling of user profiles present in `C:\Users` but missing from WMI/CIM profile lists.
- Corrected username extraction for domain profiles with dots in the username or domain name.

---

## [1.2.0] - 2025-06-03
### Added
- Administrator privilege check at script start; script exits with a message if not run as admin.
- Countdown and user-interruptible pause before execution (press Enter to continue or Ctrl+C to abort).
- Logging of enabled and skipped cleanup steps, with clear output for WhatIf (simulation) mode.
- Enhanced summary reporting, including before/after free space, per-step size tracking, and total time taken.
- Improved error handling and logging, including detailed error objects and critical error highlighting.
- Class-based structure (`RemovalResult`) for structured file/directory removal results.
- Modular cleanup functions for each step (Windows Temp, C:\Temp, User Temp, Windows Update, Ivanti Patch Cache, Font Cache, Recycle Bin, Shadow Copies, Windows Prefetch, Recent Files, Windows Patch Cache, IIS Logs).
- WhatIf support for all destructive actions, with clear simulation output.
- User profile filtering to exclude system and service accounts from user temp cleanup.
- IIS Logs cleanup: compresses logs >30 days old, deletes archives >60 days old, with per-step logging.
- Recycle Bin handling: lists contents per user, empties bin, and logs before/after sizes.
- Shadow Copies cleanup using `vssadmin`, with error handling and WhatIf support.
- Utility functions for logging, error logging, size conversion, and safe path checks.

### Changed
- Unified summary reporting with per-step size tracking and improved formatting.
- Improved code readability and maintainability with detailed comments and consistent parameter blocks.
- Enhanced logging: all actions, errors, and WhatIf operations are logged to file and optionally to console.
- Improved handling of log file path: supports both directory and file input, ensures directory exists.
- Refactored service handling: stops/starts services as needed for cleanup steps, with timeout and error handling.
- Improved handling of skipped steps and reporting in both WhatIf and live modes.

### Fixed
- Improved error handling for missing paths, failed deletions, and service operations.
- Fixed issues with user profile filtering and dynamic path generation for user temp and recent files.
- Fixed summary reporting to handle unknown or non-numeric free space values gracefully.

---

## [1.1.0] - 2025-05-26
### Added
- Consistent parameter block formatting and comments for all functions.
- Enhanced logging and error handling throughout the script.
- Detailed comments and explanations for maintainability.
- Countdown and user-interruptible pause before execution.
- Enhanced Recycle Bin and shadow copy handling and reporting.
- Class for structured removal results.
- General code clean-up and uniformity improvements.

---

## [1.0.0] - 2025-05-23
### Added
- Initial version: modular cleanup functions for Windows temp files, user temp files, C:\Temp, Windows Update leftovers, ProPatch cache, font cache, shadow copies, $PatchCache, and Recycle Bin.
- Logging of actions and summary reporting.
- Must be run as Administrator.