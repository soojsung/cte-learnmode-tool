#requires -Version 5.0
<#
.SYNOPSIS
    CTE Tool - A utility for parsing Vormetric DataSecurityExpert agent logs and listing user/process access.

.DESCRIPTION
    This tool reads Vormetric log files (vorvmd*.log) from the specified path
    and provides a detailed list of users and processes that accessed guarded resources.
    No additional parameters are needed - it simply lists all access information found.

.PARAMETER LogPath
    Path to the log file or directory containing log files.
    Default: C:\ProgramData\Vormetric\DataSecurityExpert\agent\log\vorvmd.log

.PARAMETER All
    When specified, processes INFO labeled access logs instead of LEARN MODE logs.
    By default, only LEARN MODE logs are processed.

.EXAMPLE
    .\cte-tool.ps1
    Processes default log file and displays users and processes that accessed guarded resources (LEARN MODE only).

.EXAMPLE
    .\cte-tool.ps1 -LogPath "C:\Logs\vorvmd.log"
    Processes a specific log file and displays users and processes that accessed guarded resources (LEARN MODE only).

.EXAMPLE
    .\cte-tool.ps1 -LogPath "C:\ProgramData\Vormetric\DataSecurityExpert\agent\log"
    Processes all log files in the specified directory and displays users and processes that accessed guarded resources (LEARN MODE only).

.EXAMPLE
    .\cte-tool.ps1 -All
    Processes all log files in the default directory including only INFO labeled access logs.

.EXAMPLE
    .\cte-tool.ps1 -LogPath "C:\Logs\vorvmd.log" -All
    Processes a specific log file including only INFO labeled access logs.

.NOTES
    Author: CTE Tool
    Version: 3.0
#>

param (
    [ValidateNotNullOrEmpty()]
    [string]$logpath = "C:\ProgramData\Vormetric\DataSecurityExpert\agent\log",
    
    [switch]$all
)

# =========================== CONSTANTS ===========================
# Define constants for better readability
$script:PROGRESS_UPDATE_FREQUENCY = 1000  # Update progress every X lines
$script:MAX_ITEMS_TO_DISPLAY = 1000      # Increased to show all items (virtually no limit)
$script:DEFAULT_CONSOLE_WIDTH = 80       # Default console width if not available

# Unicode characters for modern display
$script:UNICODE_BOX_DOUBLE = [char]0x2550
$script:UNICODE_BOX_SINGLE = [char]0x2500
$script:UNICODE_ARROW = [char]0x2192
$script:UNICODE_BULLET = "-"  # Changed from Unicode bullet to simple hyphen
$script:UNICODE_CHECK = [char]0x2713

# =========================== FUNCTIONS ===========================

# Get console width with fallback if not available
function Get-ConsoleWidth {
    try {
        # Try to get the actual console width
        if ($host -and $host.UI -and $host.UI.RawUI -and $host.UI.RawUI.WindowSize -and $host.UI.RawUI.WindowSize.Width) {
            return $host.UI.RawUI.WindowSize.Width
        }
    } catch {
        # Silently handle any errors
    }
    
    # Return default width if actual width not available
    return $script:DEFAULT_CONSOLE_WIDTH
}

# Create a divider string with the specified character and length
function Get-Divider {
    param(
        [string]$Character,
        [int]$Length
    )
    
    # Create a string of repeated characters using PadRight
    return "".PadRight($Length, $Character[0])
}

function Format-FileSize {
    param([long]$Size)
    
    if ($Size -lt 1KB) {
        return "$Size bytes"
    }
    elseif ($Size -lt 1MB) {
        return "{0:N2} KB" -f ($Size / 1KB)
    }
    elseif ($Size -lt 1GB) {
        return "{0:N2} MB" -f ($Size / 1MB)
    }
    else {
        return "{0:N2} GB" -f ($Size / 1GB)
    }
}

function Get-LogFiles {
    param([string]$Path)
    
    if ([string]::IsNullOrEmpty($Path)) {
        Write-Host "Error: Empty path specified" -ForegroundColor Red
        return $null
    }
    
    # Make sure the path is absolute
    try {
        $Path = [System.IO.Path]::GetFullPath($Path)
    } catch {
        Write-Host "Error: Invalid path format: $Path" -ForegroundColor Red
        return $null
    }
    
    Write-Host "Checking path: $Path" -ForegroundColor Cyan
    
    # Verify the path is a directory
    if (-not (Test-Path -Path $Path -PathType Container)) {
        Write-Host "Error: The specified path is not a directory: $Path" -ForegroundColor Red
        Write-Host "The -LogPath parameter must specify a directory containing log files, not a specific file." -ForegroundColor Yellow
        return $null
    }
    
        # Look for Vormetric log files with Windows patterns
        try {
        $LogFiles = @(Get-ChildItem -Path $Path -Filter "vorvmd*.log*" -ErrorAction Stop | ForEach-Object { $_.FullName })
            
            if ($LogFiles.Count -eq 0) {
            Write-Host "Could not find any CTE log files matching pattern 'vorvmd*.log*' in $Path" -ForegroundColor Red
                return $null
            }
            
            # Verify each file can be accessed
            $ValidFiles = @()
            foreach ($file in $LogFiles) {
                try {
                    # Check if file can be opened for reading
                    $stream = [System.IO.File]::Open($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    $stream.Close()
                    $stream.Dispose()
                    $ValidFiles += $file
                } 
                catch {
                    Write-Host "Warning: File $(Split-Path -Leaf $file) cannot be accessed (it may be locked by another process): $_" -ForegroundColor Yellow
                }
            }
            
            if ($ValidFiles.Count -eq 0) {
            Write-Host "No accessible log files found in $Path" -ForegroundColor Red
                return $null
            }
            
            return $ValidFiles
        }
        catch {
        Write-Host "Error accessing directory $Path`: $_" -ForegroundColor Red
        Write-Host "Please check directory permissions or try running as Administrator" -ForegroundColor Yellow
            return $null
    }
}

# Define a class to store log entries
class LogEntry {
    [string]$Policy
    [string]$UserName
    [string]$UserDomain
    [string]$ProcessName
    [string]$ResourcePath
    [string]$ActionName
    [string[]]$UserGroups = @()
    [int]$Count = 1
    
    LogEntry([string]$policy, [string]$user, [string]$domain, [string]$process, [string]$resource, [string]$action, [string[]]$groups) {
        $this.Policy = $policy
        $this.UserName = $user
        $this.UserDomain = $domain
        $this.ProcessName = $process
        $this.ResourcePath = $resource
        $this.ActionName = $action
        $this.UserGroups = $groups
    }
    
    [string] ToString() {
        return "$($this.Policy) | $($this.UserName) | $($this.ProcessName) | $($this.ResourcePath) | $($this.ActionName) | $($this.Count)"
    }
}

# Define a class for the log model
class LogModel {
    [System.Collections.ArrayList]$Entries = [System.Collections.ArrayList]::new()
    [hashtable]$ActionDescriptions = @{
        'create_file' = @('creating', 'f_cre')
        'flush_dir' = @('', '')
        'flush_file' = @('', '')
        'get_key' = @('', '')
        'ioctl_dir' = @('', '')
        'ioctl_file' = @('', '')
        'key_op' = @('', '')
        'link' = @('creating', 'write')
        'lock_dir' = @('', '')
        'lock_file' = @('', '')
        'make_dir' = @('creating', 'd_mkdir')
        'mknod' = @('creating', 'd_mknod')
        'read_attr' = @('reading meta', 'f_rd_att')
        'read_dir' = @('listing', 'd_rd')
        'read_dir_attr' = @('reading meta', 'd_rd_att')
        'read_dir_sec_attr' = @('reading meta', 'd_rd_sec')
        'read_file' = @('reading', 'f_rd')
        'read_file_sec_attr' = @('reading meta', 'f_rd_sec')
        'remove_dir' = @('removing', 'd_rmdir')
        'remove_file' = @('removing', 'f_rm')
        'rename' = @('renaming', 'f_ren')
        'symlink' = @('creating', 'write')
        'unknown_acc' = @('unknown', '')
        'write_app' = @('writing', 'f_wr_app')
        'write_dir_attr' = @('writing meta', 'd_chg_att')
        'write_dir_sec_attr' = @('writing meta', 'd_chg_sec')
        'write_dir_sec_attr_size' = @('writing meta', 'd_chg_sec')
        'write_file' = @('writing', 'f_wr')
        'write_file_attr' = @('writing meta', 'f_chg_att')
        'write_file_sec_attr' = @('writing meta', 'f_chg_sec')
        'write_file_sec_attr_size' = @('writing meta', 'f_chg_sec')
    }
    
    # To store guardpoint paths
    [System.Collections.ArrayList]$GuardPoints = [System.Collections.ArrayList]::new()
    
    [void] AddEntry([LogEntry]$entry) {
        # Try to find an existing matching entry to update count
        $existingEntry = $this.Entries | Where-Object {
            $_.Policy -eq $entry.Policy -and
            $_.UserName -eq $entry.UserName -and
            $_.UserDomain -eq $entry.UserDomain -and
            $_.ProcessName -eq $entry.ProcessName -and
            $_.ResourcePath -eq $entry.ResourcePath -and
            $_.ActionName -eq $entry.ActionName
        } | Select-Object -First 1
        
        if ($existingEntry) {
            $existingEntry.Count++
            
            # Merge any new groups into the existing entry's groups
            foreach ($group in $entry.UserGroups) {
                if (-not $existingEntry.UserGroups.Contains($group)) {
                    $existingEntry.UserGroups += $group
                }
            }
        }
        else {
            [void]$this.Entries.Add($entry)
        }
        
        # Extract potential guardpoint folders
        $this.TryAddGuardPoint($entry.ResourcePath)
    }
    
    [void] TryAddGuardPoint([string]$path) {
        try {
            # For resources like files, get their parent directory
            $dirPath = [System.IO.Path]::GetDirectoryName($path)
            
            # If the path itself is a directory that ends with a backslash, use it directly
            if ([string]::IsNullOrEmpty($dirPath) -and $path -match '\\$') {
                $dirPath = $path.TrimEnd('\')
            }
            
            # If dirPath is empty but path matches a drive letter pattern, use the path
            if ([string]::IsNullOrEmpty($dirPath) -and $path -match '^[A-Za-z]:$') {
                $dirPath = $path
            }

            # SQL Server data path detection
            if ($path -match '^([A-Za-z]:\\Program Files\\Microsoft SQL Server\\[^\\]+\\MSSQL\\DATA)') {
                $sqlDataPath = $matches[1]
                if (-not ($this.GuardPoints -contains $sqlDataPath)) {
                    [void]$this.GuardPoints.Add($sqlDataPath)
                }
                return
            }

            # Add the specific directory as a potential guardpoint
            if (-not [string]::IsNullOrEmpty($dirPath)) {
                # Check for common application data paths that should be considered as guardpoints
                $potentialGuardpoints = @()

                # Add the immediate parent directory
                $potentialGuardpoints += $dirPath

                # Add SQL Server related paths
                if ($dirPath -match '\\Microsoft SQL Server\\') {
                    $sqlMatch = [regex]::Match($dirPath, '^([A-Za-z]:\\Program Files\\Microsoft SQL Server\\[^\\]+\\MSSQL\\[^\\]+)')
                    if ($sqlMatch.Success) {
                        $potentialGuardpoints += $sqlMatch.Groups[1].Value
                    }
                }

                # Add other application-specific paths here as needed
                # Example: if ($dirPath -match '\\AppName\\') { ... }

                # Add each potential guardpoint if it's not already in the list
                foreach ($guardpoint in $potentialGuardpoints) {
                    if (-not ($this.GuardPoints -contains $guardpoint)) {
                        [void]$this.GuardPoints.Add($guardpoint)
                    }
                }
            }
        } catch {
            # Silently ignore if path parsing fails
        }
    }
    
    [string] GetActionDescription([string]$actionName) {
        if ($this.ActionDescriptions.ContainsKey($actionName)) {
            $desc = $this.ActionDescriptions[$actionName][0]
            return $(if ($desc) { $desc } else { "unknown ($actionName)" })
        }
        return "unknown ($actionName)"
    }
    
    [string] GetActionDict([string]$actionName) {
        if ($this.ActionDescriptions.ContainsKey($actionName)) {
            $dict = $this.ActionDescriptions[$actionName][1]
            return $(if ($dict) { $dict } else { "unknown ($actionName)" })
        }
        return "unknown ($actionName)"
    }
    
    [void] ListByGuardPoints() {
        # Identify all guardpoints from entries
        $guardPointMap = @{}
        
        # Extract potential guardpoint folders from all log entries
        foreach ($entry in $this.Entries) {
            $resourcePath = $entry.ResourcePath.Replace('/', '\')
            
            # Check for various resource path patterns to extract guardpoints
            $guardPointPath = $null
            
            # Pattern 1: SQL Server data paths
            if ($resourcePath -match '^([A-Za-z]:\\Program Files\\Microsoft SQL Server\\[^\\]+\\MSSQL\\DATA)') {
                $guardPointPath = $matches[1]
            }
            # Pattern 2: SQL Server specific paths
            elseif ($resourcePath -match '^([A-Za-z]:\\Program Files\\Microsoft SQL Server\\[^\\]+\\MSSQL\\[^\\]+)') {
                $guardPointPath = $matches[1]
            }
            # Pattern 3: Try to get the directory name
            else {
                try {
                    $dirPath = [System.IO.Path]::GetDirectoryName($resourcePath)
                    if (-not [string]::IsNullOrEmpty($dirPath)) {
                        $guardPointPath = $dirPath
                    }
                }
                catch {
                    # Silently ignore path errors
                }
            }
            
            # Default to drive root if no guardpoint detected but we have a drive letter
            if ([string]::IsNullOrEmpty($guardPointPath) -and $resourcePath -match '^([A-Za-z]:)') {
                $guardPointPath = $matches[1]
            }
            
            # If we found a guardpoint path, add it to the map
            if (-not [string]::IsNullOrEmpty($guardPointPath)) {
                if (-not $guardPointMap.ContainsKey($guardPointPath)) {
                    $guardPointMap[$guardPointPath] = [System.Collections.ArrayList]::new()
                }
                [void]$guardPointMap[$guardPointPath].Add($entry)
            }
        }
        
        # Display list of all guardpoints
        Write-Host "`n=== DETECTED GUARDPOINT FOLDERS ===" -ForegroundColor Cyan
        
        if ($guardPointMap.Keys.Count -gt 0) {
            # Sort guardpoints by number of entries (most active first)
            $sortedGuardPoints = $guardPointMap.Keys | Sort-Object { ($guardPointMap[$_] | Measure-Object -Property Count -Sum).Sum } -Descending
            
            Write-Host "  Found $($sortedGuardPoints.Count) guardpoint folders:" -ForegroundColor White
            
            # Display each guardpoint with stats
            foreach ($guardPoint in $sortedGuardPoints) {
                $guardPointEntries = $guardPointMap[$guardPoint]
                $accessCount = ($guardPointEntries | Measure-Object -Property Count -Sum).Sum
                
                Write-Host "`n=== GUARDPOINT: $guardPoint ($accessCount accesses) ===" -ForegroundColor Yellow
                
                # Get users for this guardpoint first
                $users = $guardPointEntries | Group-Object -Property UserName, UserDomain | Sort-Object Count -Descending
                
                # Count only unique users that will be displayed
                $displayedUsers = @($users | Where-Object { $_.Count -gt 0 })
                
                # Calculate statistics
                $userCount = $displayedUsers.Count
                $processCount = ($guardPointEntries | Select-Object -Property ProcessName -Unique).Count
                $resourceCount = ($guardPointEntries | Select-Object -Property ResourcePath -Unique).Count
                
                Write-Host "  Statistics:" -ForegroundColor White
                Write-Host "    $($script:UNICODE_BULLET) Users: $userCount" -ForegroundColor Gray
                Write-Host "    $($script:UNICODE_BULLET) Processes: $processCount" -ForegroundColor Gray
                Write-Host "    $($script:UNICODE_BULLET) Resources: $resourceCount" -ForegroundColor Gray
                Write-Host "    $($script:UNICODE_BULLET) Access Events: $accessCount" -ForegroundColor Gray
                
                # 1. USERS section for this guardpoint
                Write-Host "`n  Users:" -ForegroundColor White
                
                foreach ($user in $displayedUsers | Select-Object -First $script:MAX_ITEMS_TO_DISPLAY) {
                    # Get raw value for parsing
                    $rawUserName = $user.Name
                    
                    # Clean up the username by removing group information
                    # Format: "userName, domain" or just "userName"
                    $userParts = $rawUserName -split ', '
                    $rawName = $userParts[0]  # This might still have groups in it
                    $domain = if ($userParts.Count -gt 1) { $userParts[1] } else { "" }
                    
                    # System account special case
                    if ($rawName -match 'SYSTEM\\\\NT AUTHORITY' -or ($domain -eq "NT AUTHORITY" -and $rawName -eq "SYSTEM")) {
                        $domain = "NT AUTHORITY"
                        $userName = "SYSTEM"
                        $displayName = "NT AUTHORITY\SYSTEM"
                    }
                    # Extract username from potential group info for regular cases
                    else {
                        # Extract just username without groups
                        $cleanName = $rawName
                        
                        # Check for "domain\user" format with possible groups
                        if ($cleanName -match '^([^\\,]+)\\([^\\,@]+)') {
                            # Found standard domain\user format
                            $domain = $matches[1]
                            $userName = $matches[2]
                        }
                        # Check for service accounts
                        elseif ($domain -eq "NT SERVICE") {
                            $userName = $cleanName
                            if ($userName -match '^([^,@]+)') {
                                # Extract just the username part before any group info
                                $userName = $matches[1]
                            }
                        }
                        # Other formats - just use raw name but remove group info
                        else {
                            if ($cleanName -match '^([^,@\\]+)') {
                                $userName = $matches[1]
                            } else {
                                $userName = $cleanName
                            }
                        }
                        
                        # Format display name with domain if available
                        if (-not [string]::IsNullOrEmpty($domain)) {
                            $displayName = "$domain\$userName"
                        } else {
                            # Add specific domain mappings for known usernames from the log data
                            $knownDomains = @{
                                "SYSTEM" = "NT AUTHORITY"
                                "soojae" = "LAB"
                                "soojae2" = "LAB"
                                "MSSQLSERVER" = "NT SERVICE"
                            }
                            
                            if ($knownDomains.ContainsKey($userName)) {
                                $domain = $knownDomains[$userName]
                                $displayName = "$domain\$userName"
                            }
                            # For other users without domain, check if we can determine a domain from context
                            elseif ($guardPointEntries | Where-Object { 
                                $_.UserName -eq $userName -and -not [string]::IsNullOrEmpty($_.UserDomain) 
                            }) {
                                $possibleDomain = ($guardPointEntries | Where-Object { 
                                    $_.UserName -eq $userName -and -not [string]::IsNullOrEmpty($_.UserDomain) 
                                } | Select-Object -First 1).UserDomain
                                
                                if (-not [string]::IsNullOrEmpty($possibleDomain)) {
                                    $displayName = "$possibleDomain\$userName"
                                } else {
                                    $displayName = $userName
                                }
                            } else {
                                $displayName = $userName
                            }
                        }
                    }
                    
                    Write-Host "    $($script:UNICODE_BULLET) $displayName ($($user.Count) accesses)" -ForegroundColor Gray
                    
                    # Get all distinct groups for this user across all entries
                    # Match any entries that have the same UserName/UserDomain or match the raw name format
                    $userEntries = $guardPointEntries | Where-Object { 
                        ($_.UserName -eq $userName -and $_.UserDomain -eq $domain) -or
                        # Also check for matches in the original format from the logs
                        ($rawUserName -match "$($_.UserName)" -and $_.UserDomain -eq $domain) -or
                        ($rawUserName -match "$($_.UserName)" -and $rawUserName -match "$($_.UserDomain)")
                    }
                    
                    # Extract all groups from all matching entries
                    $allGroups = @()
                    foreach ($entry in $userEntries) {
                        if ($entry.UserGroups -and $entry.UserGroups.Count -gt 0) {
                            $allGroups += $entry.UserGroups
                        }
                    }
                    $allGroups = $allGroups | Select-Object -Unique
                    
                    # Display group information if available
                    if ($allGroups -and $allGroups.Count -gt 0) {
                        # Remove meaningless groups like backslashes
                        $filteredGroups = $allGroups | Where-Object { 
                            $_ -ne "\" -and
                            $_ -ne "\\" -and 
                            $_ -ne "" -and
                            -not [string]::IsNullOrWhiteSpace($_)
                        }
                        
                        # Skip displaying groups if we only have meaningless entries
                        if ($filteredGroups.Count -eq 0) {
                            # No meaningful groups to display, but continue processing other users
                            continue
                        }
                        
                        # Categorize groups by type and domain
                        $categorizedGroups = @{
                            "Security Groups" = @()
                            "Domain Groups" = @()
                            "Mandatory Labels" = @()
                            "Server Groups" = @()
                            "Other Groups" = @()
                        }
                        
                        # Special group patterns for categorization
                        $securityGroupPatterns = @("Administrators", "Users", "Domain Admins", "Enterprise Admins", "Schema Admins", "Policy Creator")
                        $mandatoryLabelPatterns = @("Mandatory Label")
                        $serverGroupPatterns = @("@DOMAINSERVER", "@localhost")
                        
                        foreach ($group in $filteredGroups) {
                            $categorized = $false
                            
                            # Skip empty or meaningless groups
                            if ([string]::IsNullOrWhiteSpace($group) -or $group -eq "\" -or $group -eq "\\") {
                                continue
                            }
                            
                            # Categorize by pattern matching
                            foreach ($pattern in $securityGroupPatterns) {
                                if ($group -match $pattern) {
                                    $categorizedGroups["Security Groups"] += $group
                                    $categorized = $true
                                    break
                                }
                            }
                            
                            if (-not $categorized) {
                                foreach ($pattern in $mandatoryLabelPatterns) {
                                    if ($group -match $pattern) {
                                        $categorizedGroups["Mandatory Labels"] += $group
                                        $categorized = $true
                                        break
                                    }
                                }
                            }
                            
                            if (-not $categorized) {
                                foreach ($pattern in $serverGroupPatterns) {
                                    if ($group -match $pattern) {
                                        $categorizedGroups["Server Groups"] += $group
                                        $categorized = $true
                                        break
                                    }
                                }
                            }
                            
                            # Check if the current value exists in the hashtable to avoid any errors
                            if (-not $categorized -and ($group -match '\\\\' -or $group -match '\.')) {
                                $categorizedGroups["Domain Groups"] += $group
                                $categorized = $true
                            }
                            
                            # If not categorized by now, put in Other
                            if (-not $categorized) {
                                $categorizedGroups["Other Groups"] += $group
                            }
                        }
                        
                        # Check if there are any groups to display at all
                        $hasAnyGroups = $false
                        foreach ($category in $categorizedGroups.Keys) {
                            $groups = $categorizedGroups[$category] | Sort-Object
                            # Only count categories with at least one non-empty group
                            if ($groups.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace(($groups | Select-Object -First 1))) {
                                $hasAnyGroups = $true
                                break
                            }
                        }
                        
                        # Display group membership section if there are actual groups to show
                        if ($hasAnyGroups) {
                            Write-Host "      Group Memberships:" -ForegroundColor DarkGray
                            
                            foreach ($category in $categorizedGroups.Keys) {
                                $groups = $categorizedGroups[$category] | Sort-Object
                                
                                # Only display categories that have at least one non-empty group
                                if ($groups.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace(($groups | Select-Object -First 1))) {
                                    Write-Host "        $($category):" -ForegroundColor DarkGray
                                    
                                    # Group by domain if they have domain qualifiers
                                    $domainGroups = @{}
                                    $plainGroups = @()
                                    
                                    foreach ($group in $groups) {
                                        if ($group -match '@(.+)$') {
                                            $domain = $matches[1]
                                            $groupName = $group -replace '@.+$', ''
                                            
                                            # Don't add empty group names
                                            if (-not [string]::IsNullOrWhiteSpace($groupName)) {
                                                if (-not $domainGroups.ContainsKey($domain)) {
                                                    $domainGroups[$domain] = @()
                                                }
                                                $domainGroups[$domain] += $groupName
                                            }
                                        }
                                        else {
                                            # Don't add empty groups
                                            if (-not [string]::IsNullOrWhiteSpace($group)) {
                                                $plainGroups += $group
                                            }
                                        }
                                    }
                                    
                                    # Display domain-qualified groups
                                    foreach ($domain in $domainGroups.Keys | Sort-Object) {
                                        $domainGroupList = $domainGroups[$domain] | Sort-Object -Unique
                                        
                                        # Only display domains that have at least one group
                                        if ($domainGroupList.Count -gt 0) {
                                            # Clean up any extra backslashes in domain names
                                            $cleanDomain = $domain -replace '\\+', '\'
                                            Write-Host "          Domain: $cleanDomain" -ForegroundColor DarkGray
                                            foreach ($group in $domainGroupList) {
                                                # Clean up any extra backslashes in group names
                                                $cleanGroup = $group -replace '\\+', '\'
                                                # Remove leading backslash
                                                $cleanGroup = $cleanGroup -replace '^\\', ''
                                                Write-Host "            $($script:UNICODE_BULLET) $cleanGroup" -ForegroundColor DarkGray
                                            }
                                        }
                                    }
                                    
                                    # Display non-domain groups
                                    if ($plainGroups.Count -gt 0) {
                                        if ($domainGroups.Count -gt 0) {
                                            Write-Host "          General Groups:" -ForegroundColor DarkGray
                                        }
                                        foreach ($group in ($plainGroups | Sort-Object -Unique)) {
                                            # Clean up the display by removing any trailing domain indicators
                                            $cleanGroup = $group -replace '\\\\.*$', ''
                                            # Remove leading single backslash in group names
                                            $cleanGroup = $cleanGroup -replace '^\\', ''
                                            # Clean up any remaining double backslashes
                                            $cleanGroup = $cleanGroup -replace '\\+', '\'
                                            
                                            # Don't display empty groups
                                            if (-not [string]::IsNullOrWhiteSpace($cleanGroup)) {
                                                Write-Host "            $($script:UNICODE_BULLET) $cleanGroup" -ForegroundColor DarkGray
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                if ($displayedUsers.Count -gt $script:MAX_ITEMS_TO_DISPLAY) {
                    Write-Host "    $($script:UNICODE_BULLET) ... and $($displayedUsers.Count - $script:MAX_ITEMS_TO_DISPLAY) more users" -ForegroundColor DarkGray
                }
                
                # 2. PROCESSES section for this guardpoint
                Write-Host "`n  Processes:" -ForegroundColor White
                $processes = $guardPointEntries | Group-Object -Property ProcessName | Sort-Object Count -Descending
                
                foreach ($process in $processes | Select-Object -First $script:MAX_ITEMS_TO_DISPLAY) {
                    $exeName = Split-Path -Leaf $process.Name
                    $cleanPath = Clean-Path -Path $process.Name -ForDisplay $true
                    
                    Write-Host "    $($script:UNICODE_BULLET) $exeName ($($process.Count) accesses)" -ForegroundColor Gray
                    Write-Host "      Path: $cleanPath" -ForegroundColor DarkGray
                }
                
                if ($processes.Count -gt $script:MAX_ITEMS_TO_DISPLAY) {
                    Write-Host "    $($script:UNICODE_BULLET) ... and $($processes.Count - $script:MAX_ITEMS_TO_DISPLAY) more processes" -ForegroundColor DarkGray
                }
                
                # 3. RESOURCES section for this guardpoint
                Write-Host "`n  Resources:" -ForegroundColor White
                $resources = $guardPointEntries | Group-Object -Property ResourcePath | Sort-Object Count -Descending
                
                foreach ($resource in $resources | Select-Object -First $script:MAX_ITEMS_TO_DISPLAY) {
                    $cleanPath = Clean-Path -Path $resource.Name -ForDisplay $true
                    
                    # Determine most common action on this resource
                    $actions = $guardPointEntries | Where-Object { $_.ResourcePath -eq $resource.Name } | 
                               Group-Object -Property ActionName | Sort-Object Count -Descending
                    $commonAction = if ($actions.Count -gt 0) { 
                        $this.GetActionDescription($actions[0].Name) 
                    } else { 
                        "unknown" 
                    }
                    
                    Write-Host "    $($script:UNICODE_BULLET) $cleanPath ($($resource.Count) accesses)" -ForegroundColor Gray
                    Write-Host "      Common action: $commonAction" -ForegroundColor DarkGray
                }
                
                if ($resources.Count -gt $script:MAX_ITEMS_TO_DISPLAY) {
                    Write-Host "    $($script:UNICODE_BULLET) ... and $($resources.Count - $script:MAX_ITEMS_TO_DISPLAY) more resources" -ForegroundColor DarkGray
                }
            }
        } else {
            Write-Host "  No guardpoint folders detected in log entries" -ForegroundColor Gray
        }
        
        # Show overall summary
        $this.ShowSummary()
    }
    
    [void] ShowSummary() {
        # Simplified header
        Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
        
        # Build a summary table
        $userCount = ($this.Entries | Select-Object -Property UserName, UserDomain -Unique).Count
        $processCount = ($this.Entries | Select-Object -Property ProcessName -Unique).Count
        $totalResources = ($this.Entries | Select-Object -Property ResourcePath -Unique).Count
        $totalEvents = ($this.Entries | Measure-Object -Property Count -Sum).Sum
        
        # Count unique guardpoint paths using same logic as ListByGuardPoints
        $guardPointPaths = @{}
        foreach ($entry in $this.Entries) {
            $resourcePath = $entry.ResourcePath.Replace('/', '\')
            
            # Check for various resource path patterns to extract guardpoints
            $guardPointPath = $null
            
            # Pattern 1: Standard Windows path with first level folder (C:\Folder\file.txt)
            if ($resourcePath -match '^([A-Za-z]:\\[^\\]+)') {
                $guardPointPath = $matches[1]
            }
            # Pattern 2: Root drive only (C:\ or C:)
            elseif ($resourcePath -match '^([A-Za-z]:\\?)$') {
                $guardPointPath = $matches[1].TrimEnd('\')
            }
            # Pattern 3: Try to get the directory name
            else {
                try {
                    $dirPath = [System.IO.Path]::GetDirectoryName($resourcePath)
                    if (-not [string]::IsNullOrEmpty($dirPath)) {
                        if ($dirPath -match '^([A-Za-z]:\\[^\\]+)') {
                            $guardPointPath = $matches[1]
                        }
                        else {
                            # If no first-level folder match, try to get the drive root
                            if ($dirPath -match '^([A-Za-z]:)') {
                                $guardPointPath = $matches[1]
                            }
                        }
                    }
                }
                catch {
                    # Silently ignore path errors
                }
            }
            
            # Default to drive root if no guardpoint detected but we have a drive letter
            if ([string]::IsNullOrEmpty($guardPointPath) -and $resourcePath -match '^([A-Za-z]:)') {
                $guardPointPath = $matches[1]
            }
            
            # If we found a guardpoint path, add it to the count
            if (-not [string]::IsNullOrEmpty($guardPointPath)) {
                $guardPointPaths[$guardPointPath] = $true
            }
        }
        $guardPointCount = $guardPointPaths.Count
        
        # Display summary items with simple format
        Write-Host "  Total Users: $userCount" -ForegroundColor White
        Write-Host "  Total Processes: $processCount" -ForegroundColor White
        Write-Host "  Total Resources: $totalResources" -ForegroundColor White
        Write-Host "  Detected GuardPoints: $guardPointCount" -ForegroundColor White
        Write-Host "  Total Access Events: $totalEvents" -ForegroundColor White
    }
}

# Pre-compile the regex pattern for better performance
$script:LogLineRegex = [regex]::new(@'
(?<DATE>[\d-]+)\s+
(?<TIME>[\d\:\.]+)\s+
\[[\w\s]+\]\s+
\[[\w\s]+\]\s+
\[(?<PID>\d+)\]\s+
\[[\w\s]+\]\s+
\[(?<TYPE>LEARN\sMODE|AUDIT|INFO)\]\s+
Policy\[(?<POLICY>[\w-]+)\]\s+
User\[(?<USER>[^\]]+)\]\s+
Process\[(?<PROCESS>[^\]]+)\]\s+
Action\[(?<ACTION>\w+)\]\s+
Res\[(?<RESOURCE>[^\]]+)\]\s+
(\[([^\]])+\]\s+)?
(Key\[(?<KEY>[^\]]+)\]\s+)?
Effect\[(?<EFFECT>[^\]]+)\]
'@, [System.Text.RegularExpressions.RegexOptions]::IgnorePatternWhitespace)

function Parse-LogLine {
    param(
        [string]$LogLine,
        [LogModel]$LogModel
    )

    # Safety check - don't process empty/null lines
    if ([string]::IsNullOrEmpty($LogLine)) {
        return $false
    }

    try {
        # Use the pre-compiled regex pattern for better performance
        $match = $script:LogLineRegex.Match($LogLine)
        if (-not $match.Success) {
            return $false
        }

        # Verify required groups exist
        if (-not $match.Groups['POLICY'].Success -or 
            -not $match.Groups['USER'].Success -or 
            -not $match.Groups['PROCESS'].Success -or 
            -not $match.Groups['RESOURCE'].Success -or 
            -not $match.Groups['ACTION'].Success -or
            -not $match.Groups['TYPE'].Success) {
            return $false
        }
        
        # Check entry type based on the -all parameter
        $entryType = $match.Groups['TYPE'].Value
        
        # If -all is specified, only process INFO logs; otherwise only process LEARN MODE logs
        if (($all -and $entryType -ne "INFO") -or (-not $all -and $entryType -ne "LEARN MODE")) {
            return $false
        }

        $policy = $match.Groups['POLICY'].Value
        
        # Get the raw user information from the log
        $userInfo = $match.Groups['USER'].Value
        
        # Initialize variables
        $userName = ""
        $domain = ""
        $userGroups = @()
        
        # Extract format examples from logs:
        # 1. "SYSTEM\\\\NT AUTHORITY"
        # 2. "soojae\\Domain Users,Domain Admins,...\\LAB,lab.au.safenet-inc.com"
        
        # Special handling for SYSTEM account
        if ($userInfo -match 'SYSTEM\\\\NT AUTHORITY' -or $userInfo -match 'NT AUTHORITY\\SYSTEM') {
            $domain = "NT AUTHORITY"
            $userName = "SYSTEM"
        }
        # Handle complex format: username\groups\domain,domain
        elseif ($userInfo -match '^([^\\]+)\\(.+)\\\\([^,]+),?(.*)$') {
            # Example: soojae\groups\LAB,domain.com
            $userName = $matches[1]  # Username
            $groupsPart = $matches[2]  # Groups part
            $domain = $matches[3]  # Primary domain
            $otherDomain = $matches[4]  # Other domain info if any
            
            # Extract groups from the groups part
            $groupList = $groupsPart -split ','
            foreach ($group in $groupList) {
                $cleanGroup = $group.Trim()
                if (-not [string]::IsNullOrWhiteSpace($cleanGroup)) {
                    $userGroups += $cleanGroup
                }
            }
            
            # Add domain-qualified groups
            if ($userInfo -match '@([^,]+)') {
                $domainQualified = $matches[1]
                $userGroups += "Domain: $domainQualified"
            }
            
            # Add any others from otherDomain
            if (-not [string]::IsNullOrWhiteSpace($otherDomain)) {
                $userGroups += "Domain: $otherDomain"
            }
        }
        # Basic domain\user format
        elseif ($userInfo -match '^([^\\]+)\\([^\\,@]+)') {
            $domain = $matches[1]
            $userName = $matches[2]
            
            # Check for group information after the username
            if ($userInfo -match '^[^\\]+\\[^\\,@]+,(.+)$') {
                $groupList = $matches[1] -split ','
                foreach ($group in $groupList) {
                    $cleanGroup = $group.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($cleanGroup)) {
                        $userGroups += $cleanGroup
                    }
                }
            }
        }
        # Fallback for any other format
        else {
            $userName = $userInfo
        }
        
        # Also look for @ patterns which indicate domain-qualified groups
        $atMatches = [regex]::Matches($userInfo, '([^@,]+)@([^,]+)')
        foreach ($atMatch in $atMatches) {
            if ($atMatch.Groups.Count -ge 3) {
                $groupName = $atMatch.Groups[1].Value.Trim() 
                $groupDomain = $atMatch.Groups[2].Value.Trim()
                $userGroups += "$groupName@$groupDomain"
            }
        }
        
        # Deduplicate groups
        $userGroups = $userGroups | Select-Object -Unique
        
        $process = $match.Groups['PROCESS'].Value
        $resource = $match.Groups['RESOURCE'].Value
        $action = $match.Groups['ACTION'].Value
        
        # Create and add a log entry to the model
        $entry = [LogEntry]::new($policy, $userName, $domain, $process, $resource, $action, $userGroups)
        $LogModel.AddEntry($entry)
        
        return $true
    }
    catch {
        # If any unexpected errors occur during parsing, just skip the line
        return $false
    }
}

function Process-LogFiles {
    param([string]$LogPath)
    
    # Check if the path is a directory or a specific file
    Write-Host "Processing log files from: $LogPath" -ForegroundColor Cyan
    $logFiles = Get-LogFiles -Path $LogPath
    
    if (-not $logFiles -or $logFiles.Count -eq 0) {
        Write-Host "No valid log files found at $LogPath" -ForegroundColor Red
        return $null
    }
    
    # Calculate total logs size for progress reporting
    $totalSize = 0
    $fileInfos = @()
    foreach ($filePath in $logFiles) {
        try {
            $fileInfo = Get-Item -Path $filePath -ErrorAction Stop
            $fileInfos += $fileInfo
            $totalSize += $fileInfo.Length
        } catch {
            Write-Host "Warning: Unable to get file info for $filePath : $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "Found $($fileInfos.Count) accessible log file(s) with total size: $(Format-FileSize -Size $totalSize)" -ForegroundColor Cyan
    for ($i = 0; $i -lt $fileInfos.Count; $i++) {
        Write-Host "  $($i+1). $($fileInfos[$i].Name) - $(Format-FileSize -Size $fileInfos[$i].Length)" -ForegroundColor White
    }
    
    # Create log model
    $logModel = [LogModel]::new()
    $processedEntries = 0
    $skippedLines = 0
    
    # Process each log file
    for ($i = 0; $i -lt $fileInfos.Count; $i++) {
        $fileInfo = $fileInfos[$i]
        $logFile = $fileInfo.FullName
        $fileSize = $fileInfo.Length
        $processedBytes = 0
        
        Write-Host "Processing file $($i+1) of $($fileInfos.Count): $($fileInfo.Name)" -ForegroundColor Cyan
        
        try {
            # Read the file line by line - with improved error handling
            $reader = $null
            try {
                # Ensure the file path is properly quoted in case of spaces
                Write-Host "Opening file: $logFile" -ForegroundColor Cyan
                $reader = New-Object System.IO.StreamReader -ArgumentList $logFile
                $lineCount = 0
                
                while ($reader -ne $null -and -not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    
                    # Skip null or empty lines
                    if ([string]::IsNullOrEmpty($line)) {
                        $skippedLines++
                        continue
                    }
                    
                    $lineCount++
                    $processedBytes += [System.Text.Encoding]::UTF8.GetByteCount($line) + 2  # +2 for newline chars
                    
                    # Update progress based on constant frequency
                    if ($lineCount % $script:PROGRESS_UPDATE_FREQUENCY -eq 0) {
                        $percentComplete = [math]::Min(100, [math]::Round(($processedBytes / $fileSize) * 100))
                        Write-Progress -Activity "Processing $($fileInfo.Name)" -Status "$percentComplete% Complete" -PercentComplete $percentComplete
                    }
                    
                    # Parse the line
                    if (-not (Parse-LogLine -LogLine $line -LogModel $logModel)) {
                        $skippedLines++
                    }
                    else {
                        $processedEntries++
                    }
                }
            }
            catch {
                Write-Host "Error reading file $($fileInfo.Name): $_" -ForegroundColor Red
                Write-Host "Check that the file is not locked by another process or corrupted" -ForegroundColor Yellow
            }
            finally {
                # Ensure reader is properly closed
                if ($reader -ne $null) {
                    $reader.Close()
                    $reader.Dispose()
                }
                Write-Progress -Activity "Processing $($fileInfo.Name)" -Completed
            }
        }
        catch {
            Write-Host "Failed to process file $($fileInfo.Name): $_" -ForegroundColor Red
        }
    }
    
    # Only report success if we processed at least some entries
    if ($processedEntries -gt 0) {
        Write-Host "Processed $processedEntries log entries ($skippedLines lines skipped)" -ForegroundColor Green
        return $logModel
    }
    else {
        Write-Host "No valid log entries were found in the specified file(s)" -ForegroundColor Red
        return $null
    }
}

# Clean up a Windows path for display or storage
# This function will normalize backslashes to forward slashes for JSON storage
function Clean-Path {
    param(
        [string]$Path,
        [bool]$ForDisplay = $false
    )
    
    if ($ForDisplay) {
        # For display purposes, ensure we have single backslashes (not doubled)
        return $Path.Replace('\\', '\')
    } else {
        # For JSON storage, use forward slashes
        return $Path.Replace('\', '/')
    }
}

# Clean up user domain information for display
function Format-UserDomain {
    param(
        [string]$Domain,
        [string]$UserName
    )
    
    # If no domain, just return the username
    if ([string]::IsNullOrEmpty($Domain)) {
        return $UserName
    }
    
    # Handle special case for SYSTEM account
    if ($Domain -eq "NT AUTHORITY" -and $UserName -eq "SYSTEM") {
        return "NT AUTHORITY\SYSTEM"
    }
    
    # Clean up backslashes
    $cleanDomain = $Domain.Replace('\\', '\')
    $cleanUserName = $UserName
    
    # Handle complex username with group information
    if ($cleanUserName -match ',|@|\\\\') {
        # Username contains commas, @ signs, or double backslashes (likely groups)
        # Extract just the username part before any of these special characters
        if ($cleanUserName -match '^([^,@\\]+)') {
            $cleanUserName = $matches[1]
        }
    }
    
    # Standard domain\user format
    return "$cleanDomain\$cleanUserName"
}

# =========================== MAIN SCRIPT ===========================

# Process the log file(s) with simplified header
Write-Host "`n=== CTE Tool - Log File Access Analyzer ===" -ForegroundColor Cyan
if ($all) {
    Write-Host "Mode: Processing INFO labeled logs only" -ForegroundColor Cyan
} else {
    Write-Host "Mode: Processing LEARN MODE logs only (use -all to process INFO logs instead)" -ForegroundColor Cyan
}

# Verify the log path exists before attempting to process
if (-not (Test-Path -Path $logpath -PathType Container)) {
    # Check if the user has specified a file instead of a directory
    if (Test-Path -Path $logpath -PathType Leaf) {
        Write-Host "Error: The specified path is a file, but a directory is required: $logpath" -ForegroundColor Red
        Write-Host "Please specify a directory path containing log files." -ForegroundColor Yellow
        exit 1
    }
    
    # If the default path doesn't exist
    if ($logpath -eq "C:\ProgramData\Vormetric\DataSecurityExpert\agent\log") {
        Write-Host "Default log directory not found: $logpath" -ForegroundColor Yellow
        Write-Host "Please specify a valid path to a directory containing log files." -ForegroundColor Yellow
    } else {
        Write-Host "Log directory not found: $logpath" -ForegroundColor Yellow
        Write-Host "Please specify a valid path to a directory containing log files." -ForegroundColor Yellow
    }
    
        Write-Host ""
        Write-Host "Example usage:" -ForegroundColor Cyan
        Write-Host "  .\cte-tool.ps1" -ForegroundColor Cyan
        Write-Host "  .\cte-tool.ps1 -LogPath C:\path\to\logs" -ForegroundColor Cyan
        exit 1
}

$logModel = Process-LogFiles -LogPath $logpath

if (-not $logModel) {
    Write-Host "Failed to process log file(s). Exiting." -ForegroundColor Red
    exit 1
}

# Display the reorganized output by guardpoint folders
$logModel.ListByGuardPoints()

Write-Host "`nDone!" -ForegroundColor Green 