# Note: Module requirements are checked dynamically at runtime by Test-Prerequisites

<#
.SYNOPSIS
    Interactive user and device management tool for Entra ID, Active Directory,
    Intune, and Microsoft Defender for Endpoint (MDE).
    Supports multiple MDE sign-in methods: Interactive Browser (passkey/FIDO2/Hello),
    Device Code, and WAM (Windows SSO).

.DESCRIPTION
    Connects to Microsoft Graph (Entra ID / Intune), Active Directory, and the
    MDE API to:

    Main menu:
      [1] Search for a user   - view info, take user actions, drill into devices
      [2] Search for a device - search MDE-onboarded machines, take device actions
      [3] Connect to MDE      - connect or reconnect to Defender for Endpoint
      [4] Connect to AD       - connect or reconnect to Active Directory
      [5] Exit

    User actions:
      - Reset password (AD) + revoke Entra sessions
      - Require password change at next logon (AD)
      - Disable account (AD) + revoke Entra sessions
      - Revoke Entra sessions only
      - Unlock AD account
      - Select a linked device for device actions

    Device actions (from user context or device search):
      MDE (requires MDE onboarding):
        - Isolate device (Full)
        - Isolate device (Selective)
        - Release from isolation
      Intune (actions vary by device category):
        Corporate Windows PC:
          Sync, Restart, Defender Scan (Quick/Full), Fresh Start, Retire, Wipe
        Personal/BYOD Windows PC:
          Sync, Restart, Retire
        Corporate Mobile (iOS/Android):
          Sync, Remote Lock, Restart, Retire, Wipe
          (+Lost Mode for supervised iOS)
        Personal Mobile (iOS/Android):
          Sync, Remote Lock, Retire
        Corporate macOS:
          Sync, Restart, Remote Lock, Retire, Wipe
        Personal macOS:
          Sync, Retire
      Composite:
        - Offboard Device: guided workflow that chains the appropriate
          steps -- Intune Wipe/Retire (based on ownership), MDE isolation,
          disable Entra device object, and revoke user sessions.
          Each step is individually prompted.

    Devices enrolled in Intune but not onboarded to MDE will still show
    Entra + Intune detail and offer Intune actions.

.NOTES
    Required Graph permissions (Delegated):
      - User.ReadWrite.All
      - Directory.ReadWrite.All
      - Device.Read.All
      - DeviceManagementManagedDevices.Read.All        (Intune device detail)
      - DeviceManagementManagedDevices.PrivilegedOperations.All  (Intune actions)
      - AuditLog.Read.All                              (Sign-in logs -- requires Entra ID P1/P2)

    Required MDE API permissions (Delegated):
      - Machine.Read.All
      - Machine.Isolate
      - Machine.ReadWrite.All  (for isolation actions)

    Required to auto-create an MDE App Registration (optional):
      - Application.ReadWrite.All (Graph, Delegated)
      - DelegatedPermissionGrant.ReadWrite.All (Graph, Delegated)
      - Or: Application Administrator / Global Administrator role

    MDE sign-in notes:
      - Interactive Browser requires a redirect URI of http://localhost
        configured on the App Registration (under Authentication > Mobile
        and desktop applications). The default Azure PowerShell client
        already has this.
      - WAM (Windows SSO) requires the MSAL.PS module.
      - Device Code works everywhere with no extra configuration.

    Required AD permissions:
      - Account Operator or equivalent (password reset, disable, set pwd flags)

    AD connectivity:
      - Domain-joined machines auto-discover a DC.
      - Hybrid Azure AD Joined machines that cannot auto-discover are
        prompted for a domain / DC FQDN (cached credentials are used).
      - Non-joined machines are prompted for domain, username, and password.

    Required PowerShell modules (auto-installed if missing):
      - Microsoft.Graph.Users
      - Microsoft.Graph.Identity.DirectoryManagement
      - Microsoft.Graph.Identity.SignIns
      - MSAL.PS (optional -- only for WAM sign-in)
      - ActiveDirectory (requires RSAT -- cannot be auto-installed)
#>

[CmdletBinding()]
param()

# ==============================================================================
# FUNCTIONS -- PREREQUISITES
# ==============================================================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Checks for required PowerShell modules and offers to install any that
        are missing. Returns $true if all critical requirements are met.
    #>

    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  CHECKING PREREQUISITES" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor White
    Write-Host ""

    # Define required modules
    # Format: @{ Name = "ModuleName"; Required = $true/$false; InstallNote = "extra info" }
    $modules = @(
        @{
            Name        = "Microsoft.Graph.Users"
            Required    = $true
            Installable = $true
            InstallNote = $null
        }
        @{
            Name        = "Microsoft.Graph.Identity.DirectoryManagement"
            Required    = $true
            Installable = $true
            InstallNote = $null
        }
        @{
            Name        = "Microsoft.Graph.Identity.SignIns"
            Required    = $true
            Installable = $true
            InstallNote = $null
        }
        @{
            Name        = "MSAL.PS"
            Required    = $false
            Installable = $true
            InstallNote = "Only required for WAM (Windows SSO) sign-in to MDE"
        }
        @{
            Name        = "ActiveDirectory"
            Required    = $false
            Installable = $false
            InstallNote = "Requires RSAT. Install via: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
        }
    )

    $missingRequired   = @()
    $missingOptional   = @()
    $installedModules  = @()

    # Check each module
    foreach ($mod in $modules) {
        $name = $mod.Name
        Write-Host "  Checking $name... " -ForegroundColor White -NoNewline

        $installed = Get-Module -ListAvailable -Name $name -ErrorAction SilentlyContinue

        if ($installed) {
            $version = ($installed | Sort-Object Version -Descending | Select-Object -First 1).Version
            Write-Host "OK (v$version)" -ForegroundColor Green
            $installedModules += $name
        }
        else {
            if ($mod.Required) {
                Write-Host "MISSING (Required)" -ForegroundColor Red
                $missingRequired += $mod
            }
            else {
                Write-Host "MISSING (Optional)" -ForegroundColor Yellow
                $missingOptional += $mod
            }
        }
    }

    Write-Host ""

    # Handle missing required modules
    if ($missingRequired.Count -gt 0) {
        Write-Host "  The following REQUIRED modules are missing:" -ForegroundColor Red
        foreach ($mod in $missingRequired) {
            Write-Host "    - $($mod.Name)" -ForegroundColor Red
        }
        Write-Host ""

        # Check if any can be auto-installed
        $installable = $missingRequired | Where-Object { $_.Installable -eq $true }

        if ($installable.Count -gt 0) {
            Write-Host "  Would you like to install the missing required modules?" -ForegroundColor Yellow
            Write-Host "  This will run: Install-Module <ModuleName> -Scope CurrentUser -Force" -ForegroundColor DarkGray
            Write-Host ""

            $installChoice = Read-Host "  Install missing required modules? (Y/N)"

            if ($installChoice -eq "Y" -or $installChoice -eq "y") {
                foreach ($mod in $installable) {
                    Write-Host ""
                    Write-Host "  Installing $($mod.Name)..." -ForegroundColor Cyan -NoNewline

                    try {
                        Install-Module -Name $mod.Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                        Write-Host " Done" -ForegroundColor Green

                        # Import the module
                        Import-Module -Name $mod.Name -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Host " FAILED" -ForegroundColor Red
                        Write-Warning "    Error: $_"
                        Write-Host ""
                        Write-Host "  You may need to run PowerShell as Administrator, or install manually:" -ForegroundColor Yellow
                        Write-Host "    Install-Module $($mod.Name) -Scope CurrentUser" -ForegroundColor White
                        return $false
                    }
                }

                Write-Host ""
                Write-Host "  Required modules installed successfully." -ForegroundColor Green
            }
            else {
                Write-Host ""
                Write-Host "  Cannot continue without required modules." -ForegroundColor Red
                Write-Host "  Install them manually with:" -ForegroundColor Yellow
                foreach ($mod in $installable) {
                    Write-Host "    Install-Module $($mod.Name) -Scope CurrentUser" -ForegroundColor White
                }
                return $false
            }
        }
        else {
            # None are installable via Install-Module
            Write-Host "  These modules cannot be installed automatically." -ForegroundColor Red
            foreach ($mod in $missingRequired) {
                if ($mod.InstallNote) {
                    Write-Host "    $($mod.Name): $($mod.InstallNote)" -ForegroundColor Yellow
                }
            }
            return $false
        }
    }

    # Handle missing optional modules (just inform, don't block)
    if ($missingOptional.Count -gt 0) {
        Write-Host "  The following OPTIONAL modules are missing:" -ForegroundColor Yellow
        foreach ($mod in $missingOptional) {
            $note = if ($mod.InstallNote) { " -- $($mod.InstallNote)" } else { "" }
            Write-Host "    - $($mod.Name)$note" -ForegroundColor Yellow
        }
        Write-Host ""

        # Offer to install optional modules that are installable
        $installableOptional = $missingOptional | Where-Object { $_.Installable -eq $true }

        if ($installableOptional.Count -gt 0) {
            $installOptChoice = Read-Host "  Install optional modules? (Y/N)"

            if ($installOptChoice -eq "Y" -or $installOptChoice -eq "y") {
                foreach ($mod in $installableOptional) {
                    Write-Host "  Installing $($mod.Name)..." -ForegroundColor Cyan -NoNewline

                    try {
                        Install-Module -Name $mod.Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                        Write-Host " Done" -ForegroundColor Green
                        Import-Module -Name $mod.Name -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Host " FAILED (non-critical)" -ForegroundColor Yellow
                        Write-Warning "    Error: $_"
                    }
                }
                Write-Host ""
            }
            else {
                Write-Host "  Skipping optional modules." -ForegroundColor DarkGray
                Write-Host ""
            }
        }

        # Show install instructions for non-installable optional modules
        $nonInstallableOptional = $missingOptional | Where-Object { $_.Installable -eq $false }
        if ($nonInstallableOptional.Count -gt 0) {
            Write-Host "  To install non-PowerShell-Gallery modules:" -ForegroundColor DarkGray
            foreach ($mod in $nonInstallableOptional) {
                if ($mod.InstallNote) {
                    Write-Host "    $($mod.Name): $($mod.InstallNote)" -ForegroundColor DarkGray
                }
            }
            Write-Host ""
        }
    }

    # Import all available modules
    Write-Host "  Loading modules..." -ForegroundColor Cyan

    $modulesToImport = @(
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Identity.SignIns"
    )

    foreach ($modName in $modulesToImport) {
        if (Get-Module -ListAvailable -Name $modName -ErrorAction SilentlyContinue) {
            try {
                Import-Module -Name $modName -ErrorAction Stop
            }
            catch {
                Write-Warning "  Failed to import $modName : $_"
            }
        }
    }

    # Import ActiveDirectory if available (don't fail if missing)
    if (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        }
        catch {}
    }

    Write-Host "  Modules loaded." -ForegroundColor Green
    Write-Host ""

    return $true
}

# ==============================================================================
# FUNCTIONS -- CONFIG PERSISTENCE
# ==============================================================================

function Get-ConfigPath {
    <#
    .SYNOPSIS
        Returns the path to config.json, stored alongside the running script.
        Falls back to $HOME if the script path cannot be determined.
    #>
    $scriptDir = $null

    # $PSScriptRoot is set when running a .ps1 file
    if ($PSScriptRoot) {
        $scriptDir = $PSScriptRoot
    }
    # Fallback: try $MyInvocation from the script scope
    elseif ($script:MyInvocation -and $script:MyInvocation.MyCommand -and $script:MyInvocation.MyCommand.Path) {
        $scriptDir = Split-Path -Parent $script:MyInvocation.MyCommand.Path
    }

    if (-not $scriptDir) { $scriptDir = $HOME }

    return Join-Path $scriptDir "config.json"
}

function Read-Config {
    <#
    .SYNOPSIS
        Reads config.json and returns a hashtable. Returns an empty hashtable
        if the file does not exist or is invalid.
    #>
    $path = Get-ConfigPath

    if (-not (Test-Path $path)) { return @{} }

    try {
        $json = Get-Content -Path $path -Raw -ErrorAction Stop
        $obj  = $json | ConvertFrom-Json -ErrorAction Stop

        # Convert PSCustomObject to hashtable for easy use
        $config = @{}
        foreach ($prop in $obj.PSObject.Properties) {
            $config[$prop.Name] = $prop.Value
        }
        return $config
    }
    catch {
        Write-Host "  Warning: Could not read config.json -- $_" -ForegroundColor DarkYellow
        return @{}
    }
}

function Save-Config {
    <#
    .SYNOPSIS
        Saves a hashtable to config.json, merging with any existing values.
        Only non-sensitive data should be saved (domain, username -- never passwords).
    #>
    param([hashtable]$NewValues)

    $path   = Get-ConfigPath
    $config = Read-Config

    foreach ($key in $NewValues.Keys) {
        $config[$key] = $NewValues[$key]
    }

    try {
        $config | ConvertTo-Json -Depth 4 | Set-Content -Path $path -Encoding UTF8 -Force -ErrorAction Stop
        Write-Host "  Config saved to $path" -ForegroundColor DarkGray
    }
    catch {
        Write-Host "  Warning: Could not save config.json -- $_" -ForegroundColor DarkYellow
    }
}

# ==============================================================================
# FUNCTIONS -- CONNECTION
# ==============================================================================

function Connect-ToGraph {
    Write-Host "Checking for existing Microsoft Graph session..." -ForegroundColor Cyan

    $needsConnect = $true
    try {
        $context = Get-MgContext
        if ($null -ne $context -and ($context.Account -or $context.ClientId)) {
            $currentScopes = $context.Scopes
            $hasUserWrite    = ($currentScopes -contains "User.ReadWrite.All") -or ($currentScopes -contains "Directory.ReadWrite.All")
            $hasUserRead     = ($currentScopes -contains "User.Read.All") -or ($currentScopes -contains "Directory.Read.All") -or $hasUserWrite
            $hasDeviceRead   = ($currentScopes -contains "Device.Read.All") -or ($currentScopes -contains "Directory.Read.All") -or ($currentScopes -contains "Directory.ReadWrite.All")
            $hasIntuneRead   = ($currentScopes -contains "DeviceManagementManagedDevices.Read.All") -or ($currentScopes -contains "DeviceManagementManagedDevices.ReadWrite.All")
            $hasIntuneAction = ($currentScopes -contains "DeviceManagementManagedDevices.PrivilegedOperations.All")
            $hasAuditLog     = ($currentScopes -contains "AuditLog.Read.All")

            if ($hasUserWrite -and $hasUserRead -and $hasDeviceRead -and $hasIntuneRead -and $hasIntuneAction -and $hasAuditLog) {
                try {
                    Get-MgOrganization -Top 1 -ErrorAction Stop | Out-Null
                    $sessionId = if ($context.Account) { $context.Account } else { "AppId: $($context.ClientId)" }
                    Write-Host "Active Graph session validated for $sessionId." -ForegroundColor Green
                    $needsConnect = $false
                }
                catch {
                    Write-Host "Graph session expired. Re-authenticating..." -ForegroundColor Yellow
                    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                }
            }
            else {
                $missing = @()
                if (-not $hasUserWrite)    { $missing += "User.ReadWrite.All or Directory.ReadWrite.All" }
                if (-not $hasDeviceRead)   { $missing += "Device.Read.All or Directory.Read.All" }
                if (-not $hasIntuneRead)   { $missing += "DeviceManagementManagedDevices.Read.All" }
                if (-not $hasIntuneAction) { $missing += "DeviceManagementManagedDevices.PrivilegedOperations.All" }
                if (-not $hasAuditLog)     { $missing += "AuditLog.Read.All" }
                Write-Host "Session missing scopes: $($missing -join ', ')" -ForegroundColor Yellow
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
    catch {
        # No session
    }

    if ($needsConnect) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Device.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.PrivilegedOperations.All", "AuditLog.Read.All" -ErrorAction Stop
        $ctx = Get-MgContext
        $id = if ($ctx.Account) { $ctx.Account } else { "AppId: $($ctx.ClientId)" }
        Write-Host "Connected to Graph as $id." -ForegroundColor Green
    }
}

function Ensure-GraphCLIConsent {
    <#
    .SYNOPSIS
        Checks whether admin consent has been granted for the Microsoft Graph
        Command Line Tools enterprise application (the app used by Connect-MgGraph)
        for the scopes this script requires. If consent is missing, it creates or
        updates an oauth2PermissionGrant to cover the required scopes.

        Requires: DelegatedPermissionGrant.ReadWrite.All (or Global/App Admin role).
        If the current session lacks that scope, the function will attempt to
        reconnect with the additional permission.
    #>

    Write-Host ""
    Write-Host "Checking admin consent for Microsoft Graph Command Line Tools..." -ForegroundColor Cyan

    # Well-known App IDs
    $graphCLIAppId   = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph Command Line Tools
    $msGraphAppId    = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph

    # The scopes this script needs
    $requiredScopes = @(
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",
        "Device.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementManagedDevices.PrivilegedOperations.All",
        "AuditLog.Read.All"
    )

    # -- Look up the Graph CLI service principal in the tenant -----------------
    try {
        $cliSPResult = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$graphCLIAppId'" `
            -ErrorAction Stop

        if (-not $cliSPResult.value -or $cliSPResult.value.Count -eq 0) {
            Write-Host "  Microsoft Graph Command Line Tools service principal not found in tenant." -ForegroundColor Yellow
            Write-Host "  This is created automatically when Connect-MgGraph is first used." -ForegroundColor DarkGray
            Write-Host "  Skipping consent check." -ForegroundColor DarkGray
            return
        }

        $cliSP = $cliSPResult.value[0]
    }
    catch {
        Write-Host "  Could not query service principals: $_" -ForegroundColor Yellow
        Write-Host "  Skipping consent check." -ForegroundColor DarkGray
        return
    }

    # -- Look up the Microsoft Graph resource service principal ----------------
    try {
        $graphSPResult = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$msGraphAppId'" `
            -ErrorAction Stop

        if (-not $graphSPResult.value -or $graphSPResult.value.Count -eq 0) {
            Write-Host "  Microsoft Graph service principal not found. Skipping consent check." -ForegroundColor Yellow
            return
        }

        $graphSP = $graphSPResult.value[0]
    }
    catch {
        Write-Host "  Could not look up Microsoft Graph service principal: $_" -ForegroundColor Yellow
        return
    }

    # -- Check existing oauth2PermissionGrants for the CLI app -----------------
    try {
        $existingGrants = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($cliSP.id)' and resourceId eq '$($graphSP.id)' and consentType eq 'AllPrincipals'" `
            -ErrorAction Stop
    }
    catch {
        Write-Host "  Could not query existing permission grants: $_" -ForegroundColor Yellow
        Write-Host "  Skipping consent check." -ForegroundColor DarkGray
        return
    }

    $existingGrant = $null
    $existingScopeList = @()

    if ($existingGrants.value -and $existingGrants.value.Count -gt 0) {
        $existingGrant = $existingGrants.value[0]
        $existingScopeList = @($existingGrant.scope -split '\s+' | Where-Object { $_ -ne '' })
    }

    # Determine which required scopes are missing
    $missingScopes = @($requiredScopes | Where-Object { $_ -notin $existingScopeList })

    if ($missingScopes.Count -eq 0) {
        Write-Host "  Admin consent already granted for all required scopes." -ForegroundColor Green
        return
    }

    Write-Host "  Missing admin consent for: $($missingScopes -join ', ')" -ForegroundColor Yellow

    # -- Ensure current session has DelegatedPermissionGrant.ReadWrite.All ------
    $ctx = Get-MgContext
    $currentScopes = @($ctx.Scopes)

    if ("DelegatedPermissionGrant.ReadWrite.All" -notin $currentScopes) {
        Write-Host "  Your Graph session needs DelegatedPermissionGrant.ReadWrite.All to grant consent." -ForegroundColor Yellow
        Write-Host "  You will be prompted to re-authenticate with the additional scope." -ForegroundColor Yellow
        Write-Host ""

        $scopeConfirm = Read-Host "  Reconnect Graph with extra scope to grant consent? (Y/N)"
        if ($scopeConfirm -ne "Y" -and $scopeConfirm -ne "y") {
            Write-Host "  Skipping consent grant. Users may be prompted to consent individually." -ForegroundColor DarkGray
            return
        }

        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            $allScopes = @(
                "User.ReadWrite.All",
                "Directory.ReadWrite.All",
                "Device.Read.All",
                "DeviceManagementManagedDevices.Read.All",
                "DeviceManagementManagedDevices.PrivilegedOperations.All",
                "AuditLog.Read.All",
                "DelegatedPermissionGrant.ReadWrite.All"
            )
            Connect-MgGraph -Scopes $allScopes -ErrorAction Stop
            Write-Host "  Graph reconnected with additional scope." -ForegroundColor Green
        }
        catch {
            Write-Warning "  Failed to reconnect: $_"
            Write-Host "  Attempting to reconnect with original scopes..." -ForegroundColor Yellow
            try {
                Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Device.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.PrivilegedOperations.All", "AuditLog.Read.All" -ErrorAction Stop
            } catch {}
            return
        }
    }

    # -- Grant or update consent ------------------------------------------------
    $newScopeString = (($existingScopeList + $missingScopes) | Sort-Object -Unique) -join ' '

    if ($existingGrant) {
        # Update the existing grant to include missing scopes
        Write-Host "  Updating existing admin consent grant..." -ForegroundColor Cyan -NoNewline

        try {
            Invoke-MgGraphRequest -Method PATCH `
                -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($existingGrant.id)" `
                -Body (@{ scope = $newScopeString } | ConvertTo-Json) `
                -ContentType "application/json" `
                -ErrorAction Stop | Out-Null

            Write-Host " Done" -ForegroundColor Green
            Write-Host "  Admin consent granted for: $newScopeString" -ForegroundColor Green
        }
        catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Warning "  Error updating consent grant: $_"
            Write-Host "  Users may be prompted to consent individually." -ForegroundColor Yellow
        }
    }
    else {
        # Create a new admin consent grant
        Write-Host "  Creating admin consent grant..." -ForegroundColor Cyan -NoNewline

        $grantBody = @{
            clientId    = $cliSP.id
            consentType = "AllPrincipals"
            resourceId  = $graphSP.id
            scope       = $newScopeString
        }

        try {
            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
                -Body ($grantBody | ConvertTo-Json) `
                -ContentType "application/json" `
                -ErrorAction Stop | Out-Null

            Write-Host " Done" -ForegroundColor Green
            Write-Host "  Admin consent granted for: $newScopeString" -ForegroundColor Green
        }
        catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Warning "  Error creating consent grant: $_"
            Write-Host "  Users may be prompted to consent individually." -ForegroundColor Yellow
        }
    }
}

function Connect-ToAD {
    <#
    .SYNOPSIS
        Connects to Active Directory. Tries automatic domain discovery first.
        If that fails, checks whether the machine is Hybrid Azure AD Joined
        (in which case it prompts only for a domain/DC name) or not joined at
        all (in which case it prompts for domain, username, and password).

        Saved defaults (domain, username) are loaded from config.json and
        offered as defaults in the prompts. On successful connection the
        values are saved back to config.json for next time.
        Passwords are NEVER saved.

        Stores connection parameters in script-scoped variables:
          $script:adServer     - the DC / domain to target with -Server
          $script:adCredential - PSCredential (or $null if using current user)

        All subsequent AD cmdlet calls should use Get-ADConnectionParams to
        obtain the correct -Server / -Credential splat.
    #>
    Write-Host "Checking Active Directory module and connectivity..." -ForegroundColor Cyan

    # Reset script-scoped AD connection params
    $script:adServer     = $null
    $script:adCredential = $null

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "ActiveDirectory module is not installed. Install RSAT or the AD PowerShell module."
        return $false
    }

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    # -- Load saved defaults from config.json -----------------------------------
    $savedConfig   = Read-Config
    $savedDomain   = if ($savedConfig['ADDomain'])   { $savedConfig['ADDomain'] }   else { $null }
    $savedUsername  = if ($savedConfig['ADUsername'])  { $savedConfig['ADUsername'] }  else { $null }

    # -- Attempt 1: Automatic domain discovery (machine is domain-joined & can reach a DC)
    try {
        Get-ADDomainController -Discover -ErrorAction Stop | Out-Null
        $domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
        Write-Host "Connected to Active Directory domain: $domain" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  Automatic domain discovery failed." -ForegroundColor Yellow
    }

    # -- Attempt 2: Detect device join state via dsregcmd ----------------------------
    Write-Host "  Checking device join state..." -ForegroundColor Cyan

    $isAzureADJoined = $false
    $isDomainJoined  = $false

    try {
        $dsregOutput = dsregcmd /status 2>&1 | Out-String

        if ($dsregOutput -match 'AzureAdJoined\s*:\s*YES')  { $isAzureADJoined = $true }
        if ($dsregOutput -match 'DomainJoined\s*:\s*YES')   { $isDomainJoined  = $true }
    }
    catch {
        Write-Host "  Could not run dsregcmd. Assuming non-joined workstation." -ForegroundColor DarkGray
    }

    $isHybridJoined = ($isAzureADJoined -and $isDomainJoined)

    if ($isHybridJoined) {
        # -------------------------------------------------------------------
        # HYBRID JOINED: machine has a domain trust but can't auto-discover
        # a DC (e.g. VPN not connected, DNS issue). Ask for domain / DC only;
        # the user's cached Windows credentials should work.
        # -------------------------------------------------------------------
        Write-Host ""
        Write-Host "  Device is Hybrid Azure AD Joined." -ForegroundColor Cyan
        Write-Host "  Auto-discovery failed (DC may not be reachable via default DNS)." -ForegroundColor Yellow
        Write-Host "  Please provide a domain name or domain controller FQDN." -ForegroundColor White
        Write-Host ""

        $domainPrompt = "  Domain or DC FQDN (e.g. corp.contoso.com)"
        if ($savedDomain) {
            $domainPrompt += " [$savedDomain]"
        }

        $adServerInput = Read-Host $domainPrompt

        if ([string]::IsNullOrWhiteSpace($adServerInput)) {
            if ($savedDomain) {
                $adServerInput = $savedDomain
                Write-Host "  Using saved domain: $savedDomain" -ForegroundColor DarkGray
            }
            else {
                Write-Host "  No domain entered. AD actions will be unavailable." -ForegroundColor Red
                return $false
            }
        }

        $script:adServer = $adServerInput.Trim()

        Write-Host "  Testing connectivity to $($script:adServer)..." -ForegroundColor Cyan -NoNewline

        try {
            Get-ADDomainController -DomainName $script:adServer -Discover -ErrorAction Stop | Out-Null
            Write-Host " OK" -ForegroundColor Green
        }
        catch {
            # Fall back to direct -Server; discovery may fail but the cmdlet might still work
            Write-Host " Discovery failed, will try direct connection." -ForegroundColor Yellow
        }

        try {
            $adDomain = Get-ADDomain -Server $script:adServer -ErrorAction Stop
            Write-Host "  Connected to Active Directory domain: $($adDomain.DNSRoot)" -ForegroundColor Green

            # Save domain to config for next time
            Save-Config @{ ADDomain = $script:adServer }

            return $true
        }
        catch {
            Write-Host "  Failed to connect to $($script:adServer): $_" -ForegroundColor Red
            Write-Host "  AD actions will be unavailable." -ForegroundColor Red
            $script:adServer = $null
            return $false
        }
    }
    else {
        # -------------------------------------------------------------------
        # NOT HYBRID JOINED (cloud-only, workgroup, or Azure AD Joined only).
        # Need full credentials: domain, username, password.
        # -------------------------------------------------------------------
        $joinState = if ($isAzureADJoined) { "Azure AD Joined (cloud-only)" } else { "Not domain-joined" }
        Write-Host ""
        Write-Host "  Device join state: $joinState" -ForegroundColor Yellow
        Write-Host "  To use AD features, provide a domain controller and credentials." -ForegroundColor White
        Write-Host ""

        $domainPrompt = "  Domain or DC FQDN (e.g. corp.contoso.com)"
        if ($savedDomain) {
            $domainPrompt += " [$savedDomain]"
        }
        $domainPrompt += " [Enter to skip]"

        $adServerInput = Read-Host $domainPrompt

        if ([string]::IsNullOrWhiteSpace($adServerInput)) {
            if ($savedDomain) {
                $adServerInput = $savedDomain
                Write-Host "  Using saved domain: $savedDomain" -ForegroundColor DarkGray
            }
            else {
                Write-Host "  Skipping AD connection." -ForegroundColor DarkGray
                return $false
            }
        }

        $script:adServer = $adServerInput.Trim()

        Write-Host ""
        Write-Host "  Enter credentials for $($script:adServer):" -ForegroundColor Cyan

        $usernamePrompt = "  Username (DOMAIN\user or user@domain.com)"
        if ($savedUsername) {
            $usernamePrompt += " [$savedUsername]"
        }

        $adUsername = Read-Host $usernamePrompt

        if ([string]::IsNullOrWhiteSpace($adUsername)) {
            if ($savedUsername) {
                $adUsername = $savedUsername
                Write-Host "  Using saved username: $savedUsername" -ForegroundColor DarkGray
            }
            else {
                Write-Host "  No username entered. AD actions will be unavailable." -ForegroundColor Red
                $script:adServer = $null
                return $false
            }
        }

        $adPassword = Read-Host "  Password" -AsSecureString

        $script:adCredential = New-Object System.Management.Automation.PSCredential ($adUsername, $adPassword)

        Write-Host ""
        Write-Host "  Testing connectivity to $($script:adServer)..." -ForegroundColor Cyan -NoNewline

        try {
            $adDomain = Get-ADDomain -Server $script:adServer -Credential $script:adCredential -ErrorAction Stop
            Write-Host " OK" -ForegroundColor Green
            Write-Host "  Connected to Active Directory domain: $($adDomain.DNSRoot)" -ForegroundColor Green

            # Save domain and username to config for next time (never passwords)
            Save-Config @{
                ADDomain   = $script:adServer
                ADUsername  = $adUsername
            }

            return $true
        }
        catch {
            Write-Host " FAILED" -ForegroundColor Red

            $errMsg = "$_"
            if ($errMsg -match 'logon failure|password|credential|access denied|authentication' ) {
                Write-Host "  Authentication failed. Check your username and password." -ForegroundColor Red
            }
            elseif ($errMsg -match 'server is not operational|cannot contact|unable to connect') {
                Write-Host "  Cannot reach domain controller '$($script:adServer)'." -ForegroundColor Red
                Write-Host "  Verify the FQDN and ensure you have network connectivity." -ForegroundColor Yellow
            }
            else {
                Write-Host "  Error: $errMsg" -ForegroundColor Red
            }

            $script:adServer     = $null
            $script:adCredential = $null
            return $false
        }
    }
}

function Get-ADConnectionParams {
    <#
    .SYNOPSIS
        Returns a hashtable suitable for splatting into AD cmdlets.
        Includes -Server and/or -Credential only when script-scoped
        values have been set by Connect-ToAD (i.e. non-domain-joined scenarios).

        Usage:  $adParams = Get-ADConnectionParams
                Get-ADUser @adParams -Filter "..."
    #>
    $params = @{}
    if ($script:adServer)     { $params['Server']     = $script:adServer }
    if ($script:adCredential) { $params['Credential'] = $script:adCredential }
    return $params
}

function Connect-ToMDE {
    <#
    .SYNOPSIS
        Authenticates to the Microsoft Defender for Endpoint API.
        Offers multiple sign-in methods: Interactive Browser, Device Code, or WAM.
        Stores the token in script-scoped variables.
    #>
    Write-Host "Connecting to Microsoft Defender for Endpoint..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  MDE requires an App Registration with 'WindowsDefenderATP'" -ForegroundColor White
    Write-Host "  API permissions. Enter your App's Client ID below." -ForegroundColor White
    Write-Host ""
    Write-Host "  Don't have one?" -ForegroundColor DarkGray
    Write-Host "    Type 'CREATE' to auto-create one via Graph (needs App Admin role)" -ForegroundColor DarkGray
    Write-Host "    Type 'GUIDE'  to see manual setup steps" -ForegroundColor DarkGray
    Write-Host "    Press Enter   to try the default Azure PowerShell client" -ForegroundColor DarkGray
    Write-Host ""

    $customClientId = Read-Host "  App Client ID (or Enter / CREATE / GUIDE)"

    if ($customClientId -eq "GUIDE" -or $customClientId -eq "guide") {
        Show-MDEAppRegistrationGuide
        $customClientId = Read-Host "  App Client ID (or Enter for default, CREATE to auto-create)"
    }

    if ($customClientId -eq "CREATE" -or $customClientId -eq "create") {
        $createdAppId = New-MDEAppRegistration
        if ($createdAppId) {
            $customClientId = $createdAppId
            Write-Host "  Using newly created App Client ID: $createdAppId" -ForegroundColor Green
        }
        else {
            Write-Host "  App creation failed or was cancelled." -ForegroundColor Yellow
            $customClientId = Read-Host "  App Client ID (or Enter for default)"
        }
    }

    # Default: Azure PowerShell well-known public client ID
    $clientId = if ([string]::IsNullOrWhiteSpace($customClientId)) {
        Write-Host "  Using default Azure PowerShell public client." -ForegroundColor DarkGray
        "1950a258-227b-4e31-a9cf-717495945fc2"
    } else {
        $customClientId.Trim()
    }

    # Try to inherit tenant from existing Graph session
    $tenantId = "common"
    try {
        $ctx = Get-MgContext
        if ($ctx.TenantId) { $tenantId = $ctx.TenantId }
    } catch {}

    # Show sign-in method menu
    Write-Host ""
    Write-Host "  -- Sign-in Method --" -ForegroundColor Yellow
    Write-Host "    [1] Interactive Browser  (opens browser -- supports passkey, FIDO2, Windows Hello, MFA)"
    Write-Host "    [2] Device Code          (paste a code at https://microsoft.com/devicelogin -- best for remote/SSH)"
    Write-Host "    [3] WAM (Windows SSO)    (uses cached Windows credential via broker -- requires MSAL.PS module)"
    Write-Host "    [4] Cancel"
    Write-Host ""

    $authMethod = Read-Host "  Select"

    switch ($authMethod) {
        "1" { return Connect-ToMDE-Browser   -ClientId $clientId -TenantId $tenantId }
        "2" { return Connect-ToMDE-DeviceCode -ClientId $clientId -TenantId $tenantId }
        "3" { return Connect-ToMDE-WAM        -ClientId $clientId -TenantId $tenantId }
        "4" {
            Write-Host "  Cancelled." -ForegroundColor DarkGray
            return $false
        }
        default {
            Write-Host "  Invalid selection." -ForegroundColor Yellow
            return $false
        }
    }
}

function Show-MDEAppRegistrationGuide {
    <#
    .SYNOPSIS
        Prints step-by-step instructions for creating an Entra App Registration
        with the MDE (WindowsDefenderATP) API permissions.
    #>
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host "  HOW TO CREATE AN APP REGISTRATION FOR MDE" -ForegroundColor Yellow
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  The MDE API requires its own App Registration in Entra ID." -ForegroundColor White
    Write-Host "  Your user account may have MDE permissions, but the OAuth" -ForegroundColor White
    Write-Host "  application used to sign in must ALSO have the MDE API" -ForegroundColor White
    Write-Host "  permissions configured. These are separate things." -ForegroundColor White
    Write-Host ""
    Write-Host "  Step 1: Register a new app" -ForegroundColor Cyan
    Write-Host "    - Go to: https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps" -ForegroundColor White
    Write-Host "    - Click 'New registration'" -ForegroundColor White
    Write-Host "    - Name: e.g. 'MDE Management Tool'" -ForegroundColor White
    Write-Host "    - Supported account types: 'Single tenant'" -ForegroundColor White
    Write-Host "    - Redirect URI: Select 'Public client/native (mobile & desktop)'" -ForegroundColor White
    Write-Host "      and enter: http://localhost" -ForegroundColor Yellow
    Write-Host "    - Click 'Register'" -ForegroundColor White
    Write-Host ""
    Write-Host "  Step 2: Add MDE API permissions" -ForegroundColor Cyan
    Write-Host "    - Go to 'API permissions' in the left menu" -ForegroundColor White
    Write-Host "    - Click 'Add a permission'" -ForegroundColor White
    Write-Host "    - Select 'APIs my organization uses'" -ForegroundColor White
    Write-Host "    - Search for 'WindowsDefenderATP' and select it" -ForegroundColor White
    Write-Host "    - Select 'Delegated permissions'" -ForegroundColor White
    Write-Host "    - Tick these permissions:" -ForegroundColor White
    Write-Host "        Machine.Isolate" -ForegroundColor Yellow
    Write-Host "        Machine.Read.All" -ForegroundColor Yellow
    Write-Host "        Machine.ReadWrite.All" -ForegroundColor Yellow
    Write-Host "    - Click 'Add permissions'" -ForegroundColor White
    Write-Host ""
    Write-Host "  Step 3: Grant admin consent" -ForegroundColor Cyan
    Write-Host "    - Still on the 'API permissions' page, click" -ForegroundColor White
    Write-Host "      'Grant admin consent for <your tenant>'" -ForegroundColor Yellow
    Write-Host "    - Confirm when prompted" -ForegroundColor White
    Write-Host ""
    Write-Host "  Step 4: Enable public client flows" -ForegroundColor Cyan
    Write-Host "    - Go to 'Authentication' in the left menu" -ForegroundColor White
    Write-Host "    - Under 'Advanced settings', set" -ForegroundColor White
    Write-Host "      'Allow public client flows' to Yes" -ForegroundColor Yellow
    Write-Host "    - Click 'Save'" -ForegroundColor White
    Write-Host ""
    Write-Host "  Step 5: Copy the Application (client) ID" -ForegroundColor Cyan
    Write-Host "    - Go to the app's 'Overview' page" -ForegroundColor White
    Write-Host "    - Copy the 'Application (client) ID' value" -ForegroundColor White
    Write-Host "    - Paste it when this script prompts for 'App Client ID'" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host ""
}

function New-MDEAppRegistration {
    <#
    .SYNOPSIS
        Automates the creation of an Entra App Registration configured for MDE.
        Uses the existing Microsoft Graph session. Requires the caller to have
        Application.ReadWrite.All and DelegatedPermissionGrant.ReadWrite.All
        permissions (or Global / Application Administrator role).

        Returns the new Application (client) ID as a string, or $null on failure.
    #>

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  CREATE MDE APP REGISTRATION" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This will use your current Graph session to automatically:" -ForegroundColor White
    Write-Host "    1. Create a new App Registration" -ForegroundColor White
    Write-Host "    2. Add WindowsDefenderATP delegated permissions" -ForegroundColor White
    Write-Host "    3. Grant admin consent" -ForegroundColor White
    Write-Host "    4. Enable public client flows + redirect URIs" -ForegroundColor White
    Write-Host ""
    Write-Host "  Requires: Application Administrator or Global Administrator role." -ForegroundColor Yellow
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return $null
    }

    # -- Ensure Graph session has the required scopes ------------------------------
    Write-Host ""
    Write-Host "  Checking Graph permissions..." -ForegroundColor Cyan

    $ctx = $null
    try { $ctx = Get-MgContext } catch {}

    if (-not $ctx) {
        Write-Warning "No active Graph session. Cannot create app registration."
        return $null
    }

    $currentScopes = @($ctx.Scopes)
    $needsReconnect = $false

    $requiredScopes = @("Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All")
    foreach ($rs in $requiredScopes) {
        if ($rs -notin $currentScopes) {
            $needsReconnect = $true
            break
        }
    }

    if ($needsReconnect) {
        Write-Host "  Your Graph session needs additional scopes to create apps." -ForegroundColor Yellow
        Write-Host "  You will be prompted to re-authenticate with:" -ForegroundColor Yellow
        Write-Host "    Application.ReadWrite.All" -ForegroundColor White
        Write-Host "    DelegatedPermissionGrant.ReadWrite.All" -ForegroundColor White
        Write-Host ""

        $scopeConfirm = Read-Host "  Reconnect Graph with extra scopes? (Y/N)"
        if ($scopeConfirm -ne "Y" -and $scopeConfirm -ne "y") {
            Write-Host "  Cancelled." -ForegroundColor DarkGray
            return $null
        }

        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            $allScopes = @(
                "User.ReadWrite.All",
                "Directory.ReadWrite.All",
                "Device.Read.All",
                "DeviceManagementManagedDevices.Read.All",
                "DeviceManagementManagedDevices.PrivilegedOperations.All",
                "AuditLog.Read.All",
                "Application.ReadWrite.All",
                "DelegatedPermissionGrant.ReadWrite.All"
            )
            Connect-MgGraph -Scopes $allScopes -ErrorAction Stop
            Write-Host "  Graph reconnected with additional scopes." -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to reconnect Graph with additional scopes: $_"
            Write-Host "  Attempting to reconnect with original scopes..." -ForegroundColor Yellow
            try {
                Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Device.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.PrivilegedOperations.All", "AuditLog.Read.All" -ErrorAction Stop
            } catch {}
            return $null
        }
    }
    else {
        Write-Host "  Graph session has required scopes." -ForegroundColor Green
    }

    # -- App name ------------------------------------------------------------------
    Write-Host ""
    $appNameInput = Read-Host "  App display name (Enter for 'MDE Management Tool')"
    $appName = if ([string]::IsNullOrWhiteSpace($appNameInput)) { "MDE Management Tool" } else { $appNameInput.Trim() }

    # -- WindowsDefenderATP service principal & permission IDs ---------------------
    Write-Host ""
    Write-Host "  [1/5] Looking up WindowsDefenderATP service principal..." -ForegroundColor Cyan -NoNewline

    $mdeSPAppId = "fc780465-2017-40d4-a0c5-307022471b92"  # Well-known MDE first-party app ID

    try {
        $mdeSPResult = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$mdeSPAppId'" `
            -ErrorAction Stop

        if (-not $mdeSPResult.value -or $mdeSPResult.value.Count -eq 0) {
            Write-Host " NOT FOUND" -ForegroundColor Red
            Write-Host ""
            Write-Host "  The WindowsDefenderATP service principal was not found in your tenant." -ForegroundColor Red
            Write-Host "  This usually means MDE (Defender for Endpoint) is not provisioned." -ForegroundColor Yellow
            Write-Host "  Ensure your tenant has an active MDE license and that the service" -ForegroundColor Yellow
            Write-Host "  principal exists before creating an app registration." -ForegroundColor Yellow
            return $null
        }

        $mdeSP = $mdeSPResult.value[0]
        Write-Host " Found (ID: $($mdeSP.id))" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error looking up MDE service principal: $_"
        return $null
    }

    # Resolve delegated permission (oauth2PermissionScope) IDs
    $requiredPermNames = @("Machine.Read.All", "Machine.ReadWrite.All", "Machine.Isolate")
    $resolvedPerms = @()
    $allScopes = @($mdeSP.oauth2PermissionScopes)

    foreach ($permName in $requiredPermNames) {
        $match = $allScopes | Where-Object { $_.value -eq $permName }
        if ($match) {
            $resolvedPerms += @{ id = $match.id; type = "Scope" }
            Write-Host "    Resolved: $permName -> $($match.id)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "    WARNING: Permission '$permName' not found on MDE service principal." -ForegroundColor Yellow
        }
    }

    if ($resolvedPerms.Count -eq 0) {
        Write-Warning "  No MDE permissions could be resolved. Aborting."
        return $null
    }

    # -- Create the app registration -----------------------------------------------
    Write-Host ""
    Write-Host "  [2/5] Creating app registration '$appName'..." -ForegroundColor Cyan -NoNewline

    $appBody = @{
        displayName            = $appName
        signInAudience         = "AzureADMyOrg"
        isFallbackPublicClient = $true
        publicClient           = @{
            redirectUris = @(
                "http://localhost"
                "https://login.microsoftonline.com/common/oauth2/nativeclient"
                "urn:ietf:wg:oauth:2.0:oob"
            )
        }
        requiredResourceAccess = @(
            @{
                resourceAppId  = $mdeSPAppId
                resourceAccess = @($resolvedPerms)
            }
        )
    }

    try {
        $newApp = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/applications" `
            -Body ($appBody | ConvertTo-Json -Depth 10) `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host " Done" -ForegroundColor Green
        Write-Host "    Application ID : $($newApp.appId)" -ForegroundColor White
        Write-Host "    Object ID      : $($newApp.id)" -ForegroundColor DarkGray
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error creating app registration: $_"

        $errStatus = $null
        try { $errStatus = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($errStatus -eq 403) {
            Write-Host ""
            Write-Host "  Your account does not have permission to create app registrations." -ForegroundColor Yellow
            Write-Host "  You need the Application Administrator or Global Administrator role." -ForegroundColor Yellow
        }
        return $null
    }

    # -- Create the service principal for the new app --------------------------------
    Write-Host "  [3/5] Creating service principal for the app..." -ForegroundColor Cyan -NoNewline

    try {
        $newSP = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
            -Body (@{ appId = $newApp.appId } | ConvertTo-Json) `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error creating service principal: $_"
        Write-Host "  The app was created but admin consent cannot be granted automatically." -ForegroundColor Yellow
        Write-Host "  Grant consent manually in the Entra portal for App ID: $($newApp.appId)" -ForegroundColor Yellow
        return $newApp.appId
    }

    # -- Grant admin consent (delegated permission grant) ----------------------------
    Write-Host "  [4/5] Granting admin consent for MDE permissions..." -ForegroundColor Cyan -NoNewline

    $scopeString = ($requiredPermNames -join ' ')

    $grantBody = @{
        clientId    = $newSP.id
        consentType = "AllPrincipals"
        resourceId  = $mdeSP.id
        scope       = $scopeString
    }

    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
            -Body ($grantBody | ConvertTo-Json) `
            -ContentType "application/json" `
            -ErrorAction Stop | Out-Null

        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error granting admin consent: $_"
        Write-Host ""
        Write-Host "  The app was created but admin consent was not granted." -ForegroundColor Yellow
        Write-Host "  Grant consent manually in the Entra portal:" -ForegroundColor Yellow
        Write-Host "  https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps" -ForegroundColor White
        Write-Host "  Find '$appName' -> API permissions -> Grant admin consent" -ForegroundColor White
        Write-Host ""
        Write-Host "  The app can still be used once consent is granted." -ForegroundColor White
        Write-Host "  App Client ID: $($newApp.appId)" -ForegroundColor Yellow
        return $newApp.appId
    }

    # -- Summary --------------------------------------------------------------------
    Write-Host "  [5/5] Verifying configuration..." -ForegroundColor Cyan -NoNewline

    # Quick verification: read the app back
    try {
        $verifyApp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/applications/$($newApp.id)" `
            -ErrorAction Stop
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " Could not verify (non-critical)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host "  APP REGISTRATION CREATED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  App Name      : $appName" -ForegroundColor White
    Write-Host "  App Client ID : $($newApp.appId)" -ForegroundColor Yellow
    Write-Host "  Tenant         : $(if ($ctx.TenantId) { $ctx.TenantId } else { 'Unknown' })" -ForegroundColor White
    Write-Host ""
    Write-Host "  Permissions granted:" -ForegroundColor White
    foreach ($p in $requiredPermNames) {
        Write-Host "    - WindowsDefenderATP / $p (Delegated, Admin Consented)" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "  Public client flows : Enabled" -ForegroundColor White
    Write-Host "  Redirect URIs       : http://localhost + native client defaults" -ForegroundColor White
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host ""

    return $newApp.appId
}

function Test-MDEConnection {
    <#
    .SYNOPSIS
        Validates the MDE access token by making a lightweight API call.
        Returns $true on success. On failure, detects the specific error
        (401/403 = app permissions, other = network/config) and shows guidance.
    #>
    try {
        $testUri = "https://api.securitycenter.microsoft.com/api/machines?`$top=1"
        Invoke-RestMethod -Method GET -Uri $testUri -Headers @{
            Authorization = "Bearer $($script:mdeAccessToken)"
        } -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        $statusCode = $null
        try { $statusCode = $_.Exception.Response.StatusCode.value__ } catch {}

        $script:mdeAccessToken = $null

        if ($statusCode -eq 403 -or $statusCode -eq 401) {
            Write-Host ""
            Write-Host "  ACCESS DENIED (HTTP $statusCode)" -ForegroundColor Red
            Write-Host ""
            Write-Host "  Your sign-in succeeded, but the MDE API rejected the request." -ForegroundColor Yellow
            Write-Host "  This almost always means the App Registration (Client ID) you" -ForegroundColor Yellow
            Write-Host "  used does not have the 'WindowsDefenderATP' API permissions" -ForegroundColor Yellow
            Write-Host "  configured and admin-consented in your Entra tenant." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Your user account having MDE roles is NOT enough --" -ForegroundColor White
            Write-Host "  the OAuth app itself needs API permissions separately." -ForegroundColor White
            Write-Host ""
            Write-Host "  Use option [3] from the main menu and type 'CREATE' to" -ForegroundColor Cyan
            Write-Host "  auto-create a correctly configured app, or type 'GUIDE'" -ForegroundColor Cyan
            Write-Host "  for manual setup steps." -ForegroundColor Cyan
        }
        else {
            Write-Warning "MDE API validation failed (HTTP $statusCode): $_"
            Write-Host ""
            Write-Host "  If you are using the default Azure PowerShell client ID," -ForegroundColor DarkGray
            Write-Host "  it likely does not have MDE permissions in your tenant." -ForegroundColor DarkGray
            Write-Host "  Run the script again and enter a dedicated App Client ID." -ForegroundColor DarkGray
        }

        return $false
    }
}

function Connect-ToMDE-Browser {
    <#
    .SYNOPSIS
        Authenticates to MDE via interactive browser using Authorization Code + PKCE.
        Opens the system browser -- supports passkey, FIDO2, Windows Hello, smart card,
        and any other method the tenant's Entra Conditional Access allows.
    #>
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [string]$TenantId = "common"
    )

    Write-Host ""
    Write-Host "  Starting interactive browser sign-in..." -ForegroundColor Cyan

    # Ensure System.Web is loaded for HttpUtility.ParseQueryString (PS 5.1 compat)
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $scope      = "https://api.securitycenter.microsoft.com/.default offline_access"
    $tokenUrl   = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $authorizeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize"

    # Generate PKCE code verifier & challenge
    $codeVerifierBytes = [byte[]]::new(64)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($codeVerifierBytes)
    $codeVerifier = [Convert]::ToBase64String($codeVerifierBytes) -replace '\+','-' -replace '/','_' -replace '='
    $challengeBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::ASCII.GetBytes($codeVerifier)
    )
    $codeChallenge = [Convert]::ToBase64String($challengeBytes) -replace '\+','-' -replace '/','_' -replace '='

    $state = [Guid]::NewGuid().ToString()

    # Find a free port and start listener
    $listener = [System.Net.HttpListener]::new()
    $port = 0
    foreach ($candidatePort in 8400..8420) {
        try {
            $listener.Prefixes.Clear()
            $listener.Prefixes.Add("http://localhost:${candidatePort}/")
            $listener.Start()
            $port = $candidatePort
            break
        }
        catch {
            $listener = [System.Net.HttpListener]::new()
        }
    }

    if ($port -eq 0) {
        Write-Warning "Could not start a local HTTP listener on ports 8400-8420."
        Write-Warning "Ensure no other process is using these ports, or use Device Code instead."
        return $false
    }

    $redirectUri = "http://localhost:$port/"

    # Build authorize URL
    $authParams = @(
        "client_id=$ClientId"
        "response_type=code"
        "redirect_uri=$([Uri]::EscapeDataString($redirectUri))"
        "response_mode=query"
        "scope=$([Uri]::EscapeDataString($scope))"
        "state=$state"
        "code_challenge=$codeChallenge"
        "code_challenge_method=S256"
        "prompt=select_account"
    )
    $fullAuthUrl = "$authorizeUrl`?$($authParams -join '&')"

    # Open browser
    Write-Host "  Opening browser for sign-in..." -ForegroundColor White
    Write-Host "  (If a browser doesn't open, copy this URL manually:)" -ForegroundColor DarkGray
    Write-Host "  $fullAuthUrl" -ForegroundColor DarkGray
    Write-Host ""

    try {
        if ($IsWindows -or $env:OS -match 'Windows') {
            Start-Process $fullAuthUrl
        }
        elseif ($IsMacOS) {
            Start-Process "open" -ArgumentList $fullAuthUrl
        }
        else {
            Start-Process "xdg-open" -ArgumentList $fullAuthUrl
        }
    }
    catch {
        Write-Host "  Could not open browser automatically. Please open the URL above." -ForegroundColor Yellow
    }

    Write-Host "  Waiting for browser sign-in..." -ForegroundColor Yellow

    # Wait for the redirect (60 second timeout)
    $asyncResult = $listener.BeginGetContext($null, $null)
    $completed = $asyncResult.AsyncWaitHandle.WaitOne(120000)  # 2 minutes

    if (-not $completed) {
        $listener.Stop()
        $listener.Close()
        Write-Warning "Browser sign-in timed out after 2 minutes."
        return $false
    }

    $context  = $listener.EndGetContext($asyncResult)
    $request  = $context.Request
    $response = $context.Response

    # Parse query string
    $queryParams = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)
    $authCode    = $queryParams["code"]
    $returnState = $queryParams["state"]
    $authError   = $queryParams["error"]

    # Send a response page to the browser
    $responseHtml = if ($authCode -and $returnState -eq $state) {
        "<html><body style='font-family:sans-serif;text-align:center;padding:60px'><h2>&#x2705; Sign-in successful</h2><p>You can close this tab and return to PowerShell.</p></body></html>"
    } else {
        $errDesc = $queryParams["error_description"]
        "<html><body style='font-family:sans-serif;text-align:center;padding:60px'><h2>&#x274C; Sign-in failed</h2><p>$authError : $errDesc</p></body></html>"
    }

    $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($responseHtml)
    $response.ContentType     = "text/html"
    $response.ContentLength64 = $responseBytes.Length
    $response.OutputStream.Write($responseBytes, 0, $responseBytes.Length)
    $response.Close()
    $listener.Stop()
    $listener.Close()

    # Validate state
    if ($returnState -ne $state) {
        Write-Warning "OAuth state mismatch -- possible CSRF. Sign-in aborted."
        return $false
    }

    if ($authError) {
        $errDesc = $queryParams["error_description"]
        Write-Warning "Browser sign-in error: $authError -- $errDesc"
        return $false
    }

    if (-not $authCode) {
        Write-Warning "No authorization code received from browser."
        return $false
    }

    # Exchange code for tokens
    Write-Host "  Exchanging authorization code for token..." -ForegroundColor Cyan

    try {
        $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body @{
            client_id     = $ClientId
            grant_type    = "authorization_code"
            code          = $authCode
            redirect_uri  = $redirectUri
            code_verifier = $codeVerifier
            scope         = $scope
        } -ErrorAction Stop

        $script:mdeAccessToken  = $tokenResponse.access_token
        $script:mdeRefreshToken = $tokenResponse.refresh_token
        $script:mdeTokenExpiry  = (Get-Date).AddSeconds($tokenResponse.expires_in - 120)
        $script:mdeClientId     = $ClientId
        $script:mdeTokenUrl     = $tokenUrl
    }
    catch {
        Write-Warning "Token exchange failed: $_"
        return $false
    }

    if (-not (Test-MDEConnection)) { return $false }

    Write-Host "  Connected to MDE via interactive browser." -ForegroundColor Green
    return $true
}

function Connect-ToMDE-DeviceCode {
    <#
    .SYNOPSIS
        Authenticates to MDE via OAuth2 device code flow.
        Best for remote sessions, SSH, or environments without a local browser.
    #>
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [string]$TenantId = "common"
    )

    Write-Host ""
    Write-Host "  Starting device code sign-in..." -ForegroundColor Cyan

    $deviceCodeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $tokenUrl      = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $scope         = "https://api.securitycenter.microsoft.com/.default offline_access"

    try {
        $deviceCodeResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body @{
            client_id = $ClientId
            scope     = $scope
        } -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to initiate device code flow: $_"
        return $false
    }

    Write-Host ""
    Write-Host "  $($deviceCodeResponse.message)" -ForegroundColor Yellow
    Write-Host ""

    $timeout  = (Get-Date).AddSeconds($deviceCodeResponse.expires_in)
    $interval = if ($deviceCodeResponse.interval) { $deviceCodeResponse.interval } else { 5 }

    while ((Get-Date) -lt $timeout) {
        Start-Sleep -Seconds $interval
        try {
            $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body @{
                client_id   = $ClientId
                grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                device_code = $deviceCodeResponse.device_code
            } -ErrorAction Stop

            $script:mdeAccessToken  = $tokenResponse.access_token
            $script:mdeRefreshToken = $tokenResponse.refresh_token
            $script:mdeTokenExpiry  = (Get-Date).AddSeconds($tokenResponse.expires_in - 120)
            $script:mdeClientId     = $ClientId
            $script:mdeTokenUrl     = $tokenUrl

            if (-not (Test-MDEConnection)) { return $false }

            Write-Host "  Connected to MDE via device code." -ForegroundColor Green
            return $true
        }
        catch {
            $errBody = $null
            try { $errBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}

            if ($errBody.error -eq "authorization_pending") { continue }
            if ($errBody.error -eq "slow_down") {
                $interval += 5
                continue
            }

            $errMsg = if ($errBody.error_description) { $errBody.error_description } else { $_ }
            Write-Warning "Device code authentication failed: $errMsg"
            return $false
        }
    }

    Write-Warning "Device code authentication timed out."
    return $false
}

function Connect-ToMDE-WAM {
    <#
    .SYNOPSIS
        Authenticates to MDE via WAM (Web Account Manager) / Windows broker.
        Uses the MSAL.PS module to leverage cached Windows credentials for SSO.
        Falls back to an interactive broker prompt if silent auth fails.
        Requires: Install-Module MSAL.PS -Scope CurrentUser
    #>
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [string]$TenantId = "common"
    )

    Write-Host ""
    Write-Host "  Starting WAM (Windows SSO) sign-in..." -ForegroundColor Cyan

    # Check MSAL.PS availability
    if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
        Write-Host ""
        Write-Host "  The MSAL.PS module is required for WAM / Windows broker sign-in." -ForegroundColor Red
        Write-Host "  Install it with:" -ForegroundColor White
        Write-Host "    Install-Module MSAL.PS -Scope CurrentUser" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Alternatively, select 'Interactive Browser' or 'Device Code' instead." -ForegroundColor White
        return $false
    }

    Import-Module MSAL.PS -ErrorAction SilentlyContinue

    $scope    = "https://api.securitycenter.microsoft.com/.default"
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $msalParams = @{
        ClientId = $ClientId
        TenantId = $TenantId
        Scopes   = @($scope)
    }

    # Try silent token first (cached credentials), then fall back to interactive broker
    $tokenResult = $null
    try {
        Write-Host "  Attempting silent SSO via Windows broker..." -ForegroundColor White
        $tokenResult = Get-MsalToken @msalParams -Silent -ErrorAction Stop
    }
    catch {
        Write-Host "  Silent SSO unavailable, launching broker prompt..." -ForegroundColor Yellow
        try {
            $tokenResult = Get-MsalToken @msalParams -Interactive -UseEmbeddedWebView:$false -ErrorAction Stop
        }
        catch {
            Write-Warning "WAM authentication failed: $_"
            Write-Host ""
            Write-Host "  Tip: If your organisation hasn't configured WAM, try" -ForegroundColor DarkGray
            Write-Host "  'Interactive Browser' or 'Device Code' instead." -ForegroundColor DarkGray
            return $false
        }
    }

    if (-not $tokenResult -or -not $tokenResult.AccessToken) {
        Write-Warning "WAM returned no token."
        return $false
    }

    $script:mdeAccessToken  = $tokenResult.AccessToken
    $script:mdeRefreshToken = $null  # MSAL manages refresh internally
    $script:mdeTokenExpiry  = $tokenResult.ExpiresOn.UtcDateTime.AddMinutes(-2)
    $script:mdeClientId     = $ClientId
    $script:mdeTokenUrl     = $tokenUrl
    # Store MSAL params for silent refresh later
    $script:mdeMsalParams   = $msalParams

    if (-not (Test-MDEConnection)) { return $false }

    Write-Host "  Connected to MDE via Windows broker (WAM)." -ForegroundColor Green
    return $true
}

# ==============================================================================
# FUNCTIONS -- MDE API HELPERS
# ==============================================================================

function Update-MDEToken {
    <#
    .SYNOPSIS
        Silently refreshes the MDE access token.
        Uses refresh_token for Browser/DeviceCode flows, or MSAL silent renewal for WAM.
        Returns $true on success.
    #>

    # WAM / MSAL.PS path -- use silent token acquisition
    if ($script:mdeMsalParams) {
        try {
            $msalRefreshParams = $script:mdeMsalParams
            $tokenResult = Get-MsalToken @msalRefreshParams -Silent -ForceRefresh -ErrorAction Stop
            if ($tokenResult -and $tokenResult.AccessToken) {
                $script:mdeAccessToken = $tokenResult.AccessToken
                $script:mdeTokenExpiry = $tokenResult.ExpiresOn.UtcDateTime.AddMinutes(-2)
                return $true
            }
        }
        catch {
            Write-Warning "MSAL silent token refresh failed: $_"
            return $false
        }
    }

    # Browser / Device Code path -- use refresh token
    if (-not $script:mdeRefreshToken) { return $false }

    try {
        $tokenResponse = Invoke-RestMethod -Method POST -Uri $script:mdeTokenUrl -Body @{
            client_id     = $script:mdeClientId
            grant_type    = "refresh_token"
            refresh_token = $script:mdeRefreshToken
            scope         = "https://api.securitycenter.microsoft.com/.default offline_access"
        } -ErrorAction Stop

        $script:mdeAccessToken  = $tokenResponse.access_token
        $script:mdeRefreshToken = $tokenResponse.refresh_token
        $script:mdeTokenExpiry  = (Get-Date).AddSeconds($tokenResponse.expires_in - 120)
        return $true
    }
    catch {
        Write-Warning "Failed to refresh MDE token: $_"
        return $false
    }
}

function Invoke-MDERequest {
    <#
    .SYNOPSIS
        Makes an authenticated request to the MDE API. Handles token refresh.
        Returns the parsed response or $null on failure.
    #>
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Endpoint,
        [hashtable]$Body
    )

    if (-not $script:mdeAccessToken) {
        Write-Warning "MDE is not connected."
        return $null
    }

    # Refresh token if close to expiry
    if ((Get-Date) -ge $script:mdeTokenExpiry) {
        if (-not (Update-MDEToken)) {
            Write-Warning "MDE token expired and could not be refreshed. Please reconnect."
            return $null
        }
    }

    $baseUri = "https://api.securitycenter.microsoft.com"
    $uri     = "$baseUri$Endpoint"

    $params = @{
        Method      = $Method
        Uri         = $uri
        Headers     = @{ Authorization = "Bearer $($script:mdeAccessToken)" }
        ContentType = "application/json"
        ErrorAction = "Stop"
    }

    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 5)
    }

    try {
        return Invoke-RestMethod @params
    }
    catch {
        $errDetail = $null
        try { $errDetail = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
        $msg = if ($errDetail.error.message) { $errDetail.error.message } else { $_ }
        Write-Warning "MDE API error ($Method $Endpoint): $msg"
        return $null
    }
}

# ==============================================================================
# FUNCTIONS -- SEARCH
# ==============================================================================

function Search-Users {
    param([string]$SearchTerm)

    Write-Host "Searching Entra ID for '$SearchTerm'..." -ForegroundColor Cyan
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $safeTerm = $SearchTerm -replace "'", "''"
        $graphFilter = "startsWith(userPrincipalName,'$safeTerm') or startsWith(displayName,'$safeTerm') or startsWith(givenName,'$safeTerm') or startsWith(surname,'$safeTerm')"
        $entraUsers = Get-MgUser -Filter $graphFilter -Top 25 `
            -Property "id","displayName","userPrincipalName","givenName","surname","jobTitle","department","accountEnabled","mail","lastPasswordChangeDateTime" `
            -ErrorAction Stop
    }
    catch {
        Write-Host "  Graph filter failed, trying search..." -ForegroundColor DarkGray
        try {
            $entraUsers = Get-MgUser -Search "displayName:$SearchTerm" -Top 25 `
                -Property "id","displayName","userPrincipalName","givenName","surname","jobTitle","department","accountEnabled","mail","lastPasswordChangeDateTime" `
                -ConsistencyLevel eventual -ErrorAction Stop
        }
        catch {
            Write-Warning "Graph search failed: $_"
            $entraUsers = @()
        }
    }

    foreach ($eu in $entraUsers) {
        $results.Add([PSCustomObject]@{
            Id             = $eu.Id
            DisplayName    = $eu.DisplayName
            UPN            = $eu.UserPrincipalName
            GivenName      = $eu.GivenName
            Surname        = $eu.Surname
            JobTitle       = $eu.JobTitle
            Department     = $eu.Department
            Mail           = $eu.Mail
            AccountEnabled = $eu.AccountEnabled
            LastPwdChange  = $eu.LastPasswordChangeDateTime
        })
    }

    return $results
}

function Search-MDEDevices {
    param([string]$SearchTerm)

    Write-Host "Searching MDE for '$SearchTerm'..." -ForegroundColor Cyan

    $safeTerm = $SearchTerm -replace "'", "''"
    $filter   = "startswith(computerDnsName,'$safeTerm')"
    $result   = Invoke-MDERequest -Method GET -Endpoint "/api/machines?`$filter=$filter&`$top=25"

    if (-not $result -or -not $result.value -or $result.value.Count -eq 0) {
        # Fall back: try contains filter (supported on some tenants)
        $filter = "contains(computerDnsName,'$safeTerm')"
        $result = Invoke-MDERequest -Method GET -Endpoint "/api/machines?`$filter=$filter&`$top=25"
    }

    if (-not $result -or -not $result.value) {
        return @()
    }

    return $result.value
}

function Get-MDEMachineByAADDeviceId {
    <#
    .SYNOPSIS
        Looks up an MDE machine by its Entra (AAD) device ID.
    #>
    param([string]$AADDeviceId)

    if (-not $AADDeviceId) { return $null }

    $result = Invoke-MDERequest -Method GET -Endpoint "/api/machines?`$filter=aadDeviceId eq $AADDeviceId"

    if ($result -and $result.value -and $result.value.Count -gt 0) {
        return $result.value[0]
    }

    return $null
}

# ==============================================================================
# FUNCTIONS -- INTUNE (via Microsoft Graph)
# ==============================================================================

function Get-IntuneManagedDevice {
    <#
    .SYNOPSIS
        Looks up an Intune managed device by its Entra (AAD) device ID.
        Returns the managed device object, or $null if not found / not enrolled.
    #>
    param([string]$AADDeviceId)

    if (-not $AADDeviceId) { return $null }

    try {
        $result = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$AADDeviceId'" `
            -ErrorAction Stop

        if ($result.value -and $result.value.Count -gt 0) {
            return $result.value[0]
        }
    }
    catch {
        # 403 = tenant may not have Intune licence or user lacks role
        $statusCode = $null
        try { $statusCode = $_.Exception.Response.StatusCode.value__ } catch {}

        if ($statusCode -eq 403) {
            Write-Host "  Intune query denied (HTTP 403). You may need an Intune Administrator role." -ForegroundColor DarkGray
        }
        elseif ($statusCode -ne 404) {
            Write-Host "  Could not query Intune: $_" -ForegroundColor DarkGray
        }
    }

    return $null
}

function Show-EntraDeviceDetail {
    <#
    .SYNOPSIS
        Displays Entra device properties for a device object that was already
        fetched by Show-UserDevices / Get-MgDevice. Useful as a fallback when
        MDE is not available.
    #>
    param($Device)

    if (-not $Device) { return }

    Write-Host ""
    Write-Host "  -- Entra Device Detail --" -ForegroundColor Cyan

    $dName    = if ($Device.DisplayName)            { $Device.DisplayName }            else { "--" }
    $dOS      = if ($Device.OperatingSystem)         { $Device.OperatingSystem }         else { "--" }
    $dOSVer   = if ($Device.OperatingSystemVersion)  { $Device.OperatingSystemVersion }  else { "" }
    $dMfr     = if ($Device.Manufacturer)            { $Device.Manufacturer }            else { "" }
    $dModel   = if ($Device.Model)                   { $Device.Model }                   else { "" }
    $dHardware = if ($dMfr -or $dModel) { "$dMfr $dModel".Trim() } else { "--" }
    $dTrust   = if ($Device.TrustType)               { $Device.TrustType }               else { "--" }
    $dProfile = if ($Device.ProfileType)             { $Device.ProfileType }             else { "" }

    $complianceText   = switch ($Device.IsCompliant)    { $true { "Compliant" } $false { "Non-Compliant" } default { "Unknown" } }
    $complianceColour = switch ($Device.IsCompliant)    { $true { "Green" }     $false { "Red" }           default { "DarkGray" } }
    $managedText      = switch ($Device.IsManaged)      { $true { "Managed" }   $false { "Unmanaged" }     default { "Unknown" } }
    $managedColour    = switch ($Device.IsManaged)      { $true { "Green" }     $false { "Yellow" }        default { "DarkGray" } }
    $enabledText      = switch ($Device.AccountEnabled) { $true { "Enabled" }   $false { "Disabled" }      default { "--" } }
    $enabledColour    = switch ($Device.AccountEnabled) { $true { "Green" }     $false { "Red" }           default { "DarkGray" } }

    $dRegistered = if ($Device.RegistrationDateTime)          { $Device.RegistrationDateTime.ToString("yyyy-MM-dd HH:mm") }          else { "--" }
    $dLastSignIn = if ($Device.ApproximateLastSignInDateTime)  { $Device.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd HH:mm") } else { "--" }

    Write-Host "  Display Name   : $dName" -ForegroundColor White
    Write-Host "  OS             : $dOS $dOSVer" -ForegroundColor White
    Write-Host "  Hardware       : $dHardware" -ForegroundColor White
    Write-Host "  Trust Type     : $dTrust" -ForegroundColor $(switch ($dTrust) { "AzureAd" { "Cyan" } "ServerAd" { "DarkCyan" } "Workplace" { "DarkYellow" } default { "White" } })
    if ($dProfile) {
        Write-Host "  Profile Type   : $dProfile" -ForegroundColor White
    }
    Write-Host "  Status         : " -ForegroundColor White -NoNewline
    Write-Host $enabledText -ForegroundColor $enabledColour -NoNewline
    Write-Host " | " -NoNewline
    Write-Host $complianceText -ForegroundColor $complianceColour -NoNewline
    Write-Host " | " -NoNewline
    Write-Host $managedText -ForegroundColor $managedColour
    Write-Host "  Registered     : $dRegistered" -ForegroundColor White
    Write-Host "  Last Sign-In   : $dLastSignIn" -ForegroundColor White
    Write-Host "  Device ID      : $($Device.DeviceId)" -ForegroundColor DarkGray
}

function Show-IntuneDeviceDetail {
    <#
    .SYNOPSIS
        Displays Intune managed device properties.
    #>
    param($ManagedDevice)

    if (-not $ManagedDevice) { return }

    Write-Host ""
    Write-Host "  -- Intune Managed Device Detail --" -ForegroundColor Magenta

    $iName     = if ($ManagedDevice.deviceName)              { $ManagedDevice.deviceName }              else { "--" }
    $iOS       = if ($ManagedDevice.operatingSystem)         { $ManagedDevice.operatingSystem }         else { "--" }
    $iOSVer    = if ($ManagedDevice.osVersion)               { $ManagedDevice.osVersion }               else { "" }
    $iSerial   = if ($ManagedDevice.serialNumber)            { $ManagedDevice.serialNumber }            else { "--" }
    $iMfr      = if ($ManagedDevice.manufacturer)            { $ManagedDevice.manufacturer }            else { "" }
    $iModel    = if ($ManagedDevice.model)                   { $ManagedDevice.model }                   else { "" }
    $iHardware = if ($iMfr -or $iModel) { "$iMfr $iModel".Trim() } else { "--" }
    $iOwner    = if ($ManagedDevice.managedDeviceOwnerType)  { $ManagedDevice.managedDeviceOwnerType }  else { "--" }
    $iEnrolled = if ($ManagedDevice.enrolledDateTime)        { $ManagedDevice.enrolledDateTime }        else { "--" }
    $iLastSync = if ($ManagedDevice.lastSyncDateTime)        { $ManagedDevice.lastSyncDateTime }        else { "--" }
    $iUPN      = if ($ManagedDevice.userPrincipalName)       { $ManagedDevice.userPrincipalName }       else { "--" }
    $iMgmtAgent = if ($ManagedDevice.managementAgent)        { $ManagedDevice.managementAgent }         else { "--" }
    $iCategory  = if ($ManagedDevice.deviceCategoryDisplayName) { $ManagedDevice.deviceCategoryDisplayName } else { "--" }

    # Compliance state
    $compState = if ($ManagedDevice.complianceState) { $ManagedDevice.complianceState } else { "unknown" }
    $compColour = switch ($compState) {
        "compliant"    { "Green" }
        "noncompliant" { "Red" }
        "conflict"     { "Yellow" }
        "error"        { "Red" }
        "inGracePeriod" { "Yellow" }
        "configManager" { "Cyan" }
        default        { "DarkGray" }
    }

    # Management state
    $mgmtState = if ($ManagedDevice.managementState) { $ManagedDevice.managementState } else { "--" }
    $mgmtColour = switch ($mgmtState) {
        "managed"       { "Green" }
        "retirePending" { "Yellow" }
        "wipePending"   { "Red" }
        default         { "White" }
    }

    # Encryption
    $encrypted = if ($null -ne $ManagedDevice.isEncrypted) {
        if ($ManagedDevice.isEncrypted) { "Yes" } else { "No" }
    } else { "--" }
    $encColour = switch ($encrypted) { "Yes" { "Green" } "No" { "Red" } default { "DarkGray" } }

    # Supervised
    $supervised = if ($null -ne $ManagedDevice.isSupervised) {
        if ($ManagedDevice.isSupervised) { "Yes" } else { "No" }
    } else { "--" }

    Write-Host "  Device Name    : $iName" -ForegroundColor White
    Write-Host "  OS             : $iOS $iOSVer" -ForegroundColor White
    Write-Host "  Hardware       : $iHardware" -ForegroundColor White
    Write-Host "  Serial Number  : $iSerial" -ForegroundColor White
    Write-Host "  Ownership      : $iOwner" -ForegroundColor $(if ($iOwner -eq 'company') { "Cyan" } else { "White" })
    Write-Host "  Mgmt Agent     : $iMgmtAgent" -ForegroundColor White
    Write-Host "  Mgmt State     : $mgmtState" -ForegroundColor $mgmtColour
    Write-Host "  Compliance     : $compState" -ForegroundColor $compColour
    Write-Host "  Encrypted      : $encrypted" -ForegroundColor $encColour
    Write-Host "  Supervised     : $supervised" -ForegroundColor White
    Write-Host "  Category       : $iCategory" -ForegroundColor White
    Write-Host "  Primary User   : $iUPN" -ForegroundColor White
    Write-Host "  Enrolled       : $iEnrolled" -ForegroundColor White
    Write-Host "  Last Sync      : $iLastSync" -ForegroundColor White
    Write-Host "  Intune ID      : $($ManagedDevice.id)" -ForegroundColor DarkGray
}

function Get-IntuneAvailableActions {
    <#
    .SYNOPSIS
        Returns an ordered list of Intune actions available for a managed device
        based on its operating system, ownership type, and supervised state.

        Device categories and their available actions:
          Corporate Windows  : Sync, Restart, Defender Quick Scan, Defender Full Scan, Fresh Start, Retire, Wipe
          Personal Windows   : Sync, Restart, Retire
          Corporate iOS      : Sync, Remote Lock, Restart, Retire, Wipe  (+Lost Mode if supervised)
          Corporate Android  : Sync, Remote Lock, Restart, Retire, Wipe
          Personal iOS/Android : Sync, Remote Lock, Retire
          Corporate macOS    : Sync, Restart, Remote Lock, Retire, Wipe
          Personal macOS     : Sync, Retire

        Returns: Array of hashtables with keys: Label, ActionKey, Colour
    #>
    param($ManagedDevice)

    if (-not $ManagedDevice) { return @() }

    $os         = if ($ManagedDevice.operatingSystem) { $ManagedDevice.operatingSystem } else { "" }
    $ownership  = if ($ManagedDevice.managedDeviceOwnerType) { $ManagedDevice.managedDeviceOwnerType } else { "unknown" }
    $supervised = if ($null -ne $ManagedDevice.isSupervised) { $ManagedDevice.isSupervised } else { $false }

    $isCorporate = ($ownership -eq "company")
    $isWinOS   = ($os -match '^Windows')
    $isIOS       = ($os -match '^iOS|^iPadOS')
    $isAndroid   = ($os -match '^Android')
    $isMacPlatform     = ($os -match '^macOS|^Mac OS')
    $isMobile    = ($isIOS -or $isAndroid)

    $actions = [System.Collections.Generic.List[hashtable]]::new()

    # -- Sync is always available --
    $actions.Add(@{ Label = "Sync device";                ActionKey = "intune_sync";             Colour = "White" })

    # -- Restart: all corporate; personal Windows only --
    if ($isCorporate -or $isWinOS) {
        $actions.Add(@{ Label = "Restart device";         ActionKey = "intune_restart";           Colour = "White" })
    }

    # -- Remote Lock: mobile devices (all), corporate macOS --
    if ($isMobile -or ($isMacPlatform -and $isCorporate)) {
        $actions.Add(@{ Label = "Remote Lock";            ActionKey = "intune_lock";              Colour = "White" })
    }

    # -- Windows Defender Scan: Windows only, any ownership --
    if ($isWinOS) {
        $actions.Add(@{ Label = "Defender Scan (Quick)";  ActionKey = "intune_defender_quick";    Colour = "White" })
        $actions.Add(@{ Label = "Defender Scan (Full)";   ActionKey = "intune_defender_full";     Colour = "White" })
    }

    # -- Fresh Start: corporate Windows only --
    if ($isWinOS -and $isCorporate) {
        $actions.Add(@{ Label = "Fresh Start";            ActionKey = "intune_freshstart";        Colour = "Yellow" })
    }

    # -- Lost Mode: supervised iOS only, corporate --
    if ($isIOS -and $isCorporate -and $supervised) {
        $actions.Add(@{ Label = "Enable Lost Mode";       ActionKey = "intune_lostmode_on";       Colour = "Yellow" })
        $actions.Add(@{ Label = "Disable Lost Mode";      ActionKey = "intune_lostmode_off";      Colour = "White" })
    }

    # -- Retire is always available --
    $actions.Add(@{     Label = "Retire device";          ActionKey = "intune_retire";            Colour = "Yellow" })

    # -- Wipe: corporate only --
    if ($isCorporate) {
        $actions.Add(@{ Label = "Wipe device";            ActionKey = "intune_wipe";              Colour = "Red" })
    }

    return @($actions)
}

function Invoke-IntuneSyncDevice {
    <#
    .SYNOPSIS
        Triggers an Intune policy sync on a managed device.
    #>
    param(
        [Parameter(Mandatory)][string]$IntuneDeviceId,
        [string]$DeviceName
    )

    Write-Host ""
    Write-Host "  SYNC DEVICE (Intune)" -ForegroundColor Cyan
    Write-Host "  This will trigger an immediate policy and configuration sync." -ForegroundColor White
    Write-Host "  Device: $DeviceName" -ForegroundColor White
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Sending sync request..." -ForegroundColor Cyan -NoNewline

    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/syncDevice" `
            -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
        Write-Host "  The device will sync on its next check-in." -ForegroundColor Yellow
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error: $_"
    }
}

function Invoke-IntuneRestartDevice {
    <#
    .SYNOPSIS
        Sends a remote restart command to an Intune managed device.
    #>
    param(
        [Parameter(Mandatory)][string]$IntuneDeviceId,
        [string]$DeviceName
    )

    Write-Host ""
    Write-Host "  RESTART DEVICE (Intune)" -ForegroundColor Yellow
    Write-Host "  This will remotely restart the device." -ForegroundColor White
    Write-Host "  Device: $DeviceName" -ForegroundColor White
    Write-Host ""
    Write-Host "  WARNING: Unsaved work on the device will be lost." -ForegroundColor Red

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Sending restart command..." -ForegroundColor Cyan -NoNewline

    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/rebootNow" `
            -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
        Write-Host "  The device will restart shortly." -ForegroundColor Yellow
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error: $_"
    }
}

function Invoke-IntuneRemoteLock {
    <#
    .SYNOPSIS
        Sends a remote lock command to an Intune managed device.
        Primarily used for mobile devices and macOS.
    #>
    param(
        [Parameter(Mandatory)][string]$IntuneDeviceId,
        [string]$DeviceName
    )

    Write-Host ""
    Write-Host "  REMOTE LOCK (Intune)" -ForegroundColor Yellow
    Write-Host "  This will immediately lock the device screen." -ForegroundColor White
    Write-Host "  The user will need to unlock with their PIN/password/biometrics." -ForegroundColor White
    Write-Host "  Device: $DeviceName" -ForegroundColor White
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Sending remote lock command..." -ForegroundColor Cyan -NoNewline

    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/remoteLock" `
            -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
        Write-Host "  The device will lock on its next check-in." -ForegroundColor Yellow
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error: $_"
    }
}

function Invoke-IntuneDefenderScan {
    <#
    .SYNOPSIS
        Triggers a Windows Defender scan on a managed Windows device.
    #>
    param(
        [Parameter(Mandatory)][string]$IntuneDeviceId,
        [string]$DeviceName,
        [Parameter(Mandatory)][bool]$QuickScan
    )

    $scanType = if ($QuickScan) { "Quick" } else { "Full" }

    Write-Host ""
    Write-Host "  WINDOWS DEFENDER SCAN - $scanType (Intune)" -ForegroundColor Cyan
    Write-Host "  Device: $DeviceName" -ForegroundColor White
    if (-not $QuickScan) {
        Write-Host "  A full scan may take a long time and can impact" -ForegroundColor Yellow
        Write-Host "  device performance during the scan." -ForegroundColor Yellow
    }
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Triggering $scanType scan..." -ForegroundColor Cyan -NoNewline

    try {
        $body = @{ quickScan = $QuickScan } | ConvertTo-Json
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/windowsDefenderScan" `
            -Body $body -ContentType "application/json" `
            -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
        Write-Host "  $scanType scan will start on the device's next check-in." -ForegroundColor Yellow
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error: $_"
    }
}

function Invoke-IntuneFreshStart {
    <#
    .SYNOPSIS
        Triggers a Fresh Start on a corporate-owned Windows device.
        This reinstalls Windows, optionally keeping user data, and
        removes all pre-installed (OEM) apps.
    #>
    param(
        [Parameter(Mandatory)][string]$IntuneDeviceId,
        [string]$DeviceName
    )

    Write-Host ""
    Write-Host "  FRESH START (Intune)" -ForegroundColor Yellow
    Write-Host "  This will reinstall Windows and remove all OEM/pre-installed apps." -ForegroundColor White
    Write-Host "  Device: $DeviceName" -ForegroundColor White
    Write-Host ""
    Write-Host "  WARNING: All installed applications will be removed." -ForegroundColor Red
    Write-Host "  The device will need to re-download apps from Intune." -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  Keep user data (files in user profile)?" -ForegroundColor Cyan
    $keepData = Read-Host "  (Y = keep user data / N = remove everything)"
    $keepUserData = ($keepData -eq "Y" -or $keepData -eq "y")

    $keepLabel = if ($keepUserData) { "Yes - user files will be preserved" } else { "No - all data will be removed" }
    Write-Host ""
    Write-Host "  Keep user data: $keepLabel" -ForegroundColor $(if ($keepUserData) { "Green" } else { "Red" })

    $confirm = Read-Host "  Type 'FRESHSTART' to confirm (or anything else to cancel)"
    if ($confirm -ne "FRESHSTART") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Sending Fresh Start command..." -ForegroundColor Cyan -NoNewline

    try {
        $body = @{ keepUserData = $keepUserData } | ConvertTo-Json
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/cleanWindowsDevice" `
            -Body $body -ContentType "application/json" `
            -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
        Write-Host "  Fresh Start will begin on the device's next check-in." -ForegroundColor Yellow
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error: $_"
    }
}

function Invoke-IntuneEnableLostMode {
    <#
    .SYNOPSIS
        Enables Lost Mode on a supervised iOS device.
        Locks the device and displays a custom message and phone number.
    #>
    param(
        [Parameter(Mandatory)][string]$IntuneDeviceId,
        [string]$DeviceName
    )

    Write-Host ""
    Write-Host "  ENABLE LOST MODE (Intune)" -ForegroundColor Yellow
    Write-Host "  This will lock the device and display a message on screen." -ForegroundColor White
    Write-Host "  Only available for supervised iOS devices." -ForegroundColor White
    Write-Host "  Device: $DeviceName" -ForegroundColor White
    Write-Host ""

    $lostMessage = Read-Host "  Message to display on device (e.g. 'This device has been lost')"
    if ([string]::IsNullOrWhiteSpace($lostMessage)) {
        $lostMessage = "This device has been lost. Please contact the IT department."
    }

    $lostPhone = Read-Host "  Phone number to display (optional, press Enter to skip)"
    $lostFooter = Read-Host "  Footer text (optional, press Enter to skip)"

    Write-Host ""
    $confirm = Read-Host "  Enable Lost Mode? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Enabling Lost Mode..." -ForegroundColor Cyan -NoNewline

    try {
        $body = @{ message = $lostMessage }
        if (-not [string]::IsNullOrWhiteSpace($lostPhone))  { $body["phoneNumber"] = $lostPhone }
        if (-not [string]::IsNullOrWhiteSpace($lostFooter)) { $body["footer"]      = $lostFooter }

        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/enableLostMode" `
            -Body ($body | ConvertTo-Json) -ContentType "application/json" `
            -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
        Write-Host "  Lost Mode will activate on the device's next check-in." -ForegroundColor Yellow
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error: $_"
    }
}

function Invoke-IntuneDisableLostMode {
    <#
    .SYNOPSIS
        Disables Lost Mode on a supervised iOS device.
    #>
    param(
        [Parameter(Mandatory)][string]$IntuneDeviceId,
        [string]$DeviceName
    )

    Write-Host ""
    Write-Host "  DISABLE LOST MODE (Intune)" -ForegroundColor Cyan
    Write-Host "  This will turn off Lost Mode and return the device to normal." -ForegroundColor White
    Write-Host "  Device: $DeviceName" -ForegroundColor White
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Disabling Lost Mode..." -ForegroundColor Cyan -NoNewline

    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/disableLostMode" `
            -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
        Write-Host "  Lost Mode will be disabled on the device's next check-in." -ForegroundColor Yellow
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error: $_"
    }
}

function Invoke-IntuneRetireDevice {
    <#
    .SYNOPSIS
        Sends a retire command to an Intune managed device.
        Retire removes company data but leaves personal data intact.
    #>
    param(
        [Parameter(Mandatory)][string]$IntuneDeviceId,
        [string]$DeviceName
    )

    Write-Host ""
    Write-Host "  RETIRE DEVICE (Intune)" -ForegroundColor Red
    Write-Host "  This will REMOVE all company data, apps, and profiles" -ForegroundColor White
    Write-Host "  from the device. Personal data will remain." -ForegroundColor White
    Write-Host "  Device: $DeviceName" -ForegroundColor White
    Write-Host ""
    Write-Host "  WARNING: This action cannot be easily undone." -ForegroundColor Red
    Write-Host "  The device will need to be re-enrolled to restore" -ForegroundColor Red
    Write-Host "  company access." -ForegroundColor Red
    Write-Host ""

    $confirm = Read-Host "  Type 'RETIRE' to confirm (or anything else to cancel)"
    if ($confirm -ne "RETIRE") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Sending retire command..." -ForegroundColor Cyan -NoNewline

    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/retire" `
            -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
        Write-Host "  The device will be retired on its next check-in." -ForegroundColor Yellow
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error: $_"
    }
}

function Invoke-IntuneWipeDevice {
    <#
    .SYNOPSIS
        Sends a full wipe command to an Intune managed device.
        This factory-resets the device, removing ALL data.
        Only available for corporate-owned devices.
    #>
    param(
        [Parameter(Mandatory)][string]$IntuneDeviceId,
        [string]$DeviceName
    )

    Write-Host ""
    Write-Host "  !!  WIPE DEVICE (Intune)  !!" -ForegroundColor Red
    Write-Host "  This will FACTORY RESET the device, removing ALL data" -ForegroundColor Red
    Write-Host "  including personal files, apps, and settings." -ForegroundColor Red
    Write-Host "  Device: $DeviceName" -ForegroundColor White
    Write-Host ""
    Write-Host "  THIS ACTION IS DESTRUCTIVE AND IRREVERSIBLE." -ForegroundColor Red
    Write-Host ""

    $confirm = Read-Host "  Type 'WIPE' to confirm (or anything else to cancel)"
    if ($confirm -ne "WIPE") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Sending wipe command..." -ForegroundColor Cyan -NoNewline

    try {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/wipe" `
            -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
        Write-Host "  The device will be wiped on its next check-in." -ForegroundColor Yellow
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error: $_"
    }
}

# ==============================================================================
# FUNCTIONS -- DISPLAY
# ==============================================================================

function Show-UserDetail {
    param([PSCustomObject]$User)

    $userId = $User.Id
    $upn    = $User.UPN

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  USER DETAILS" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor White

    # -- Entra ID info ---------------------------------------------------------
    Write-Host ""
    Write-Host "  -- Entra ID --" -ForegroundColor Cyan
    Write-Host "  Display Name   : $($User.DisplayName)" -ForegroundColor White
    Write-Host "  UPN            : $upn" -ForegroundColor White
    Write-Host "  Object ID      : $userId" -ForegroundColor DarkGray
    Write-Host "  First Name     : $($User.GivenName)" -ForegroundColor White
    Write-Host "  Last Name      : $($User.Surname)" -ForegroundColor White
    Write-Host "  Job Title      : $($User.JobTitle)" -ForegroundColor White
    Write-Host "  Department     : $($User.Department)" -ForegroundColor White
    Write-Host "  Email          : $($User.Mail)" -ForegroundColor White
    Write-Host "  Account Enabled: $($User.AccountEnabled)" -ForegroundColor $(if ($User.AccountEnabled -eq $true) { "Green" } else { "Red" })
    Write-Host "  Last Pwd Change: $($User.LastPwdChange)" -ForegroundColor White

    # -- Try to get Entra risk info --------------------------------------------
    try {
        $riskyUser = Get-MgRiskyUser -RiskyUserId $userId -ErrorAction Stop
        if ($riskyUser) {
            Write-Host ""
            Write-Host "  -- Entra Risk Status --" -ForegroundColor Yellow
            Write-Host "  Risk State     : $($riskyUser.RiskState)" -ForegroundColor $(switch ($riskyUser.RiskState) { "atRisk" { "Red" } "confirmedCompromised" { "Red" } "dismissed" { "Green" } "remediated" { "Green" } default { "Yellow" } })
            Write-Host "  Risk Level     : $($riskyUser.RiskLevel)" -ForegroundColor $(switch ($riskyUser.RiskLevel) { "high" { "Red" } "medium" { "Yellow" } "low" { "DarkYellow" } default { "White" } })
            Write-Host "  Risk Updated   : $($riskyUser.RiskLastUpdatedDateTime)" -ForegroundColor White
        }
    }
    catch {
        Write-Host ""
        Write-Host "  -- Entra Risk Status --" -ForegroundColor Yellow
        Write-Host "  No risk record found for this user." -ForegroundColor DarkGray
    }

    # -- Recent sign-ins (last 30 days, top 5) ---------------------------------
    Write-Host ""
    Write-Host "  -- Recent Sign-Ins (last 30 days) --" -ForegroundColor Cyan

    try {
        $signInCutoff = (Get-Date).AddDays(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $signInFilter = "userId eq '$userId' and createdDateTime ge $signInCutoff"
        $signInUri    = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$signInFilter&`$top=5&`$orderby=createdDateTime desc"

        $signInResult = Invoke-MgGraphRequest -Method GET -Uri $signInUri -ErrorAction Stop

        if ($signInResult.value -and $signInResult.value.Count -gt 0) {
            foreach ($si in $signInResult.value) {
                $siTime   = if ($si.createdDateTime) {
                    ([datetime]$si.createdDateTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                } else { "--" }
                $siApp    = if ($si.appDisplayName)      { $si.appDisplayName }      else { "--" }
                $siStatus = if ($si.status -and $si.status.errorCode -eq 0) { "Success" }
                            elseif ($si.status) { "Failed ($($si.status.errorCode))" }
                            else { "--" }
                $siStatusColour = if ($siStatus -eq "Success") { "Green" } else { "Red" }
                $siIP     = if ($si.ipAddress)            { $si.ipAddress }            else { "--" }
                $siLoc    = "--"
                if ($si.location) {
                    $locParts = @()
                    if ($si.location.city)           { $locParts += $si.location.city }
                    if ($si.location.countryOrRegion) { $locParts += $si.location.countryOrRegion }
                    if ($locParts.Count -gt 0)       { $siLoc = $locParts -join ', ' }
                }
                $siDevice = "--"
                if ($si.deviceDetail) {
                    $devParts = @()
                    if ($si.deviceDetail.displayName)     { $devParts += $si.deviceDetail.displayName }
                    if ($si.deviceDetail.operatingSystem)  { $devParts += $si.deviceDetail.operatingSystem }
                    if ($si.deviceDetail.browser)          { $devParts += $si.deviceDetail.browser }
                    if ($devParts.Count -gt 0)            { $siDevice = $devParts -join ' / ' }
                }
                $siCA = "--"
                if ($si.conditionalAccessStatus) {
                    $siCA = switch ($si.conditionalAccessStatus) {
                        "success"      { "Applied" }
                        "failure"      { "BLOCKED" }
                        "notApplied"   { "Not Applied" }
                        default        { $si.conditionalAccessStatus }
                    }
                }
                $siCAColour = switch ($siCA) {
                    "Applied"     { "Green" }
                    "BLOCKED"     { "Red" }
                    "Not Applied" { "DarkGray" }
                    default       { "White" }
                }

                Write-Host "    $siTime  " -ForegroundColor White -NoNewline
                Write-Host $siStatus.PadRight(16) -ForegroundColor $siStatusColour -NoNewline
                Write-Host $siApp -ForegroundColor White
                Write-Host "                   IP: $siIP  Location: $siLoc" -ForegroundColor DarkGray
                Write-Host "                   Device: $siDevice" -ForegroundColor DarkGray
                Write-Host "                   CA Policy: " -ForegroundColor DarkGray -NoNewline
                Write-Host $siCA -ForegroundColor $siCAColour
            }
        }
        else {
            Write-Host "  No sign-ins found in the last 30 days." -ForegroundColor DarkGray
        }
    }
    catch {
        $siErrMsg = "$_"
        if ($siErrMsg -match '403|Forbidden|Authorization') {
            Write-Host "  Sign-in logs require AuditLog.Read.All permission or an Entra ID P1/P2 licence." -ForegroundColor DarkGray
        }
        else {
            Write-Host "  Could not retrieve sign-in logs: $_" -ForegroundColor DarkGray
        }
    }

    # -- Active Directory info -------------------------------------------------
    Write-Host ""
    Write-Host "  -- Active Directory --" -ForegroundColor Cyan

    $samAccount = ($upn -split '@')[0]

    try {
        $adParams = Get-ADConnectionParams
        $domainDN = (Get-ADDomain @adParams -ErrorAction Stop).DistinguishedName

        $adUser = Get-ADUser @adParams -Filter "SamAccountName -eq '$samAccount'" `
            -SearchBase $domainDN -SearchScope Subtree -Properties `
            Enabled, LockedOut, PasswordLastSet, PasswordExpired, `
            PasswordNeverExpires, LastLogonDate, LastBadPasswordAttempt, `
            BadPwdCount, Description, whenCreated, MemberOf -ErrorAction Stop

        if (-not $adUser) {
            $adUser = Get-ADUser @adParams -Filter "UserPrincipalName -eq '$upn'" `
                -SearchBase $domainDN -SearchScope Subtree -Properties `
                Enabled, LockedOut, PasswordLastSet, PasswordExpired, `
                PasswordNeverExpires, LastLogonDate, LastBadPasswordAttempt, `
                BadPwdCount, Description, whenCreated, MemberOf -ErrorAction Stop
        }

        if (-not $adUser) {
            Write-Host "  No AD account found for '$samAccount' (searched all OUs)." -ForegroundColor Yellow
            return $null
        }

        if ($adUser -is [array]) { $adUser = $adUser[0] }

        Write-Host "  sAMAccountName : $($adUser.SamAccountName)" -ForegroundColor White
        Write-Host "  AD Enabled     : $($adUser.Enabled)" -ForegroundColor $(if ($adUser.Enabled) { "Green" } else { "Red" })
        Write-Host "  Locked Out     : $($adUser.LockedOut)" -ForegroundColor $(if ($adUser.LockedOut) { "Red" } else { "Green" })
        Write-Host "  Pwd Last Set   : $($adUser.PasswordLastSet)" -ForegroundColor White
        Write-Host "  Pwd Expired    : $($adUser.PasswordExpired)" -ForegroundColor $(if ($adUser.PasswordExpired) { "Red" } else { "Green" })
        Write-Host "  Pwd Never Exp  : $($adUser.PasswordNeverExpires)" -ForegroundColor $(if ($adUser.PasswordNeverExpires) { "Yellow" } else { "White" })
        Write-Host "  Last Logon     : $($adUser.LastLogonDate)" -ForegroundColor White
        Write-Host "  Last Bad Pwd   : $($adUser.LastBadPasswordAttempt)" -ForegroundColor White
        Write-Host "  Bad Pwd Count  : $($adUser.BadPwdCount)" -ForegroundColor $(if ($adUser.BadPwdCount -gt 0) { "Yellow" } else { "White" })
        Write-Host "  Description    : $($adUser.Description)" -ForegroundColor White
        Write-Host "  Created        : $($adUser.whenCreated)" -ForegroundColor White

        if ($adUser.MemberOf -and $adUser.MemberOf.Count -gt 0) {
            Write-Host ""
            Write-Host "  -- Group Memberships (top 10) --" -ForegroundColor DarkCyan
            $groups = $adUser.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' } | Select-Object -First 10
            foreach ($g in $groups) {
                Write-Host "    - $g" -ForegroundColor DarkGray
            }
            if ($adUser.MemberOf.Count -gt 10) {
                Write-Host "    ... and $($adUser.MemberOf.Count - 10) more" -ForegroundColor DarkGray
            }
        }

        return $adUser
    }
    catch {
        Write-Host "  Could not find AD account for '$samAccount': $_" -ForegroundColor Yellow
        return $null
    }
}

function Show-UserDevices {
    <#
    .SYNOPSIS
        Displays Entra-linked devices for a user and returns them as an ordered
        array so the caller can offer device selection.
        Returns: [PSCustomObject[]] (index-aligned with display numbers).
    #>
    param([PSCustomObject]$User)

    $userId = $User.Id

    Write-Host ""
    Write-Host "  -- Linked Devices --" -ForegroundColor Cyan

    $allDevices = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()

    $deviceProperties = "id","displayName","operatingSystem","operatingSystemVersion","deviceId",
                        "trustType","isCompliant","isManaged","profileType",
                        "registrationDateTime","approximateLastSignInDateTime",
                        "accountEnabled","manufacturer","model"

    # Registered devices
    try {
        $registered = Get-MgUserRegisteredDevice -UserId $userId -All -ErrorAction Stop
        foreach ($dev in $registered) {
            $odataType = $dev.AdditionalProperties['@odata.type']
            if ($odataType -and $odataType -ne '#microsoft.graph.device') { continue }

            if (-not $allDevices.ContainsKey($dev.Id)) {
                try {
                    $full = Get-MgDevice -DeviceId $dev.Id -Property $deviceProperties -ErrorAction Stop
                    $full | Add-Member -NotePropertyName '_Source' -NotePropertyValue 'Registered' -Force
                    $allDevices[$dev.Id] = $full
                }
                catch {
                    $dev | Add-Member -NotePropertyName '_Source' -NotePropertyValue 'Registered' -Force
                    $allDevices[$dev.Id] = $dev
                }
            }
        }
    }
    catch {
        Write-Host "  Could not retrieve registered devices: $_" -ForegroundColor Yellow
    }

    # Owned devices
    try {
        $owned = Get-MgUserOwnedDevice -UserId $userId -All -ErrorAction Stop
        foreach ($dev in $owned) {
            $odataType = $dev.AdditionalProperties['@odata.type']
            if ($odataType -and $odataType -ne '#microsoft.graph.device') { continue }

            if ($allDevices.ContainsKey($dev.Id)) {
                $existing = $allDevices[$dev.Id]
                if ($existing._Source -notlike '*Owned*') {
                    $existing._Source = "$($existing._Source) + Owned"
                }
            }
            else {
                try {
                    $full = Get-MgDevice -DeviceId $dev.Id -Property $deviceProperties -ErrorAction Stop
                    $full | Add-Member -NotePropertyName '_Source' -NotePropertyValue 'Owned' -Force
                    $allDevices[$dev.Id] = $full
                }
                catch {
                    $dev | Add-Member -NotePropertyName '_Source' -NotePropertyValue 'Owned' -Force
                    $allDevices[$dev.Id] = $dev
                }
            }
        }
    }
    catch {
        Write-Host "  Could not retrieve owned devices: $_" -ForegroundColor Yellow
    }

    if ($allDevices.Count -eq 0) {
        Write-Host "  No devices linked to this user." -ForegroundColor DarkGray
        return @()
    }

    Write-Host "  Found $($allDevices.Count) device(s):" -ForegroundColor White
    Write-Host ""

    $deviceList = @($allDevices.Values)

    $deviceIndex = 1
    foreach ($d in $deviceList) {

        $dName     = if ($d.DisplayName)            { $d.DisplayName }            else { "N/A" }
        $dOS       = if ($d.OperatingSystem)         { $d.OperatingSystem }         else { "--" }
        $dOSVer    = if ($d.OperatingSystemVersion)  { $d.OperatingSystemVersion }  else { "" }
        $dMfr      = if ($d.Manufacturer)            { $d.Manufacturer }            else { "" }
        $dModel    = if ($d.Model)                   { $d.Model }                   else { "" }
        $dHardware = if ($dMfr -or $dModel) { "$dMfr $dModel".Trim() } else { "--" }
        $dTrust    = if ($d.TrustType)               { $d.TrustType }               else { "--" }
        $dProfile  = if ($d.ProfileType)             { $d.ProfileType }             else { "" }
        $dSource   = if ($d._Source)                 { $d._Source }                 else { "--" }

        $complianceText   = switch ($d.IsCompliant)    { $true { "Compliant" } $false { "Non-Compliant" } default { "Unknown" } }
        $complianceColour = switch ($d.IsCompliant)    { $true { "Green" }     $false { "Red" }           default { "DarkGray" } }
        $managedText      = switch ($d.IsManaged)      { $true { "Managed" }   $false { "Unmanaged" }     default { "Unknown" } }
        $managedColour    = switch ($d.IsManaged)      { $true { "Green" }     $false { "Yellow" }        default { "DarkGray" } }
        $enabledText      = switch ($d.AccountEnabled) { $true { "Enabled" }   $false { "Disabled" }      default { "--" } }
        $enabledColour    = switch ($d.AccountEnabled) { $true { "Green" }     $false { "Red" }           default { "DarkGray" } }

        $dRegistered = if ($d.RegistrationDateTime)          { $d.RegistrationDateTime.ToString("yyyy-MM-dd HH:mm") }          else { "--" }
        $dLastSignIn = if ($d.ApproximateLastSignInDateTime)  { $d.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd HH:mm") } else { "--" }

        $staleWarning = ""
        if ($d.ApproximateLastSignInDateTime) {
            $daysSince = ((Get-Date) - $d.ApproximateLastSignInDateTime).Days
            if ($daysSince -ge 90) {
                $staleWarning = " (STALE - ${daysSince}d ago)"
            }
        }

        Write-Host "    [$deviceIndex] $dName" -ForegroundColor White
        Write-Host "        OS           : $dOS $dOSVer" -ForegroundColor White
        Write-Host "        Hardware     : $dHardware" -ForegroundColor White
        Write-Host "        Trust Type   : $dTrust" -ForegroundColor $(switch ($dTrust) { "AzureAd" { "Cyan" } "ServerAd" { "DarkCyan" } "Workplace" { "DarkYellow" } default { "White" } })
        if ($dProfile) {
            Write-Host "        Profile Type : $dProfile" -ForegroundColor White
        }
        Write-Host "        Relationship : $dSource" -ForegroundColor DarkGray
        Write-Host "        Status       : " -ForegroundColor White -NoNewline
        Write-Host $enabledText -ForegroundColor $enabledColour -NoNewline
        Write-Host " | " -NoNewline
        Write-Host $complianceText -ForegroundColor $complianceColour -NoNewline
        Write-Host " | " -NoNewline
        Write-Host $managedText -ForegroundColor $managedColour
        Write-Host "        Registered   : $dRegistered" -ForegroundColor White
        Write-Host "        Last Sign-In : $dLastSignIn" -ForegroundColor White -NoNewline
        if ($staleWarning) {
            Write-Host $staleWarning -ForegroundColor Red
        }
        else {
            Write-Host ""
        }
        Write-Host "        Device ID    : $($d.DeviceId)" -ForegroundColor DarkGray
        Write-Host ""

        $deviceIndex++
    }

    return $deviceList
}

function Show-DeviceNetworkLocation {
    <#
    .SYNOPSIS
        Displays the last known public IP addresses and locations for a device.
        Sources:
          - MDE: lastIpAddress / lastExternalIpAddress (if MDE machine provided)
          - Sign-in logs: last 5 unique IP/location combinations seen from
            this device in the last 30 days (requires AuditLog.Read.All + P1/P2).
        Falls back gracefully when data is unavailable.
    #>
    param(
        $EntraDevice,     # For matching by device ID in sign-in logs
        $IntuneDevice,    # For UPN and device name fallback
        $MDEMachine,      # For MDE-reported IPs
        $User             # For scoping sign-in log query
    )

    Write-Host ""
    Write-Host "  -- Network / Location --" -ForegroundColor Cyan

    $hasAnyData = $false

    # -- MDE-reported IPs (quick, no extra API call) ----------------------------
    if ($MDEMachine) {
        $mdeIntIP  = if ($MDEMachine.lastIpAddress)        { $MDEMachine.lastIpAddress }        else { $null }
        $mdeExtIP  = if ($MDEMachine.lastExternalIpAddress) { $MDEMachine.lastExternalIpAddress } else { $null }
        $mdeLastSeen = if ($MDEMachine.lastSeen)           { $MDEMachine.lastSeen }              else { $null }

        if ($mdeIntIP -or $mdeExtIP) {
            $hasAnyData = $true
            Write-Host "  MDE Reported:" -ForegroundColor DarkCyan
            if ($mdeIntIP)  { Write-Host "    Internal IP  : $mdeIntIP" -ForegroundColor White }
            if ($mdeExtIP)  { Write-Host "    External IP  : $mdeExtIP" -ForegroundColor White }
            if ($mdeLastSeen) { Write-Host "    As of        : $mdeLastSeen" -ForegroundColor DarkGray }
        }
    }

    # -- Sign-in log lookup for device IP / location ----------------------------
    # Determine user ID to scope the sign-in query
    $queryUserId = $null
    if ($User -and $User.Id) {
        $queryUserId = $User.Id
    }
    elseif ($IntuneDevice -and $IntuneDevice.userId) {
        $queryUserId = $IntuneDevice.userId
    }
    elseif ($IntuneDevice -and $IntuneDevice.userPrincipalName) {
        # Look up user ID from UPN
        try {
            $upnLookup = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users/$($IntuneDevice.userPrincipalName)?`$select=id" `
                -ErrorAction Stop
            if ($upnLookup -and $upnLookup.id) { $queryUserId = $upnLookup.id }
        }
        catch { }
    }
    elseif ($EntraDevice -and $EntraDevice.Id) {
        # Try registered owner
        try {
            $regOwners = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/devices/$($EntraDevice.Id)/registeredOwners?`$select=id" `
                -ErrorAction Stop
            if ($regOwners.value -and $regOwners.value.Count -gt 0) {
                $queryUserId = $regOwners.value[0].id
            }
        }
        catch { }
    }

    if (-not $queryUserId) {
        if (-not $hasAnyData) {
            Write-Host "  Could not determine device owner -- unable to query sign-in logs." -ForegroundColor DarkGray
        }
        return
    }

    # Build device name to match against sign-in deviceDetail
    $matchDeviceName = $null
    $matchDeviceId   = $null

    if ($EntraDevice -and $EntraDevice.DeviceId)   { $matchDeviceId   = $EntraDevice.DeviceId }
    if ($EntraDevice -and $EntraDevice.DisplayName) { $matchDeviceName = $EntraDevice.DisplayName }
    elseif ($IntuneDevice -and $IntuneDevice.deviceName) { $matchDeviceName = $IntuneDevice.deviceName }

    try {
        $siCutoff = (Get-Date).AddDays(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $siFilter = "userId eq '$queryUserId' and createdDateTime ge $siCutoff"
        $siUri    = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$siFilter&`$top=50&`$orderby=createdDateTime desc&`$select=createdDateTime,ipAddress,location,deviceDetail,status,appDisplayName"

        $siResult = Invoke-MgGraphRequest -Method GET -Uri $siUri -ErrorAction Stop

        if ($siResult.value -and $siResult.value.Count -gt 0) {
            # Filter for sign-ins from THIS device
            $deviceSignIns = @()
            foreach ($entry in $siResult.value) {
                $devDetail = $entry.deviceDetail
                if (-not $devDetail) { continue }

                $isMatch = $false
                # Match by device ID (most reliable)
                if ($matchDeviceId -and $devDetail.deviceId -and ($devDetail.deviceId -eq $matchDeviceId)) {
                    $isMatch = $true
                }
                # Match by display name (fallback)
                elseif ($matchDeviceName -and $devDetail.displayName -and ($devDetail.displayName -eq $matchDeviceName)) {
                    $isMatch = $true
                }

                if ($isMatch) { $deviceSignIns += $entry }
            }

            if ($deviceSignIns.Count -gt 0) {
                $hasAnyData = $true

                # Deduplicate by IP to show unique locations
                $seenIPs  = @{}
                $uniqueEntries = @()

                foreach ($si in $deviceSignIns) {
                    $ip = if ($si.ipAddress) { $si.ipAddress } else { "Unknown" }
                    if (-not $seenIPs.ContainsKey($ip)) {
                        $seenIPs[$ip] = $true
                        $uniqueEntries += $si
                    }
                    if ($uniqueEntries.Count -ge 5) { break }
                }

                Write-Host "  Sign-In Log (last 30 days, $($uniqueEntries.Count) unique IP(s)):" -ForegroundColor DarkCyan

                foreach ($si in $uniqueEntries) {
                    $ipAddr = if ($si.ipAddress) { $si.ipAddress } else { "--" }
                    $siTime = if ($si.createdDateTime) {
                        ([datetime]$si.createdDateTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                    } else { "--" }

                    $locDisplay = "--"
                    if ($si.location) {
                        $locParts = @()
                        if ($si.location.city)             { $locParts += $si.location.city }
                        if ($si.location.state)            { $locParts += $si.location.state }
                        if ($si.location.countryOrRegion)  { $locParts += $si.location.countryOrRegion }
                        if ($locParts.Count -gt 0)         { $locDisplay = $locParts -join ', ' }
                    }

                    $latLon = ""
                    if ($si.location -and $si.location.geoCoordinates) {
                        $lat = $si.location.geoCoordinates.latitude
                        $lon = $si.location.geoCoordinates.longitude
                        if ($null -ne $lat -and $null -ne $lon) {
                            $latLon = " ($lat, $lon)"
                        }
                    }

                    Write-Host "    $ipAddr" -ForegroundColor White -NoNewline
                    Write-Host "  $locDisplay$latLon" -ForegroundColor DarkGray -NoNewline
                    Write-Host "  (last seen $siTime)" -ForegroundColor DarkGray
                }
            }
            elseif (-not $hasAnyData) {
                Write-Host "  No sign-ins found from this device in the last 30 days." -ForegroundColor DarkGray
            }
        }
        elseif (-not $hasAnyData) {
            Write-Host "  No sign-in data available for this device." -ForegroundColor DarkGray
        }
    }
    catch {
        $netErrMsg = "$_"
        if ($netErrMsg -match '403|Forbidden|Authorization') {
            if (-not $hasAnyData) {
                Write-Host "  Sign-in logs require AuditLog.Read.All and Entra ID P1/P2." -ForegroundColor DarkGray
            }
        }
        else {
            if (-not $hasAnyData) {
                Write-Host "  Could not retrieve sign-in logs: $_" -ForegroundColor DarkGray
            }
        }
    }

    if (-not $hasAnyData) {
        Write-Host "  No network/location data available." -ForegroundColor DarkGray
    }
}

function Show-MDEDeviceDetail {
    <#
    .SYNOPSIS
        Displays detailed MDE information for a machine object.
    #>
    param($Machine)

    if (-not $Machine) {
        Write-Host "  No MDE record available for this device." -ForegroundColor DarkGray
        return
    }

    Write-Host ""
    Write-Host "  -- MDE Device Detail --" -ForegroundColor Magenta

    $mName = if ($Machine.computerDnsName)      { $Machine.computerDnsName }      else { "--" }
    $mOS   = if ($Machine.osPlatform)           { $Machine.osPlatform }           else { "--" }
    $mVer  = if ($Machine.version)              { $Machine.version }              else { "" }
    $mBld  = if ($Machine.osBuild)              { $Machine.osBuild }              else { "" }
    $mOSFull = "$mOS $mVer".Trim()
    if ($mBld) { $mOSFull += " (Build $mBld)" }

    $mHealth   = if ($Machine.healthStatus)     { $Machine.healthStatus }         else { "--" }
    $mOnboard  = if ($Machine.onboardingStatus) { $Machine.onboardingStatus }     else { "--" }
    $mRisk     = if ($Machine.riskScore)        { $Machine.riskScore }            else { "--" }
    $mExposure = if ($Machine.exposureLevel)    { $Machine.exposureLevel }        else { "--" }
    $mValue    = if ($Machine.deviceValue)      { $Machine.deviceValue }          else { "--" }
    $mIP       = if ($Machine.lastIpAddress)    { $Machine.lastIpAddress }        else { "--" }
    $mExtIP    = if ($Machine.lastExternalIpAddress) { $Machine.lastExternalIpAddress } else { "--" }
    $mFirst    = if ($Machine.firstSeen)        { $Machine.firstSeen }            else { "--" }
    $mLast     = if ($Machine.lastSeen)         { $Machine.lastSeen }             else { "--" }
    $mAADId    = if ($Machine.aadDeviceId)      { $Machine.aadDeviceId }          else { "--" }
    $mMachId   = if ($Machine.id)               { $Machine.id }                   else { "--" }

    $mTags = if ($Machine.machineTags -and $Machine.machineTags.Count -gt 0) {
        $Machine.machineTags -join ', '
    } else { "--" }

    Write-Host "  Computer Name  : $mName" -ForegroundColor White
    Write-Host "  OS             : $mOSFull" -ForegroundColor White
    Write-Host "  Health Status  : $mHealth" -ForegroundColor $(switch ($mHealth) { "Active" { "Green" } "Inactive" { "DarkGray" } "ImpairedCommunication" { "Yellow" } "NoSensorData" { "Yellow" } "NoSensorDataImpairedCommunication" { "Red" } default { "White" } })
    Write-Host "  Onboarding     : $mOnboard" -ForegroundColor $(if ($mOnboard -eq "Onboarded") { "Green" } else { "Yellow" })
    Write-Host "  Risk Score     : $mRisk" -ForegroundColor $(switch ($mRisk) { "High" { "Red" } "Medium" { "Yellow" } "Low" { "Green" } "None" { "Green" } default { "White" } })
    Write-Host "  Exposure Level : $mExposure" -ForegroundColor $(switch ($mExposure) { "High" { "Red" } "Medium" { "Yellow" } "Low" { "Green" } default { "White" } })
    Write-Host "  Device Value   : $mValue" -ForegroundColor White
    Write-Host "  Last IP        : $mIP" -ForegroundColor White
    Write-Host "  External IP    : $mExtIP" -ForegroundColor White
    Write-Host "  First Seen     : $mFirst" -ForegroundColor White
    Write-Host "  Last Seen      : $mLast" -ForegroundColor White
    Write-Host "  MDE Tags       : $mTags" -ForegroundColor DarkCyan
    Write-Host "  AAD Device ID  : $mAADId" -ForegroundColor DarkGray
    Write-Host "  MDE Machine ID : $mMachId" -ForegroundColor DarkGray

    # -- Show recent isolation actions if any ----------------------------------
    try {
        $actionsResult = Invoke-MDERequest -Method GET `
            -Endpoint "/api/machines/$($Machine.id)/machineactions?`$top=5&`$orderby=lastUpdateDateTimeUtc desc&`$filter=type eq 'Isolate' or type eq 'Unisolate'"

        if ($actionsResult -and $actionsResult.value -and $actionsResult.value.Count -gt 0) {
            Write-Host ""
            Write-Host "  -- Recent Isolation Actions --" -ForegroundColor DarkCyan
            foreach ($action in $actionsResult.value) {
                $aType   = $action.type
                $aStatus = $action.status
                $aTime   = $action.lastUpdateDateTimeUtc
                $aBy     = if ($action.requestor) { $action.requestor } else { "--" }

                $statusColour = switch ($aStatus) {
                    "Succeeded" { "Green" }
                    "Pending"   { "Yellow" }
                    "Failed"    { "Red" }
                    default     { "White" }
                }

                Write-Host "    $aType " -ForegroundColor White -NoNewline
                Write-Host "[$aStatus]" -ForegroundColor $statusColour -NoNewline
                Write-Host " at $aTime by $aBy" -ForegroundColor DarkGray
            }
        }
    }
    catch {
        # Silently ignore -- not all tenants expose machine actions
    }
}

# ==============================================================================
# FUNCTIONS -- USER ACTIONS
# ==============================================================================

function Invoke-ResetPasswordAndRevoke {
    param(
        [PSCustomObject]$User,
        [Microsoft.ActiveDirectory.Management.ADUser]$ADUser
    )

    if (-not $ADUser) {
        Write-Host "  No AD account found. Cannot reset password." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  PASSWORD RESET + SESSION REVOKE" -ForegroundColor Yellow
    Write-Host "  This will:" -ForegroundColor White
    Write-Host "    1. Reset the AD password to a random temporary password" -ForegroundColor White
    Write-Host "    2. Set 'must change password at next logon' in AD" -ForegroundColor White
    Write-Host "    3. Revoke all Entra ID sign-in sessions" -ForegroundColor White
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    $length = 16
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new($length)
    $rng.GetBytes($bytes)
    $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

    Write-Host "  [1/3] Resetting AD password..." -ForegroundColor Cyan -NoNewline
    try {
        $adParams = Get-ADConnectionParams
        Set-ADAccountPassword @adParams -Identity $ADUser.SamAccountName -NewPassword $securePassword -Reset -ErrorAction Stop
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
        return
    }

    Write-Host "  [2/3] Setting change password at next logon..." -ForegroundColor Cyan -NoNewline
    try {
        Set-ADUser @adParams -Identity $ADUser.SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
    }

    Write-Host "  [3/3] Revoking Entra ID sessions..." -ForegroundColor Cyan -NoNewline
    try {
        $revokeUri = "https://graph.microsoft.com/v1.0/users/$($User.Id)/revokeSignInSessions"
        Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
    }

    Write-Host ""
    Write-Host "  Temporary password: $password" -ForegroundColor Yellow
    Write-Host "  IMPORTANT: Communicate this to the user securely." -ForegroundColor Yellow
    Write-Host "  The user must change it at next logon." -ForegroundColor Yellow
}

function Invoke-RequirePasswordChange {
    param(
        [Microsoft.ActiveDirectory.Management.ADUser]$ADUser
    )

    if (-not $ADUser) {
        Write-Host "  No AD account found. Cannot set password flag." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  REQUIRE PASSWORD CHANGE AT NEXT LOGON" -ForegroundColor Yellow
    Write-Host "  This will flag the AD account so the user must change" -ForegroundColor White
    Write-Host "  their password at next sign-in." -ForegroundColor White
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Setting change password at next logon..." -ForegroundColor Cyan -NoNewline
    try {
        $adParams = Get-ADConnectionParams
        Set-ADUser @adParams -Identity $ADUser.SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
    }
}

function Invoke-DisableAndRevoke {
    param(
        [PSCustomObject]$User,
        [Microsoft.ActiveDirectory.Management.ADUser]$ADUser
    )

    Write-Host ""
    Write-Host "  DISABLE ACCOUNT + REVOKE SESSIONS" -ForegroundColor Red
    Write-Host "  This will:" -ForegroundColor White
    if ($ADUser) {
        Write-Host "    1. Disable the account in Active Directory" -ForegroundColor White
        Write-Host "    2. Revoke all Entra ID sign-in sessions" -ForegroundColor White
    }
    else {
        Write-Host "    1. No AD account found - will skip AD disable" -ForegroundColor Yellow
        Write-Host "    2. Revoke all Entra ID sign-in sessions" -ForegroundColor White
    }
    Write-Host ""

    Write-Host "  WARNING: The user will be unable to sign in." -ForegroundColor Red
    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    if ($ADUser) {
        Write-Host "  [1/2] Disabling AD account..." -ForegroundColor Cyan -NoNewline
        try {
            $adParams = Get-ADConnectionParams
            Disable-ADAccount @adParams -Identity $ADUser.SamAccountName -ErrorAction Stop
            Write-Host " Done" -ForegroundColor Green
        }
        catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Warning "    Error: $_"
        }
    }
    else {
        Write-Host "  [1/2] Skipped AD disable (no AD account)." -ForegroundColor Yellow
    }

    Write-Host "  [2/2] Revoking Entra ID sessions..." -ForegroundColor Cyan -NoNewline
    try {
        $revokeUri = "https://graph.microsoft.com/v1.0/users/$($User.Id)/revokeSignInSessions"
        Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
    }

    Write-Host ""
    Write-Host "  Account disabled and sessions revoked." -ForegroundColor Red
}

# ==============================================================================
# FUNCTIONS -- DEVICE ACTIONS (MDE)
# ==============================================================================

function Invoke-IsolateDevice {
    <#
    .SYNOPSIS
        Isolates a device in MDE (Full or Selective).
    #>
    param(
        [Parameter(Mandatory)][string]$MachineId,
        [string]$MachineName,
        [ValidateSet("Full","Selective")][string]$IsolationType = "Full"
    )

    Write-Host ""
    Write-Host "  ISOLATE DEVICE ($IsolationType)" -ForegroundColor Red

    if ($IsolationType -eq "Full") {
        Write-Host "  This will fully isolate the device from the network." -ForegroundColor White
        Write-Host "  Only connections to the MDE cloud service will remain." -ForegroundColor White
    }
    else {
        Write-Host "  This will selectively isolate the device." -ForegroundColor White
        Write-Host "  Outlook, Teams, and Skype connectivity will be preserved." -ForegroundColor White
    }

    Write-Host "  Device: $MachineName" -ForegroundColor White
    Write-Host ""

    $comment = Read-Host "  Enter a reason / ticket reference"
    if ([string]::IsNullOrWhiteSpace($comment)) {
        $comment = "Isolated via User Management Tool"
    }

    $confirm = Read-Host "  Proceed with $IsolationType isolation? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Sending isolation request..." -ForegroundColor Cyan -NoNewline

    $body = @{
        Comment       = $comment
        IsolationType = $IsolationType
    }

    $result = Invoke-MDERequest -Method POST -Endpoint "/api/machines/$MachineId/isolate" -Body $body

    if ($result) {
        Write-Host " Submitted" -ForegroundColor Green
        Write-Host "  Action ID : $($result.id)" -ForegroundColor DarkGray
        Write-Host "  Status    : $($result.status)" -ForegroundColor Yellow
        Write-Host "  The device will be isolated shortly." -ForegroundColor Yellow
    }
    else {
        Write-Host " FAILED" -ForegroundColor Red
    }
}

function Invoke-UnisolateDevice {
    <#
    .SYNOPSIS
        Releases a device from MDE isolation.
    #>
    param(
        [Parameter(Mandatory)][string]$MachineId,
        [string]$MachineName
    )

    Write-Host ""
    Write-Host "  RELEASE FROM ISOLATION" -ForegroundColor Green
    Write-Host "  This will remove network isolation on the device." -ForegroundColor White
    Write-Host "  Device: $MachineName" -ForegroundColor White
    Write-Host ""

    $comment = Read-Host "  Enter a reason / ticket reference"
    if ([string]::IsNullOrWhiteSpace($comment)) {
        $comment = "Released via User Management Tool"
    }

    $confirm = Read-Host "  Proceed with release from isolation? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Sending release request..." -ForegroundColor Cyan -NoNewline

    $body = @{ Comment = $comment }

    $result = Invoke-MDERequest -Method POST -Endpoint "/api/machines/$MachineId/unisolate" -Body $body

    if ($result) {
        Write-Host " Submitted" -ForegroundColor Green
        Write-Host "  Action ID : $($result.id)" -ForegroundColor DarkGray
        Write-Host "  Status    : $($result.status)" -ForegroundColor Yellow
        Write-Host "  The device will be released shortly." -ForegroundColor Yellow
    }
    else {
        Write-Host " FAILED" -ForegroundColor Red
    }
}

# ==============================================================================
# FUNCTIONS -- DEVICE ACTION MENU (shared by user-context & device-search flows)
# ==============================================================================

function Invoke-OffboardDevice {
    <#
    .SYNOPSIS
        Composite "Offboard Device" workflow that chains the appropriate steps
        based on device ownership and what services the device is enrolled in.

        Steps (each prompted individually):
          1. Intune action -- Corporate: Wipe or Retire; Personal: Retire
          2. MDE isolation (if onboarded)
          3. Disable Entra device object
          4. Revoke user sign-in sessions

        The operator is asked at each step whether to proceed or skip.
    #>
    param(
        $EntraDevice,     # May be $null if from MDE search
        $IntuneDevice,    # May be $null if not enrolled
        $MDEMachine,      # May be $null if not onboarded
        $User             # May be $null if from MDE search; needed for session revocation
    )

    $deviceName = "Unknown"
    if ($EntraDevice -and $EntraDevice.DisplayName)       { $deviceName = $EntraDevice.DisplayName }
    elseif ($IntuneDevice -and $IntuneDevice.deviceName)  { $deviceName = $IntuneDevice.deviceName }
    elseif ($MDEMachine -and $MDEMachine.computerDnsName) { $deviceName = $MDEMachine.computerDnsName }

    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Red
    Write-Host "  OFFBOARD DEVICE" -ForegroundColor Red
    Write-Host "  ========================================================" -ForegroundColor Red
    Write-Host "  Device: $deviceName" -ForegroundColor White

    # -- Determine ownership and OS from Intune if available -------------------
    $isCorporate = $false
    $ownerLabel  = "Unknown"
    $osLabel     = "Unknown"

    if ($IntuneDevice) {
        $isCorporate = ($IntuneDevice.managedDeviceOwnerType -eq "company")
        $ownerLabel  = if ($isCorporate) { "Corporate" } else { "Personal / BYOD" }
        $osLabel     = if ($IntuneDevice.operatingSystem) { $IntuneDevice.operatingSystem } else { "Unknown" }
    }
    elseif ($EntraDevice) {
        # Infer from trust type if no Intune record
        $isCorporate = ($EntraDevice.TrustType -eq "AzureAd" -and $EntraDevice.ProfileType -eq "RegisteredDevice") -or
                       ($EntraDevice.TrustType -eq "ServerAd")
        $ownerLabel  = if ($isCorporate) { "Corporate (inferred)" } else { "Personal / BYOD (inferred)" }
        $osLabel     = if ($EntraDevice.OperatingSystem) { $EntraDevice.OperatingSystem } else { "Unknown" }
    }

    Write-Host "  Ownership: $ownerLabel" -ForegroundColor $(if ($isCorporate) { "Cyan" } else { "Yellow" })
    Write-Host "  OS: $osLabel" -ForegroundColor White

    # Show what services the device is known to
    $inServices = @()
    if ($EntraDevice)   { $inServices += "Entra ID" }
    if ($IntuneDevice)  { $inServices += "Intune" }
    if ($MDEMachine)    { $inServices += "MDE" }
    Write-Host "  Enrolled in: $($inServices -join ', ')" -ForegroundColor White
    Write-Host ""

    Write-Host "  This workflow will walk you through each offboarding step." -ForegroundColor DarkGray
    Write-Host "  You can skip any step by answering N." -ForegroundColor DarkGray
    Write-Host ""

    $overallConfirm = Read-Host "  Begin offboarding? (Y/N)"
    if ($overallConfirm -ne "Y" -and $overallConfirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    $stepNum = 1

    # ==========================================================================
    # STEP: Intune action (Wipe / Retire)
    # ==========================================================================
    if ($IntuneDevice) {
        Write-Host ""
        Write-Host "  -- Step $stepNum : Intune Device Action --" -ForegroundColor Yellow
        $stepNum++

        if ($isCorporate) {
            Write-Host "  Corporate device: you can Wipe (factory reset) or Retire (remove company data)." -ForegroundColor White
            Write-Host "    [W] Wipe   - factory reset, removes ALL data" -ForegroundColor Red
            Write-Host "    [R] Retire - removes company data/apps/profiles only" -ForegroundColor Yellow
            Write-Host "    [S] Skip   - do not take any Intune action" -ForegroundColor DarkGray
            $intuneChoice = Read-Host "  Choice (W/R/S)"

            switch ($intuneChoice.ToUpper()) {
                "W" {
                    Write-Host "  Sending wipe command..." -ForegroundColor Cyan -NoNewline
                    try {
                        Invoke-MgGraphRequest -Method POST `
                            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($IntuneDevice.id)/wipe" `
                            -ErrorAction Stop | Out-Null
                        Write-Host " Done" -ForegroundColor Green
                    }
                    catch {
                        Write-Host " FAILED" -ForegroundColor Red
                        Write-Warning "    Error: $_"
                    }
                }
                "R" {
                    Write-Host "  Sending retire command..." -ForegroundColor Cyan -NoNewline
                    try {
                        Invoke-MgGraphRequest -Method POST `
                            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($IntuneDevice.id)/retire" `
                            -ErrorAction Stop | Out-Null
                        Write-Host " Done" -ForegroundColor Green
                    }
                    catch {
                        Write-Host " FAILED" -ForegroundColor Red
                        Write-Warning "    Error: $_"
                    }
                }
                default {
                    Write-Host "  Skipped Intune action." -ForegroundColor DarkGray
                }
            }
        }
        else {
            # Personal / BYOD -- only Retire is appropriate
            Write-Host "  Personal device: Retire will remove company data, apps, and profiles." -ForegroundColor White
            Write-Host "  Personal data on the device will NOT be affected." -ForegroundColor White
            $retireConfirm = Read-Host "  Retire this device? (Y/N)"

            if ($retireConfirm -eq "Y" -or $retireConfirm -eq "y") {
                Write-Host "  Sending retire command..." -ForegroundColor Cyan -NoNewline
                try {
                    Invoke-MgGraphRequest -Method POST `
                        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($IntuneDevice.id)/retire" `
                        -ErrorAction Stop | Out-Null
                    Write-Host " Done" -ForegroundColor Green
                }
                catch {
                    Write-Host " FAILED" -ForegroundColor Red
                    Write-Warning "    Error: $_"
                }
            }
            else {
                Write-Host "  Skipped Intune retire." -ForegroundColor DarkGray
            }
        }
    }

    # ==========================================================================
    # STEP: MDE isolation
    # ==========================================================================
    if ($MDEMachine -and $script:mdeAccessToken) {
        Write-Host ""
        Write-Host "  -- Step $stepNum : MDE Network Isolation --" -ForegroundColor Yellow
        $stepNum++

        Write-Host "  Isolate this device from the network?" -ForegroundColor White
        Write-Host "    [F] Full isolation (device can only reach MDE service)" -ForegroundColor White
        Write-Host "    [S] Selective isolation (Outlook/Teams/Skype remain)" -ForegroundColor White
        Write-Host "    [N] Skip -- do not isolate" -ForegroundColor DarkGray
        $isoChoice = Read-Host "  Choice (F/S/N)"

        switch ($isoChoice.ToUpper()) {
            "F" {
                Write-Host "  Sending full isolation request..." -ForegroundColor Cyan -NoNewline
                $body = @{
                    Comment       = "Offboarded via User Management Tool"
                    IsolationType = "Full"
                }
                $result = Invoke-MDERequest -Method POST -Endpoint "/api/machines/$($MDEMachine.id)/isolate" -Body $body
                if ($result) {
                    Write-Host " Submitted (Status: $($result.status))" -ForegroundColor Green
                } else {
                    Write-Host " FAILED" -ForegroundColor Red
                }
            }
            "S" {
                Write-Host "  Sending selective isolation request..." -ForegroundColor Cyan -NoNewline
                $body = @{
                    Comment       = "Offboarded via User Management Tool"
                    IsolationType = "Selective"
                }
                $result = Invoke-MDERequest -Method POST -Endpoint "/api/machines/$($MDEMachine.id)/isolate" -Body $body
                if ($result) {
                    Write-Host " Submitted (Status: $($result.status))" -ForegroundColor Green
                } else {
                    Write-Host " FAILED" -ForegroundColor Red
                }
            }
            default {
                Write-Host "  Skipped MDE isolation." -ForegroundColor DarkGray
            }
        }
    }

    # ==========================================================================
    # STEP: Disable Entra device object
    # ==========================================================================
    if ($EntraDevice -and $EntraDevice.Id) {
        Write-Host ""
        Write-Host "  -- Step $stepNum : Disable Entra Device Object --" -ForegroundColor Yellow
        $stepNum++

        $currentlyEnabled = $EntraDevice.AccountEnabled
        if ($currentlyEnabled -eq $false) {
            Write-Host "  Device is already disabled in Entra ID." -ForegroundColor DarkGray
        }
        else {
            Write-Host "  This will set AccountEnabled = false on the Entra device object." -ForegroundColor White
            Write-Host "  The device will no longer be able to authenticate against Entra ID." -ForegroundColor White
            $disableConfirm = Read-Host "  Disable Entra device object? (Y/N)"

            if ($disableConfirm -eq "Y" -or $disableConfirm -eq "y") {
                Write-Host "  Disabling Entra device object..." -ForegroundColor Cyan -NoNewline
                try {
                    $body = @{ accountEnabled = $false } | ConvertTo-Json
                    Invoke-MgGraphRequest -Method PATCH `
                        -Uri "https://graph.microsoft.com/v1.0/devices/$($EntraDevice.Id)" `
                        -Body $body -ContentType "application/json" `
                        -ErrorAction Stop | Out-Null
                    Write-Host " Done" -ForegroundColor Green

                    # Update local object so the display refreshes correctly
                    $EntraDevice | Add-Member -NotePropertyName 'AccountEnabled' -NotePropertyValue $false -Force
                }
                catch {
                    Write-Host " FAILED" -ForegroundColor Red
                    Write-Warning "    Error: $_"
                }
            }
            else {
                Write-Host "  Skipped disabling Entra device." -ForegroundColor DarkGray
            }
        }
    }

    # ==========================================================================
    # STEP: Revoke user sign-in sessions
    # ==========================================================================

    # Resolve user if not provided (e.g. came from device search)
    $revokeUserId  = $null
    $revokeUserUPN = $null

    if ($User -and $User.Id) {
        $revokeUserId  = $User.Id
        $revokeUserUPN = if ($User.UPN) { $User.UPN } else { $User.Id }
    }
    elseif ($EntraDevice -and $EntraDevice.Id) {
        # Try to look up the registered owner from the Entra device
        try {
            $owners = Get-MgDeviceRegisteredOwner -DeviceId $EntraDevice.Id -ErrorAction Stop
            if ($owners -and $owners.Count -gt 0) {
                $ownerId = $owners[0].Id
                $ownerUser = Get-MgUser -UserId $ownerId -Property "id","userPrincipalName" -ErrorAction Stop
                if ($ownerUser) {
                    $revokeUserId  = $ownerUser.Id
                    $revokeUserUPN = $ownerUser.UserPrincipalName
                }
            }
        }
        catch {
            # Could not resolve owner -- will skip session revocation
        }
    }

    if ($revokeUserId) {
        Write-Host ""
        Write-Host "  -- Step $stepNum : Revoke Sign-In Sessions --" -ForegroundColor Yellow
        $stepNum++

        Write-Host "  This will invalidate all refresh tokens and session cookies" -ForegroundColor White
        Write-Host "  for user: $revokeUserUPN" -ForegroundColor White
        Write-Host "  The user will be forced to re-authenticate everywhere." -ForegroundColor White
        $revokeConfirm = Read-Host "  Revoke all sign-in sessions? (Y/N)"

        if ($revokeConfirm -eq "Y" -or $revokeConfirm -eq "y") {
            Write-Host "  Revoking sessions..." -ForegroundColor Cyan -NoNewline
            try {
                $revokeUri = "https://graph.microsoft.com/v1.0/users/$revokeUserId/revokeSignInSessions"
                Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ErrorAction Stop | Out-Null
                Write-Host " Done" -ForegroundColor Green
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Warning "    Error: $_"
            }
        }
        else {
            Write-Host "  Skipped session revocation." -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host ""
        Write-Host "  -- Step $stepNum : Revoke Sign-In Sessions --" -ForegroundColor Yellow
        $stepNum++
        Write-Host "  Could not determine the device owner. Skipping session revocation." -ForegroundColor DarkGray
        Write-Host "  You can revoke sessions manually from the user search menu." -ForegroundColor DarkGray
    }

    # ==========================================================================
    # Summary
    # ==========================================================================
    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Green
    Write-Host "  Offboarding workflow complete for: $deviceName" -ForegroundColor Green
    Write-Host "  ========================================================" -ForegroundColor Green
    Write-Host ""
}

function Show-DeviceActionMenu {
    <#
    .SYNOPSIS
        Displays device detail and an action menu for a single device.
        Adapts to what is available:
          - Entra device properties (always, if EntraDevice is provided)
          - Intune managed device detail + actions (if enrolled in Intune)
          - MDE device detail + isolation actions (if onboarded to MDE)
        Includes a composite "Offboard Device" workflow that chains
        the appropriate steps based on device category.
        Used both from the user-device drill-down and from standalone device search.
        Returns when the user chooses to go back.
    #>
    param(
        $EntraDevice,   # May be $null if from device search
        $MDEMachine,    # May be $null if device isn't in MDE
        $User           # May be $null if from device search; used for session revocation
    )

    $backToParent   = $false
    $intuneDevice   = $null
    $intuneLookedUp = $false
    $mdeLookedUp    = $false

    while (-not $backToParent) {

        # -- Resolve MDE machine (once) ----------------------------------------
        if (-not $MDEMachine -and -not $mdeLookedUp -and $EntraDevice -and $EntraDevice.DeviceId -and $script:mdeAccessToken) {
            Write-Host "  Looking up device in MDE..." -ForegroundColor Cyan
            $MDEMachine = Get-MDEMachineByAADDeviceId -AADDeviceId $EntraDevice.DeviceId
            $mdeLookedUp = $true
        }

        # -- Resolve Intune managed device (once) ------------------------------
        if (-not $intuneDevice -and -not $intuneLookedUp -and $EntraDevice -and $EntraDevice.DeviceId) {
            Write-Host "  Looking up device in Intune..." -ForegroundColor Cyan
            $intuneDevice = Get-IntuneManagedDevice -AADDeviceId $EntraDevice.DeviceId
            $intuneLookedUp = $true
        }

        # -- Display detail sections -------------------------------------------

        # Entra detail (always show if we have the Entra object)
        if ($EntraDevice) {
            Show-EntraDeviceDetail -Device $EntraDevice
        }

        # Intune detail
        if ($intuneDevice) {
            Show-IntuneDeviceDetail -ManagedDevice $intuneDevice
        }
        elseif ($intuneLookedUp -and $EntraDevice) {
            Write-Host ""
            Write-Host "  -- Intune Managed Device Detail --" -ForegroundColor Magenta
            Write-Host "  Device not enrolled in Intune (or no Intune licence)." -ForegroundColor DarkGray
        }

        # MDE detail
        if ($MDEMachine) {
            Show-MDEDeviceDetail -Machine $MDEMachine
        }
        elseif ($mdeLookedUp) {
            Write-Host ""
            Write-Host "  -- MDE Device Detail --" -ForegroundColor Magenta
            Write-Host "  Device not onboarded to MDE." -ForegroundColor DarkGray
        }
        elseif (-not $script:mdeAccessToken -and -not $MDEMachine) {
            Write-Host ""
            Write-Host "  -- MDE Device Detail --" -ForegroundColor Magenta
            Write-Host "  MDE is not connected. Connect from the main menu to see MDE detail." -ForegroundColor DarkGray
        }

        # Network / Location (consolidated from MDE + sign-in logs)
        Show-DeviceNetworkLocation -EntraDevice $EntraDevice -IntuneDevice $intuneDevice -MDEMachine $MDEMachine -User $User

        # -- Build action menu dynamically -------------------------------------
        Write-Host ""
        Write-Host "  -- DEVICE ACTIONS --" -ForegroundColor Yellow

        $hasMDE    = ($null -ne $script:mdeAccessToken) -and ($null -ne $MDEMachine)
        $hasIntune = ($null -ne $intuneDevice)

        $menuIndex  = 1
        $actionMap  = @{}   # maps displayed number -> action key

        # MDE actions
        if ($hasMDE) {
            Write-Host "    [$menuIndex] Isolate device (Full)       [MDE]"
            $actionMap["$menuIndex"] = "mde_isolate_full";  $menuIndex++

            Write-Host "    [$menuIndex] Isolate device (Selective)  [MDE]"
            $actionMap["$menuIndex"] = "mde_isolate_sel";   $menuIndex++

            Write-Host "    [$menuIndex] Release from isolation      [MDE]"
            $actionMap["$menuIndex"] = "mde_unisolate";     $menuIndex++
        }
        else {
            if (-not $script:mdeAccessToken) {
                Write-Host "    MDE not connected -- isolation actions unavailable." -ForegroundColor DarkGray
            }
            elseif (-not $MDEMachine) {
                Write-Host "    Device not in MDE -- isolation actions unavailable." -ForegroundColor DarkGray
            }
        }

        # Intune actions (context-aware based on OS / ownership / supervised)
        if ($hasIntune) {
            $intuneDeviceName = if ($intuneDevice.deviceName) { $intuneDevice.deviceName } else { "device" }
            $intuneActions = Get-IntuneAvailableActions -ManagedDevice $intuneDevice

            # Show device category for clarity
            $iOS   = if ($intuneDevice.operatingSystem) { $intuneDevice.operatingSystem } else { "Unknown OS" }
            $iOwn  = if ($intuneDevice.managedDeviceOwnerType -eq 'company') { "Corporate" } else { "Personal" }
            Write-Host "    Intune ($iOwn $iOS):" -ForegroundColor DarkCyan

            foreach ($ia in $intuneActions) {
                $padLabel = $ia.Label.PadRight(30)
                Write-Host "    [$menuIndex] $padLabel [Intune]" -ForegroundColor $ia.Colour
                $actionMap["$menuIndex"] = $ia.ActionKey; $menuIndex++
            }
        }
        else {
            if (-not $EntraDevice) {
                # Came from MDE device search -- no Entra context
            }
            elseif ($intuneLookedUp) {
                Write-Host "    Device not in Intune -- Intune actions unavailable." -ForegroundColor DarkGray
            }
        }

        # Separator + Offboard Device composite action
        if ($hasIntune -or $hasMDE -or $EntraDevice) {
            Write-Host ""
            Write-Host "    [$menuIndex] " -NoNewline
            Write-Host "Offboard Device" -ForegroundColor Red -NoNewline
            Write-Host "                [Composite]" -ForegroundColor DarkGray
            $actionMap["$menuIndex"] = "offboard"; $menuIndex++
        }

        # Common actions (always available)
        Write-Host ""
        Write-Host "    [$menuIndex] Refresh"
        $actionMap["$menuIndex"] = "refresh"; $menuIndex++

        Write-Host "    [$menuIndex] Back"
        $actionMap["$menuIndex"] = "back";    $menuIndex++

        Write-Host ""

        $deviceAction = Read-Host "  Action"

        $actionKey = $actionMap[$deviceAction]

        switch ($actionKey) {
            # -- MDE actions --
            "mde_isolate_full" {
                Invoke-IsolateDevice -MachineId $MDEMachine.id -MachineName $MDEMachine.computerDnsName -IsolationType "Full"
            }
            "mde_isolate_sel" {
                Invoke-IsolateDevice -MachineId $MDEMachine.id -MachineName $MDEMachine.computerDnsName -IsolationType "Selective"
            }
            "mde_unisolate" {
                Invoke-UnisolateDevice -MachineId $MDEMachine.id -MachineName $MDEMachine.computerDnsName
            }

            # -- Intune actions --
            "intune_sync" {
                Invoke-IntuneSyncDevice -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName
            }
            "intune_restart" {
                Invoke-IntuneRestartDevice -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName
            }
            "intune_lock" {
                Invoke-IntuneRemoteLock -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName
            }
            "intune_defender_quick" {
                Invoke-IntuneDefenderScan -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName -QuickScan $true
            }
            "intune_defender_full" {
                Invoke-IntuneDefenderScan -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName -QuickScan $false
            }
            "intune_freshstart" {
                Invoke-IntuneFreshStart -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName
            }
            "intune_lostmode_on" {
                Invoke-IntuneEnableLostMode -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName
            }
            "intune_lostmode_off" {
                Invoke-IntuneDisableLostMode -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName
            }
            "intune_retire" {
                Invoke-IntuneRetireDevice -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName
            }
            "intune_wipe" {
                Invoke-IntuneWipeDevice -IntuneDeviceId $intuneDevice.id -DeviceName $intuneDevice.deviceName
            }

            # -- Composite actions --
            "offboard" {
                Invoke-OffboardDevice -EntraDevice $EntraDevice -IntuneDevice $intuneDevice -MDEMachine $MDEMachine -User $User
            }

            # -- Common actions --
            "refresh" {
                # Re-fetch MDE data
                if ($MDEMachine) {
                    $refreshed = Invoke-MDERequest -Method GET -Endpoint "/api/machines/$($MDEMachine.id)"
                    if ($refreshed) { $MDEMachine = $refreshed }
                }
                # Re-fetch Intune data
                if ($intuneDevice -and $EntraDevice -and $EntraDevice.DeviceId) {
                    $refreshedIntune = Get-IntuneManagedDevice -AADDeviceId $EntraDevice.DeviceId
                    if ($refreshedIntune) { $intuneDevice = $refreshedIntune }
                }
                # Re-try lookups if first attempt returned nothing
                if (-not $MDEMachine -and $EntraDevice -and $EntraDevice.DeviceId -and $script:mdeAccessToken) {
                    $MDEMachine = Get-MDEMachineByAADDeviceId -AADDeviceId $EntraDevice.DeviceId
                }
                if (-not $intuneDevice -and $EntraDevice -and $EntraDevice.DeviceId) {
                    $intuneDevice = Get-IntuneManagedDevice -AADDeviceId $EntraDevice.DeviceId
                }
            }
            "back" {
                $backToParent = $true
            }
            default {
                Write-Host "  Invalid option." -ForegroundColor Yellow
            }
        }
    }
}

# ==============================================================================
# MAIN
# ==============================================================================

Write-Host "============================================================" -ForegroundColor White
Write-Host "  USER & DEVICE MANAGEMENT TOOL" -ForegroundColor Cyan
Write-Host "  Entra ID + Active Directory + MDE" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor White

# -- Check prerequisites -------------------------------------------------------
$prerequisitesMet = Test-Prerequisites

if (-not $prerequisitesMet) {
    Write-Host ""
    Write-Host "  Prerequisites not met. Exiting." -ForegroundColor Red
    Write-Host ""
    exit 1
}

# -- Connect to services ------------------------------------------------------
Connect-ToGraph
Ensure-GraphCLIConsent

Write-Host ""
$adConnected = Connect-ToAD

if (-not $adConnected) {
    Write-Host ""
    Write-Host "Active Directory is not available. AD actions will be limited." -ForegroundColor Yellow
    Write-Host "Entra-only actions will still work." -ForegroundColor Yellow
}

Write-Host ""

# MDE connection (optional -- prompts user, with retry)
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  MDE (Microsoft Defender for Endpoint) enables device" -ForegroundColor White
Write-Host "  isolation actions and detailed device health information." -ForegroundColor White
Write-Host ""
$connectMDE = Read-Host "  Connect to MDE? (Y/N)"

$mdeConnected = $false
if ($connectMDE -eq "Y" -or $connectMDE -eq "y") {
    while (-not $mdeConnected) {
        $mdeConnected = Connect-ToMDE
        if (-not $mdeConnected) {
            Write-Host ""
            $retryMDE = Read-Host "  Retry MDE connection? (Y/N)"
            if ($retryMDE -ne "Y" -and $retryMDE -ne "y") {
                Write-Host "  Skipping MDE. You can reconnect from the main menu." -ForegroundColor DarkGray
                break
            }
        }
    }
}
else {
    Write-Host "  Skipping MDE. You can connect later from the main menu." -ForegroundColor DarkGray
}

Write-Host ""

# -- Main loop -----------------------------------------------------------------
$exitScript = $false

while (-not $exitScript) {
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host "  MAIN MENU" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host "    [1] Search for a user"
    Write-Host "    [2] Search for a device (MDE)" -ForegroundColor $(if ($mdeConnected) { "White" } else { "DarkGray" })

    if ($mdeConnected) {
        Write-Host "    [3] Reconnect to MDE" -ForegroundColor DarkGray
    } else {
        Write-Host "    [3] Connect to MDE" -ForegroundColor Yellow
    }

    if ($adConnected) {
        Write-Host "    [4] Reconnect to AD" -ForegroundColor DarkGray
    } else {
        Write-Host "    [4] Connect to AD" -ForegroundColor Yellow
    }

    Write-Host "    [5] Exit"
    Write-Host ""

    $menuChoice = Read-Host "  Select"

    switch ($menuChoice) {

    # ======================================================================
    # [1] USER SEARCH
    # ======================================================================
    "1" {
        $backToMenu = $false

        while (-not $backToMenu -and -not $exitScript) {
            Write-Host ""
            Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
            Write-Host "  SEARCH FOR A USER" -ForegroundColor Cyan
            Write-Host "  Enter a search term (partial UPN, first name, or last name)" -ForegroundColor White
            Write-Host "  Or type 'BACK' to return to the main menu." -ForegroundColor DarkGray
            Write-Host ""

            $searchTerm = Read-Host "  Search"

            if ([string]::IsNullOrWhiteSpace($searchTerm)) {
                Write-Host "  No search term entered." -ForegroundColor Yellow
                continue
            }
            if ($searchTerm -eq "BACK" -or $searchTerm -eq "back") {
                $backToMenu = $true
                break
            }
            if ($searchTerm -eq "EXIT" -or $searchTerm -eq "exit") {
                $exitScript = $true
                break
            }

            $searchResults = Search-Users -SearchTerm $searchTerm

            if (-not $searchResults -or $searchResults.Count -eq 0) {
                Write-Host "  No users found matching '$searchTerm'." -ForegroundColor Yellow
                continue
            }

            Write-Host ""
            Write-Host "  Found $($searchResults.Count) user(s):" -ForegroundColor Green
            Write-Host ""

            $i = 1
            foreach ($sr in $searchResults) {
                $enabledTag    = if ($sr.AccountEnabled -eq $true) { "[Enabled]" } else { "[Disabled]" }
                $enabledColour = if ($sr.AccountEnabled -eq $true) { "Green" }     else { "Red" }
                Write-Host "    [$i] " -ForegroundColor White -NoNewline
                Write-Host "$($sr.DisplayName)" -ForegroundColor White -NoNewline
                Write-Host " - $($sr.UPN) " -ForegroundColor DarkCyan -NoNewline
                Write-Host $enabledTag -ForegroundColor $enabledColour
                $i++
            }

            Write-Host ""
            Write-Host "    [0] Back to search" -ForegroundColor DarkGray
            Write-Host ""

            $userChoice = Read-Host "  Select a user (number)"

            if ($userChoice -eq "0" -or [string]::IsNullOrWhiteSpace($userChoice)) {
                continue
            }

            $selectedIndex = 0
            if (-not [int]::TryParse($userChoice, [ref]$selectedIndex)) {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
                continue
            }

            $searchArray = @($searchResults)
            if ($selectedIndex -lt 1 -or $selectedIndex -gt $searchArray.Count) {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
                continue
            }

            $selectedUser = $searchArray[$selectedIndex - 1]

            # -- User detail + action loop -------------------------------------
            $backToSearch = $false

            while (-not $backToSearch -and -not $backToMenu -and -not $exitScript) {
                $adUser     = Show-UserDetail -User $selectedUser
                $deviceList = Show-UserDevices -User $selectedUser

                Write-Host ""
                Write-Host "  -- ACTIONS --" -ForegroundColor Yellow
                Write-Host "    [1] Reset password (AD) + Revoke Entra sessions"
                Write-Host "    [2] Require password change at next logon (AD)"
                Write-Host "    [3] Disable account (AD) + Revoke Entra sessions"
                Write-Host "    [4] Revoke Entra sessions only"
                Write-Host "    [5] Unlock AD account"

                if ($deviceList -and $deviceList.Count -gt 0) {
                    Write-Host "    [6] Select a device for device actions" -ForegroundColor Cyan
                }
                else {
                    Write-Host "    [6] Select a device for device actions" -ForegroundColor DarkGray
                }

                Write-Host "    [7] Back to search"
                Write-Host "    [8] Back to main menu"
                Write-Host "    [9] Exit"
                Write-Host ""

                $actionChoice = Read-Host "  Action"

                switch ($actionChoice) {
                    "1" {
                        if (-not $adConnected) {
                            Write-Host "  Active Directory is not connected. Cannot reset password." -ForegroundColor Red
                        }
                        else {
                            Invoke-ResetPasswordAndRevoke -User $selectedUser -ADUser $adUser
                        }
                    }
                    "2" {
                        if (-not $adConnected) {
                            Write-Host "  Active Directory is not connected. Cannot set password flag." -ForegroundColor Red
                        }
                        else {
                            Invoke-RequirePasswordChange -ADUser $adUser
                        }
                    }
                    "3" {
                        if (-not $adConnected) {
                            Write-Host "  AD not connected. Revoking Entra sessions only." -ForegroundColor Yellow
                        }
                        Invoke-DisableAndRevoke -User $selectedUser -ADUser $adUser
                    }
                    "4" {
                        Write-Host ""
                        $confirmRevoke = Read-Host "  Revoke all Entra sessions for $($selectedUser.DisplayName)? (Y/N)"
                        if ($confirmRevoke -eq "Y" -or $confirmRevoke -eq "y") {
                            Write-Host "  Revoking Entra ID sessions..." -ForegroundColor Cyan -NoNewline
                            try {
                                $revokeUri = "https://graph.microsoft.com/v1.0/users/$($selectedUser.Id)/revokeSignInSessions"
                                Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ErrorAction Stop | Out-Null
                                Write-Host " Done" -ForegroundColor Green
                            }
                            catch {
                                Write-Host " FAILED" -ForegroundColor Red
                                Write-Warning "    Error: $_"
                            }
                        }
                        else {
                            Write-Host "  Cancelled." -ForegroundColor DarkGray
                        }
                    }
                    "5" {
                        if (-not $adConnected) {
                            Write-Host "  Active Directory is not connected. Cannot unlock." -ForegroundColor Red
                        }
                        elseif (-not $adUser) {
                            Write-Host "  No AD account found." -ForegroundColor Red
                        }
                        else {
                            Write-Host "  Unlocking AD account..." -ForegroundColor Cyan -NoNewline
                            try {
                                $adParams = Get-ADConnectionParams
                                Unlock-ADAccount @adParams -Identity $adUser.SamAccountName -ErrorAction Stop
                                Write-Host " Done" -ForegroundColor Green
                            }
                            catch {
                                Write-Host " FAILED" -ForegroundColor Red
                                Write-Warning "    Error: $_"
                            }
                        }
                    }
                    "6" {
                        # -- Device selection submenu ------------------------------
                        if (-not $deviceList -or $deviceList.Count -eq 0) {
                            Write-Host "  No linked devices to select." -ForegroundColor Yellow
                        }
                        else {
                            Write-Host ""
                            Write-Host "  Select a device by number (from the list above):" -ForegroundColor Cyan
                            $devChoice = Read-Host "  Device #"

                            $devIdx = 0
                            if ([int]::TryParse($devChoice, [ref]$devIdx) -and $devIdx -ge 1 -and $devIdx -le $deviceList.Count) {
                                $selectedDevice = $deviceList[$devIdx - 1]
                                $deviceName = if ($selectedDevice.DisplayName) { $selectedDevice.DisplayName } else { "Unknown" }

                                Write-Host ""
                                Write-Host "  ========================================================" -ForegroundColor White
                                Write-Host "  DEVICE: $deviceName" -ForegroundColor Cyan
                                Write-Host "  ========================================================" -ForegroundColor White
                                Write-Host "  Entra Device ID: $($selectedDevice.DeviceId)" -ForegroundColor DarkGray

                                $mdeMachine = $null
                                if ($script:mdeAccessToken -and $selectedDevice.DeviceId) {
                                    Write-Host "  Looking up device in MDE..." -ForegroundColor Cyan
                                    $mdeMachine = Get-MDEMachineByAADDeviceId -AADDeviceId $selectedDevice.DeviceId
                                }

                                Show-DeviceActionMenu -EntraDevice $selectedDevice -MDEMachine $mdeMachine -User $selectedUser
                            }
                            else {
                                Write-Host "  Invalid device selection." -ForegroundColor Yellow
                            }
                        }
                    }
                    "7" {
                        $backToSearch = $true
                    }
                    "8" {
                        $backToMenu = $true
                    }
                    "9" {
                        $exitScript = $true
                    }
                    default {
                        Write-Host "  Invalid option." -ForegroundColor Yellow
                    }
                }

                # After a user action (not device select, not navigation), offer refresh
                if (-not $backToSearch -and -not $backToMenu -and -not $exitScript -and $actionChoice -notin @("6","7","8","9")) {
                    Write-Host ""
                    Write-Host "  Press Enter to refresh user details, or type 'B' to go back to search." -ForegroundColor DarkGray
                    $postAction = Read-Host "  "
                    if ($postAction -eq "B" -or $postAction -eq "b") {
                        $backToSearch = $true
                    }
                }
            }
        }
    }

    # ======================================================================
    # [2] DEVICE SEARCH (MDE)
    # ======================================================================
    "2" {
        if (-not $mdeConnected) {
            Write-Host "  MDE is not connected. Cannot search for devices." -ForegroundColor Yellow
            Write-Host "  Use option [3] from the main menu to connect to MDE." -ForegroundColor DarkGray
            continue
        }

        $backToMenu = $false

        while (-not $backToMenu -and -not $exitScript) {
            Write-Host ""
            Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
            Write-Host "  SEARCH FOR A DEVICE (MDE)" -ForegroundColor Cyan
            Write-Host "  Enter a computer name (or partial name)" -ForegroundColor White
            Write-Host "  Or type 'BACK' to return to the main menu." -ForegroundColor DarkGray
            Write-Host ""

            $deviceSearchTerm = Read-Host "  Search"

            if ([string]::IsNullOrWhiteSpace($deviceSearchTerm)) {
                Write-Host "  No search term entered." -ForegroundColor Yellow
                continue
            }
            if ($deviceSearchTerm -eq "BACK" -or $deviceSearchTerm -eq "back") {
                $backToMenu = $true
                break
            }
            if ($deviceSearchTerm -eq "EXIT" -or $deviceSearchTerm -eq "exit") {
                $exitScript = $true
                break
            }

            $mdeResults = Search-MDEDevices -SearchTerm $deviceSearchTerm

            if (-not $mdeResults -or $mdeResults.Count -eq 0) {
                Write-Host "  No MDE devices found matching '$deviceSearchTerm'." -ForegroundColor Yellow
                continue
            }

            $mdeArray = @($mdeResults)

            Write-Host ""
            Write-Host "  Found $($mdeArray.Count) device(s):" -ForegroundColor Green
            Write-Host ""

            $j = 1
            foreach ($md in $mdeArray) {
                $healthColour = switch ($md.healthStatus) {
                    "Active"   { "Green" }
                    "Inactive" { "DarkGray" }
                    default    { "Yellow" }
                }
                $riskColour = switch ($md.riskScore) {
                    "High"   { "Red" }
                    "Medium" { "Yellow" }
                    "Low"    { "Green" }
                    default  { "White" }
                }

                $mdName   = if ($md.computerDnsName) { $md.computerDnsName } else { "N/A" }
                $mdOS     = if ($md.osPlatform)      { $md.osPlatform }      else { "" }
                $mdHealth = if ($md.healthStatus)     { $md.healthStatus }    else { "--" }
                $mdRisk   = if ($md.riskScore)        { $md.riskScore }       else { "--" }

                Write-Host "    [$j] " -ForegroundColor White -NoNewline
                Write-Host "$mdName" -ForegroundColor White -NoNewline
                Write-Host " ($mdOS) " -ForegroundColor DarkCyan -NoNewline
                Write-Host "[$mdHealth]" -ForegroundColor $healthColour -NoNewline
                Write-Host " Risk:" -NoNewline
                Write-Host "$mdRisk" -ForegroundColor $riskColour
                $j++
            }

            Write-Host ""
            Write-Host "    [0] Back to search" -ForegroundColor DarkGray
            Write-Host ""

            $devicePickChoice = Read-Host "  Select a device (number)"

            if ($devicePickChoice -eq "0" -or [string]::IsNullOrWhiteSpace($devicePickChoice)) {
                continue
            }

            $devPickIdx = 0
            if (-not [int]::TryParse($devicePickChoice, [ref]$devPickIdx)) {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
                continue
            }

            if ($devPickIdx -lt 1 -or $devPickIdx -gt $mdeArray.Count) {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
                continue
            }

            $selectedMDEDevice = $mdeArray[$devPickIdx - 1]

            Write-Host ""
            Write-Host "  ========================================================" -ForegroundColor White
            $dNameDisplay = if ($selectedMDEDevice.computerDnsName) { $selectedMDEDevice.computerDnsName } else { "Unknown" }
            Write-Host "  DEVICE: $dNameDisplay" -ForegroundColor Cyan
            Write-Host "  ========================================================" -ForegroundColor White

            Show-DeviceActionMenu -EntraDevice $null -MDEMachine $selectedMDEDevice
        }
    }

    # ======================================================================
    # [3] CONNECT / RECONNECT MDE
    # ======================================================================
    "3" {
        $mdeConnected = Connect-ToMDE
        if ($mdeConnected) {
            Write-Host "  MDE is now available." -ForegroundColor Green
        }
    }

    # ======================================================================
    # [4] CONNECT / RECONNECT AD
    # ======================================================================
    "4" {
        $adConnected = Connect-ToAD
        if ($adConnected) {
            Write-Host "  Active Directory is now available." -ForegroundColor Green
        }
        else {
            Write-Host "  AD connection failed. AD actions will remain unavailable." -ForegroundColor Yellow
        }
    }

    # ======================================================================
    # [5] EXIT
    # ======================================================================
    "5" {
        $exitScript = $true
    }

    default {
        Write-Host "  Invalid option." -ForegroundColor Yellow
    }

    } # end switch
}

# -- Cleanup -------------------------------------------------------------------
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Would you like to disconnect from services?" -ForegroundColor Cyan
Write-Host "  [1] Yes - disconnect from Graph and clear MDE token"
Write-Host "  [2] No  - keep sessions active"
Write-Host ""
$disconnectChoice = Read-Host "Select an option (1/2)"

if ($disconnectChoice -eq "1") {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disconnected from Microsoft Graph." -ForegroundColor DarkGray
    Write-Host "Note: AD connectivity is domain-based and does not require disconnection." -ForegroundColor DarkGray
    if ($mdeConnected) {
        Write-Host "MDE token cleared." -ForegroundColor DarkGray
    }
}
else {
    Write-Host "Sessions kept active." -ForegroundColor Green
    Write-Host "  Graph: Run 'Disconnect-MgGraph' when finished." -ForegroundColor DarkGray
}

# -- Clear variables -----------------------------------------------------------
Write-Host "Clearing script variables..." -ForegroundColor DarkGray

$variablesToClear = @(
    # Prerequisites
    'prerequisitesMet', 'modules', 'mod', 'modName', 'modulesToImport',
    'missingRequired', 'missingOptional', 'installedModules',
    'installable', 'installableOptional', 'nonInstallableOptional',
    'installChoice', 'installOptChoice', 'installed', 'version', 'name', 'note',
    # Connection
    'context', 'ctx', 'needsConnect', 'sessionId', 'id',
    'currentScopes', 'hasUserWrite', 'hasUserRead', 'hasDeviceRead', 'missing',
    'adConnected', 'mdeConnected', 'connectMDE', 'retryMDE', 'domain',
    'adServer', 'adCredential', 'adServerInput', 'adUsername', 'adPassword',
    'isAzureADJoined', 'isDomainJoined', 'isHybridJoined', 'dsregOutput',
    'adDomain', 'joinState', 'adParams',
    'savedConfig', 'savedDomain', 'savedUsername', 'domainPrompt', 'usernamePrompt',
    'hasIntuneRead', 'hasIntuneAction', 'hasAuditLog',
    # Graph CLI consent
    'graphCLIAppId', 'msGraphAppId', 'cliSPResult', 'cliSP',
    'graphSPResult', 'graphSP', 'existingGrants', 'existingGrant',
    'existingScopeList', 'missingScopes', 'newScopeString', 'grantBody',
    # MDE auth / tokens
    'mdeAccessToken', 'mdeRefreshToken', 'mdeTokenExpiry', 'mdeClientId', 'mdeTokenUrl',
    'mdeMsalParams', 'msalRefreshParams', 'customClientId', 'authMethod',
    'deviceCodeResponse', 'tokenResponse', 'tokenResult', 'errBody', 'errMsg',
    'createdAppId', 'appNameInput', 'appName', 'scopeConfirm',
    'mdeSPAppId', 'mdeSPResult', 'mdeSP', 'requiredPermNames', 'resolvedPerms',
    'newApp', 'newSP', 'grantBody', 'scopeString', 'verifyApp', 'appBody',
    'codeVerifierBytes', 'codeVerifier', 'challengeBytes', 'codeChallenge',
    'state', 'listener', 'port', 'candidatePort', 'redirectUri',
    'authParams', 'fullAuthUrl', 'asyncResult', 'completed',
    'context', 'request', 'response', 'queryParams',
    'authCode', 'returnState', 'authError', 'errDesc',
    'responseHtml', 'responseBytes', 'msalParams',
    # Navigation
    'exitScript', 'backToSearch', 'backToMenu', 'menuChoice',
    # User search
    'searchTerm', 'searchResults', 'searchArray',
    'userChoice', 'selectedIndex', 'selectedUser',
    'adUser', 'samAccount', 'domainDN', 'riskyUser',
    'signInCutoff', 'signInFilter', 'signInUri', 'signInResult',
    'si', 'siTime', 'siApp', 'siStatus', 'siStatusColour',
    'siIP', 'siLoc', 'locParts', 'siDevice', 'devParts',
    'siCA', 'siCAColour', 'siErrMsg',
    # Device network/location
    'mdeIntIP', 'mdeExtIP', 'mdeLastSeen', 'queryUserId', 'upnLookup', 'regOwners',
    'matchDeviceName', 'matchDeviceId', 'siCutoff', 'siFilter', 'siUri', 'siResult',
    'deviceSignIns', 'devDetail', 'isMatch', 'seenIPs', 'uniqueEntries',
    'ipAddr', 'locDisplay', 'latLon', 'lat', 'lon', 'netErrMsg',
    'actionChoice', 'postAction',
    # User actions
    'confirm', 'confirmRevoke', 'confirmDismiss', 'confirmCompromised',
    'password', 'securePassword', 'length', 'chars', 'rng', 'bytes',
    'revokeUri', 'body',
    # Search internals
    'graphFilter', 'safeTerm', 'entraUsers', 'eu',
    'enabledTag', 'enabledColour',
    'groups', 'g',
    # Device display
    'allDevices', 'registered', 'owned', 'dev', 'full', 'entry', 'd', 'odataType',
    'deviceIndex', 'deviceProperties', 'deviceList',
    'dName', 'dOS', 'dOSVer', 'dMfr', 'dModel', 'dHardware',
    'dTrust', 'dProfile', 'dSource',
    'complianceText', 'complianceColour', 'managedText', 'managedColour',
    'enabledText', 'enabledColour', 'dRegistered', 'dLastSignIn',
    'staleWarning', 'daysSince',
    # Device search / actions
    'deviceSearchTerm', 'mdeResults', 'mdeArray',
    'devicePickChoice', 'devPickIdx', 'selectedMDEDevice', 'dNameDisplay',
    'devChoice', 'devIdx', 'selectedDevice', 'deviceName', 'mdeMachine',
    'deviceAction', 'backToParent', 'actionKey', 'actionMap', 'menuIndex',
    'hasMDE', 'hasIntune', 'intuneDevice', 'intuneLookedUp', 'mdeLookedUp',
    'intuneDeviceName', 'refreshedIntune',
    # Intune display
    'iName', 'iOS', 'iOSVer', 'iSerial', 'iMfr', 'iModel', 'iHardware',
    'iOwner', 'iEnrolled', 'iLastSync', 'iUPN', 'iMgmtAgent', 'iCategory',
    'compState', 'compColour', 'mgmtState', 'mgmtColour',
    'encrypted', 'encColour', 'supervised',
    # Intune actions
    'intuneActions', 'ia', 'iOwn', 'padLabel',
    'os', 'ownership', 'isCorporate', 'isWinOS', 'isIOS', 'isAndroid',
    'isMacPlatform', 'isMobile', 'scanType', 'keepData', 'keepUserData', 'keepLabel',
    'lostMessage', 'lostPhone', 'lostFooter',
    # Offboard composite
    'ownerLabel', 'osLabel', 'inServices', 'overallConfirm', 'stepNum',
    'intuneChoice', 'retireConfirm', 'isoChoice', 'currentlyEnabled',
    'disableConfirm', 'revokeUserId', 'revokeUserUPN', 'owners', 'ownerId', 'ownerUser',
    'revokeConfirm',
    'mName', 'mOS', 'mVer', 'mBld', 'mOSFull',
    'mHealth', 'mOnboard', 'mRisk', 'mExposure', 'mValue',
    'mIP', 'mExtIP', 'mFirst', 'mLast', 'mAADId', 'mMachId', 'mTags',
    'actionsResult', 'aType', 'aStatus', 'aTime', 'aBy', 'statusColour',
    'mdName', 'mdOS', 'mdHealth', 'mdRisk', 'healthColour', 'riskColour',
    # Cleanup
    'disconnectChoice',
    'i', 'j', 'sr', 'md'
)

foreach ($var in $variablesToClear) {
    Remove-Variable -Name $var -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name $var -ErrorAction SilentlyContinue
}
Remove-Variable -Name 'variablesToClear' -ErrorAction SilentlyContinue

Write-Host "Done.`n" -ForegroundColor DarkGray
