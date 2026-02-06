# Note: Module requirements are checked dynamically at runtime by Test-Prerequisites

<#
.SYNOPSIS
    Interactive user and device management tool for Entra ID, Active Directory,
    and Microsoft Defender for Endpoint (MDE).
    Supports multiple MDE sign-in methods: Interactive Browser (passkey/FIDO2/Hello),
    Device Code, and WAM (Windows SSO).

.DESCRIPTION
    Connects to Microsoft Graph (Entra ID), Active Directory, and the MDE API to:

    Main menu:
      [1] Search for a user   - view info, take user actions, drill into devices
      [2] Search for a device - search MDE-onboarded machines, take device actions
      [3] Connect to MDE      - connect or reconnect to Defender for Endpoint
      [4] View active incidents - list non-resolved MDE/Defender XDR incidents
      [5] Exit

    User actions:
      - Reset password (AD) + revoke Entra sessions
      - Require password change at next logon (AD)
      - Disable account (AD) + revoke Entra sessions
      - Revoke Entra sessions only
      - Unlock AD account
      - Select a linked device for device actions

    Device actions (from user context or device search):
      - Isolate device (MDE - Full)
      - Isolate device (MDE - Selective)
      - Release from isolation (MDE)

.NOTES
    Required Graph permissions (Delegated):
      - User.ReadWrite.All
      - Directory.ReadWrite.All
      - Device.Read.All

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
      - When connecting manually: credentials with the above permissions on
        the target domain, and network access to the domain controller.

    AD connectivity:
      - Tries automatic domain discovery first (works when domain-joined).
      - If discovery fails (non-domain-joined, DC unreachable, VPN, etc.),
        offers manual connection by specifying a DC FQDN/IP and credentials.
      - Manual connection uses $PSDefaultParameterValues so all AD cmdlets
        automatically inherit the -Server and -Credential settings.
      - On successful manual connection, saves DC address, domain name, and
        username to ad-connection.json alongside the script. On subsequent
        runs the saved settings are offered as a quick-connect option.
        Passwords are never saved to disk.

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
# FUNCTIONS -- CONNECTION
# ==============================================================================

function Connect-ToGraph {
    Write-Host "Checking for existing Microsoft Graph session..." -ForegroundColor Cyan

    $needsConnect = $true
    try {
        $context = Get-MgContext
        if ($null -ne $context -and ($context.Account -or $context.ClientId)) {
            $currentScopes = $context.Scopes
            $hasUserWrite  = ($currentScopes -contains "User.ReadWrite.All") -or ($currentScopes -contains "Directory.ReadWrite.All")
            $hasUserRead   = ($currentScopes -contains "User.Read.All") -or ($currentScopes -contains "Directory.Read.All") -or $hasUserWrite
            $hasDeviceRead = ($currentScopes -contains "Device.Read.All") -or ($currentScopes -contains "Directory.Read.All") -or ($currentScopes -contains "Directory.ReadWrite.All")

            if ($hasUserWrite -and $hasUserRead -and $hasDeviceRead) {
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
                if (-not $hasUserWrite)  { $missing += "User.ReadWrite.All or Directory.ReadWrite.All" }
                if (-not $hasDeviceRead) { $missing += "Device.Read.All or Directory.Read.All" }
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
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Device.Read.All" -ErrorAction Stop
        $ctx = Get-MgContext
        $id = if ($ctx.Account) { $ctx.Account } else { "AppId: $($ctx.ClientId)" }
        Write-Host "Connected to Graph as $id." -ForegroundColor Green
    }
}

function Connect-ToAD {
    <#
    .SYNOPSIS
        Connects to Active Directory. Tries automatic discovery first; if that
        fails, offers the user the option to specify a domain controller and
        credentials manually.
        Stores connection details via $PSDefaultParameterValues so every AD
        cmdlet in the session automatically inherits -Server / -Credential.
        Saves manual connection settings (DC, domain, username) to a JSON file
        alongside the script so they persist between runs. Passwords are never
        saved -- only the username is stored for the credential prompt.
    #>

    Write-Host "Checking Active Directory module and connectivity..." -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "ActiveDirectory module is not installed. Install RSAT or the AD PowerShell module."
        return $false
    }

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    # -- Helper: clear any previous AD default parameter values ----------------
    $adCmdlets = @(
        "Get-ADDomain", "Get-ADDomainController", "Get-ADUser",
        "Set-ADUser", "Set-ADAccountPassword",
        "Disable-ADAccount", "Unlock-ADAccount"
    )
    foreach ($cmd in $adCmdlets) {
        $PSDefaultParameterValues.Remove("${cmd}:Server")
        $PSDefaultParameterValues.Remove("${cmd}:Credential")
    }

    # -- Config file path (same folder as the script) --------------------------
    $adConfigPath = Join-Path $PSScriptRoot "ad-connection.json"

    # -- Attempt 1: automatic domain discovery ---------------------------------
    try {
        Get-ADDomainController -Discover -ErrorAction Stop | Out-Null
        $domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
        Write-Host "Connected to Active Directory domain: $domain" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  Auto-discovery failed: $_" -ForegroundColor Yellow
    }

    # -- Check for saved connection settings -----------------------------------
    $savedConfig = $null
    if (Test-Path $adConfigPath) {
        try {
            $savedConfig = Get-Content -Path $adConfigPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Host "  Could not read saved AD config: $_" -ForegroundColor DarkGray
            $savedConfig = $null
        }
    }

    # -- Attempt 2: let user specify a DC / domain manually --------------------
    Write-Host ""
    Write-Host "  Automatic domain discovery was unsuccessful." -ForegroundColor Yellow
    Write-Host "  This usually means the machine is not domain-joined," -ForegroundColor DarkGray
    Write-Host "  or the domain controller is not reachable on this network." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  You can connect manually by providing a domain controller" -ForegroundColor White
    Write-Host "  FQDN or IP address, and credentials for that domain." -ForegroundColor White
    Write-Host ""

    if ($savedConfig) {
        Write-Host "    [1] Use saved connection: $($savedConfig.Server)" -ForegroundColor Cyan
        Write-Host "        Domain: $($savedConfig.Domain) | User: $($savedConfig.Username)" -ForegroundColor DarkCyan
        Write-Host "    [2] Specify a new domain controller"
        Write-Host "    [3] Skip AD (Entra-only mode)"
    }
    else {
        Write-Host "    [1] Specify a domain controller manually"
        Write-Host "    [2] Skip AD (Entra-only mode)"
    }
    Write-Host ""

    $adChoice = Read-Host "  Select"

    # -- Route: use saved settings ---------------------------------------------
    if ($savedConfig -and $adChoice -eq "1") {
        $dcInput   = $savedConfig.Server
        $savedUser = $savedConfig.Username

        Write-Host ""
        Write-Host "  Using saved DC: $dcInput" -ForegroundColor White
        Write-Host "  Enter password for $savedUser" -ForegroundColor White
        Write-Host ""

        try {
            $adCred = Get-Credential -UserName $savedUser -Message "Active Directory credentials for $dcInput"
        }
        catch {
            Write-Host "  Credential prompt cancelled. Skipping AD." -ForegroundColor Yellow
            return $false
        }

        if (-not $adCred) {
            Write-Host "  No credentials provided. Skipping AD." -ForegroundColor Yellow
            return $false
        }

        Write-Host "  Testing connection to $dcInput..." -ForegroundColor Cyan
        try {
            $domain = (Get-ADDomain -Server $dcInput -Credential $adCred -ErrorAction Stop).DNSRoot
        }
        catch {
            Write-Error "Cannot connect to Active Directory via $dcInput : $_"
            Write-Host "  Saved settings may be outdated. Try option [2] to enter new details." -ForegroundColor Yellow
            return $false
        }

        # Inject defaults and return
        foreach ($cmd in $adCmdlets) {
            $PSDefaultParameterValues["${cmd}:Server"]     = $dcInput
            $PSDefaultParameterValues["${cmd}:Credential"] = $adCred
        }

        Write-Host "Connected to Active Directory domain: $domain  (via $dcInput)" -ForegroundColor Green
        return $true
    }

    # -- Route: skip AD --------------------------------------------------------
    $skipOption = if ($savedConfig) { "3" } else { "2" }
    if ($adChoice -eq $skipOption -or ($adChoice -ne "1" -and $adChoice -ne "2" -and -not $savedConfig)) {
        return $false
    }
    # If saved config exists and user chose "2", or no saved config and user chose "1",
    # fall through to the new-entry flow below.

    # -- Route: new manual entry -----------------------------------------------
    $dcInput = Read-Host "  Domain controller FQDN or IP (e.g. dc01.corp.contoso.com)"
    if ([string]::IsNullOrWhiteSpace($dcInput)) {
        Write-Host "  No server entered. Skipping AD." -ForegroundColor Yellow
        return $false
    }
    $dcInput = $dcInput.Trim()

    Write-Host ""
    Write-Host "  Enter credentials for the target domain." -ForegroundColor White
    Write-Host "  Use DOMAIN\\username or user@domain.com format." -ForegroundColor DarkGray
    Write-Host ""

    try {
        $adCred = Get-Credential -Message "Active Directory credentials for $dcInput"
    }
    catch {
        Write-Host "  Credential prompt cancelled. Skipping AD." -ForegroundColor Yellow
        return $false
    }

    if (-not $adCred) {
        Write-Host "  No credentials provided. Skipping AD." -ForegroundColor Yellow
        return $false
    }

    # Test the connection with the supplied server + credential
    Write-Host "  Testing connection to $dcInput..." -ForegroundColor Cyan
    try {
        $domain = (Get-ADDomain -Server $dcInput -Credential $adCred -ErrorAction Stop).DNSRoot
    }
    catch {
        Write-Error "Cannot connect to Active Directory via $dcInput : $_"
        return $false
    }

    # -- Success: inject -Server and -Credential into every AD cmdlet ----------
    foreach ($cmd in $adCmdlets) {
        $PSDefaultParameterValues["${cmd}:Server"]     = $dcInput
        $PSDefaultParameterValues["${cmd}:Credential"] = $adCred
    }

    # -- Save settings to JSON (no password -- only username) ------------------
    try {
        $configToSave = @{
            Server   = $dcInput
            Domain   = $domain
            Username = $adCred.UserName
            SavedAt  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
        $configToSave | ConvertTo-Json | Set-Content -Path $adConfigPath -Encoding UTF8 -Force
        Write-Host "  AD connection settings saved to: $adConfigPath" -ForegroundColor DarkGray
    }
    catch {
        Write-Host "  Could not save AD connection settings: $_" -ForegroundColor DarkGray
    }

    Write-Host "Connected to Active Directory domain: $domain  (via $dcInput)" -ForegroundColor Green
    return $true
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
                Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Device.Read.All" -ErrorAction Stop
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

    $result = Invoke-MDERequest -Method GET -Endpoint "/api/machines?`$filter=aadDeviceId eq '$AADDeviceId'"

    if ($result -and $result.value -and $result.value.Count -gt 0) {
        return $result.value[0]
    }

    return $null
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

    # -- Active Directory info -------------------------------------------------
    Write-Host ""
    Write-Host "  -- Active Directory --" -ForegroundColor Cyan

    $samAccount = ($upn -split '@')[0]

    try {
        $domainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName

        $adUser = Get-ADUser -Filter "SamAccountName -eq '$samAccount'" `
            -SearchBase $domainDN -SearchScope Subtree -Properties `
            Enabled, LockedOut, PasswordLastSet, PasswordExpired, `
            PasswordNeverExpires, LastLogonDate, LastBadPasswordAttempt, `
            BadPwdCount, Description, whenCreated, MemberOf -ErrorAction Stop

        if (-not $adUser) {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$upn'" `
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
            -Endpoint "/api/machineactions?`$filter=machineId eq '$($Machine.id)' and (type eq 'Isolate' or type eq 'Unisolate')&`$top=5&`$orderby=creationDateTimeUtc desc"

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
        Set-ADAccountPassword -Identity $ADUser.SamAccountName -NewPassword $securePassword -Reset -ErrorAction Stop
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
        return
    }

    Write-Host "  [2/3] Setting change password at next logon..." -ForegroundColor Cyan -NoNewline
    try {
        Set-ADUser -Identity $ADUser.SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
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
        Set-ADUser -Identity $ADUser.SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
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
            Disable-ADAccount -Identity $ADUser.SamAccountName -ErrorAction Stop
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

function Show-DeviceActionMenu {
    <#
    .SYNOPSIS
        Displays MDE device detail and an action menu for a single device.
        Used both from the user-device drill-down and from standalone device search.
        Returns when the user chooses to go back.
    #>
    param(
        $EntraDevice,   # May be $null if from device search
        $MDEMachine     # May be $null if device isn't in MDE
    )

    $backToParent = $false

    while (-not $backToParent) {

        # Resolve MDE machine if we have an Entra device but no MDE machine yet
        if (-not $MDEMachine -and $EntraDevice -and $EntraDevice.DeviceId -and $script:mdeAccessToken) {
            Write-Host "  Looking up device in MDE..." -ForegroundColor Cyan
            $MDEMachine = Get-MDEMachineByAADDeviceId -AADDeviceId $EntraDevice.DeviceId
        }

        if ($MDEMachine) {
            Show-MDEDeviceDetail -Machine $MDEMachine
        }
        elseif ($script:mdeAccessToken) {
            Write-Host ""
            Write-Host "  -- MDE Device Detail --" -ForegroundColor Magenta
            Write-Host "  Device not found in MDE (not onboarded or ID mismatch)." -ForegroundColor DarkGray
        }

        Write-Host ""
        Write-Host "  -- DEVICE ACTIONS --" -ForegroundColor Yellow

        if ($script:mdeAccessToken -and $MDEMachine) {
            Write-Host "    [1] Isolate device (Full)"
            Write-Host "    [2] Isolate device (Selective)"
            Write-Host "    [3] Release from isolation"
            Write-Host "    [4] Refresh"
            Write-Host "    [5] Back"
        }
        elseif (-not $script:mdeAccessToken) {
            Write-Host "    MDE is not connected. Isolation actions unavailable." -ForegroundColor DarkGray
            Write-Host "    [4] Refresh"
            Write-Host "    [5] Back"
        }
        else {
            Write-Host "    Device not found in MDE. Isolation actions unavailable." -ForegroundColor DarkGray
            Write-Host "    [4] Refresh"
            Write-Host "    [5] Back"
        }
        Write-Host ""

        $deviceAction = Read-Host "  Action"

        switch ($deviceAction) {
            "1" {
                if ($script:mdeAccessToken -and $MDEMachine) {
                    Invoke-IsolateDevice -MachineId $MDEMachine.id -MachineName $MDEMachine.computerDnsName -IsolationType "Full"
                } else { Write-Host "  Action unavailable." -ForegroundColor Yellow }
            }
            "2" {
                if ($script:mdeAccessToken -and $MDEMachine) {
                    Invoke-IsolateDevice -MachineId $MDEMachine.id -MachineName $MDEMachine.computerDnsName -IsolationType "Selective"
                } else { Write-Host "  Action unavailable." -ForegroundColor Yellow }
            }
            "3" {
                if ($script:mdeAccessToken -and $MDEMachine) {
                    Invoke-UnisolateDevice -MachineId $MDEMachine.id -MachineName $MDEMachine.computerDnsName
                } else { Write-Host "  Action unavailable." -ForegroundColor Yellow }
            }
            "4" {
                if ($MDEMachine) {
                    $refreshed = Invoke-MDERequest -Method GET -Endpoint "/api/machines/$($MDEMachine.id)"
                    if ($refreshed) { $MDEMachine = $refreshed }
                }
            }
            "5" {
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

# ==============================================================================
# FUNCTIONS -- MDE INCIDENTS
# ==============================================================================

function Show-MDEIncidents {
    <#
    .SYNOPSIS
        Lists active (non-resolved) incidents from the MDE / Defender XDR Incidents API.
        GET /api/incidents?$filter=status eq 'Active'
        After resolving an incident, automatically refreshes the list.
    #>

    $refreshList = $true

    while ($refreshList) {
        $refreshList = $false

        Write-Host ""
        Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  ACTIVE MDE INCIDENTS" -ForegroundColor Cyan
        Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Fetching active incidents..." -ForegroundColor DarkCyan

        $result = Invoke-MDERequest -Method GET `
            -Endpoint "/api/incidents?`$filter=status eq 'Active'&`$top=50"

        if (-not $result -or -not $result.value -or $result.value.Count -eq 0) {
            Write-Host "  No active incidents found." -ForegroundColor Green
            return
        }

        $incidents = @($result.value)

        # Sort: High → Medium → Low → Informational
        $severityOrder = @{ "High" = 0; "Medium" = 1; "Low" = 2; "Informational" = 3 }
        $incidents = $incidents | Sort-Object {
            if ($severityOrder.ContainsKey($_.severity)) { $severityOrder[$_.severity] } else { 99 }
        }, { $_.lastUpdateTime } -Descending

        Write-Host ""
        Write-Host "  Found $($incidents.Count) active incident(s):" -ForegroundColor Yellow
        Write-Host ""

        $i = 1
        foreach ($inc in $incidents) {
            $sevColour = switch ($inc.severity) {
                "High"          { "Red" }
                "Medium"        { "Yellow" }
                "Low"           { "Cyan" }
                "Informational" { "DarkGray" }
                default         { "White" }
            }

            $incName     = if ($inc.incidentName)  { $inc.incidentName }  else { "(unnamed)" }
            $incId       = $inc.incidentId
            $incSev      = if ($inc.severity)      { $inc.severity }      else { "--" }
            $alertCount  = if ($inc.alerts)         { $inc.alerts.Count }  else { 0 }
            $assignee    = if ($inc.assignedTo)     { $inc.assignedTo }    else { "Unassigned" }
            $created     = if ($inc.createdTime)    { try { ([datetime]$inc.createdTime).ToString("yyyy-MM-dd HH:mm") } catch { $inc.createdTime } } else { "--" }
            $updated     = if ($inc.lastUpdateTime) { try { ([datetime]$inc.lastUpdateTime).ToString("yyyy-MM-dd HH:mm") } catch { $inc.lastUpdateTime } } else { "--" }
            $classif     = if ($inc.classification -and $inc.classification -ne "Unknown") { $inc.classification } else { "" }

            Write-Host "    [$i] " -ForegroundColor White -NoNewline
            Write-Host "ID $incId " -ForegroundColor DarkGray -NoNewline
            Write-Host "$incName" -ForegroundColor White
            Write-Host "        Severity: " -NoNewline
            Write-Host "$incSev" -ForegroundColor $sevColour -NoNewline
            Write-Host "  |  Alerts: $alertCount  |  Assigned: $assignee" -ForegroundColor DarkCyan
            Write-Host "        Created: $created  |  Updated: $updated" -ForegroundColor DarkGray -NoNewline
            if ($classif) {
                Write-Host "  |  Classification: $classif" -ForegroundColor DarkGray
            } else {
                Write-Host ""
            }

            Write-Host ""
            $i++
        }

        # -- Detail drill-down loop ------------------------------------------------
        while ($true) {
            Write-Host "  Enter an incident number to view details and actions, or type 'BACK' to return." -ForegroundColor DarkGray
            Write-Host ""
            $pick = Read-Host "  Select"

            if ([string]::IsNullOrWhiteSpace($pick) -or $pick -eq "BACK" -or $pick -eq "back") {
                break
            }

            $pickIdx = 0
            if (-not [int]::TryParse($pick, [ref]$pickIdx) -or $pickIdx -lt 1 -or $pickIdx -gt $incidents.Count) {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
                continue
            }

            $selInc = $incidents[$pickIdx - 1]

            # -- Inner action loop for the selected incident -----------------------
            $backToList = $false
            while (-not $backToList) {

                # Re-fetch the incident to get fresh state
                $refreshed = Invoke-MDERequest -Method GET -Endpoint "/api/incidents/$($selInc.incidentId)"
                if ($refreshed) { $selInc = $refreshed }

            Write-Host ""
            Write-Host "  ========================================================" -ForegroundColor White
            Write-Host "  INCIDENT $($selInc.incidentId): $($selInc.incidentName)" -ForegroundColor Cyan
            Write-Host "  ========================================================" -ForegroundColor White

            # Show incident metadata
            $incAssign = if ($selInc.assignedTo) { $selInc.assignedTo } else { "Unassigned" }
            $incStatus = if ($selInc.status)     { $selInc.status }     else { "--" }
            $incDeterm = if ($selInc.determination -and $selInc.determination -ne "NotAvailable") { $selInc.determination } else { "--" }
            $incClass  = if ($selInc.classification -and $selInc.classification -ne "Unknown") { $selInc.classification } else { "--" }

            $statusColour = switch ($incStatus) {
                "Active"     { "Red" }
                "InProgress" { "Yellow" }
                "Resolved"   { "Green" }
                default      { "White" }
            }

            Write-Host "  Severity:       " -NoNewline
            $sevC = switch ($selInc.severity) { "High" { "Red" } "Medium" { "Yellow" } "Low" { "Cyan" } default { "White" } }
            Write-Host "$($selInc.severity)" -ForegroundColor $sevC
            Write-Host "  Status:         " -NoNewline
            Write-Host "$incStatus" -ForegroundColor $statusColour
            Write-Host "  Assigned to:    $incAssign"
            Write-Host "  Classification: $incClass"
            Write-Host "  Determination:  $incDeterm"

            if ($selInc.tags -and $selInc.tags.Count -gt 0) {
                Write-Host "  Tags:           $($selInc.tags -join ', ')" -ForegroundColor DarkCyan
            }

            # Show alerts belonging to this incident
            $alerts = @($selInc.alerts)
            if ($alerts.Count -eq 0) {
                Write-Host ""
                Write-Host "  No alerts embedded in this incident." -ForegroundColor DarkGray
            } else {
                Write-Host ""
                Write-Host "  -- Alerts ($($alerts.Count)) --" -ForegroundColor DarkCyan

                foreach ($alert in $alerts) {
                    $aSev = if ($alert.severity) { $alert.severity } else { "--" }
                    $aSevColour = switch ($aSev) {
                        "High"          { "Red" }
                        "Medium"        { "Yellow" }
                        "Low"           { "Cyan" }
                        "Informational" { "DarkGray" }
                        default         { "White" }
                    }
                    $aStatus = if ($alert.status) { $alert.status } else { "--" }
                    $aTitle  = if ($alert.title)  { $alert.title }  else { "(no title)" }
                    $aCat    = if ($alert.category) { $alert.category } else { "" }
                    $aSource = if ($alert.serviceSource) { $alert.serviceSource } else { if ($alert.detectionSource) { $alert.detectionSource } else { "" } }

                    Write-Host "    - " -NoNewline
                    Write-Host "[$aSev]" -ForegroundColor $aSevColour -NoNewline
                    Write-Host " $aTitle" -ForegroundColor White -NoNewline
                    Write-Host "  ($aStatus)" -ForegroundColor DarkGray

                    $metaParts = @()
                    if ($aCat)    { $metaParts += "Category: $aCat" }
                    if ($aSource) { $metaParts += "Source: $aSource" }
                    if ($alert.alertId) { $metaParts += "AlertID: $($alert.alertId)" }
                    if ($metaParts.Count -gt 0) {
                        Write-Host "      $($metaParts -join '  |  ')" -ForegroundColor DarkGray
                    }

                    # Show devices involved in the alert
                    if ($alert.devices -and $alert.devices.Count -gt 0) {
                        foreach ($dev in $alert.devices) {
                            $devName = if ($dev.deviceDnsName) { $dev.deviceDnsName } else { $dev.DeviceId }
                            $devOS   = if ($dev.osPlatform) { " ($($dev.osPlatform))" } else { "" }
                            Write-Host "      Device: $devName$devOS" -ForegroundColor DarkGray
                        }
                    }
                }
            }

            # Show comments if any
            if ($selInc.comments -and $selInc.comments.Count -gt 0) {
                Write-Host ""
                Write-Host "  -- Comments --" -ForegroundColor DarkCyan
                foreach ($comment in $selInc.comments) {
                    $cBy   = if ($comment.createdBy) { $comment.createdBy } else { "Unknown" }
                    $cTime = if ($comment.createdTime) { try { ([datetime]$comment.createdTime).ToString("yyyy-MM-dd HH:mm") } catch { $comment.createdTime } } else { "" }
                    Write-Host "    [$cBy - $cTime]" -ForegroundColor DarkGray
                    Write-Host "    $($comment.comment)"
                }
            }

            # -- Action menu ---------------------------------------------------
            Write-Host ""
            Write-Host "  -- Actions --" -ForegroundColor Cyan
            Write-Host "    [1] Assign to myself"
            Write-Host "    [2] Assign to someone else"
            Write-Host "    [3] Update status"
            Write-Host "    [4] Close incident (Resolve)"
            if ($alerts.Count -gt 0) {
                Write-Host "    [5] View alert details ($($alerts.Count) alert$(if ($alerts.Count -ne 1) {'s'}))"
            } else {
                Write-Host "    [5] View alert details" -ForegroundColor DarkGray
            }
            Write-Host "    [6] Back to incident list"
            Write-Host ""

            $actionPick = Read-Host "  Action"

            switch ($actionPick) {

                # ==============================================================
                # [1] ASSIGN TO MYSELF
                # ==============================================================
                "1" {
                    $myUpn = $null
                    try {
                        $ctx = Get-MgContext
                        if ($ctx -and $ctx.Account) { $myUpn = $ctx.Account }
                    } catch {}

                    if (-not $myUpn) {
                        Write-Host "  Could not determine your UPN from the current Graph session." -ForegroundColor Yellow
                        $myUpn = Read-Host "  Enter your email / UPN"
                        if ([string]::IsNullOrWhiteSpace($myUpn)) {
                            Write-Host "  Cancelled." -ForegroundColor DarkGray
                            continue
                        }
                    }

                    Write-Host "  Assigning incident $($selInc.incidentId) to $myUpn..." -ForegroundColor Cyan
                    $updateBody = @{ assignedTo = $myUpn }

                    $commentText = Read-Host "  Add a comment (optional, press Enter to skip)"
                    if (-not [string]::IsNullOrWhiteSpace($commentText)) {
                        $updateBody.comment = $commentText
                    }

                    $result = Invoke-MDERequest -Method PATCH `
                        -Endpoint "/api/incidents/$($selInc.incidentId)" -Body $updateBody

                    if ($result) {
                        Write-Host "  Incident assigned to $myUpn." -ForegroundColor Green
                    } else {
                        Write-Host "  Failed to assign incident." -ForegroundColor Red
                    }
                }

                # ==============================================================
                # [2] ASSIGN TO SOMEONE ELSE
                # ==============================================================
                "2" {
                    $targetUpn = Read-Host "  Enter the assignee's email / UPN"
                    if ([string]::IsNullOrWhiteSpace($targetUpn)) {
                        Write-Host "  Cancelled." -ForegroundColor DarkGray
                        continue
                    }

                    Write-Host "  Assigning incident $($selInc.incidentId) to $targetUpn..." -ForegroundColor Cyan
                    $updateBody = @{ assignedTo = $targetUpn }

                    $commentText = Read-Host "  Add a comment (optional, press Enter to skip)"
                    if (-not [string]::IsNullOrWhiteSpace($commentText)) {
                        $updateBody.comment = $commentText
                    }

                    $result = Invoke-MDERequest -Method PATCH `
                        -Endpoint "/api/incidents/$($selInc.incidentId)" -Body $updateBody

                    if ($result) {
                        Write-Host "  Incident assigned to $targetUpn." -ForegroundColor Green
                    } else {
                        Write-Host "  Failed to assign incident." -ForegroundColor Red
                    }
                }

                # ==============================================================
                # [3] UPDATE STATUS
                # ==============================================================
                "3" {
                    Write-Host ""
                    Write-Host "  Set status to:" -ForegroundColor Cyan
                    Write-Host "    [1] Active"
                    Write-Host "    [2] In Progress"
                    Write-Host "    [3] Cancel"
                    Write-Host ""
                    $statusPick = Read-Host "  Select"

                    $newStatus = switch ($statusPick) {
                        "1" { "Active" }
                        "2" { "InProgress" }
                        default { $null }
                    }

                    if (-not $newStatus) {
                        Write-Host "  Cancelled." -ForegroundColor DarkGray
                        continue
                    }

                    Write-Host "  Setting status to '$newStatus'..." -ForegroundColor Cyan
                    $updateBody = @{ status = $newStatus }

                    $commentText = Read-Host "  Add a comment (optional, press Enter to skip)"
                    if (-not [string]::IsNullOrWhiteSpace($commentText)) {
                        $updateBody.comment = $commentText
                    }

                    $result = Invoke-MDERequest -Method PATCH `
                        -Endpoint "/api/incidents/$($selInc.incidentId)" -Body $updateBody

                    if ($result) {
                        Write-Host "  Status updated to '$newStatus'." -ForegroundColor Green
                    } else {
                        Write-Host "  Failed to update status." -ForegroundColor Red
                    }
                }

                # ==============================================================
                # [4] CLOSE INCIDENT (RESOLVE)
                # ==============================================================
                "4" {
                    Write-Host ""
                    Write-Host "  Classification:" -ForegroundColor Cyan
                    Write-Host "    [1] True Positive"
                    Write-Host "    [2] Informational / Expected Activity"
                    Write-Host "    [3] False Positive"
                    Write-Host "    [4] Cancel"
                    Write-Host ""
                    $classPick = Read-Host "  Select"

                    $classification  = $null
                    $determinations  = $null

                    switch ($classPick) {
                        "1" {
                            $classification = "TruePositive"
                            $determinations = [ordered]@{
                                "1" = @{ Label = "Multi-staged attack";     Value = "MultiStagedAttack" }
                                "2" = @{ Label = "Malicious user activity"; Value = "MaliciousUserActivity" }
                                "3" = @{ Label = "Compromised account";     Value = "CompromisedAccount" }
                                "4" = @{ Label = "Malware";                 Value = "Malware" }
                                "5" = @{ Label = "Phishing";                Value = "Phishing" }
                                "6" = @{ Label = "Unwanted software";       Value = "UnwantedSoftware" }
                                "7" = @{ Label = "Other";                   Value = "Other" }
                            }
                        }
                        "2" {
                            $classification = "InformationalExpectedActivity"
                            $determinations = [ordered]@{
                                "1" = @{ Label = "Security test";           Value = "SecurityTesting" }
                                "2" = @{ Label = "Line-of-business app";    Value = "LineOfBusinessApplication" }
                                "3" = @{ Label = "Confirmed activity";      Value = "ConfirmedActivity" }
                                "4" = @{ Label = "Other";                   Value = "Other" }
                            }
                        }
                        "3" {
                            $classification = "FalsePositive"
                            $determinations = [ordered]@{
                                "1" = @{ Label = "Not malicious";              Value = "Clean" }
                                "2" = @{ Label = "Not enough data to validate"; Value = "NoEnoughDataToValidate" }
                                "3" = @{ Label = "Other";                       Value = "Other" }
                            }
                        }
                        default {
                            Write-Host "  Cancelled." -ForegroundColor DarkGray
                            continue
                        }
                    }

                    # Prompt for determination
                    Write-Host ""
                    Write-Host "  Determination:" -ForegroundColor Cyan
                    foreach ($key in $determinations.Keys) {
                        Write-Host "    [$key] $($determinations[$key].Label)"
                    }
                    $cancelKey = ([int]($determinations.Keys | Select-Object -Last 1) + 1).ToString()
                    Write-Host "    [$cancelKey] Cancel"
                    Write-Host ""
                    $determPick = Read-Host "  Select"

                    if (-not $determinations.Contains($determPick)) {
                        Write-Host "  Cancelled." -ForegroundColor DarkGray
                        continue
                    }

                    $determination = $determinations[$determPick].Value

                    # Confirmation
                    Write-Host ""
                    Write-Host "  You are about to RESOLVE incident $($selInc.incidentId):" -ForegroundColor Yellow
                    Write-Host "    Classification: $classification"
                    Write-Host "    Determination:  $determination ($($determinations[$determPick].Label))"
                    Write-Host ""
                    $confirm = Read-Host "  Proceed? (Y/N)"

                    if ($confirm -ne "Y" -and $confirm -ne "y") {
                        Write-Host "  Cancelled." -ForegroundColor DarkGray
                        continue
                    }

                    $updateBody = @{
                        status         = "Resolved"
                        classification = $classification
                        determination  = $determination
                    }

                    $commentText = Read-Host "  Add a closing comment (optional, press Enter to skip)"
                    if (-not [string]::IsNullOrWhiteSpace($commentText)) {
                        $updateBody.comment = $commentText
                    }

                    Write-Host "  Resolving incident $($selInc.incidentId)..." -ForegroundColor Cyan
                    $result = Invoke-MDERequest -Method PATCH `
                        -Endpoint "/api/incidents/$($selInc.incidentId)" -Body $updateBody

                    if ($result) {
                        Write-Host "  Incident $($selInc.incidentId) resolved." -ForegroundColor Green
                        Write-Host ""
                        Write-Host "  Returning to incident list..." -ForegroundColor DarkCyan
                        $backToList  = $true
                        $refreshList = $true
                    } else {
                        Write-Host "  Failed to resolve incident." -ForegroundColor Red
                    }
                }

                # ==============================================================
                # [5] VIEW ALERT DETAILS
                # ==============================================================
                "5" {
                    if ($alerts.Count -eq 0) {
                        Write-Host "  No alerts on this incident." -ForegroundColor Yellow
                        continue
                    }

                    $selectedAlert = $null

                    if ($alerts.Count -eq 1) {
                        $selectedAlert = $alerts[0]
                    }
                    else {
                        Write-Host ""
                        Write-Host "  Select an alert to view:" -ForegroundColor Cyan
                        Write-Host ""
                        $ai = 1
                        foreach ($a in $alerts) {
                            $aTitle = if ($a.title) { $a.title } else { "(no title)" }
                            $aSev   = if ($a.severity) { $a.severity } else { "--" }
                            $aSevC  = switch ($aSev) { "High" { "Red" } "Medium" { "Yellow" } "Low" { "Cyan" } "Informational" { "DarkGray" } default { "White" } }
                            Write-Host "    [$ai] " -NoNewline -ForegroundColor White
                            Write-Host "[$aSev]" -ForegroundColor $aSevC -NoNewline
                            Write-Host " $aTitle" -ForegroundColor White
                            $ai++
                        }
                        Write-Host "    [$ai] Cancel"
                        Write-Host ""
                        $alertPick = Read-Host "  Select"
                        $alertIdx  = 0
                        if (-not [int]::TryParse($alertPick, [ref]$alertIdx) -or $alertIdx -lt 1 -or $alertIdx -gt $alerts.Count) {
                            Write-Host "  Cancelled." -ForegroundColor DarkGray
                            continue
                        }
                        $selectedAlert = $alerts[$alertIdx - 1]
                    }

                    # -- Display full alert details --------------------------------
                    Write-Host ""
                    Write-Host "  --------------------------------------------------------" -ForegroundColor DarkGray
                    Write-Host "  ALERT DETAILS" -ForegroundColor Cyan
                    Write-Host "  --------------------------------------------------------" -ForegroundColor DarkGray

                    $dTitle  = if ($selectedAlert.title)    { $selectedAlert.title }    else { "(no title)" }
                    $dId     = if ($selectedAlert.alertId)  { $selectedAlert.alertId }  else { "--" }
                    $dSev    = if ($selectedAlert.severity) { $selectedAlert.severity } else { "--" }
                    $dSevC   = switch ($dSev) { "High" { "Red" } "Medium" { "Yellow" } "Low" { "Cyan" } "Informational" { "DarkGray" } default { "White" } }
                    $dStatus = if ($selectedAlert.status)   { $selectedAlert.status }   else { "--" }

                    Write-Host "  Title:          $dTitle" -ForegroundColor White
                    Write-Host "  Alert ID:       $dId" -ForegroundColor DarkGray
                    Write-Host "  Severity:       " -NoNewline
                    Write-Host "$dSev" -ForegroundColor $dSevC
                    Write-Host "  Status:         $dStatus"

                    if ($selectedAlert.category) {
                        Write-Host "  Category:       $($selectedAlert.category)"
                    }
                    if ($selectedAlert.serviceSource) {
                        Write-Host "  Service source: $($selectedAlert.serviceSource)"
                    }
                    if ($selectedAlert.detectionSource) {
                        Write-Host "  Detection src:  $($selectedAlert.detectionSource)"
                    }
                    if ($selectedAlert.classification -and $selectedAlert.classification -ne "Unknown") {
                        Write-Host "  Classification: $($selectedAlert.classification)"
                    }
                    if ($selectedAlert.determination -and $selectedAlert.determination -ne "NotAvailable") {
                        Write-Host "  Determination:  $($selectedAlert.determination)"
                    }
                    if ($selectedAlert.assignedTo) {
                        Write-Host "  Assigned to:    $($selectedAlert.assignedTo)"
                    }

                    # Timestamps
                    $dCreated  = if ($selectedAlert.createdTime)       { try { ([datetime]$selectedAlert.createdTime).ToString("yyyy-MM-dd HH:mm:ss") }       catch { $selectedAlert.createdTime } }       else { $null }
                    $dUpdated  = if ($selectedAlert.lastUpdatedTime)   { try { ([datetime]$selectedAlert.lastUpdatedTime).ToString("yyyy-MM-dd HH:mm:ss") }   catch { $selectedAlert.lastUpdatedTime } }   else { $null }
                    $dResolved = if ($selectedAlert.resolvedTime)      { try { ([datetime]$selectedAlert.resolvedTime).ToString("yyyy-MM-dd HH:mm:ss") }      catch { $selectedAlert.resolvedTime } }      else { $null }
                    $dFirst    = if ($selectedAlert.firstActivity)     { try { ([datetime]$selectedAlert.firstActivity).ToString("yyyy-MM-dd HH:mm:ss") }     catch { $selectedAlert.firstActivity } }     else { $null }
                    $dLast     = if ($selectedAlert.lastActivity)      { try { ([datetime]$selectedAlert.lastActivity).ToString("yyyy-MM-dd HH:mm:ss") }      catch { $selectedAlert.lastActivity } }      else { $null }

                    Write-Host ""
                    Write-Host "  -- Timeline --" -ForegroundColor DarkCyan
                    if ($dCreated)  { Write-Host "  Created:        $dCreated" -ForegroundColor DarkGray }
                    if ($dFirst)    { Write-Host "  First activity: $dFirst"   -ForegroundColor DarkGray }
                    if ($dLast)     { Write-Host "  Last activity:  $dLast"    -ForegroundColor DarkGray }
                    if ($dUpdated)  { Write-Host "  Last updated:   $dUpdated" -ForegroundColor DarkGray }
                    if ($dResolved) { Write-Host "  Resolved:       $dResolved" -ForegroundColor DarkGray }

                    # Description / recommended actions
                    if ($selectedAlert.description) {
                        Write-Host ""
                        Write-Host "  -- Description --" -ForegroundColor DarkCyan
                        Write-Host "  $($selectedAlert.description)" -ForegroundColor White
                    }
                    if ($selectedAlert.recommendedAction) {
                        Write-Host ""
                        Write-Host "  -- Recommended Action --" -ForegroundColor DarkCyan
                        Write-Host "  $($selectedAlert.recommendedAction)" -ForegroundColor White
                    }

                    # Devices
                    if ($selectedAlert.devices -and $selectedAlert.devices.Count -gt 0) {
                        Write-Host ""
                        Write-Host "  -- Devices ($($selectedAlert.devices.Count)) --" -ForegroundColor DarkCyan
                        foreach ($dev in $selectedAlert.devices) {
                            $devName  = if ($dev.deviceDnsName) { $dev.deviceDnsName } elseif ($dev.aadDeviceId) { $dev.aadDeviceId } else { $dev.deviceId }
                            $devOS    = if ($dev.osPlatform) { $dev.osPlatform } else { "" }
                            $devVer   = if ($dev.version)    { $dev.version }    else { "" }
                            $devHealth = if ($dev.healthStatus) { $dev.healthStatus } else { "" }
                            $devRisk   = if ($dev.riskScore)   { $dev.riskScore }   else { "" }
                            $devIp     = if ($dev.lastIpAddress) { $dev.lastIpAddress } elseif ($dev.lastExternalIpAddress) { $dev.lastExternalIpAddress } else { "" }

                            Write-Host "    Device:   $devName" -ForegroundColor White
                            $devMeta = @()
                            if ($devOS)     { $devMeta += "OS: $devOS" }
                            if ($devVer)    { $devMeta += "Ver: $devVer" }
                            if ($devHealth) { $devMeta += "Health: $devHealth" }
                            if ($devRisk)   { $devMeta += "Risk: $devRisk" }
                            if ($devIp)     { $devMeta += "IP: $devIp" }
                            if ($devMeta.Count -gt 0) {
                                Write-Host "              $($devMeta -join '  |  ')" -ForegroundColor DarkGray
                            }

                            # Show logged-on users for the device
                            if ($dev.loggedOnUsers -and $dev.loggedOnUsers.Count -gt 0) {
                                $userNames = ($dev.loggedOnUsers | ForEach-Object {
                                    if ($_.accountName -and $_.domainName) { "$($_.domainName)\$($_.accountName)" }
                                    elseif ($_.accountName) { $_.accountName }
                                }) -join ", "
                                if ($userNames) {
                                    Write-Host "              Logged-on: $userNames" -ForegroundColor DarkGray
                                }
                            }
                        }
                    }

                    # Entities (users, IPs, files, etc.)
                    if ($selectedAlert.entities -and $selectedAlert.entities.Count -gt 0) {
                        Write-Host ""
                        Write-Host "  -- Entities ($($selectedAlert.entities.Count)) --" -ForegroundColor DarkCyan
                        foreach ($ent in $selectedAlert.entities) {
                            $entType = if ($ent.entityType) { $ent.entityType } else { "Unknown" }

                            switch ($entType) {
                                "User" {
                                    $entName = if ($ent.userPrincipalName) { $ent.userPrincipalName }
                                              elseif ($ent.accountName -and $ent.domainName) { "$($ent.domainName)\$($ent.accountName)" }
                                              elseif ($ent.accountName) { $ent.accountName }
                                              else { "(unknown user)" }
                                    Write-Host "    User:     $entName" -ForegroundColor White
                                }
                                "Ip" {
                                    $entIp = if ($ent.ipAddress) { $ent.ipAddress } else { "(unknown)" }
                                    Write-Host "    IP:       $entIp" -ForegroundColor White
                                }
                                "Url" {
                                    $entUrl = if ($ent.url) { $ent.url } else { "(unknown)" }
                                    Write-Host "    URL:      $entUrl" -ForegroundColor White
                                }
                                "File" {
                                    $entFile = if ($ent.fileName) { $ent.fileName } else { "(unknown)" }
                                    $entHash = if ($ent.sha256) { $ent.sha256 } elseif ($ent.sha1) { $ent.sha1 } else { "" }
                                    Write-Host "    File:     $entFile" -ForegroundColor White
                                    if ($entHash) {
                                        Write-Host "              Hash: $entHash" -ForegroundColor DarkGray
                                    }
                                }
                                "Process" {
                                    $entProc = if ($ent.fileName) { $ent.fileName } elseif ($ent.processId) { "PID $($ent.processId)" } else { "(unknown)" }
                                    $entCmd  = if ($ent.processCommandLine) { $ent.processCommandLine } else { "" }
                                    Write-Host "    Process:  $entProc" -ForegroundColor White
                                    if ($ent.processId) {
                                        Write-Host "              PID: $($ent.processId)" -ForegroundColor DarkGray
                                    }
                                    # Process creation time
                                    if ($ent.processCreationTime -and "$($ent.processCreationTime)" -ne "") {
                                        $procTimeStr = "$($ent.processCreationTime)"
                                        $procTimeDisplay = try { ([datetime]::Parse($procTimeStr)).ToString("yyyy-MM-dd HH:mm:ss") } catch { $procTimeStr }
                                        Write-Host "              Time: $procTimeDisplay" -ForegroundColor DarkGray
                                    }
                                    if ($entCmd) {
                                        $displayCmd = if ($entCmd.Length -gt 120) { $entCmd.Substring(0, 117) + "..." } else { $entCmd }
                                        Write-Host "              Cmd: $displayCmd" -ForegroundColor DarkGray
                                    }
                                    # Account
                                    $acctDisplay = if ($ent.accountName -and $ent.domainName) { "$($ent.domainName)\$($ent.accountName)" }
                                                   elseif ($ent.accountName) { $ent.accountName }
                                                   else { "--" }
                                    Write-Host "              Account: $acctDisplay" -ForegroundColor DarkGray
                                    # Verdict
                                    $verdictText   = if ($ent.verdict) { $ent.verdict } else { "--" }
                                    $verdictColour = switch ($verdictText) { "Malicious" { "Red" } "Suspicious" { "Yellow" } "Clean" { "Green" } default { "DarkGray" } }
                                    Write-Host "              Verdict: " -NoNewline -ForegroundColor DarkGray
                                    Write-Host "$verdictText" -ForegroundColor $verdictColour
                                    # File hashes
                                    if ($ent.sha256) { Write-Host "              SHA256: $($ent.sha256)" -ForegroundColor DarkGray }
                                    elseif ($ent.sha1) { Write-Host "              SHA1: $($ent.sha1)" -ForegroundColor DarkGray }
                                    # Parent process
                                    if ($ent.parentProcessId) {
                                        Write-Host "              Parent PID: $($ent.parentProcessId)" -ForegroundColor DarkGray
                                    }
                                    if ($ent.parentProcessCreationTime -and "$($ent.parentProcessCreationTime)" -ne "") {
                                        $parentTimeStr = "$($ent.parentProcessCreationTime)"
                                        $parentTimeDisplay = try { ([datetime]::Parse($parentTimeStr)).ToString("yyyy-MM-dd HH:mm:ss") } catch { $parentTimeStr }
                                        Write-Host "              Parent time: $parentTimeDisplay" -ForegroundColor DarkGray
                                    }
                                }
                                "MailMessage" {
                                    $entSubj   = if ($ent.subject) { $ent.subject } else { "(no subject)" }
                                    $entSender = if ($ent.sender)  { $ent.sender }  else { "" }
                                    Write-Host "    Email:    $entSubj" -ForegroundColor White
                                    if ($entSender) {
                                        Write-Host "              From: $entSender" -ForegroundColor DarkGray
                                    }
                                }
                                "Mailbox" {
                                    $entMbx = if ($ent.mailboxPrimaryAddress) { $ent.mailboxPrimaryAddress }
                                              elseif ($ent.mailboxDisplayName) { $ent.mailboxDisplayName }
                                              else { "(unknown)" }
                                    Write-Host "    Mailbox:  $entMbx" -ForegroundColor White
                                }
                                "Registry" {
                                    $entKey = if ($ent.registryKey) { $ent.registryKey } else { "(unknown)" }
                                    $entVal = if ($ent.registryValueName) { $ent.registryValueName } else { "" }
                                    Write-Host "    Registry: $entKey" -ForegroundColor White
                                    if ($entVal) {
                                        Write-Host "              Value: $entVal" -ForegroundColor DarkGray
                                    }
                                }
                                default {
                                    Write-Host "    [$entType]: " -ForegroundColor White -NoNewline
                                    # Try common name fields
                                    $entLabel = if ($ent.fileName) { $ent.fileName }
                                                elseif ($ent.accountName) { $ent.accountName }
                                                elseif ($ent.ipAddress) { $ent.ipAddress }
                                                elseif ($ent.url) { $ent.url }
                                                else { "(details not available)" }
                                    Write-Host "$entLabel" -ForegroundColor DarkGray
                                }
                            }
                        }
                    }

                    # Investigation state
                    if ($selectedAlert.investigationState) {
                        Write-Host ""
                        Write-Host "  Investigation:  $($selectedAlert.investigationState)" -ForegroundColor DarkCyan
                    }
                    if ($selectedAlert.investigationId) {
                        Write-Host "  Investigation ID: $($selectedAlert.investigationId)" -ForegroundColor DarkGray
                    }

                    Write-Host ""
                    Write-Host "  --------------------------------------------------------" -ForegroundColor DarkGray
                    Read-Host "  Press Enter to return to incident actions"
                }

                # ==============================================================
                # [6] BACK TO INCIDENT LIST
                # ==============================================================
                "6" {
                    $backToList = $true
                }

                default {
                    Write-Host "  Invalid option." -ForegroundColor Yellow
                }

            } # end action switch
        } # end inner action loop

        # If an incident was resolved, break the drill-down loop to refresh the list
        if ($refreshList) { break }

    } # end outer selection loop
    } # end refreshList loop
}

# -- Main loop -----------------------------------------------------------------
$exitScript = $false

while (-not $exitScript) {
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host "  MAIN MENU" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkGray

    # -- Incident summary (if MDE connected) -----------------------------------
    if ($mdeConnected) {
        try {
            $incSummary = Invoke-MDERequest -Method GET `
                -Endpoint "/api/incidents?`$filter=status eq 'Active'&`$top=50"

            if ($incSummary -and $incSummary.value -and $incSummary.value.Count -gt 0) {
                $activeIncs = @($incSummary.value)
                $totalActive = $activeIncs.Count

                # Group alerts across all incidents by category
                $catCounts = @{}
                $sevCounts = @{ "High" = 0; "Medium" = 0; "Low" = 0; "Informational" = 0 }
                foreach ($inc in $activeIncs) {
                    if ($inc.alerts) {
                        foreach ($al in $inc.alerts) {
                            $cat = if ($al.category) { $al.category } else { "Uncategorised" }
                            if ($catCounts.ContainsKey($cat)) { $catCounts[$cat]++ } else { $catCounts[$cat] = 1 }
                        }
                    }
                    # Severity counts at incident level
                    $sev = if ($inc.severity) { $inc.severity } else { "Informational" }
                    if ($sevCounts.ContainsKey($sev)) { $sevCounts[$sev]++ } else { $sevCounts[$sev] = 1 }
                }

                Write-Host ""
                Write-Host "  INCIDENT SUMMARY" -ForegroundColor Yellow
                Write-Host "  Active incidents: " -NoNewline
                $totalColour = if ($sevCounts["High"] -gt 0) { "Red" } elseif ($sevCounts["Medium"] -gt 0) { "Yellow" } else { "White" }
                Write-Host "$totalActive" -ForegroundColor $totalColour -NoNewline

                # Inline severity breakdown
                $sevParts = @()
                if ($sevCounts["High"] -gt 0)          { $sevParts += "$($sevCounts['High']) High" }
                if ($sevCounts["Medium"] -gt 0)        { $sevParts += "$($sevCounts['Medium']) Medium" }
                if ($sevCounts["Low"] -gt 0)           { $sevParts += "$($sevCounts['Low']) Low" }
                if ($sevCounts["Informational"] -gt 0) { $sevParts += "$($sevCounts['Informational']) Info" }
                if ($sevParts.Count -gt 0) {
                    Write-Host "  ($($sevParts -join ', '))" -ForegroundColor DarkGray
                } else {
                    Write-Host ""
                }

                # Category breakdown
                $sortedCats = $catCounts.GetEnumerator() | Sort-Object Value -Descending
                foreach ($c in $sortedCats) {
                    Write-Host "    $($c.Value) " -NoNewline -ForegroundColor White
                    Write-Host "$($c.Key)" -ForegroundColor DarkCyan
                }
            }
            else {
                Write-Host ""
                Write-Host "  INCIDENT SUMMARY" -ForegroundColor Yellow
                Write-Host "  No active incidents." -ForegroundColor Green
            }
        }
        catch {
            Write-Host ""
            Write-Host "  INCIDENT SUMMARY" -ForegroundColor Yellow
            Write-Host "  Could not fetch incidents." -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "    [1] Search for a user"
    Write-Host "    [2] Search for a device (MDE)" -ForegroundColor $(if ($mdeConnected) { "White" } else { "DarkGray" })

    if ($mdeConnected) {
        Write-Host "    [3] Reconnect to MDE" -ForegroundColor DarkGray
    } else {
        Write-Host "    [3] Connect to MDE" -ForegroundColor Yellow
    }

    Write-Host "    [4] View active incidents (MDE)" -ForegroundColor $(if ($mdeConnected) { "White" } else { "DarkGray" })
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
                                Unlock-ADAccount -Identity $adUser.SamAccountName -ErrorAction Stop
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

                                Show-DeviceActionMenu -EntraDevice $selectedDevice -MDEMachine $mdeMachine
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
    # [4] VIEW ACTIVE INCIDENTS (MDE)
    # ======================================================================
    "4" {
        if (-not $mdeConnected) {
            Write-Host "  MDE is not connected. Cannot view incidents." -ForegroundColor Yellow
            Write-Host "  Use option [3] from the main menu to connect to MDE." -ForegroundColor DarkGray
            continue
        }

        Show-MDEIncidents
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

    # Clear AD default parameter values (Server / Credential) if set
    $adCmdlets = @(
        "Get-ADDomain", "Get-ADDomainController", "Get-ADUser",
        "Set-ADUser", "Set-ADAccountPassword",
        "Disable-ADAccount", "Unlock-ADAccount"
    )
    foreach ($cmd in $adCmdlets) {
        $PSDefaultParameterValues.Remove("${cmd}:Server")
        $PSDefaultParameterValues.Remove("${cmd}:Credential")
    }
    Write-Host "AD session parameters cleared." -ForegroundColor DarkGray

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
    'adConfigPath', 'savedConfig', 'configToSave', 'savedUser', 'adChoice',
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
    'deviceAction', 'backToParent',
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
