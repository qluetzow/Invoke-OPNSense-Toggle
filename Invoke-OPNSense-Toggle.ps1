# Invoke-OPNSense-Toggle (C) 2025 Quinn Luetzow
# This file is part of Invoke-OPNSense-Toggle.

# Invoke-OPNSense-Toggle is free software: you can
# redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.

# Invoke-OPNSense-Toggle is distributed in the hope that
# it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
# the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Invoke-OPNSense-Toggle. If not, see
# <https://www.gnu.org/licenses/>.

<#
        .SYNOPSIS
        Script for enabling/disabling an automation rule via the OPNSense API.
        When enabled the rule will be enforced.
        When disabled the rule will not be enforced.

        .PARAMETER opnsense_host
        Specifies the FQDN:Port or IP:Port of the OPNSense host.
        If no port is specified, the default HTTP/HTTPS ports (80/443) are used.

        .PARAMETER uuid
        Specifies the UUID of the OPNSense automation rule.

        .PARAMETER api_key
        Specifies the API key to use with OPNSense HTTP requests.

        .PARAMETER api_secret
        Specifies the API secret to use with OPNSense HTTP requests.

        .PARAMETER enable
        Specifies to enable OPNSense automation rule.
        This cannot be passed along with -disable.

        .PARAMETER disable
        Specifies to disable OPNSense automation rule.
        This cannot be passed along with -enable.

        .PARAMETER version
        Specifies to print version string of the script and exit.
        This cannot be passed along with any other options.

        .INPUTS
        None.

        .OUTPUTS
        None.

        .EXAMPLE
        Run with CLI parameters:
        .\opensense_rule_toggler.ps1 [-v|--version] -opnsense_host 192.168.1.1 `
            -uuid 9u2905r6m-fj4e-729f-3mz5-35w7s822sd530
            -api_key tuQjYj7Px3WBsALnp2CuwjBW79SrkdNT5qsNszsaEs3xVKT5iEqr2b4f7GAVbRxSda2Z5q98FXFNLxHc
            -api_secret tuQjYj7Px3WBsALnp2CuwjBW79SrkdNT5qsNszsaEs3xVKT5iEqr2b4f7GAVbRxSda2Z5q98FXFNLxHc
            -enable|-disable

        .EXAMPLE
        Run with interactive parameters: .\opensense_rule_toggler.ps1

        .EXAMPLE
        Get version string: .\opensense_rule_toggler.ps1 -version
#>

[CmdletBinding()]
param (
    [string]$opnsense_host = $(Read-Host "OPNSense Host"),
    [string]$uuid = $(Read-Host "Rule UUID"),
    [string]$api_key = $(Read-Host "API Key"),
    [string]$api_secret = $(Read-Host "API Secret"),
    [switch]$enable,
    [switch]$disable,
    [switch]$version
)

function Get-RuleStatus {
    <#
        .SYNOPSIS
        Make one GET request to the API.
        Pulls current status of filter rule.

        .PARAMETER hostname
        Specifies the FQDN:Port or IP:Port of the OPNSense host.
        If no port is specified, the default HTTP/HTTPS ports (80/443) are used.

        .PARAMETER uuid
        Specifies the UUID of the OPNSense automation rule.

        .PARAMETER credential
        Specifies the API secret to use with OPNSense HTTP requests.
        
        .INPUTS
        None.

        .OUTPUTS
        Returns $true if the rule is currently enabled, or $false if it is not.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$hostname,
        
        [Parameter(Mandatory)]
        [string]$id,
        
        [Parameter(Mandatory)]
        [PSCredential]$credential
    )

    $endpoint = "https://" + $hostname + "/api/firewall/filter/getRule/" + $id

    $response = Invoke-RestMethod -Uri $endpoint `
        -Method Get `
        -Credential $credential `
        -Authentication Basic `
        -ContentType "application/x-www-form-urlencoded"


    # This is needed as OPNSense sends JSON with empty brackets, which PS will fail to deserialize
    # into a PSCustomObject and instead returns as a string of the full JSON. Converting to a
    # hashtable avoids trying to parse the string ourselves and allows for key:value interactions.
    $response = $response | ConvertFrom-Json -AsHashtable


    if ($response["rule"]["enabled"] -eq "1") {
        return $true
    }
    elseif ($response["rule"]["enabled"] -eq "0") {
        return $false
    }
    else {
        # if neither True nor False, either we've received bad data from the API or the JSON response
        # data format has changed. Neither one is recoverable, so throw an error.
        throw New-Object -TypeName System.Exception -ArgumentList
            ("OPNSense reports neither enabled or disabled for the rule." +
            "Bad data or the API response was not evaluated correctly." +
            "The response JSON structure may have changed." +
            "Reported status is: " + $response["rule"]["enabled"])
    }
}


function Set-RuleStatus {
    <#
        .SYNOPSIS
        Make two POST requests to the API.
        First enables/disables filter rule.
        Second applies changes in OPNSense.

        .PARAMETER hostname
        Specifies the FQDN:Port or IP:Port of the OPNSense host.
        If no port is specified, the default HTTP/HTTPS ports (80/443) are used.

        .PARAMETER uuid
        Specifies the UUID of the OPNSense automation rule.

        .PARAMETER credential
        Specifies the API secret to use with OPNSense HTTP requests.

        .PARAMETER enable_rule
        Specifies to enable OPNSense automation rule.
        This cannot be passed along with -disable-rule.

        .PARAMETER disable_rule
        Specifies to disable OPNSense automation rule.
        This cannot be passed along with -enable-rule.

        .INPUTS
        None.

        .OUTPUTS
        None.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$hostname,
        
        [Parameter(Mandatory)]
        [string]$id,
        
        [Parameter(Mandatory)]
        [PSCredential]$credential,

        [switch]$enable_rule,

        [switch]$disable_rule
    )

    if ($enable_rule -and $disable_rule) {
        Write-Error "Both enable and disable switches were supplied. These parameters are mutually exclusive."
        Exit 1
    }
    if (-not $enable_rule -and -not $disable_rule) {
        Write-Error "Neither enable or disable switches were passed, at least one is required."
        Exit 1
    }


    $toggle_endpoint = "https://" + $hostname + "/api/firewall/filter/toggleRule/" + $id

    if ($enable_rule) {
        $toggle_endpoint += "/1"
    }
    elseif ($disable_rule) {
        $toggle_endpoint += "/0"
    }


    $apply_endpoint = "https://" + $hostname + "/api/firewall/filter/apply"


    $change = Invoke-RestMethod -Uri $toggle_endpoint `
        -Method Post `
        -Credential $credential `
        -Authentication Basic `
        -ContentType "application/x-www-form-urlencoded"

    $apply = Invoke-RestMethod -Uri $apply_endpoint `
        -Method Post `
        -Credential $credential `
        -Authentication Basic `
        -ContentType "application/x-www-form-urlencoded"


    if (-not ($change.PSObject.Properties["changed"].Value -eq $true -and
        $apply.PSObject.Properties["Status"].Value.Trim() -eq "OK")) {
        
        throw New-Object -TypeName System.Exception -ArgumentList "Failed to set rule status or apply filter changes."
    }
}



$version_string = 1.0

if ($PSVersionTable.PSVersion -lt 7) {
    Write-Error "This script requires Powershell 7 or higher to function."
    Exit 1
}
if ($version) {
    Write-Host "Invoke-OPNSense-Toggle version " + $version_string
    Exit 0
}
if ($enable -and $disable) {
    Write-Error "Both enable and disable switches were supplied. These parameters are mutually exclusive."
    Exit 1
}
if (-not $enable -and -not $disable) {
    Write-Error "Neither enable or disable switches were passed, at least one is required."
    Exit 1
}



$api_secret = ConvertTo-SecureString $api_secret -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($api_key, $api_secret)


$current_status = Get-RuleStatus -hostname $opnsense_host -id $uuid -credential $credentials

if ($current_status -eq $true -and $enable) {
    Write-Host "Rule is already enabled."
    Exit 0
}
elseif ($current_status -eq $false -and $disable) {
    Write-Host "Rule is already disabled."
    Exit 0
}


if ($enable) {
    Set-RuleStatus -hostname $opnsense_host -id $uuid -credential $credentials -enable_rule
    Write-Host "Rule has been successfully enabled."
    Exit 0
}
else {
    Set-RuleStatus -hostname $opnsense_host -id $uuid -credential $credentials -disable_rule
    Write-Host "Rule has been successfully disabled."
    Exit 0
}