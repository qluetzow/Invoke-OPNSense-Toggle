# Invoke-OPNSense-Toggle
User interaction and interface with the OPNSense API to utilize automation rules.

### Requirements:
* [Microsoft PowerShell](https://learn.microsoft.com/en-us/powershell/) >= 7.0

### Usage:
* Run with CLI parameters:
    - `opensense_rule_toggler.ps1 -opnsense_host 192.168.1.1 \`\
    `-uuid 9u2905r6m-fj4e-729f-3mz5-35w7s822sd530 \`\
    `-api_key tuQjYj7Px3WBsALnp2CuwjBW79SrkdNT5qsNszsaEs3xVKT5iEqr2b4f7GAVbRxSda2Z5q98FXFNLxHc \`\
    `-api_secret tuQjYj7Px3WBsALnp2CuwjBW79SrkdNT5qsNszsaEs3xVKT5iEqr2b4f7GAVbRxSda2Z5q98FXFNLxHc \`\
    `-enable|-disable \`\
    `-version`


* Run with interactive parameters: `opensense_rule_toggler.ps1`
* Get version string: `opensense_rule_toggler.ps1 -version`


### Arguments:
* opnsense_host
    - IP address or FQDN or OPNSense.
* uuid
    - UUID of automation rule to be enabled/disabled.
* api_key
    - API key for OPNSense.
* api_secret
    - API secret for OPNSense.
* -enable
    - Enable automation rule in OPNSense.
* -disable
    - Disable automation rule in OPNSense.
* -version
    - Show program version and exit.

Additional information can be found by using the command: `Get-Help C:\Path\To\Script\Invoke-OPNSense-Toggle.ps1 -Full`