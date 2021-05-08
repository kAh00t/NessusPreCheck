<#
  ███╗   ██╗███████╗███████╗███████╗██╗   ██╗███████╗      ██████╗ ██████╗ ███████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
  ████╗  ██║██╔════╝██╔════╝██╔════╝██║   ██║██╔════╝      ██╔══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ██╔██╗ ██║█████╗  ███████╗███████╗██║   ██║███████╗█████╗██████╔╝██████╔╝█████╗  ██║     ███████║█████╗  ██║     █████╔╝ 
  ██║╚██╗██║██╔══╝  ╚════██║╚════██║██║   ██║╚════██║╚════╝██╔═══╝ ██╔══██╗██╔══╝  ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
  ██║ ╚████║███████╗███████║███████║╚██████╔╝███████║      ██║     ██║  ██║███████╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝      ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝                                                                                                                      
 		          ______________________ 	
                / Nessus PreCheck v0.1  \
 ┌──────────────────────────────────────────────────────┐
 │ Created by: David Manuel (@Fuzz_sh,@Weegeicast)      │
 │ Date      : 03/05/2021                               │
 │ Version   : 0.4 (Very Alpha)                         │
 │ Licence   : Opensource - always. Just don't sell it! │
 └──────────────────────────────────────────────────────┘

What Does It do?: 
At present, this tool checks the the usual suspects that go wrong when trying to perform a Credential Patch Audit in Nessus. This currently only performs checks and does not change any settings on the remote device (this may change)

What doesn't it do?: 
Make any changes to the remote device (yet). These will be optional when they do get implimented 

What does it require to run?: 
Most of the tools can probably run on a standard user account. Checking the admin shares requires the script to be loaded in the context of a domain admin (I think), but it will expilcity request the creds at the beginning anyway



To do:
Option to make required changes to the remote device
Cleanup tool to revert to the original changes
Maybe output a report of some kind? Probably overkill 
Weegiecast advertisements

`Get-NetFirewallProfile` add this, check current profile on remote machine with invoke 


Special Thanks To:

@0x616e6874
@ZephrFish (Zephr Pish) 


#>


########################################################################################################################################################################
# Global Variables

$global:globalhostname = $null
$global:globalcredentials = $null
$global:toolname = "Fuzz_sh Nessus PreCheck v0.1"
$global:dnsname = $null
$global:dcname = $null
$global:domainname = $null
# $PSDefaultParameterValues['Test-NetConnection:InformationLevel'] = 'Quiet'
# $ProgressPreference = "SilentlyContinue"


########################################################################################################################################################################
# Install Dependencies 

function InstallDependencies() {
    ## This tool requires PSOneTools for network scanning, you can install the module before use 
    ## PSOneTools function Test-PSOnePort allows timeouts which is handy when port scanning and the remote host hangs
    Install-Module -Name PSOneTools -Scope CurrentUser -Force
    
}


########################################################################################################################################################################
# Tool Functions

## Option 1: Test network connection to host NOT CURRENTLY BEING USED, SEE PING
function NetworkConnectionStatusTest() {
    Try{
    Write-Host "`n"
    Write-Host "This tool checks to see if a test connection can be made to the target device. If no connection can be made, check the physical connection and routing between this device and the target. Also, ICMP may just be blocked on SWF"
    Write-Host "`n"
    Write-Host "🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗 Output 🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗"
    Write-Host "`n"
    Test-NetConnection -ComputerName $global:globalhostname -InformationLevel "Detailed"| Select-Object -Property Computername, PingSucceeded
    
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }

    ProcessComplete
}

## Option 2: Check WinRM and Remote Registry status of remote device

function WinRMEnabledCheck() {
    Try{
    Get-Service -Computer $global:globalhostname -Name Winmgmt
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }

}

function RemoteRegistryEnabledCheck() {
    Try{
    Get-Service -Computer $global:globalhostname -Name RemoteRegistry
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

function StartWinRM{
    Try{
    Get-Service -Computer $global:globalhostname -Name Winmgmt | Start-Service
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}


function DisableWinRM{
    Try{
    Get-Service -Computer $global:globalhostname -Name Winmgmt | Stop-Service -Force
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

function StartRemoteRegistry{
    Try{
    Get-Service -Computer $global:globalhostname -Name RemoteRegistry | Start-Service
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}


function DisableRemoteRegistry{
    Try{
    Get-Service -Computer $global:globalhostname -Name RemoteRegistry | Stop-Service -Force
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}



function RemoteServiceEnabledChecks(){
    Try{
    Write-Host "`n"
    Write-Host "If output shows either RemoteRegistry or WinRM services are disabled, Nessus will not run correctly. This will need to be enabled on the remote device."
    Write-Host "`n"
    Write-Host "🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗 Output 🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗"
    RemoteRegistryEnabledCheck
    WinRMEnabledCheck
    Write-Host "`n"
    Write-Host "##################### Further Options #####################"
    Write-Host "1. Enable WinRM"
    Write-Host "2. Disable WinRM"
    Write-Host "3. Enable RemoteRegistry"
    Write-Host "4. Disable RemoteRegistry"
    Write-Host "5. Check Status" 
    Write-Host "6. Back to Main Menu"
    Write-Host "7. Quit Program"
        do
        {
            # Show-Menu -Title "================== $global:toolname ====================="
            Write-Host "`r"
            $UserInput = Read-Host ">"
            switch([validateRange(1,8)]$UserInput)
            {
                '1' {Write-Host 'Enabling WinRM';StartWinRM; Write-Host "Should now be enabled, retesting..."; Start-Sleep -Seconds 3; Clear-Host; RemoteServiceEnabledChecks }
                '2' {Write-Host 'Disabling WinRM'; DisableWinRM; Write-Host "Should now be disabled, retesting..."; Start-Sleep -Seconds 3; Clear-Host; RemoteServiceEnabledChecks}
                '3' {Write-Host 'Enabling RemoteRegistry';StartRemoteRegistry; Write-Host "Should now be enabled, retesting..."; Start-Sleep -Seconds 3; Clear-Host; RemoteServiceEnabledChecks }
                '4' {Write-Host 'Disabling RemoteRegistry'; DisableRemoteRegistry; Write-Host "Should now be disabled, retesting..."; Start-Sleep -Seconds 3; Clear-Host; RemoteServiceEnabledChecks}
                '5' {Write-Host 'Checking Status';Clear-Host; RemoteServiceEnabledChecks}
                '6' {Write-Host 'Going back to Main Menu';Clear-Host; Show-Menu}
                '7' {Write-Host 'Quitting gracefully...'; Exit}

                'q' {Clear-Host; Write-Host 'q to quit'; exit}
                default {Write-Host 'Please choose a valid option'; Clear-Host; RemoteServiceEnabledChecks}
            }
            pause
        }
        until  ($UserInput -eq 'q')

    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }

    ProcessComplete
}

## Option 3: Confirm access to remote registry by connecting to remote host

function RemoteRegistryStatusCheck() {
    Try{
    Write-Host "`n"
    Write-Host "If this tool output shows a list of registry keys, then RemoteRegistry is enabled."
    Write-Host "If anything other than this is returned, either RemoteRegistry is not enabled, or Remote Administration firewall rules are not enabled."
    Write-Host "`n"
    Write-Host "🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗 Output 🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗"
    reg query \\$global:globalhostname\hklm
    Write-Host "`n"
    
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }

    ProcessComplete
}

## Option 4: Confirm ports 139 (Netbios) and 445 (SMB) are open on remote host

function OpenPortStatusCheck() {

    Try{
    Write-Host "`n"
    Write-Host "This tool checks if port 139/445/3389/5985/5986 are open. Both of these ports must be open for Nessus to work correctly. (Timeout Set for 1000s) "
    Write-Host "If these ports are not open, open approriate firewall rules on remote device. Be sure to close them again after the audit."
    Write-Host "`n"
    Write-Host "🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗 Output 🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗"
    Write-Host "`n"
    Write-Host -nonewline "Port 139 Open: ";Test-PSOnePort -ComputerName $global:globalhostname -Port 139 -Timeout 1000
    Write-Host -nonewline "Port 445 Open: ";Test-PSOnePort -ComputerName $global:globalhostname -Port 445 -Timeout 1000
    Write-Host "`n"
    Write-Host -nonewline "Port 3389 Open: ";Test-PSOnePort -ComputerName $global:globalhostname -Port 3389 -Timeout 1000
    Write-Host "`n"
    Write-Host -nonewline "Port 5985 Open: ";Test-PSOnePort -ComputerName $global:globalhostname -Port 5985 -Timeout 1000
    Write-Host -nonewline "Port 5986 Open: ";Test-PSOnePort -ComputerName $global:globalhostname -Port 5986 -Timeout 2000
    Write-Host "`n"
    
    Write-Host "##################### Further Options #####################"
    Write-Host "1. Re-scan TCP ports 139/445/3389/5985/5986"
    Write-Host "2. Create CE_Allow_TCP_139 Firewall Rule on Private Profile only"
    Write-Host "3. Delete CE_Allow_TCP_139 Firewall Rule on Private Profile only"
    Write-Host "4. Create CE_Allow_TCP_445 Firewall Rule on Private Profile only"
    Write-Host "5. Delete CE_Allow_TCP_445 Firewall Rule on Private Profile only"
    Write-Host "6. Create CE_Allow_TCP_3389 Firewall Rule on Private Profile only"
    Write-Host "7. Delete CE_Allow_TCP_3389 Firewall Rule on Private Profile only"
    Write-Host "8. Create CE_Allow_TCP_5985 Firewall Rule on Private Profile only"
    Write-Host "9. Delete CE_Allow_TCP_5985 Firewall Rule on Private Profile only"
    Write-Host "10. Create CE_Allow_TCP_5986 Firewall Rule on Private Profile only"
    Write-Host "11. Delete CE_Allow_TCP_5986 Firewall Rule on Private Profile only"
    Write-Host "12. Check Status" 
    Write-Host "13. Back to Main Menu"
    Write-Host "14. Quit Program"
        do
        {
            # Show-Menu -Title "================== $global:toolname ====================="
            Write-Host "`r"
            $UserInput = Read-Host ">"
            switch([validateRange(1,8)]$UserInput)
            {
                '1' {Write-Host 'Re-scanning TCP ports 139/445/3389/5985/5986'; Clear-Host; OpenPortStatusCheck; Write-Host "Rescan Complete"; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck }
                '2' {Write-Host 'Creating CE_Allow_TCP_139 Firewall Rule on Software FW on Private Profile only'; CreateTCP139FWRule; Write-Host "Should now be created, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '3' {Write-Host 'Deleting CE_Allow_TCP_139 Firewall Rule on Software FW on Private Profile only'; DeleteTCP139FWRule; Write-Host "Should now be deleted, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '4' {Write-Host 'Creating CE_Allow_TCP_445 Firewall Rule on Software FW on Private Profile only'; CreateTCP445FWRule; Write-Host "Should now be created, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '5' {Write-Host 'Deleting CE_Allow_TCP_445 Firewall Rule on Software FW on Private Profile only'; DeleteTCP445FWRule; Write-Host "Should now be deleted, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '6' {Write-Host 'Creating CE_Allow_TCP_3389 Firewall Rule on Software FW on Private Profile only'; CreateTCP3389FWRule; Write-Host "Should now be created, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '7' {Write-Host 'Deleting CE_Allow_TCP_3389 Firewall Rule on Software FW on Private Profile only'; DeleteTCP3389FWRule; Write-Host "Should now be deleted, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '8' {Write-Host 'Creating CE_Allow_TCP_5985 Firewall Rule on Software FW on Private Profile only'; CreateTCP5985FWRule; Write-Host "Should now be created, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '9' {Write-Host 'Deleting CE_Allow_TCP_5985 Firewall Rule on Software FW on Private Profile only'; DeleteTCP5985FWRule; Write-Host "Should now be deleted, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '10' {Write-Host 'Creating CE_Allow_TCP_5986 Firewall Rule on Software FW on Private Profile only'; CreateTCP5986FWRule; Write-Host "Should now be created, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '11' {Write-Host 'Deleting CE_Allow_TCP_5986 Firewall Rule on Software FW on Private Profile only'; DeleteTCP5986FWRule; Write-Host "Should now be deleted, retesting..."; Start-Sleep -Seconds 3; Clear-Host; OpenPortStatusCheck}
                '12' {Write-Host 'Checking Status';Clear-Host; OpenPortStatusCheck}
                '13' {Write-Host 'Going back to Main Menu';Clear-Host; Show-Menu}
                '14' {Write-Host 'Quitting gracefully...'; Exit}

                'q' {Clear-Host; Write-Host 'q to quit'; exit}
                default {Write-Host 'Please choose a valid option'; Clear-Host; OpenPortStatusCheck}
            }
            pause
        }
        until  ($UserInput -eq 'q')



    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }

    ProcessComplete
}


## SMB/Netbios Ports (139,445) 
function CreateTCP139FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=139 override name="CE_Allow_TCP_139_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=139 name="CE_Allow_TCP_139_domain" profile=domain}

    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}
function DeleteTCP139FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_139_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_139_domain" profile=domain}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

function CreateTCP445FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=445 name="CE_Allow_TCP_445_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=445 name="CE_Allow_TCP_445_domain" profile=domain}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}
function DeleteTCP445FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_445_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_445_domain" profile=domain}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

## WMI Ports
function CreateTCP5985FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=5985 name="CE_Allow_TCP_5985_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=5985 name="CE_Allow_TCP_5985_domain" profile=domain}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}
function DeleteTCP5985FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_5985_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_5985_domain" profile=domain}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}
function CreateTCP5986FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=5986 name="CE_Allow_TCP_5986_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=5986 name="CE_Allow_TCP_5986_domain" profile=domain}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}
function DeleteTCP5986FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_5986_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_5986_domain" profile=domain}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}
## RDP Port Functions (3389)
function CreateTCP3389FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=3389 name="CE_Allow_TCP_3389_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=3389 name="CE_Allow_TCP_3389_domain" profile=domain}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}
function DeleteTCP3389FWRule{
    Try{
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_3389_private" profile=private}
    Invoke-command -computer $global:globalhostname {netsh advfirewall firewall delete rule name="CE_Allow_TCP_3389_domain" profile=domain}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

## Option 5: Confirm if LocalAccountTokenFilterPolicy is enabled on remote host

function LocalAccountFilterStatusCheck(){
    Try{
    Write-Host "`n"
    Write-Host "This tool will check if LocalAccountTokenFilterPolicy is enabled on the remote device. "
    Write-Host "If you are using a local user account on the remote device for authentication with Nessus, this registry value must be set to 1."
    Write-Host "You'd be better off adding a domain user to the local administrator group on the target devices, As you would not need to see this token or clean up."
    Write-Host "Remember cleanup! "
    Write-Host "`n"
    Write-Host "🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗 Output 🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗"
    Write-Host "`n"
    Invoke-command -computer $global:globalhostname {Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\| findstr LocalAccountTokenFilterPolicy }
    Write-Host "`n"


    Write-Host "##################### Further Options #####################"
    Write-Host "1. Enable LocalAccountTokenFilterPolicy "
    Write-Host "2. Disable LocalAccountTokenFilterPolicy"
    Write-Host "3. Check Status" 
    Write-Host "4. Back to Main Menu"
    Write-Host "5. Quit Program"
        do
        {
            # Show-Menu -Title "================== $global:toolname ====================="
            Write-Host "`r"
            $UserInput = Read-Host ">"
            switch([validateRange(1,8)]$UserInput)
            {
                '1' {Write-Host 'Enabling LocalAccountTokenFilterPolicy';EnableLocalAccountFilter; Write-Host "Should now be enabled, retesting..."; Start-Sleep -Seconds 3; Clear-Host; LocalAccountFilterStatusCheck }
                '2' {Write-Host 'Disabling LocalAccountTokenFilterPolicy'; DisableLocalAccountFilter; Write-Host "Should now be disabled, retesting..."; Start-Sleep -Seconds 3; Clear-Host; LocalAccountFilterStatusCheck}
                '3' {Write-Host 'Checking Status';Clear-Host; LocalAccountFilterStatusCheck}
                '4' {Write-Host 'Going back to Main Menu';Clear-Host; Show-Menu}
                '5' {Write-Host 'Quitting gracefully...'; Exit}

                'q' {Clear-Host; Write-Host 'q to quit'; exit}
                default {Write-Host 'Please choose a valid option'; Clear-Host; LocalAccountFilterStatusCheck}
            }
            pause
        }
        until  ($UserInput -eq 'q')
    
    }

    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }

    ProcessComplete
}

### Option 5 Subfunctions: LocalAccountFilterToker
function EnableLocalAccountFilter{
    Try{
    Invoke-command -computer $global:globalhostname {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name "LocalAccountTokenFilterPolicy" -Value 1}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

function DisableLocalAccountFilter{
    Try{
    Invoke-command -computer $global:globalhostname {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name "LocalAccountTokenFilterPolicy" -Value 0 }
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

## Option 6: Confirm IPC/C/Admin shares are open on the remote host
function RemoteShareStatusCheck(){

    Try{
    Write-Host "`n"
    Write-Host "This tool checks that the provided credentials have access to the required folders on the remote device. This shares require administrative access."
    Write-Host "If you do not have access to these shares, either the credentials provided are not administrator on the remote device, SMB inbound is blocked on firewall rules on remote device, or the shares are disabled. "
    Write-Host "`n"
    Write-Host "🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗 Output 🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗"
    Write-Host "`n"
    net use \\$global:globalhostname\ipc$ /user:$global:globalcredentials;
    net use \\$global:globalhostname\c$ /user:$global:globalcredentials;
    net use \\$global:globalhostname\admin$ /user:$global:globalcredentials;
    
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
    ProcessComplete
}

## Option 7: Confirm if AutoShareServer is enabled on the remote host
function AutoShareServerStatusCheck(){
    Try{
    Write-Host "`n"
    Write-Host "This tool checks to see if AutoShareServer is enabled, which allows access to ipc/c/admin shares required to run Nessus against remote host."
    Write-Host "If this is not enabled and you do not have access to the shares (use Option 6 to check), enable AutoShareServer and try again."
    Write-Host "`n"
    Write-Host "🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗 Output 🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗"
    Write-Host "`n"
    Invoke-command -computer $global:globalhostname {Get-SmbServerConfiguration | findstr AutoShareServer}
    Invoke-command -computer $global:globalhostname {Get-SmbServerConfiguration | findstr AutoShareWorkstation}
    Write-Host "`n"
    
    Write-Host "##################### Further Options #####################"
    Write-Host "1. Enable AutoShareServer"
    Write-Host "2. Disable AutoShareServer"
    Write-Host "3. Check Status" 
    Write-Host "4. Back to Main Menu"
    Write-Host "5. Quit Program"
        do
        {
            # Show-Menu -Title "================== $global:toolname ====================="
            Write-Host "`r"
            $UserInput = Read-Host ">"
            switch([validateRange(1,8)]$UserInput)
            {
                '1' {Write-Host 'Enabling AutoShareServer';EnableAutoShareServer; Write-Host "Should now be enabled, retesting..."; Start-Sleep -Seconds 3; Clear-Host; AutoShareServerStatusCheck }
                '2' {Write-Host 'Disabling AutoShareServer'; DisableAutoShareServer; Write-Host "Should now be disabled, retesting..."; Start-Sleep -Seconds 3; Clear-Host; AutoShareServerStatusCheck}
                '3' {Write-Host 'Checking Status';Clear-Host; AutoShareServerStatusCheck}
                '4' {Write-Host 'Going back to Main Menu';Clear-Host; Show-Menu}
                '5' {Write-Host 'Quitting gracefully...'; Exit}

                'q' {Clear-Host; Write-Host 'q to quit'; exit}
                default {Write-Host 'Please choose a valid option'; Clear-Host; AutoShareServerStatusCheck}
            }
            pause
        }
        until  ($UserInput -eq 'q')
    }

    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
    ProcessComplete
}

### Option 7 Subfunctions: EnableAutoShareServer 
function EnableAutoShareServer{
    Try{
    Invoke-command -computer $global:globalhostname {Set-SmbServerConfiguration -AutoShareServer $True -AutoShareWorkstation $True -Confirm:$false}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

function DisableAutoShareServer{
    Try{
    Invoke-command -computer $global:globalhostname {Set-SmbServerConfiguration -AutoShareServer  $False -AutoShareWorkstation $False -Confirm:$false}
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

## Option 8  EnterRemotePowershellSession
function EnterRemotePowershellSession{
   
    Clear-Host;
    # Write-Host "It at least got to here"
    # Enter-PSSession -ComputerName $global:globalhostname -Credential $global:globalcredentials

    # To add: try creating an environmental variable on the remote host  ($env:variablename) 
    # $global:globalcredentials
    Start-Process -Credential $global:globalcredentials -FilePath powershell -ArgumentList '-NOEXIT' , '$target = Read-Host "Enter target: "; Clear-Host; Enter-PSSession -ComputerName $target'
    
    # invoke-expression -ErrorAction stop 'cmd /c start powershell -NoExit -Command { $target = Read-Host "Enter target: "; Clear-Host;Enter-PSSession -ComputerName $target -Credential $null };'
    
    #invoke-command -AsJob -computer $PC -ScriptBlock {cmd /c start powershell -NoExit -Command { '$target = Read-Host "Enter target: "; Clear-Host;Enter-PSSession -ComputerName $target -Credential $null }'}}
    #invoke-command -computername workstation2 -ScriptBlock {cmd /c start powershell -NoExit -Command {'$target = Read-Host "Enter target: "; Clear-Host;Enter-PSSession -ComputerName $target -Credential $null }'}}
   
    #Write-Host "There was an error in this function. $error[0]"
    ProcessComplete
}



function PingHost() {

    Try{
    Write-Host "`n"
    Write-Host "This tool checks to see if a test connection can be made to the target device. If no connection can be made, check the physical connection and routing between this device and the target."
    Write-Host "`n"
    Write-Host "🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗 Output 🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗"
    ping $global:globalhostname;
    Write-Host "`n"
    
    }

    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }

    ProcessComplete
      
}

function DNS-Lookup{
    Try{
    $global:dnsname = Resolve-DnsName -Name $global:globalhostname | Where-Object Type -eq "A" | select-object -ExpandProperty IPAddress
    Write-Host "`n"
    Write-Host "* Performing DNS resoluton..."
    }

    Catch{
    Write-Host "Unable to resolve DNS $error[0]"
    }
}

function Domain-Lookup{
    Try{
    $global:domainname = Get-WMIObject Win32_NTDomain -ComputerName $global:globalhostname | select-object -ExpandProperty DnsForestName
    Write-Host "* Finding name of domain..."
    }

    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }

}

function DC-Lookup{
    Try{
    $global:dcname = Get-WMIObject Win32_NTDomain -ComputerName $global:globalhostname | select-object -ExpandProperty DomainControllerName | Where-Object Type -ne "$global:globalhostname"
    Write-Host "* Looking for the domain controller..."
    }
    Catch{
    Write-Host "There was an error in this function. $error[0]"
    }
}

function ProcessComplete() {
    # Runs after each tool function to make the screen a little more readable, on user input it'll show the menu again. 
    Write-Host "------------------------------------------------------------"
    Write-Host "* Process Complete." 
    Write-Host "------------------------------------------------------------"

    Read-Host "Press any key to go back to main menu."

    Write-Host "`n"
    Clear-Host
    Show-Menu   
}


# Run Functions 

## Get-Variables; Get Used Input/Variables for use within the session. Draws menu immediatly afterward 
function Get-Variables{
    Clear-Host
    Write-Host "		        ______________________ "
    Write-Host "               / Nessus PreCheck v0.1 \"
    Write-Host "┌──────────────────────────────────────────────────────┐"
    Write-Host "│ Created by: David Manuel (@Fuzz_sh,@Weegeicast)      │"
    Write-Host "│ Date      : 03/05/2021                               │"
    Write-Host "│ Version   : 0.4 (Very Alpha)                         │"
    Write-Host "│ Licence   : Opensource - always. Just don't sell it! │"
    Write-Host "└──────────────────────────────────────────────────────┘"
    Write-Host "`n"
    $global:globalhostname += Read-Host "> Please enter hostname for device to be checked"
    Write-Host "`r"
    Write-Host -nonewline "* Performing some initial lookups...give me a minute..."

    Try{
    DNS-Lookup
    }
    Catch{
    Write-Host "DNS-Lookup Failed"
    }

    try{
    Domain-Lookup
    }
    Catch{
    Write-Host "DNS-Lookup Failed"
    }

    try{
    DC-Lookup
    }
    Catch{
    Write-Host "DC Lookup Failed"
    }

    Write-Host "`r"
    Write-Host "Basic Lookups Complete."
    Write-Host "`r"
    Write-Host "Please provide Domain Administrator credentials to be used during the scan"; 
    $global:globalcredentials = Get-Credential -Credential $null
    Show-Menu

}

## Show-Menu: Draw the menu options to screen, executes Select-Choice menu straight after. 
function Show-Menu {
    Write-Host "================== $global:toolname ====================="
    Write-Host "`r"
    Write-Host "Current Target: $global:globalhostname";
    Write-Host "IP Address    : $global:dnsname";
    Write-Host "Domain        : $global:domainname"; 
    Write-Host "DC(If Avail)  : $global:dcname";
    Write-Host -NoNewLine "Username      : "; echo $global:globalcredentials.username;
    Write-Host "`r"
    Write-Host "🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗 Options 🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗🠗"
    Write-Host "`r"
    Write-Host "Press '1' to test network connection to host"
    Write-Host "Press '2' to Check/Configure WinRM and Remote Registry of target"
    Write-Host "Press '3' to Confirm RemoteRegistry enabled/accessible of target" 
    Write-Host "Press '4' to Check/Configure ports 139/445/3389/5985/5986 on target"
    Write-Host "Press '5' to Check/Configure LocalAccountTokenFilterPolicy on target"
    Write-Host "Press '6' to Confirm IPC/C/Admin shares are open on target"
    Write-Host "Press '7' to Check/Configure if AutoShareServer is enabled on target"
    Write-Host "Press '8' to open a PS Session on remote host"

    Write-Host "Press 'q' to quit"
    Select-Choice
}

## Select-Choice: Allows use to choose which function to run, press q to quit 
function Select-Choice {
    do
    {
        # Show-Menu -Title "================== $global:toolname ====================="
        Write-Host "`r"
        $UserInput = Read-Host ">"
        switch([validateRange(1,8)]$UserInput)
        {
            '1' {Clear-Host; Write-Host 'Option 1: Test network connection to target';PingHost}
            '2' {Clear-Host; Write-Host 'Option 2: Check/Configure WinRM and Remote Registry of target'; RemoteServiceEnabledChecks}
            '3' {Clear-Host; Write-Host 'Option 3: Confirm RemoteRegistry enabled/accessible of target'; RemoteRegistryStatusCheck}
            '4' {Clear-Host; Write-Host 'Option 4: Check/Configure ports 139/445/3389/5985/5986 on target'; OpenPortStatusCheck}
            '5' {Clear-Host; Write-Host 'Option 5: Check/Configure LocalAccountTokenFilterPolicy on target'; LocalAccountFilterStatusCheck}
            '6' {Clear-Host; Write-Host 'Option 6: Confirm IPC/C/Admin shares are open on target'; RemoteShareStatusCheck}
            '7' {Clear-Host; Write-Host 'Option 7: Check/Configure if AutoShareServer is enabled on target'; AutoShareServerStatusCheck}
            '8' {Write-Host 'Option 8: Open PS Session on remote host'; EnterRemotePowershellSession;}
            'q' {Clear-Host; Write-Host 'q to quit'; exit}
            default {Write-Host 'Please choose a valid option'; Clear-Host; Show-Menu}
        }
        pause
    }
    until  ($UserInput -eq 'q')
}

########################################################################################################################################################################
# Program Execution Flow

## Get-Variables starts the flow of the program3
  

Get-Variables
