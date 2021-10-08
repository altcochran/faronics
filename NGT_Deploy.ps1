<#
.notes
##############################################################################
#          Nutanix Guest Tools Active Directory Installer Script
#          Filename            :      NTNX_NGT_Startup_Installer.ps1
#          Script Version        :      2.0.14
#          Author                :      Ed McAndrew (ed.mcandrew@nutanix.com)
##############################################################################
.prerequisites
    1. Powershell 5 or above ($psversiontable.psversion.major)
    2. Nutanix AHV cluster; does not work "as-is" with ESXi or Hyper-V
    3. Populate $my_cluster_vip_addresses with ALL of the Nutanix Cluster VIP address that you wish to search for Virtual Machines on.
    4. Create idential local user accounts on each of the clusters defined in step 3 above.
        Note: This "should" work with a single LDAP / Active Directory credentials as well.  So long as the user can authenticate to each cluster. But I have not tested this.
    5. Using the GenPasswordEncryption.ps1 script, generate an AES encrypted password and hash for the above user account. Copy those to the $my_prism_pass and $my_hashkey variables below.
    6. The Windows Computer Name MUST BE identical to the Nutanix VM Name in Prism.  This is the only way for this script to find the correct VM in Prism.
        I.E.
            TestVM != testVM
            TestVM != TEstVm
            TESTVM != testvm
            TESTvM == TESTvM
    7. This script is designed to be run from an Active Directory startup GPO (using the SYSTEM account on the workstations), or via elevated SCCM jobs.
.synopsis
    Determine if Nutanix Guest Tools (NGT) is installed.  If not installed, determine mount path for NGT ISO and install from that.  Basic state information written to Application Event log under eventid 1.
.usage
    Run this script from an Active Directory startup script GPO
.author
    Ed McAndrew (ed.mcandrew@nutanix.com)
.disclaimer
    This script is provided "AS IS" without any additional support of any kind.
    This script is provided "AS IS" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and/or fitness for a particular purpose.
#>
##############################################################################
# Set Variables Below
##############################################################################
[string]$my_prism_username = "username_here" # Prism username; the username and passwords should be the same on all clusters.
[string]$my_prism_pass = "XCxwl5GlCk2bNh3V4F9HeGp+C2E8HAxc7SZKNM0O7z0=" # Use the AES password hash script for your password.
[array]$my_hashkey = (64,99,33,83,93,24,113,9,61,57,11,98,52,37,101,25,43,110,30,77,107,76,44,115,24,36,67,76,114,95,65,25) # Use the AES password hash script for your hashing key.
[array]$my_cluster_vip_addresses = @("first_cluster_ip_address","second_cluster_ip_address","third_cluster_ip_address") # Define all of your clusters by IPv4 address here!
[int]$my_rest_timeout = 5 # Define your timeout in seconds for REST API calls.
[int]$my_max_iso_retries = 5 # Define your maxim attempts to check that the NGT ISO is mounted.
[string]$my_log_directory = "c:\temp"
[bool]$my_delete_desktop_shortcut = $false # Delete desktop shortcut after installation/update: $true / $false.
[bool]$my_debug = $false # Debug mode $true / $false.
[bool]$my_dry_run = $false # Dry run mode (no installation): $true / $false.
[bool]$my_write_to_event_log = $true # Allow the script to write to the Windows Application Event Log: $true / $false. Writing to the event log will not occur if debugging is enabled.
##############################################################################
#////////////////////////////////////////////////////////////////////////////////////////////////
# CHANGE NOTHING BELOW HERE!
#////////////////////////////////////////////////////////////////////////////////////////////////
##############################################################################
[string]$my_temperract = $erroractionpreference # set error handling preferences
[string]$erroractionpreference = "stop" # set error handling preferences
[int]$ntnx_cnt = 0
[string]$my_logfile = "$($my_log_directory)\ntnx_ngt_startup.log"
if ($my_debug) { if (!(test-path -path $my_log_directory)) { new-item $my_log_directory -type directory -ea silentlycontinue | out-null }; if (test-path $my_logfile) { remove-item $my_logfile -ea silentlycontinue } }
function write-log {
    [cmdletbinding()]
    param(
        [parameter(valuefrompipeline=$true,mandatory=$true)] [validatenotnullorempty()]
        [string] $message,
        [parameter()] [validateset("Error", "Warn", "Info", "Debug")]
        [string] $level = "Info"
    )
    if ($my_write_to_event_log) {
        try {
            $eventid = 1
            $eventlogname = "Application"
            $eventsource = "Nutanix Guest Tools Installer Script"
            if (-not [diagnostics.eventlog]::sourceexists($eventsource)) { [diagnostics.eventlog]::createeventsource($eventsource, $eventlogname) }
            $log = new-object system.diagnostics.eventlog
            $log.set_log($eventlogname)
            $log.set_source($eventsource)
        }
        catch {
            write-log -message "Error Line: $($error[0].invocationinfo.scriptlinenumber)" -level error
            write-log -message "Error Code: $($error[0].invocationinfo.invocationname)" -level error
            write-log -message "Error Message: $($error[0].exception.message)" -level error
        }
    }
    $msg = '{0} : {1} : {2}' -f (get-date -format "yyyy-MM-dd HH:mm:ss"), $level.toupper(), $message
    if ($my_debug) { if (!(test-path -path $my_logfile)) {  $msg | out-file -filepath $my_logfile -force } else { $msg | out-file -filepath $my_logfile -append } }
    switch ($level) {
        "error"  { if ($my_debug) { write-host $msg -foregroundcolor red } else { $log.writeentry($message, 'Error', $eventid);  } }
        "warn"  { if ($my_debug) { write-host $msg -foregroundcolor yellow } else { $log.writeentry($message, 'Warning', $eventid);  } }
        "info"  { if ($my_debug) { write-host $msg -foregroundcolor white } else { $log.writeentry($message, 'Information', $eventid);  } }
        "debug"  { if ($my_debug) { write-host $msg -foregroundcolor cyan } else { $log.writeentry($message, 'Information', $eventid);  } }
    }
}
function create-aesmanagedobject($key, $iv) {
    $aesmanaged = new-object "system.security.cryptography.aesmanaged"
    $aesmanaged.mode = [system.security.cryptography.ciphermode]::cbc
    $aesmanaged.padding = [system.security.cryptography.paddingmode]::zeros
    $aesmanaged.blocksize = 128
    $aesmanaged.keysize = 256
    if ($iv) {
        if ($iv.gettype().name -eq "string") {
            $aesmanaged.iv = [system.convert]::frombase64string($iv)
        } else {
            $aesmanaged.iv = $iv
        }
    }
    if ($key) {
        if ($key.gettype().name -eq "string") {
            $aesmanaged.key = [system.convert]::frombase64string($key)
        } else {
            $aesmanaged.key = $key
        }
    }
    $aesmanaged
}
function decrypt-string($key, $encryptedstringwithiv) {
    $bytes = [system.convert]::frombase64string($encryptedstringwithiv)
    $iv = $bytes[0..15]
    $aesmanaged = create-aesmanagedobject $key $iv
    $decryptor = $aesmanaged.createdecryptor();
    $unencrypteddata = $decryptor.transformfinalblock($bytes, 16, $bytes.length - 16);
    $aesmanaged.clear()
    $aesmanaged.dispose()
    [system.text.encoding]::utf8.getstring($unencrypteddata).trim([char]0)
}
function isonline([string]$my_testcomputer) {
    $my_pingsuccess = $false
    try { $my_ping = new-object system.net.networkinformation.ping; $my_pingtest = $my_ping.send($my_testcomputer) }
    catch{ }
    if ($my_pingtest.status.tostring() -eq "Success") { return $true } else { return $false    }
 }
[string]$my_computername = [system.net.dns]::gethostname() # Get local hostname
if ($my_debug) {
    write-log -message "Nutanix Guest Tools Active Directory Installer Script -------- $(get-date -uformat '%m/%d/%Y %r')" -level debug
    write-log -message "Variables:" -level debug
    write-log -message " -VARS: Computer Name = $($my_computername)" -level debug
    write-log -message " -VARS: Username = $($my_prism_username)" -level debug
    write-log -message " -VARS: Write To Event Log = $($my_write_to_event_log)" -level debug
    write-log -message " -VARS: Dry Run (No installation) = $($my_dry_run)" -level debug
    write-log -message " -VARS: REST Timeout = $($my_rest_timeout)" -level debug
    write-log -message " -VARS: ISO Retries = $($my_max_iso_retries)" -level debug
    write-log -message " -VARS: Log Directory = $($my_log_directory)" -level debug
    write-log -message " -VARS: Log File = $($my_logfile)" -level debug
}
# Check that the script is running with elevated permissions.
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    write-log -message "Error Code: 0x80040005" -level error
    write-log -message "Error Message: This script must run with elevated credentials." -level error
    exit
}
# PREPARE RESTFUL API CALLS
write-log -message "Preparing to run REST API calls." -level debug
$bytes = [system.text.encoding]::ascii.getbytes("$($my_prism_username):$(decrypt-string $my_hashkey $my_prism_pass)")
$base64 = [system.convert]::tobase64string($bytes)
$basicauthvalue = "basic $base64"
$headers = @{
    'accept' = 'application/json'
    'authorization' = $basicauthvalue
    'content-type' = 'application/json'
}
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
    $certCallback = @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class ServerCertificateValidationCallback {
            public static void Ignore() {
                if(ServicePointManager.ServerCertificateValidationCallback ==null) { ServicePointManager.ServerCertificateValidationCallback += delegate ( Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors )  { return true; }; }
            }
        }
"@
    Add-Type $certCallback
 }
[servercertificatevalidationcallback]::ignore()
[net.servicepointmanager]::securityprotocol = [net.securityprotocoltype]::tls12
# Disable IE "first-run" dialog as it prevents the use of the invoke-webrequest method.
try {
    $my_keypath = 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main'
    if (!(test-path $my_keypath)) { new-item $my_keypath -force | out-null }
    if (test-path $my_keypath) { set-itemproperty -path $my_keypath -name "DisableFirstRunCustomize" -value 1 }
}
catch {
    write-log -message "Error Line: $($error[0].invocationinfo.scriptlinenumber)" -level error
    write-log -message "Error Code: $($error[0].invocationinfo.invocationname)" -level error
    write-log -message "Error Message: $($error[0].exception.message)" -level error
}
#
write-log -message "Looking for local NGT installation." -level debug
get-wmiobject -class win32_product | % { if ($_.Name -match "nutanix") { $ntnx_cnt++ } } # Check if NGT is installed.
write-log -message "Local NGT products installed: $($ntnx_cnt)" -level debug
[bool]$my_continue = $true
foreach ($cluster_vip in $my_cluster_vip_addresses) {
    # MAKE RESTFUL API CALLS TO MOUNT NGT ISO
    if (!($my_continue)) { break; }
    write-log -message "Looking for $($my_computername) on $($cluster_vip)" -level debug
    write-log -message "Checking if $($cluster_vip) is reachable..." -level debug
    if (!(isonline($cluster_vip.trim()))) { write-log -message "Cluster $($cluster_vip) is not reachable..." -level info; continue }
    $my_data = "{ ""filter"": ""vm_name==$($my_computername)"" }"
    $rest_string = "/api/nutanix/v3/vms/list"
    $restapiuri = "https://$($cluster_vip):9440$($rest_string)"
    write-log -message "REST URI: $($restapiuri)" -level debug
    write-log -message "REST Data: $($my_data)" -level debug
    write-log -message "Sending REST POST request to locate VM UUID..." -level debug
    try {
            $my_response = invoke-webrequest -uri $restapiuri -method post -body $my_data -headers $headers -timeoutsec $my_rest_timeout -credential $null
            write-log -message "Sent REST payload..." -level debug
        }
        catch {
            write-log -message "Error Line: $($error[0].invocationinfo.scriptlinenumber)" -level error
            write-log -message "Error Code: $($error[0].invocationinfo.invocationname)" -level error
            write-log -message "Error Message: $($error[0].exception.message)" -level error
        }
        $my_response = $my_response.content | convertfrom-json
        $my_ngt_response = $my_response.entities.spec | convertto-json -depth 10
        $my_vm_uuid = $my_response.entities.metadata.uuid

        if (!($my_vm_uuid)) { write-log -message "VM / $($my_computername) not found on $($cluster_vip)." -level debug; continue }
        write-log -message "Performing GET against: $($my_vm_uuid)" -level debug
        $rest_string = "/api/nutanix/v3/vms/$($my_vm_uuid)"
        $restapiuri = "https://$($cluster_vip):9440$($rest_string)"
        write-log -message "REST URI: $($restapiuri)" -level debug
        write-log -message "Sending REST GET request to collect data for $($my_vm_uuid)." -level debug
        try {
                $my_get_response = invoke-webrequest -uri $restapiuri -method get -body $null -headers $headers -timeoutsec $my_rest_timeout -credential $null
                $my_converted_get_response = $my_get_response.content | convertfrom-json
                write-log -message "Sent REST payload..." -level debug
                switch ([int]$my_get_response.statuscode) {
                    200  { write-log -message "REST Response ($($my_get_response.statuscode)) OK..." -level debug }
                    default { write-log -message "GET Response: $($my_ngt_response)" -level debug; write-log -message "Error: $($my_get_response.statuscode)" -level error }
                }
            }
            catch {
                write-log -message "Error Line: $($error[0].invocationinfo.scriptlinenumber)" -level error
                write-log -message "Error Code: $($error[0].invocationinfo.invocationname)" -level error
                write-log -message "Error Message: $($error[0].exception.message)" -level error
                break
            }
        [int]$my_spec_version = $my_converted_get_response.metadata.spec_version | convertto-json

        $my_spec_version = ($my_spec_version+1)
        write-log -message "VM UUID for $($my_computername): $($my_vm_uuid)" -level debug
        if ($my_converted_get_response.spec.resources.guest_tools) {
            write-log -message "NGT JSON configuration found. Updating..." -level debug
            $my_converted_get_response.spec.resources.guest_tools.nutanix_guest_tools.iso_mount_state = "MOUNTED"
            $my_converted_get_response.spec.resources.guest_tools.nutanix_guest_tools.state = "ENABLED"
        }
        else {
            write-log -message "NGT JSON configuration not found. Creating..." -level debug
            $my_node_to_add = "{ ""nutanix_guest_tools"":  { ""iso_mount_state"":  ""MOUNTED"", ""state"":  ""ENABLED"", ""ngt_state"":  ""UNINSTALLED"" } }"
            $my_converted_get_response.spec.resources | add-member -type noteproperty -name guest_tools -value (convertfrom-json $my_node_to_add) #add node
        }
        $my_payload = new-object -type psobject
        $my_payload | add-member -type noteproperty -name spec -value $my_converted_get_response.spec
        $my_payload | add-member -type noteproperty -name api_version -value $my_converted_get_response.api_version
        $my_payload | add-member -type noteproperty -name metadata -value $my_converted_get_response.metadata

        if (($my_vm_uuid) -and ($my_vm_uuid -ne "Not Found")) {
            $my_continue = $false
            $rest_string = "/api/nutanix/v3/vms/$($my_response.entities.metadata.uuid)"
            $restapiuri = "https://$($cluster_vip):9440$($rest_string)"
            write-log -message "REST URI: $($restapiuri)" -level debug
            $my_payload_data = ($my_payload | convertto-json -depth 20)
            try {
                $response = invoke-webrequest -uri $restapiuri -method put -body $my_payload_data -headers $headers -contenttype "application/json"
                write-log -message "Sent REST payload..." -level debug
                switch ([int]$response.statuscode) {
                    202  { write-log -message "Nutanix Guest Tools ISO mount pending..." -level info }
                    default { write-log -message "PUT Payload: $($my_ngt_response)" -level debug; write-log -message "Error: $($response.statuscode)" -level error }
                }
            }
            catch {
                write-log -message "PUT Payload: $($my_ngt_response)" -level debug;
                write-log -message "Error Line: $($error[0].invocationinfo.scriptlinenumber)" -level error
                write-log -message "Error Code: $($error[0].invocationinfo.invocationname)" -level error
                write-log -message "Error Message: $($error[0].exception.message)" -level error
                break
            }
        }
        else {
            write-log -message "Unable to find $($my_computername) on cluster $($cluster_vip)." -level info
            continue
        }

    # WAIT FOR NGT ISO TO MOUNT
    if (!($my_max_iso_retries)) { write-log -message "Maximum Retries is not set." -level error ;exit }
    $i = 0
    do {
        write-log -message "Checking for NGT ISO mount..." -level debug
        $my_driveid = (get-ciminstance win32_logicaldisk | ?{ $_.volumename -eq "nutanix_tools" }).deviceid
        if ($my_driveid) { write-log -message "Found NGT on $($my_driveid)" -level debug; break }
        $i++; start-sleep -s 5
    } while ($i -lt $my_max_iso_retries)
    # INSTALL OR UPGRADE NGT
    write-log -message "Nutanix Package Count: $($ntnx_cnt)" -level debug
    if ($ntnx_cnt -ne 6) {
        write-log -message "Nutanix Guest Tools is not installed..." -level info
        $my_driveid = (get-ciminstance win32_logicaldisk | ?{ $_.volumename -eq "nutanix_tools" }).deviceid
        $my_date = get-date -format 'MMddyyyy_HHmm'
        $my_files = @("Nutanix_Guest_Tools*")
        if ($my_driveid) {
            try {
                if (test-path "$($my_driveid)\setup.exe") {
                    if ($my_dry_run) { write-log -message "[Dry Run] - Starting Nutanix Guest Tools Installer..." -level info }
                    else { write-log -message "Starting Nutanix Guest Tools Installer..." -level info }
                    write-log -message "Running Process: $($my_driveid)\setup.exe /quiet /norestart ACCEPTEULA=YES IGNOREALLWARNINGS=yes log $($my_log_directory)\NGT\" -level debug
                    if (!($my_dry_run)) {
                        $process = start-process "$($my_driveid)\setup.exe" -windowstyle Hidden -argumentlist "/quiet /norestart ACCEPTEULA=YES IGNOREALLWARNINGS=yes log $($my_log_directory)\NGT\" -passthru -wait
                        if ($process.exitcode -eq 0) {
                            write-log -message "Installation Succeeded..." -level info; break
                        }
                        else {
                            write-log -message "Installation failed, non-zero exit code..." -level warn; break
                        }
                    }
                }
                else {
                        write-log -message "Installation failed, setup executable not found..." -level warn; break
                }
            }
            catch {
                write-log -message "Installation failed...`r`n$($_)" -level error; break
            }
            new-item -itemtype directory -force -path "$($my_log_directory)\NGT" | out-null; get-childitem -recurse ($env:temp) -include ($my_files) | move-item -destination "$($my_log_directory)\NGT\" -ea silentlycontinue
        }
        else {
            write-log -message "Installation is needed, but ISO not mounted..." -level warn; break
        }
    }
    else {
        write-log -message "Nutanix Guest Tools is already installed..." -level info
        # UPGRADE NGT
        $my_driveid = (get-ciminstance win32_logicaldisk | ?{ $_.volumename -eq "nutanix_tools" }).deviceid
        $my_files = @("Nutanix_Guest_Tools*")
        if ($my_driveid) {
            write-log -message "Checking Nutanix Guest Tools for upgrade..." -level info
            if (test-path "$($my_driveid)\setup.exe") {
                $my_setup_version = [system.diagnostics.fileversioninfo]::getversioninfo("$($my_driveid)\setup.exe").fileversion
                $registry = get-childitem "hklm:\software\wow6432node\microsoft\windows\currentversion\uninstall" -recurse
                foreach ($a in $registry) { $a.property | foreach-object { if ($a.getvalue($_) -eq "nutanix guest tools") { $my_installed_version = (get-itemproperty -path "registry::$($a.name)" -name displayversion).displayversion } } }
                if (($my_installed_version) -and ($my_setup_version)) {
                    write-log -message "Installed NGT version: $($my_installed_version) - ISO NGT version: $($my_setup_version)" -level debug
                    if ($my_setup_version -gt $my_installed_version) {
                        if ($my_dry_run) { write-log -message "[Dry Run] - Nutanix Guest Tools needs upgrading..." -level info }
                        else { write-log -message "Nutanix Guest Tools needs upgrading..." -level info }
                        write-log -message "Running Process: $($my_driveid)\setup.exe /quiet /norestart ACCEPTEULA=YES IGNOREALLWARNINGS=yes log $($my_log_directory)\NGT\" -level debug
                        if (!($my_dry_run)) {
                            $process = start-process "$($my_driveid)\setup.exe" -windowstyle hidden -argumentlist "/quiet /norestart ACCEPTEULA=YES IGNOREALLWARNINGS=yes log $($my_log_directory)\NGT\" -passthru -wait
                            if ($process.exitcode -eq 0) {
                                write-log -message "Nutanix Guest Tools upgrade succeeded." -level info; break
                              }
                            else {
                                write-log -message "Nutanix Guest Tools upgrade failed, non-zero exit code." -level warn; break
                            }
                        }
                    }
                    else {
                        write-log -message "Nutanix Guest Tools does not need Upgrading..." -level info; break
                    }
                }
                else {
                    write-log -message "Cannot get versioning information for Nutanix Guest Tools upgrade check..." -level info; break
                }
            }
        }
    }
}
if (($my_delete_desktop_shortcut) -and (test-path -path "c:\users\public\desktop\nutanix ssr.lnk")) { remove-item "c:\users\public\desktop\nutanix ssr.lnk" -force }
$erroractionpreference = $my_temperract
write-log -message "Script Completed..." -level debug
[gc]::collect()

exit
########
