<#
.SYNOPSIS
   A PowerShell script for configuring the Horizon EUC Access Gateway virtual appliance
.DESCRIPTION
   <A detailed description of the script>
.PARAMETER appliancename
	DNS Name or IP of the appliance that needs to be configured.  Mandatory
.PARAMETER adminpassword
	Password for the admin account. Mandatory
.PARAMETER GetViewConfig
   Get current configuration of the appliance
.PARAMETER SetViewConfig
	Set View Configuration. Subparameters of this parameter are:
	EnableView - Enables Horizon View connections on the appliance
	DisableView - Prevents the appliance from handling Horizon View connections
	ViewProxyDestinationURL - the DNS Hostname or IP address of a Horizon View connection server or load balanced pool of Horizon View connection servers
	ViewProxyDestinationURLThumbprints - The SSL certificate thumbprint of the Horizon View connection server or load balancer
	ViewEnablePCoIP - Enables PCoIP traffic on appliance
	ViewDisablePCoIP - Disables PCoIP traffic on appliance
	ViewPCoIPExternalIP - External/Public IP address used for PCoIP connections.  Must be an IP address.
	ViewPCoIPExternalPort - Port used for PCoIP traffic.  Defaults to 4172.  Does not need to be changed unless using a different port for PCoIP
	ViewEnableTunnel - Enables HTTPS secure tunnel.
	ViewDisableTunnel - Disables HTTPS secure tunnel
	ViewtunnelexternalURL - HTTPS URL for Secure Tunnel
	ViewEnableBlast - Enables the Blast protocol on the appliance
	ViewDisableBlast - Disables the Blast protocol on the appliance
	ViewblastExternalURL - External URL used by the Blast Protocol
	ViewBlastExternalPort - External Port used by the Blast Protocol.  Defaults to 8443
.PARAMETER GetLogBundle
	Retrieve log bundle from Appliance
.EXAMPLE
   Set-EUCGateway -appliancename 10.1.1.2 -adminpassword P@ssw0rd -GetViewConfig
.EXAMPLE
   Set-EUCGateway -appliancename 10.1.1.2 -adminpassword P@ssw0rd -SetViewConfig -ViewEnablePCoIP -ViewPCoIPExternalIP 10.1.1.3 $ViewDisableBlast
.EXAMPLE
   Set-EUCGateway -appliancename 10.1.1.2 -adminpassword P@ssw0rd -GetLogBundle -LogBundleFolder c:\temp -LogBundleName logs.zip
#>

Param
(
	[Parameter(Mandatory=$true)]$applianceName,
	[Parameter(Mandatory=$true)][String]$adminpassword,
	[Parameter(ParameterSetName="View")][switch]$GetViewConfig,
	[Parameter(ParameterSetName="View")][switch]$SetViewConfig,
	[Parameter(ParameterSetName="View")][Parameter(ParameterSetName="EnableView")][switch]$EnableView,
	[Parameter(ParameterSetName="View")][Parameter(ParameterSetName="EnableView")][switch]$DisableView,
	[Parameter(ParameterSetName="View")]$ViewproxyDestinationURL,
	[Parameter(ParameterSetName="View")]$ViewproxyDestinationURLThumbprints,
	[Parameter(ParameterSetName="View")][Parameter(ParameterSetName="EnablePCoIP")][switch]$ViewEnablePCoIP,
	[Parameter(ParameterSetName="View")][Parameter(ParameterSetName="EnablePCoIP")][switch]$ViewDisablePCoIP,
	[Parameter(ParameterSetName="View")][ValidateScript({$_ -match [IPAddress]$_ })][string]$ViewPCoIPExternalIP,
	[Parameter(ParameterSetName="View")][string]$ViewPCoIPExternalPort = "4172",
	[Parameter(ParameterSetName="View")][Parameter(ParameterSetName="EnableTunnel")][switch]$ViewEnableTunnel,
	[Parameter(ParameterSetName="View")][Parameter(ParameterSetName="EnableTunnel")][switch]$ViewDisableTunnel,
	[Parameter(ParameterSetName="View")]$ViewtunnelexternalURL,
	[Parameter(ParameterSetName="View")][Parameter(ParameterSetName="EnableBlast")][switch]$ViewEnableBlast,
	[Parameter(ParameterSetName="View")][Parameter(ParameterSetName="EnableBlast")][switch]$viewDisableBlast,
	[Parameter(ParameterSetName="View")]$ViewblastExternalURL,
	[Parameter(ParameterSetName="View")][string]$ViewBlastExternalPort = "8443",
	#[Parameter(ParameterSetName="View")]$newProxyPattern,
	
	[Parameter(ParameterSetName="vIDM")][switch]$ConfigureVIDM,
	[Parameter(ParameterSetName="Certs")][switch]$ConfigureCerts,
	[Parameter(ParameterSetName="SupportBundle")][switch]$GetLogBundle,
	[Parameter(ParameterSetName="SupportBundle")][ValidateScript({Test-Path $_ -PathType 'Container'})]$LogBundleFolder = ($env:HomeDrive + $env:HOMEPATH),
	[Parameter(ParameterSetName="SupportBundle")]$LogBundleName = $applianceName + "-logs-" + (Get-Date -Format "yyyyMMdd-HHmmss")
	)
	
Function Get-EUCAPConfig
{
	Param($applianceName,$adminpassword,$ConfigElement)
	
	$AdminUser = "admin"
	$ApplianceCred = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $Adminuser,$adminpassword
	$URI = "https://$applianceName`:9443/rest/v1/config/edgeservice/$ConfigElement"
	
	$Config = (Invoke-RestMethod -Uri $URI -Credential $ApplianceCred)

	$ApplianceCred = $Null
	Return $Config
}

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$AdminUser = "admin"
#$adminpassword = $adminpassword | ConvertTo-SecureString -AsPlainText -Force
$securestring = ConvertTo-SecureString -String $adminpassword -AsPlainText -Force
$ApplianceCred = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $Adminuser,$securestring

If($GetViewConfig)
{
	$EUCAP = Get-EUCAPConfig -applianceName $applianceName -AdminPassword $securestring -ConfigElement "VIEW"

	Write-Output $EUCAP
}

If($SetViewConfig)
{
	$EUCAP = Get-EUCAPConfig -applianceName $applianceName -adminpassword $securestring -ConfigElement "VIEW"
	
	$NewViewConfig = New-Object –TypeName PSObject
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name identifier –Value $EUCAP.identifier
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name enabled –Value $EUCAP.enabled
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name proxyDestinationUrl –Value $EUCAP.proxydestinationURL
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name proxyDestinationUrlThumbprints –Value $EUCAP.proxyDestinationURLThumbprints
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name pcoipEnabled –Value $EUCAP.pcoipEnabled
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name pcoipExternalUrl –Value $EUCAP.pcoipExternalUrl
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name tunnelEnabled –Value $EUCAP.tunnelEnabled
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name tunnelExternalUrl –Value $EUCAP.tunnelExternalUrl
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name blastEnabled –Value $EUCAP.blastEnabled
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name blastExternalUrl –Value $EUCAP.blastExternalUrl
	$NewViewConfig | Add-Member –MemberType NoteProperty –Name proxyPattern –Value $EUCAP.proxyPattern
	
	If($EnableView)
	{
		$NewViewConfig.enabled = "true"
	}	ElseIf($DisableView)
	{
		$NewViewConfig.enabled = "false"
	}
	
	If($ViewproxyDestinationURL)
	{
		$NewViewConfig.proxyDestinationUrl = $ViewproxyDestinationURL
	}
	
	If($ViewproxyDestinationURLThumbprints)
	{
		$NewViewConfig.proxyDestinationUrlThumbprints = $ViewproxyDestinationURLThumbprints
	}
	
	If($ViewEnablePCoIP)
	{
		$NewViewConfig.pcoipEnabled = "true"
	}ElseIf($ViewDisablePCoIP)
	{
		$NewViewConfig.pcoipEnabled = "false"
	}
	
	If($ViewPCoIPExternalIP)
	{
		$NewViewConfig.pcoipExternalUrl = $ViewPCoIPExternalIP + ":" + $ViewPCoIPExternalPort
	}
	
	If($ViewEnableTunnel)
	{
		$NewViewConfig.tunnelEnabled = "true"
	}ElseIf($ViewDisableTunnel)
	{
		$NewViewConfig.tunnelEnabled = "false"
	}
	
	If($ViewtunnelexternalURL)
	{
		$NewViewConfig.tunnelExternalUrl = $ViewtunnelexternalURL
	}
	
	If($ViewEnableBlast)
	{
		$NewViewConfig.blastEnabled = "true"
	}ElseIf($ViewDisableBlast)
	{
		$NewViewConfig.blastEnabled = "false"
	}
	
	If($ViewblastExternalURL)
	{
		$NewViewConfig.blastExternalUrl = $ViewblastExternalURL + ":" + $ViewBlastExternalPort
	}
	
	$json = $NewViewConfig | ConvertTo-Json
	
	try {Invoke-WebRequest -Uri https://$applianceName`:9443/rest/v1/config/edgeservice/view/ -Credential $ApplianceCred -Method Put -Body $json -ContentType 'application/json'} Catch {$exception = $_.exception.response}
		
	If($exception -eq $null)
	{
		$OutputConfig = Get-EUCAPConfig -applianceName $applianceName -adminpassword $securestring -ConfigElement "VIEW"
	
		Write-Output "Configuration Successful."
		Write-Output $OutputConfig
	}Else
	{		
		Write-Output "An Exception Occurred."
		Write-Output $exception
		
		Write-Output "For more details, please review the admin log file by downloading a log bundle using the following command: "
		Write-Output "Set-EUCGateway -appliancename $appliancename -adminpassword $adminpassword -GetLogBundle"

	}
}

If($ConfigureCerts)
{
	Write-Output "This feature is not supported yet."
}

If($ConfigureVIDM)
{
	Write-Output "This feature is not supported yet."
}

If($GetLogBundle)
{
	$Path = $LogBundleFolder + "$LogBundleName.zip"
	
	$TestPath = Test-Path $Path
	
	If($TestPath -eq $false)
	{
		Invoke-RestMethod -Uri https://$applianceName`:9443/rest/v1/monitor/support-archive -Credential $ApplianceCred -Outfile $Path
	
		Invoke-Item -Path $Path
	}
	Else
	{
		Write-Output "File Exists. Please select a new filename and rerun the script, or omit the -LogBundleName parameter to use the default."
		Exit
	}
}