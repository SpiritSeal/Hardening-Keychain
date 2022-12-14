# Make sure to set-executionpolicy unrestricted

#Headers
#Requires -RunAsAdministrator

$option = Read-Host '
1. Autos
2. Services
3. Firefox
4. Audit Policies
'

if ($option -eq 1) {
    $RM = Read-Host 'Have you done the FQs yet? (y/n)'
    if (-not ($RM -eq 'y') ){
        Write-Error "Do the FQs first"
        pause
        exit
    }

    #Meat and Potatoes
    Write-Warning "Config Anti-Rootkit Scan now, come back later"
    ./Antivirus/mbar/mbar.exe
    pause

    Write-Warning "Grab Hosts"
    cat "C:\Windows\System32\drivers\etc\hosts" >> hosts.txt
    Write-Warning "Grab Shares"
    net share >> tempFolder/shares.txt
    Write-Warning "Flush DNS"
    ipconfig /flushdns


    Write-Warning "Reset Firewall to default config"
    netsh advfirewall reset


    #Major Commands
    Write-Warning "Reset All Passwords to Asecurepassword123!"
    Get-WmiObject win32_useraccount | Foreach-object {
        ([adsi]("WinNT://" + $_.caption).replace("\", "/")).SetPassword("Asecurepassword123!")
    }


    Write-Warning "Audit Policies"
    #localpolicies-audit policies
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"DS Access" /success:enable /failure:enable
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    auditpol /set /category:"Policy Change" /success:enable
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable
    #auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
    auditpol /set /category:"System" /success:enable

    Write-Warning "Install Malwarebytes"
    ./Antivirus/MBSetup.exe

    Write-Warning "disabling Guest and Admin account"
    Get-LocalUser Guest | Disable-LocalUser
    Get-LocalUser Administrator | Disable-LocalUser

    # Scan the entire disk (Async)
    sfc /scannow
}

if ($option -eq 2) {

}

if ($option -eq 3) {
    "Configuring Firefox"
    $folder = "C:\Program Files\Mozilla Firefox\defaults\pref"
    if (-not (Test-Path -Path $Folder)) {
        "Firefox not installed to default directory"
    }
}


if ($option -eq 101) {
    "Bulk Services"
    sc.exe stop tlntsvr
    sc.exe config tlntsvr start= disabled
    sc.exe stop msftpsvc
    sc.exe config msftpsvc start= disabled
    sc.exe stop snmptrap
    sc.exe config snmptrap start= disabled
    sc.exe stop ssdpsrv
    sc.exe config ssdpsrv start= disabled
    sc.exe stop termservice
    sc.exe config termservice start= disabled
    sc.exe stop sessionenv
    sc.exe config sessionenv start= disabled
    sc.exe stop remoteregistry
    sc.exe config remoteregistry start= disabled
    sc.exe stop Messenger
    sc.exe config Messenger start= disabled
    sc.exe stop upnphos
    sc.exe config upnphos start= disabled
    sc.exe stop WAS
    sc.exe config WAS start= disabled
    sc.exe stop RemoteAccess
    sc.exe config RemoteAccess start= disabled
    sc.exe stop mnmsrvc
    sc.exe config mnmsrvc start= disabled
    sc.exe stop NetTcpPortSharing
    sc.exe config NetTcpPortSharing start= disabled
    sc.exe stop RasMan
    sc.exe config RasMan start= disabled
    sc.exe stop TabletInputService
    sc.exe config TabletInputService start= disabled
    sc.exe stop RpcSs
    sc.exe config RpcSs start= disabled
    sc.exe stop SENS
    sc.exe config SENS start= disabled
    sc.exe stop EventSystem
    sc.exe config EventSystem start= disabled
    sc.exe stop XblAuthManager
    sc.exe config XblAuthManager start= disabled
    sc.exe stop XblGameSave
    sc.exe config XblGameSave start= disabled
    sc.exe stop XboxGipSvc
    sc.exe config XboxGipSvc start= disabled
    sc.exe stop xboxgip
    sc.exe config xboxgip start= disabled
    sc.exe stop xbgm
    sc.exe config xbgm start= disabled
    sc.exe stop SysMain
    sc.exe config SysMain start= disabled
    sc.exe stop seclogon
    sc.exe config seclogon start= disabled
    sc.exe stop TapiSrv
    sc.exe config TapiSrv start= disabled
    sc.exe stop p2pimsvc
    sc.exe config p2pimsvc start= disabled
    sc.exe stop simptcp
    sc.exe config simptcp start= disabled
    sc.exe stop fax
    sc.exe config fax start= disabled
    sc.exe stop Msftpsvc
    sc.exe config Msftpsvc start= disabled
    sc.exe stop iprip
    sc.exe config iprip start= disabled
    sc.exe stop ftpsvc
    sc.exe config ftpsvc start= disabled
    sc.exe stop RasAuto
    sc.exe config RasAuto start= disabled
    sc.exe stop W3svc
    sc.exe config W3svc start= disabled
    sc.exe stop Smtpsvc
    sc.exe config Smtpsvc start= disabled
    sc.exe stop Dfs
    sc.exe config Dfs start= disabled
    sc.exe stop TrkWks
    sc.exe config TrkWks start= disabled
    sc.exe stop MSDTC
    sc.exe config MSDTC start= disabled
    sc.exe stop ERSvc
    sc.exe config ERSvc start= disabled
    sc.exe stop NtFrs
    sc.exe config NtFrs start= disabled
    sc.exe stop Iisadmin
    sc.exe config Iisadmin start= disabled
    sc.exe stop IsmServ
    sc.exe config IsmServ start= disabled
    sc.exe stop WmdmPmSN
    sc.exe config WmdmPmSN start= disabled
    sc.exe stop helpsvc
    sc.exe config helpsvc start= disabled
    sc.exe stop Spooler
    sc.exe config Spooler start= disabled
    sc.exe stop RDSessMgr
    sc.exe config RDSessMgr start= disabled
    sc.exe stop RSoPProv
    sc.exe config RSoPProv start= disabled
    sc.exe stop SCardSvr
    sc.exe config SCardSvr start= disabled
    sc.exe stop lanmanserver
    sc.exe config lanmanserver start= disabled
    sc.exe stop Sacsvr
    sc.exe config Sacsvr start= disabled
    sc.exe stop TermService
    sc.exe config TermService start= disabled
    sc.exe stop uploadmgr
    sc.exe config uploadmgr start= disabled
    sc.exe stop VDS
    sc.exe config VDS start= disabled
    sc.exe stop VSS
    sc.exe config VSS start= disabled
    sc.exe stop WINS
    sc.exe config WINS start= disabled
    sc.exe stop CscService
    sc.exe config CscService start= disabled
    sc.exe stop hidserv
    sc.exe config hidserv start= disabled
    sc.exe stop IPBusEnum
    sc.exe config IPBusEnum start= disabled
    sc.exe stop PolicyAgent
    sc.exe config PolicyAgent start= disabled
    sc.exe stop SCPolicySvc
    sc.exe config SCPolicySvc start= disabled
    sc.exe stop SharedAccess
    sc.exe config SharedAccess start= disabled
    sc.exe stop SSDPSRV
    sc.exe config SSDPSRV start= disabled
    sc.exe stop Themes
    sc.exe config Themes start= disabled
    sc.exe stop upnphost
    sc.exe config upnphost start= disabled
    sc.exe stop nfssvc
    sc.exe config nfssvc start= disabled
    sc.exe stop nfsclnt
    sc.exe config nfsclnt start= disabled
    sc.exe stop MSSQLServerADHelper
    sc.exe config MSSQLServerADHelper start= disabled
    sc.exe stop SharedAccess
    sc.exe config SharedAccess start= disabled
    sc.exe stop UmRdpService
    sc.exe config UmRdpService start= disabled
    sc.exe stop SessionEnv
    sc.exe config SessionEnv start= disabled
    sc.exe stop Server
    sc.exe config Server start= disabled
    sc.exe stop TeamViewer
    sc.exe config TeamViewer start= disabled
    sc.exe stop TeamViewer7
    sc.exe config start= disabled
    sc.exe stop HomeGroupListener
    sc.exe config HomeGroupListener start= disabled
    sc.exe stop HomeGroupProvider
    sc.exe config HomeGroupProvider start= disabled
    sc.exe stop AxInstSV
    sc.exe config AXInstSV start= disabled
    sc.exe stop Netlogon
    sc.exe config Netlogon start= disabled
    sc.exe stop lltdsvc
    sc.exe config lltdsvc start= disabled
    sc.exe stop iphlpsvc
    sc.exe config iphlpsvc start= disabled
    sc.exe stop AdobeARMservice
    sc.exe config AdobeARMservice start= disabled

    #goodservices
    sc.exe start wuauserv
    sc.exe config wuauserv start= auto
    sc.exe start EventLog
    sc.exe config EventLog start= auto
    sc.exe start MpsSvc
    sc.exe config MpsSvc start= auto
    sc.exe start WinDefend
    sc.exe config WinDefend start= auto
    sc.exe start WdNisSvc
    sc.exe config WdNisSvc start= auto
    sc.exe start Sense
    sc.exe config Sense start= auto
    sc.exe start Schedule
    sc.exe config Schedule start= auto
    sc.exe start SCardSvr
    sc.exe config SCardSvr start= auto
    sc.exe start ScDeviceEnum
    sc.exe config ScDeviceEnum start= auto
    sc.exe start SCPolicySvc
    sc.exe config SCPolicySvc start= auto
    sc.exe start wscsvc
    sc.exe config wscsvc start= auto
}
if ($option -eq 102) {
    "Bulk Features"
    dism /online /disable-feature /featurename:IIS-WebServerRole
    dism /online /disable-feature /featurename:IIS-WebServer
    dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
    dism /online /disable-feature /featurename:IIS-HttpErrors
    dism /online /disable-feature /featurename:IIS-HttpRedirect
    dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
    dism /online /disable-feature /featurename:IIS-NetFxExtensibility
    dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
    dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
    dism /online /disable-feature /featurename:IIS-HttpLogging
    dism /online /disable-feature /featurename:IIS-LoggingLibraries
    dism /online /disable-feature /featurename:IIS-RequestMonitor
    dism /online /disable-feature /featurename:IIS-HttpTracing
    dism /online /disable-feature /featurename:IIS-Security
    dism /online /disable-feature /featurename:IIS-URLAuthorization
    dism /online /disable-feature /featurename:IIS-RequestFiltering
    dism /online /disable-feature /featurename:IIS-IPSecurity
    dism /online /disable-feature /featurename:IIS-Performance
    dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
    dism /online /disable-feature /featurename:IIS-WebServerManagementTools
    dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
    dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
    dism /online /disable-feature /featurename:IIS-Metabase
    dism /online /disable-feature /featurename:IIS-HostableWebCore
    dism /online /disable-feature /featurename:IIS-StaticContent
    dism /online /disable-feature /featurename:IIS-DefaultDocument
    dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
    dism /online /disable-feature /featurename:IIS-WebDAV
    dism /online /disable-feature /featurename:IIS-WebSockets
    dism /online /disable-feature /featurename:IIS-ApplicationInit
    dism /online /disable-feature /featurename:IIS-ASPNET
    dism /online /disable-feature /featurename:IIS-ASPNET45
    dism /online /disable-feature /featurename:IIS-ASP
    dism /online /disable-feature /featurename:IIS-CGI 
    dism /online /disable-feature /featurename:IIS-ISAPIExtensions
    dism /online /disable-feature /featurename:IIS-ISAPIFilter
    dism /online /disable-feature /featurename:IIS-ServerSideIncludes
    dism /online /disable-feature /featurename:IIS-CustomLogging
    dism /online /disable-feature /featurename:IIS-BasicAuthentication
    dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
    dism /online /disable-feature /featurename:IIS-ManagementConsole
    dism /online /disable-feature /featurename:IIS-ManagementService
    dism /online /disable-feature /featurename:IIS-WMICompatibility
    dism /online /disable-feature /featurename:IIS-LegacyScripts
    dism /online /disable-feature /featurename:IIS-LegacySnapIn
    dism /online /disable-feature /featurename:IIS-FTPServer
    dism /online /disable-feature /featurename:IIS-FTPSvc
    dism /online /disable-feature /featurename:IIS-FTPExtensibility
    dism /online /disable-feature /featurename:TFTP
    dism /online /disable-feature /featurename:TelnetClient
    dism /online /disable-feature /featurename:TelnetServer
    dism /online /disable-feature /featurename:"SMB1Protocol"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

if ($option -eq 99) {
    "Backup Account Policies"
    net accounts /UNIQUEPW:24 /MAXPWAGE:60 /MINPWAGE:1 /MINPWLEN:12 /lockoutthreshold:5
}