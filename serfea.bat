    sc stop tlntsvr
    sc config tlntsvr start= disabled
    sc stop msftpsvc
    sc config msftpsvc start= disabled
    sc stop snmptrap
    sc config snmptrap start= disabled
    sc stop ssdpsrv
    sc config ssdpsrv start= disabled
    sc stop termservice
    sc config termservice start= disabled
    sc stop sessionenv
    sc config sessionenv start= disabled
    sc stop remoteregistry
    sc config remoteregistry start= disabled
    sc stop Messenger
    sc config Messenger start= disabled
    sc stop upnphos
    sc config upnphos start= disabled
    sc stop WAS
    sc config WAS start= disabled
    sc stop RemoteAccess
    sc config RemoteAccess start= disabled
    sc stop mnmsrvc
    sc config mnmsrvc start= disabled
    sc stop NetTcpPortSharing
    sc config NetTcpPortSharing start= disabled
    sc stop RasMan
    sc config RasMan start= disabled
    sc stop TabletInputService
    sc config TabletInputService start= disabled
    sc stop RpcSs
    sc config RpcSs start= disabled
    sc stop SENS
    sc config SENS start= disabled
    sc stop EventSystem
    sc config EventSystem start= disabled
    sc stop XblAuthManager
    sc config XblAuthManager start= disabled
    sc stop XblGameSave
    sc config XblGameSave start= disabled
    sc stop XboxGipSvc
    sc config XboxGipSvc start= disabled
    sc stop xboxgip
    sc config xboxgip start= disabled
    sc stop xbgm
    sc config xbgm start= disabled
    sc stop SysMain
    sc config SysMain start= disabled
    sc stop seclogon
    sc config seclogon start= disabled
    sc stop TapiSrv
    sc config TapiSrv start= disabled
    sc stop p2pimsvc
    sc config p2pimsvc start= disabled
    sc stop simptcp
    sc config simptcp start= disabled
    sc stop fax
    sc config fax start= disabled
    sc stop Msftpsvc
    sc config Msftpsvc start= disabled
    sc stop iprip
    sc config iprip start= disabled
    sc stop ftpsvc
    sc config ftpsvc start= disabled
    sc stop RasAuto
    sc config RasAuto start= disabled
    sc stop W3svc
    sc config W3svc start= disabled
    sc stop Smtpsvc
    sc config Smtpsvc start= disabled
    sc stop Dfs
    sc config Dfs start= disabled
    sc stop TrkWks
    sc config TrkWks start= disabled
    sc stop MSDTC
    sc config MSDTC start= disabled
    sc stop ERSvc
    sc config ERSvc start= disabled
    sc stop NtFrs
    sc config NtFrs start= disabled
    sc stop Iisadmin
    sc config Iisadmin start= disabled
    sc stop IsmServ
    sc config IsmServ start= disabled
    sc stop WmdmPmSN
    sc config WmdmPmSN start= disabled
    sc stop helpsvc
    sc config helpsvc start= disabled
    sc stop Spooler
    sc config Spooler start= disabled
    sc stop RDSessMgr
    sc config RDSessMgr start= disabled
    sc stop RSoPProv
    sc config RSoPProv start= disabled
    sc stop SCardSvr
    sc config SCardSvr start= disabled
    sc stop lanmanserver
    sc config lanmanserver start= disabled
    sc stop Sacsvr
    sc config Sacsvr start= disabled
    sc stop TermService
    sc config TermService start= disabled
    sc stop uploadmgr
    sc config uploadmgr start= disabled
    sc stop VDS
    sc config VDS start= disabled
    sc stop VSS
    sc config VSS start= disabled
    sc stop WINS
    sc config WINS start= disabled
    sc stop CscService
    sc config CscService start= disabled
    sc stop hidserv
    sc config hidserv start= disabled
    sc stop IPBusEnum
    sc config IPBusEnum start= disabled
    sc stop PolicyAgent
    sc config PolicyAgent start= disabled
    sc stop SCPolicySvc
    sc config SCPolicySvc start= disabled
    sc stop SharedAccess
    sc config SharedAccess start= disabled
    sc stop SSDPSRV
    sc config SSDPSRV start= disabled
    sc stop Themes
    sc config Themes start= disabled
    sc stop upnphost
    sc config upnphost start= disabled
    sc stop nfssvc
    sc config nfssvc start= disabled
    sc stop nfsclnt
    sc config nfsclnt start= disabled
    sc stop MSSQLServerADHelper
    sc config MSSQLServerADHelper start= disabled
    sc stop SharedAccess
    sc config SharedAccess start= disabled
    sc stop UmRdpService
    sc config UmRdpService start= disabled
    sc stop SessionEnv
    sc config SessionEnv start= disabled
    sc stop Server
    sc config Server start= disabled
    sc stop TeamViewer
    sc config TeamViewer start= disabled
    sc stop TeamViewer7
    sc config start= disabled
    sc stop HomeGroupListener
    sc config HomeGroupListener start= disabled
    sc stop HomeGroupProvider
    sc config HomeGroupProvider start= disabled
    sc stop AxInstSV
    sc config AXInstSV start= disabled
    sc stop Netlogon
    sc config Netlogon start= disabled
    sc stop lltdsvc
    sc config lltdsvc start= disabled
    sc stop iphlpsvc
    sc config iphlpsvc start= disabled
    sc stop AdobeARMservice
    sc config AdobeARMservice start= disabled

    sc start wuauserv
    sc config wuauserv start= auto
    sc start EventLog
    sc config EventLog start= auto
    sc start MpsSvc
    sc config MpsSvc start= auto
    sc start WinDefend
    sc config WinDefend start= auto
    sc start WdNisSvc
    sc config WdNisSvc start= auto
    sc start Sense
    sc config Sense start= auto
    sc start Schedule
    sc config Schedule start= auto
    sc start SCardSvr
    sc config SCardSvr start= auto
    sc start ScDeviceEnum
    sc config ScDeviceEnum start= auto
    sc start SCPolicySvc
    sc config SCPolicySvc start= auto
    sc start wscsvc
    sc config wscsvc start= auto


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