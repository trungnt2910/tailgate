tailgate_resource_string(Brand_ProductName VALUE [[Tailgate]])

tailgate_resource_string(Common_Cancel VALUE [[Cancel]])
tailgate_resource_string(Common_Close VALUE [[Close]])
tailgate_resource_string(Common_Connected VALUE [[Connected]])
tailgate_resource_string(Common_Disabled VALUE [[Disabled]])
tailgate_resource_string(Common_Dismiss VALUE [[Dismiss]])
tailgate_resource_string(Common_NotConnected VALUE [[Not connected]])
tailgate_resource_string(Common_Offline VALUE [[Offline]])

tailgate_resource_string(Home_AccountAutomationName VALUE [[Account]])
tailgate_resource_string(Home_Connect VALUE [[Connect]])
tailgate_resource_format_string(
    Home_ConnectDescription
    ARITY 1
    VALUE [[Connect again to talk to the other devices in the {0} tailnet.]]
)
tailgate_resource_string(Home_ConnectedStatus VALUE [[Connected]])
tailgate_resource_string(Home_CopyIpAddress VALUE [[Copy IP Address]])
tailgate_resource_string(Home_Disable VALUE [[Disable]])
tailgate_resource_string(Home_Enable VALUE [[Enable]])
tailgate_resource_string(Home_ExitNodeLabel VALUE [[EXIT NODE]])
tailgate_resource_string(Home_ExitNodeOfflineLabel VALUE [[EXIT NODE OFFLINE]])
tailgate_resource_string(Home_LogIn VALUE [[Log in]])
tailgate_resource_string(
    Home_LogInDescription
    VALUE [[Log in to join your tailnet and connect your devices.]]
)
tailgate_resource_string(Home_LoggingOutStatus VALUE [[Logging out…]])
tailgate_resource_string(Home_None VALUE [[None]])
tailgate_resource_string(Home_OtherDevices VALUE [[Other devices]])
tailgate_resource_string(Home_Ping VALUE [[Ping]])
tailgate_resource_string(Home_SearchPlaceholder VALUE [[Search...]])
tailgate_resource_string(Home_StartingStatus VALUE [[Starting…]])
tailgate_resource_string(Home_StoppingStatus VALUE [[Stopping…]])
tailgate_resource_string(Home_Welcome VALUE [[Welcome to Tailgate]])

tailgate_resource_string(Accounts_PageTitle VALUE [[Accounts]])
tailgate_resource_string(Accounts_LogOut VALUE [[Log out]])

tailgate_resource_string(Settings_About VALUE [[About Tailgate]])
tailgate_resource_string(
    Settings_AdminConsoleDescription
    VALUE [[Manage your tailnet settings in the admin console]]
)
tailgate_resource_string(Settings_BugReport VALUE [[Bug report]])
tailgate_resource_string(Settings_NotConfigured VALUE [[Not configured]])
tailgate_resource_string(Settings_NotSignedIn VALUE [[Not signed in]])
tailgate_resource_string(Settings_PageTitle VALUE [[Settings]])
tailgate_resource_string(Settings_Server VALUE [[Tailgate server]])
tailgate_resource_format_string(Settings_Version ARITY 1 VALUE [[Version {0}]])

tailgate_resource_string(SignIn_Advanced VALUE [[Advanced]])
tailgate_resource_string(SignIn_AuthKeyHeader VALUE [[Auth Key (optional)]])
tailgate_resource_string(SignIn_AuthKeyPlaceholder VALUE [[tskey-auth-...]])
tailgate_resource_string(SignIn_HostnameHeader VALUE [[Hostname (optional)]])
tailgate_resource_string(SignIn_ServerExample VALUE [[relay.example.ts.net:10000]])
tailgate_resource_string(SignIn_ServerRequired VALUE [[A Tailgate server is required.]])
tailgate_resource_string(SignIn_Title VALUE [[Sign in]])

tailgate_resource_string(
    Authorization_ApprovalInstructions
    VALUE [[Scan this QR code to open the device approval page]]
)
tailgate_resource_string(
    Authorization_ApprovalRequiredTitle
    VALUE [[Admin approval required]]
)
tailgate_resource_string(
    Authorization_AuthorizationCodeInstructions
    VALUE [[or enter this code in the Machines > Add device section of the admin console:]]
)
tailgate_resource_string(
    Authorization_FallbackInstructions
    VALUE [[Open the authorization page to continue:]]
)
tailgate_resource_string(
    Authorization_LoginInstructions
    VALUE [[Scan this QR code to log in to your tailnet]]
)
tailgate_resource_string(Authorization_LoginRequiredTitle VALUE [[Log in to your tailnet]])
tailgate_resource_string(Authorization_OpenApprovalPage VALUE [[Open Approval Page]])
tailgate_resource_string(Authorization_OpenLoginPage VALUE [[Open Login Page]])

tailgate_resource_string(Device_Ipv4 VALUE [[IPv4]])
tailgate_resource_string(Device_Ipv6 VALUE [[IPv6]])
tailgate_resource_string(Device_MagicDns VALUE [[MagicDNS]])
tailgate_resource_string(Device_OperatingSystem VALUE [[OS]])
tailgate_resource_string(Device_TailscaleAddresses VALUE [[Tailscale addresses]])

tailgate_resource_string(ExitNode_ChooseTitle VALUE [[Choose exit node]])
tailgate_resource_string(ExitNode_None VALUE [[None]])
tailgate_resource_string(ExitNode_RunAsExitNode VALUE [[Run as exit node]])

tailgate_resource_string(Ping_DirectConnection VALUE [[Direct connection]])
tailgate_resource_format_string(Ping_Milliseconds ARITY 1 VALUE [[{0} ms]])
tailgate_resource_string(Ping_NoMatchingPeer VALUE [[No matching peer]])
tailgate_resource_string(Ping_PingFailed VALUE [[Ping failed]])
tailgate_resource_format_string(Ping_Pinging ARITY 1 VALUE [[Pinging {0}]])
tailgate_resource_format_string(
    Ping_RelayedConnection
    ARITY 1
    VALUE [[Relayed connection ({0})]]
)
tailgate_resource_format_string(
    Ping_RequestTimedOut
    ARITY 1
    VALUE [[Request timed out. Make sure that '{0}' is online.]]
)
tailgate_resource_format_string(
    Ping_LocalAddress
    ARITY 1
    VALUE [[{0} is local Tailscale IP]]
)

tailgate_resource_string(Error_ConnectionCancelled VALUE [[VPN connection cancelled.]])
tailgate_resource_string(Error_DeviceApprovalRequired VALUE [[This device must be approved.]])
tailgate_resource_string(
    Error_DeviceAuthorizationRequired
    VALUE [[This device must be authorized.]]
)
tailgate_resource_string(Error_ExitNodeFailed VALUE [[The exit node could not be changed.]])
tailgate_resource_string(
    Error_ExitNodeRejected
    VALUE [[The requested exit node is no longer available.]]
)
tailgate_resource_string(
    Error_PreviousConnectionRestoreFailed
    VALUE [[The previous connection could not be restored.]]
)
tailgate_resource_string(Error_RelayConnectionFailed VALUE [[Tailgate relay connection failed.]])
tailgate_resource_string(
    Error_Unexpected
    VALUE [[An unknown error occurred. Please try again.]]
)
tailgate_resource_string(
    Error_VpnAddressUnavailable
    VALUE [[The VPN address is unavailable; reconnect Tailgate and try again.]]
)
tailgate_resource_string(
    Error_VpnBackgroundRestartTimedOut
    VALUE [[Windows did not restart the background VPN channel in time.]]
)
tailgate_resource_string(
    Error_VpnDisconnectFailed
    VALUE [[Tailgate could not disconnect the VPN profile.]]
)
tailgate_resource_string(
    Error_VpnLogoutFailed
    VALUE [[Tailgate could not remove the VPN profile.]]
)
tailgate_resource_string(
    Error_VpnProfileDidNotConnect
    VALUE [[The VPN profile did not connect.]]
)
tailgate_resource_string(
    Error_VpnProfileOperationFailed
    VALUE [[Windows could not update the VPN profile.]]
)
tailgate_resource_string(
    Error_VpnProfileTransitionTimedOut
    VALUE [[The VPN profile did not finish changing state in time.]]
)
tailgate_resource_string(
    Error_VpnServerInvalid
    VALUE [[Tailgate server must be an HTTPS URL.]]
)
tailgate_resource_string(Error_VpnServerRequired VALUE [[Tailgate server is required.]])
