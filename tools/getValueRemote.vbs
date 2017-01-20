wbemImpersonationLevelImpersonate = 3
wbemAuthenticationLevelPktPrivacy = 6

Const HKLM = &h80000002
Const HKEY_CURRENT_USER = &H80000001

if WScript.Arguments.Count < 5 then
    WScript.Echo "getValueRemote : Missing parameters"
	WScript.Quit
end if

hostname = WScript.Arguments(0)
user = WScript.Arguments(1)
pass = WScript.Arguments(2)
keyPath = WScript.Arguments(3)
valueName = WScript.Arguments(4)

domain = "root\default"

WScript.Echo hostname
WScript.Echo domain
WScript.Echo user
WScript.Echo pass
WScript.Echo keyPath
WScript.Echo valueName

Set objLocator = CreateObject("WbemScripting.SWbemLocator")
Set objService = objLocator.ConnectServer _
(hostname, domain, user, pass)

objService.Security_.ImpersonationLevel = wbemImpersonationLevelImpersonate
objService.Security_.AuthenticationLevel = wbemAuthenticationLevelPktPrivacy
Set objStdRegProv = objService.Get("StdRegProv")

objStdRegProv.GetDWORDValue HKLM, keyPath, valueName, dwValue
Wscript.Echo dwValue
