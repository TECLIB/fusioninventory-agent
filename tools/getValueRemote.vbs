if WScript.Arguments.Count < 5 then
    WScript.Echo "getValueRemote : Missing parameters"
	Wscript.Quit
end if

hostname = Wscript.Arguments(0)
user = Wscript.Arguments(1)
pass = Wscript.Arguments(2)
keyPath = Wscript.Arguments(3)
valueName = Wscript.Arguments(4)

domain = "root\default"

WScript.Echo hostname
WScript.Echo domain
WScript.Echo user
WScript.Echo pass
WScript.Echo keyPath
WScript.Echo valueName

wbemImpersonationLevelImpersonate = 3
wbemAuthenticationLevelPktPrivacy = 6

Const HKLM = &h80000002
Const HKEY_CURRENT_USER = &H80000001

Set objLocator = CreateObject("WbemScripting.SWbemLocator")
Set objService = objLocator.ConnectServer _
(hostname, domain, user, pass)
objService.Security_.ImpersonationLevel = wbemImpersonationLevelImpersonate
objservice.Security_.AuthenticationLevel = wbemAuthenticationLevelPktPrivacy
Set objStdRegProv = objService.Get("StdRegProv")

objStdRegProv.GetDWORDValue HKLM, keyPath, valueName, dwValue
Wscript.Echo dwValue
