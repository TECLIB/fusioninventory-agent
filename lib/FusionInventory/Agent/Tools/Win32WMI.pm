package Win32WMI;
use strict;
use warnings FATAL => 'all';

use Win32::OLE;
use Win32::OLE::Variant;
use Win32::Registry;

use FusionInventory::Agent::Logger::File;

use Data::Dumper;

sub getRegistryValueFromWMI {
    my (%params) = @_;

    FusionInventory::Agent::Logger::File->require();

    my $hkey;
    if ($params{root} =~ /^HKEY_LOCAL_MACHINE(?:\\|\/)(.*)$/) {
        $hkey = $Win32::Registry::HKEY_LOCAL_MACHINE;
        my $keyName = $1 . '/' . $params{keyName};
        $keyName =~ tr#/#\\#;
        $params{keyName} = $keyName;
    }
    my $dd = Data::Dumper->new([\%params, \$hkey]);
    $params{logger}->debug2($dd->Dump) if $params{logger};

    my $WMIService = connectToService(
        $params{WMIService}->{hostname},
        $params{WMIService}->{user},
        $params{WMIService}->{pass},
        "root\\default"
    );
    if (!$WMIService) {
        $params{logger}->debug2('WMIService is not defined!') if $params{logger};
        return;
    }
    my $objReg = $WMIService->Get("StdRegProv");
    if (!$objReg) {
        $params{logger}->debug2('objReg is not defined!') if $params{logger};
        return;
    }
    #    Win32::OLE::Variant->use(qw/VT_BYREF VT_BSTR/);
    #    Win32::OLE::Variant->require();
    my $result = Win32::OLE::Variant->new(Win32::OLE::Variant::VT_BYREF()|Win32::OLE::Variant::VT_BSTR(),0);
    $params{logger}->debug2('result variant created') if $params{logger};
    my $return = $objReg->GetStringValue($hkey, $params{keyName}, $params{valueName}, $result);
    return $result;
}

sub connectToService {
    my ( $hostname, $user, $pass, $root ) = @_;

    my $locator = Win32::OLE->CreateObject('WbemScripting.SWbemLocator')
        or warn;
    my $service =
        $locator->ConnectServer( $hostname, $root, "domain\\" . $user,
            $pass );

    return $service;
}

1;