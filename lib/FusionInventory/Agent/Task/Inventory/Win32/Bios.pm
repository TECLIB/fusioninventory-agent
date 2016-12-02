package FusionInventory::Agent::Task::Inventory::Win32::Bios;

use strict;
use warnings;

use English qw(-no_match_vars);

use FusionInventory::Agent::Tools::Win32;

# Only run this module if dmidecode has not been found
our $runMeIfTheseChecksFailed =
    ["FusionInventory::Agent::Task::Inventory::Generic::Dmidecode::Bios"];

sub isEnabled {
    return 1;
}

sub _dateFromIntString {
    my ($string, $logger) = @_;

    $logger->debug2('_dateFromIntString() param : ' . $string);
    if ($string && $string =~ /^(\d{4})(\d{2})(\d{2})/) {
        return "$2/$3/$1";
    } elsif ($string && $string =~ /^(\d{2})\/(\d{2})\/(\d{4})/) {
        return $1 . '/' . $2 . '/' . $3;
    }

    return $string;
}

sub doInventory {
    my (%params) = @_;

    my $inventory = $params{inventory};
    my $logger    = $params{logger};

    my $wmiParams = {};
    $wmiParams->{WMIService} = $params{inventory}->{WMIService} ? $params{inventory}->{WMIService} : undef;
    $logger->debug2('call of getRegistryValue');
    my $path = "HKEY_LOCAL_MACHINE/Hardware/Description/System/BIOS/BIOSReleaseDate";
    my $value;
    if ($wmiParams->{WMIService}) {
        my @values = getRegistryValueFromWMI(
            path => $path,
            logger => $logger,
            %$wmiParams
        );
        my $value = $values[0];
    } else {
        $value = getRegistryValue(
            path   => $path,
            logger => $logger,
            %$wmiParams
        );
    }
    my $bDate = _dateFromIntString($value, $logger);
    $logger->debug2( 'bDate now' );
    $logger->debug2( $bDate );
    $logger->debug2( 'bDate end' );
    my $bios = {
        BDATE => $bDate
    };

    $bios = appendBiosDataFromWMI(bios => $bios);

    $inventory->setBios($bios);

    SWITCH: {
        if (
            ($bios->{VERSION} && $bios->{VERSION} eq 'VirtualBox') ||
            ($bios->{MMODEL}  && $bios->{MMODEL} eq 'VirtualBox')
           ) {
            $inventory->setHardware ({
                VMSYSTEM => 'VirtualBox'
            });
            last SWITCH;
        }

        if (
            ($bios->{BIOSSERIAL} && $bios->{BIOSSERIAL} =~ /VMware/i) ||
            ($bios->{SMODEL}     && $bios->{SMODEL} eq 'VirtualBox')
           ) {
            $inventory->setHardware ({
                VMSYSTEM => 'VMware'
            });
            last SWITCH;
        }

        if (
            ($bios->{SMANUFACTURER} && $bios->{SMANUFACTURER} eq 'Xen') ||
            ($bios->{BMANUFACTURER} && $bios->{BMANUFACTURER} eq 'Xen')
           ) {
            $inventory->setHardware ({
                VMSYSTEM => 'Xen'
            });
            last SWITCH;
        }
    }

}

sub appendBiosDataFromWMI {
    my (%params) = @_;

    my $bios = $params{bios} ? $params{bios} : {};

    foreach my $object (getWMIObjects(
        class      => 'Win32_Bios',
        properties => [ qw/
            SerialNumber Version Manufacturer SMBIOSBIOSVersion BIOSVersion ReleaseDate
            / ],
        %params
    )) {
        $bios->{BIOSSERIAL}    = $object->{SerialNumber};
        $bios->{SSN}           = $object->{SerialNumber};
        $bios->{BMANUFACTURER} = $object->{Manufacturer};
        $bios->{BVERSION}      = $object->{SMBIOSBIOSVersion} ||
            $object->{BIOSVersion}       ||
            $object->{Version};
        $bios->{BDATE}         = _dateFromIntString($object->{ReleaseDate});
    }

    foreach my $object (getWMIObjects(
        class      => 'Win32_ComputerSystem',
        properties => [ qw/
            Manufacturer Model
            / ],
        %params
    )) {
        $bios->{SMANUFACTURER} = $object->{Manufacturer};
        $bios->{SMODEL}        = $object->{Model};
    }

    foreach my $object (getWMIObjects(
        class      => 'Win32_SystemEnclosure',
        properties => [ qw/
            SerialNumber SMBIOSAssetTag
            / ],
        %params
    )) {
        $bios->{ENCLOSURESERIAL} = $object->{SerialNumber} ;
        $bios->{SSN}             = $object->{SerialNumber} unless $bios->{SSN};
        $bios->{ASSETTAG}        = $object->{SMBIOSAssetTag};
    }

    foreach my $object (getWMIObjects(
        class => 'Win32_BaseBoard',
        properties => [ qw/
            SerialNumber Product Manufacturer
            / ],
        %params
    )) {
        $bios->{MSN}             = $object->{SerialNumber};
        $bios->{MMODEL}          = $object->{Product};
        $bios->{SSN}             = $object->{SerialNumber}
            unless $bios->{SSN};
        $bios->{SMANUFACTURER}   = $object->{Manufacturer}
            unless $bios->{SMANUFACTURER};

    }

    foreach (keys %$bios) {
        $bios->{$_} =~ s/\s+$// if $bios->{$_};
    }

    return $bios;
}

1;
