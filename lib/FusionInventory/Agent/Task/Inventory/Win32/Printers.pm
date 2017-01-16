package FusionInventory::Agent::Task::Inventory::Win32::Printers;

use strict;
use warnings;

use English qw(-no_match_vars);
use Storable;

use FusionInventory::Agent::Tools::Win32;

my @status = (
    'Unknown', # 0 is not defined
    'Other',
    'Unknown',
    'Idle',
    'Printing',
    'Warming Up',
    'Stopped printing',
    'Offline',
);

my @errStatus = (
    'Unknown',
    'Other',
    'No Error',
    'Low Paper',
    'No Paper',
    'Low Toner',
    'No Toner',
    'Door Open',
    'Jammed',
    'Service Requested',
    'Output Bin Full',
    'Paper Problem',
    'Cannot Print Page',
    'User Intervention Required',
    'Out of Memory',
    'Server Unknown',
);

my $registryKeyNames = {
    deviceParameters => 'Device Parameters/',
    portName         => '/PortName',
    containerId      => '/ContainerID',
    parentIdPrefix   => '/ParentIdPrefix'
};

sub isEnabled {
    my (%params) = @_;

    return !$params{no_category}->{printer};
}

sub doInventory {
    my (%params) = @_;

    my $inventory = $params{inventory};
    my $logger    = $params{logger};

    my $wmiParams = {};
    $wmiParams->{WMIService} = $params{inventory}->{WMIService} ? $params{inventory}->{WMIService} : undef;

    foreach my $object (getWMIObjects(
        class      => 'Win32_Printer',
        properties => [ qw/
            ExtendedDetectedErrorState HorizontalResolution VerticalResolution Name
            Comment Description DriverName PortName Network Shared PrinterStatus
            ServerName ShareName PrintProcessor
        / ],
        %$wmiParams
    )) {

        my $errStatus;
        if ($object->{ExtendedDetectedErrorState}) {
            $errStatus = $errStatus[$object->{ExtendedDetectedErrorState}];
        }

        my $resolution;

        if ($object->{HorizontalResolution}) {
            $resolution =
                $object->{HorizontalResolution} .
                "x"                             .
                $object->{VerticalResolution};
        }

        $object->{Serial} = _getUSBPrinterSerial($object->{PortName}, $logger, $wmiParams)
            if $object->{PortName} && $object->{PortName} =~ /USB/;

        $inventory->addEntry(
            section => 'PRINTERS',
            entry   => {
                NAME           => $object->{Name},
                COMMENT        => $object->{Comment},
                DESCRIPTION    => $object->{Description},
                DRIVER         => $object->{DriverName},
                PORT           => $object->{PortName},
                RESOLUTION     => $resolution,
                NETWORK        => $object->{Network},
                SHARED         => $object->{Shared},
                STATUS         => $status[$object->{PrinterStatus}],
                ERRSTATUS      => $errStatus,
                SERVERNAME     => $object->{ServerName},
                SHARENAME      => $object->{ShareName},
                PRINTPROCESSOR => $object->{PrintProcessor},
                SERIAL         => $object->{Serial}
            }
        );

    }
}

sub _getUSBPrinterSerial {
    my ($portName, $logger, $wmiParams) = @_;

    # the serial number can be extracted from the USB registry key, containing
    # all USB devices, but we only know the USB port identifier, meaning we
    # must first look in USBPRINT registry key, containing USB printers only,
    # and find some way to correlate entries
    my $usbprintPath = "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Enum/USBPRINT";
    my $usbprint_key = getRegistryKey(
        path   => $usbprintPath,
        logger => $logger,
        retrieveValuesForAllKeys => 1,
        retrieveSubKeysForAllKeys => 1
        %$wmiParams
    );

    my $usbPath = "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Enum/USB";
    my $usb_key = getRegistryKey(
        path   => $usbPath,
        logger => $logger,
        retrieveValuesForAllKeys => 1,
        retrieveSubKeysForAllKeys => 1,
        %$wmiParams
    );

    # the ContainerID variable seems more reliable, but is not always available
    my $containerId = _getUSBContainerID(
        usbprint_key => $usbprint_key,
        portName => $portName,
        %$wmiParams
    );
    if ($containerId) {
        my $serial = _getUSBSerialFromContainerID(
            usb => $usb_key,
            containerId => $containerId,
            %$wmiParams
        );
        return $serial if $serial;
    }

    # fallback on ParentIdPrefix variable otherwise
    my $prefix = _getUSBPrefix(
        usb => $usbprint_key,
        portName => $portName,
        %$wmiParams
    );
    if ($prefix) {
        my $serial = _getUSBSerialFromPrefix(
            usb => $usb_key,
            prefix => $prefix,
            %$wmiParams
        );
        return $serial if $serial;
    }

    # bad luck
    return;
}

sub _getUSBContainerID {
    my (%params) = @_;

    my $print = $params{usbprint_key};
    my $portName = $params{portName};

    my %keyNames = _getKeyNames(%params);

    # registry data structure:
    # USBPRINT
    # └── device
    #     └── subdevice
    #         └── ContainerID:value
    #         └── Device Parameters
    #             └── PortName:value

    foreach my $device (values %$print) {
        foreach my $subdeviceName (keys %$device) {
            my $subdevice = $device->{$subdeviceName};
            next unless
                $subdevice->{$keyNames{deviceParameters}}                &&
                $subdevice->{$keyNames{deviceParameters}}->{$keyNames{portName}} &&
                $subdevice->{$keyNames{deviceParameters}}->{$keyNames{portName}} eq $portName;
            # got it
            return $subdevice->{$keyNames{containerId}};
        };
    }

    return;
}

sub _getKeyNames {
    my (%params) = @_;

    my $keyNames = dclone $registryKeyNames;
    if ($params{WMIService}) {
        for my $k (keys %$keyNames) {
            $keyNames->{$k} =~ s{\/}{}g;
        }
    }

    return %$keyNames;
}

sub _getUSBPrefix {
    my (%params) = @_;

    my $print = $params{usb};
    my $portName = $params{portName};

    my %keyNames = _getKeyNames(%params);

    # registry data structure:
    # USBPRINT
    # └── device
    #     └── subdevice
    #         └── Device Parameters
    #             └── PortName:value

    foreach my $device (values %$print) {
        foreach my $subdeviceName (keys %$device) {
            my $subdevice = $device->{$subdeviceName};
            next unless
                $subdevice->{$keyNames{deviceParameters}}                &&
                    $subdevice->{$keyNames{deviceParameters}}->{$keyNames{portName}} &&
                    $subdevice->{$keyNames{deviceParameters}}->{$keyNames{portName}} eq $portName;
            # got it
            my $prefix = $subdeviceName;
            $prefix =~ s{&$portName/$}{};
            return $prefix;
        };
    }

    return;
}

sub _getUSBSerialFromPrefix {
    my (%params) = @_;

    my $usb = $params{usb};
    my $prefix = $params{prefix};

    my %keyNames = _getKeyNames(%params);

    # registry data structure:
    # USB
    # └── device
    #     └── subdevice
    #         └── ParentIdPrefix:value

    foreach my $device (values %$usb) {
        foreach my $subdeviceName (keys %$device) {
            my $subdevice = $device->{$subdeviceName};
            next unless
                $subdevice->{$keyNames{parentIdPrefix}} &&
                $subdevice->{$keyNames{parentIdPrefix}} eq $prefix;
            # got it
            my $serial = $subdeviceName;
            # pseudo serial generated by windows
            return if $serial =~ /&/;
            $serial =~ s{/$}{};
            return $serial;
        }
    }

    return;
}

sub _getUSBSerialFromContainerID {
    my (%params) = @_;

    my $usb = $params{usb};
    my $containerId = $params{containerId};

    my %keyNames = _getKeyNames(%params);

    # registry data structure:
    # USB
    # └── device
    #     └── subdevice
    #         └── ContainerId:value

    foreach my $device (values %$usb) {
        foreach my $subdeviceName (keys %$device) {
            my $subdevice = $device->{$subdeviceName};
            next unless
                $subdevice->{$keyNames{containerId}} &&
                $subdevice->{$keyNames{containerId}} eq $containerId;
            # pseudo serial generated by windows
            next if $subdeviceName =~ /&/;
            # got it
            my $serial = $subdeviceName;
            $serial =~ s{/$}{};
            return $serial;
        }
    }

    return;
}

1;
