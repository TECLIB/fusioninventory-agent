package FusionInventory::Agent::Task::Inventory::Win32::Networks;

use strict;
use warnings;

use FusionInventory::Agent::Tools;
use FusionInventory::Agent::Tools::Network;
use FusionInventory::Agent::Tools::Win32;

sub isEnabled {
    my (%params) = @_;
    return 0 if $params{no_category}->{network};
    return 1;
}

sub doInventory {
    my (%params) = @_;

    my $inventory = $params{inventory};
    my $wmiParams = {};
    $wmiParams->{WMIService} = $params{inventory}->{WMIService} ? $params{inventory}->{WMIService} : undef;
    my (@gateways, @dns, @ips);

    foreach my $interface (getInterfaces(%$wmiParams)) {
        push @gateways, $interface->{IPGATEWAY}
            if $interface->{IPGATEWAY};
        push @dns, $interface->{dns}
            if $interface->{dns};

        push @ips, $interface->{IPADDRESS}
            if $interface->{IPADDRESS};

        delete $interface->{dns};
        $interface->{TYPE} = _getMediaType($interface->{PNPDEVICEID}, $params{logger}, $wmiParams);
        my $interfaceType = $interface->{TYPE} ? $interface->{TYPE} : 'UNDEF';
        $params{logger}->debug2('networks > ' . $interface->{PNPDEVICEID} . ' : ' . $interfaceType);

        $inventory->addEntry(
            section => 'NETWORKS',
            entry   => $interface
        );
    }

    $inventory->setHardware({
        DEFAULTGATEWAY => join('/', uniq @gateways),
        DNS            => join('/', uniq @dns),
        IPADDR         => join('/', uniq @ips),
    });

}

sub _getMediaType {
    my ($deviceId, $logger, $wmiParams) = @_;

    return unless defined $deviceId;

    my $path = "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/Network/{4D36E972-E325-11CE-BFC1-08002BE10318}";

    if ($wmiParams && $wmiParams->{WMIService}) {
        return _getMediaTypeFromRemote($path, $deviceId, $logger, $wmiParams);
    }

    my $key = getRegistryKey(
        path   => $path,
        logger => $logger
    );

    foreach my $subkey_name (keys %$key) {
        # skip variables
        next if $subkey_name =~ m{^/};
        my $subkey = $key->{$subkey_name};
        next unless
            $subkey->{'Connection/'}                     &&
            $subkey->{'Connection/'}->{'/PnpInstanceID'} &&
            $subkey->{'Connection/'}->{'/PnpInstanceID'} eq $deviceId;
        my $subtype = $subkey->{'Connection/'}->{'/MediaSubType'};
        return
            !defined $subtype        ? 'ethernet' :
            $subtype eq '0x00000001' ? 'ethernet' :
            $subtype eq '0x00000002' ? 'wifi'     :
                                       undef;
    }

    ## no critic (ExplicitReturnUndef)
    return undef;
}

sub _getMediaTypeFromRemote {
    my ($path, $deviceId, $logger, $wmiParams) = @_;

    my $subKeys = getRegistryKey(
        path   => $path,
        logger => $logger,
        %$wmiParams
    );

    foreach my $subkey_name (@$subKeys) {
        # skip variables
        next if $subkey_name =~ m{^/}
            || $subkey_name =~ /Descriptions/;

        $logger->debug2('Networks > found key : ' . $subkey_name);

        my $subkeyPath = $path . '/' . $subkey_name;
        my $subKeyKeys = getRegistryKey(
            path   => $subkeyPath,
            logger => $logger,
            %$wmiParams
        );
        next unless $subKeyKeys;
        $logger->debug2('found subKeys');

        my %keys = map { $_ => 1 } @$subKeyKeys;
        my $keyName = 'Connection';
        next unless $keys{$keyName};
        $logger->debug2('Connection is found');

        $subkeyPath .= '/' . $keyName;
        my $values = retrieveValuesNameAndType(
            path => $subkeyPath,
            %$wmiParams
        );
        $keyName = 'PnpInstanceID';
        next unless $values;
        $logger->debug2('values found');
        my $dd = Data::Dumper->([$values]);
        $logger->debug2($dd->Dump);
        next unless $values->{$keyName};
        $logger->debug2('PnpInstanceID is a value found');
        $logger->debug2('PnpInstanceID ?eq $deviceId : ' . $values->{$keyName} . ' ?eq ' . $deviceId);
        next unless $values->{$keyName} eq $deviceId;

        my $subtype = $values->{MediaSubType};

        return
                !defined $subtype        ? 'ethernet' :
                $subtype eq '0x00000001' ? 'ethernet' :
                    $subtype eq '0x00000002' ? 'wifi'     :
                    undef;
    }

    ## no critic (ExplicitReturnUndef)
    return undef;
}

1;
