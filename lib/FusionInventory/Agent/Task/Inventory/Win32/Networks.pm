package FusionInventory::Agent::Task::Inventory::Win32::Networks;

use strict;
use warnings;

use Data::Dumper;

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

    my $dataFromRegistry = _getDataFromRemote(
        %$wmiParams,
        path => "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/Network/{4D36E972-E325-11CE-BFC1-08002BE10318}",
        logger => $params{logger}
    );

    foreach my $interface (getInterfaces(%$wmiParams, logger => $params{logger})) {
        push @gateways, $interface->{IPGATEWAY}
            if $interface->{IPGATEWAY};
        push @dns, $interface->{dns}
            if $interface->{dns};

        push @ips, $interface->{IPADDRESS}
            if $interface->{IPADDRESS};

        delete $interface->{dns};
        if ($wmiParams->{WMIService}) {
            if ($dataFromRegistry->{$interface->{PNPDEVICEID}}) {
                $interface->{TYPE} = $dataFromRegistry->{$interface->{PNPDEVICEID}};
            }
        } else {
            $interface->{TYPE} = _getMediaType($interface->{PNPDEVICEID}, $params{logger}, $wmiParams);
        }
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

sub _getDataFromRemote {
    my (%params) = @_;

    my $path = $params{path};
    my $logger = $params{logger};
    my $wmiParams = {
        WMIService => $params{WMIService}
    };

    my $subKeys = getRegistryKey(
        path   => $path,
        logger => $logger,
        %$wmiParams
    );
    my $data = {};
    foreach my $subkey_name (@$subKeys) {
        # skip variables
        next if $subkey_name =~ m{^/}
            || $subkey_name =~ /Descriptions/;

        $logger->debug2('Networks > found key : ' . $subkey_name);

        my $subkeyPath = $path . '/' . $subkey_name;
        my $subKeyKeys = getRegistryKey(
            path   => $subkeyPath,
            logger => $logger,
            retrieveValuesForKeyName => ['Connection'],
            %$wmiParams
        );
        next unless $subKeyKeys;
        $logger->debug2('found subKeys');
        my $dd = Data::Dumper->new([$subKeyKeys]);
        $logger->debug2($dd->Dump);

        next unless ref $subKeyKeys eq 'HASH';
        my %keys = map { $_ => 1 } keys %$subKeyKeys;
        my $keyName = 'Connection';
        next unless $keys{$keyName};
        $logger->debug2('Connection is found');

        my $values = $subKeyKeys->{$keyName};
        next unless $values;
        $logger->debug2('values found');
        $dd = Data::Dumper->new([$values]);
        $logger->debug2($dd->Dump);

        $keyName = 'PnpInstanceID';
        next unless $values->{$keyName};
        $logger->debug2('PnpInstanceID is a value found');

        my $subtype = $values->{MediaSubType};

        $data->{$values->{$keyName}} =
                !defined $subtype        ? 'ethernet' :
                $subtype eq '0x00000001' ? 'ethernet' :
                    $subtype eq '0x00000002' ? 'wifi'     :
                    undef;
    }

    ## no critic (ExplicitReturnUndef)
    return $data;
}

1;
