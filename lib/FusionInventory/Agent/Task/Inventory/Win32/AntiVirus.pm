package FusionInventory::Agent::Task::Inventory::Win32::AntiVirus;

use strict;
use warnings;

use Data::Dumper;

use FusionInventory::Agent::Tools::Win32;

use FusionInventory::Agent::Task::Inventory::Win32::Networks;

my $seen;

sub isEnabled {
    my (%params) = @_;
    return 0 if $params{no_category}->{antivirus};
    return 1;
}

sub doInventory {
    my (%params) = @_;

    my $logger = $params{logger};

    my $inventory = $params{inventory};
    my $wmiParams = {};
    $wmiParams->{WMIService} = $params{inventory}->{WMIService} ? $params{inventory}->{WMIService} : undef;

    if (2==1 && $wmiParams->{WMIService}) {
        my $dd;
        my $tree;
        my $p;
        $p = "HKEY_LOCAL_MACHINE/HARDWARE/DESCRIPTION/System/CentralProcessor/0";
        #    $tree = FusionInventory::Agent::Tools::Win32::getRegistryTreeFromWMI(
        #        path => $p,
        #        %$wmiParams
        #    );
        $tree = FusionInventory::Agent::Tools::Win32::retrieveValuesNameAndType(
            path => $p,
            %$wmiParams
        );
        $dd = Data::Dumper->new([ $tree ]);
        $logger->debug2($p);
        $logger->debug2($dd->Dump);

        $p = "HKEY_LOCAL_MACHINE/HARDWARE/DESCRIPTION/System/CentralProcessor/1";
        #    $tree = FusionInventory::Agent::Tools::Win32::getRegistryTreeFromWMI(
        #        path => $p,
        #        %$wmiParams
        #    );
        $tree = FusionInventory::Agent::Tools::Win32::retrieveValuesNameAndType(
            path => $p,
            %$wmiParams
        );
        $dd = Data::Dumper->new([ $tree ]);
        $logger->debug2($p);
        $logger->debug2($dd->Dump);

        my $data = FusionInventory::Agent::Task::Inventory::Win32::Networks::_getDataFromRemote(
            %$wmiParams,
            path => "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/Network/{4D36E972-E325-11CE-BFC1-08002BE10318}",
            logger => $logger
        );
        $dd = Data::Dumper->new([ $tree ]);
        $logger->debug2($p);
        $logger->debug2($dd->Dump);
    }
    $DB::single = 1;
    my @antiviruses = getAntivirusesFromWMI(%$wmiParams);
    foreach my $antivirus (@antiviruses) {
        # McAfee data
        if ($antivirus->{NAME} =~ /McAfee/i) {
            my $info = _getMcAfeeInfo($logger);
            $antivirus->{$_} = $info->{$_} foreach keys %$info;
        }

        $inventory->addEntry(
            section => 'ANTIVIRUS',
            entry   => $antivirus
        );
    }
}

# Doesn't works on Win2003 Server
# On Win7, we need to use SecurityCenter2
sub getAntivirusesFromWMI {
    my @antiviruses;
    foreach my $instance (qw/SecurityCenter SecurityCenter2/) {
        my $moniker = "winmgmts:{impersonationLevel=impersonate,(security)}!//./root/$instance";

        foreach my $object (getWMIObjects(
            moniker    => $moniker,
            class      => "AntiVirusProduct",
            properties => [ qw/
                companyName displayName instanceGuid onAccessScanningEnabled
                productUptoDate versionNumber productState
                / ],
            @_
        )) {
            $DB::single = 1;
            next unless $object;

            my $antivirus = {
                COMPANY  => $object->{companyName},
                NAME     => $object->{displayName},
                GUID     => $object->{instanceGuid},
                VERSION  => $object->{versionNumber},
                ENABLED  => $object->{onAccessScanningEnabled},
                UPTODATE => $object->{productUptoDate}
            };

            if ($object->{productState}) {
                my $bin = sprintf( "%b\n", $object->{productState});
                # http://blogs.msdn.com/b/alejacma/archive/2008/05/12/how-to-get-antivirus-information-with-wmi-vbscript.aspx?PageIndex=2#comments
                if ($bin =~ /(\d)\d{5}(\d)\d{6}(\d)\d{5}$/) {
                    $antivirus->{UPTODATE} = $1 || $2;
                    $antivirus->{ENABLED} = $3 ? 0 : 1;
                }
            }

            # avoid duplicates
            next if $seen->{$antivirus->{NAME}}->{$antivirus->{VERSION} || '_undef_'}++;

            push @antiviruses, $antivirus;
        }
    }

    return @antiviruses;
}

sub _getMcAfeeInfo {
    my (%params) = @_;

    my $path;
    if (is64bit(%params)) {
        $path = 'HKEY_LOCAL_MACHINE/SOFTWARE/Wow6432Node/McAfee/AVEngine';
    } else {
        $path = 'HKEY_LOCAL_MACHINE/SOFTWARE/McAfee/AVEngine';
    }

    if ($params{WMIService}) {
        $DB::single = 1;
        return unless (isDefinedRemoteRegistryKey(
            %params,
            path => $path
        ));
    } else {
        return unless (defined getRegistryKey(path => $path));
    }

    my %properties = (
        DATFILEVERSION  => [ 'AVDatVersion',         'AVDatVersionMinor' ],
        ENGINEVERSION32 => [ 'EngineVersion32Major', 'EngineVersion32Minor' ],
        ENGINEVERSION64 => [ 'EngineVersionMajor',   'EngineVersionMinor' ],
    );

    my $info;

    # major.minor versions properties
    foreach my $property (keys %properties) {
        my $keys = $properties{$property};
        my $major = getRegistryValue(
            %params,
            path => $path . '/' . $keys->[0]
        );
        my $minor = getRegistryValue(
            %params,
            path => $path . '/' . $keys->[1],
        );
        $info->{$property} = sprintf("%04d.%04d", hex($major), hex($minor))
            if defined $major && defined $major;
    }

    # file creation date property
    my $avDatDate            =
        getRegistryValue(
            %params,
            path => $path . '/AVDatDate'
        );

    if (defined $avDatDate) {
        my $datFileCreation = encodeFromRegistry( $avDatDate );
        # from YYYY/MM/DD to DD/MM/YYYY
        if ($datFileCreation =~ /(\d\d\d\d)\/(\d\d)\/(\d\d)/) {
            $datFileCreation = join( '/', ($3, $2, $1) );
        }
        $info->{DATFILECREATION} = $datFileCreation;
    }

    return $info;
}

1;
