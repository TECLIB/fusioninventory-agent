package FusionInventory::Agent::Task::Inventory::Win32::AntiVirus;

use strict;
use warnings;

use parent 'FusionInventory::Agent::Task::Inventory::Module';

use FusionInventory::Agent::Tools;
use FusionInventory::Agent::Tools::Win32;

sub isEnabled {
    my (%params) = @_;
    return 0 if $params{no_category}->{antivirus};
    return 1;
}

sub isEnabledForRemote {
    my (%params) = @_;
    return 0 if $params{no_category}->{antivirus};
    return 1;
}

sub doInventory {
    my (%params) = @_;

    my $inventory = $params{inventory};
    my $seen;

    # Doesn't works on Win2003 Server
    # On Win7, we need to use SecurityCenter2
    foreach my $instance (qw/SecurityCenter SecurityCenter2/) {
        my $moniker = "winmgmts:{impersonationLevel=impersonate,(security)}!//./root/$instance";

        foreach my $object (getWMIObjects(
                moniker    => $moniker,
                class      => "AntiVirusProduct",
                properties => [ qw/
                    companyName displayName instanceGuid onAccessScanningEnabled
                    productUptoDate versionNumber productState
               / ]
        )) {
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
                my $hex = dec2hex($object->{productState});
                # See http://neophob.com/2010/03/wmi-query-windows-securitycenter2/
                my ($enabled, $uptodate) = $hex =~ /(.{2})(.{2})$/;
                if (defined($enabled) && defined($uptodate)) {
                    $antivirus->{ENABLED}  =  $enabled =~ /^1.$/ ? 1 : 0;
                    $antivirus->{UPTODATE} = $uptodate =~ /^00$/ ? 1 : 0;
                }
            }

            # Also support WMI access to Windows Defender
            if (!$antivirus->{VERSION} && $antivirus->{NAME} =~ /Windows Defender/i) {
                my ($defender) = getWMIObjects(
                    moniker    => 'winmgmts://./root/microsoft/windows/defender',
                    class      => "MSFT_MpComputerStatus",
                    properties => [ qw/AMProductVersion AntivirusEnabled
                        AntivirusSignatureVersion/ ]
                );
                if ($defender) {
                    $antivirus->{VERSION} = $defender->{AMProductVersion}
                        if $defender->{AMProductVersion};
                    $antivirus->{ENABLED}  = $defender->{AntivirusEnabled} =~ /TRUE/i ? 1 : 0;
                    $antivirus->{BASE_VERSION} = $defender->{AntivirusSignatureVersion}
                        if $defender->{AntivirusSignatureVersion};
                }
                $antivirus->{COMPANY} = "Microsoft Corporation";
            }

            # Finally try to get version from software installation in registry
            if (!$antivirus->{VERSION} || !$antivirus->{COMPANY}) {
                my $registry = _getAntivirusUninstall($antivirus->{NAME});
                if ($registry) {
                    $antivirus->{VERSION} = encodeFromRegistry($registry->{"/DisplayVersion"})
                        if (!$antivirus->{VERSION} && $registry->{"/DisplayVersion"});
                    $antivirus->{COMPANY} = encodeFromRegistry($registry->{"/Publisher"})
                        if (!$antivirus->{COMPANY} && $registry->{"/Publisher"});
                }
            }

            # avoid duplicates
            next if $seen->{$antivirus->{NAME}}->{$antivirus->{VERSION}||'_undef_'}++;

            # Check for other product datas for update
            if ($antivirus->{NAME} =~ /McAfee/i) {
                _setMcAfeeInfos($antivirus);
            } elsif ($antivirus->{NAME} =~ /Kaspersky/i) {
                _setKasperskyInfos($antivirus);
            } elsif ($antivirus->{NAME} =~ /ESET/i) {
                _setESETInfos($antivirus);
            } elsif ($antivirus->{NAME} =~ /Avira/i) {
                _setAviraInfos($antivirus);
            }

            $inventory->addEntry(
                section => 'ANTIVIRUS',
                entry   => $antivirus
            );
        }
    }
}

sub _getAntivirusUninstall {
    my ($name) = @_;

    return unless $name;

    # Cleanup name from localized chars to keep a clean regex pattern
    my ($pattern) = $name =~ /^([a-zA-Z0-9 ._-]+)/
        or return;
    # Escape dot in pattern
    $pattern =~ s/\./\\./g;
    my $match = qr/^$pattern/i;

    return _getSoftwareRegistryKeys(
        'Microsoft/Windows/CurrentVersion/Uninstall',
        [ 'DisplayName', 'DisplayVersion', 'Publisher' ],
        sub {
            my ($registry) = @_;
            return first {
                $_->{"/DisplayName"} && $_->{"/DisplayName"} =~ $match;
            } values(%{$registry});
        }
    );
}

sub _setMcAfeeInfos {
    my ($antivirus) = @_;

    my %properties = (
        'BASE_VERSION'     => [ 'AVDatVersion',         'AVDatVersionMinor'    ],
        '32ENGINE_VERSION' => [ 'EngineVersion32Major', 'EngineVersion32Minor' ],
        '64ENGINE_VERSION' => [ 'EngineVersionMajor',   'EngineVersionMinor'   ],
    );

    my $regvalues = [ map { @{$_} } values(%properties) ];

    my $macafeeReg = _getSoftwareRegistryKeys('McAfee/AVEngine', $regvalues)
        or return;

    # major.minor versions properties
    foreach my $property (keys %properties) {
        my $keys = $properties{$property};
        my $major = $macafeeReg->{'/' . $keys->[0]};
        my $minor = $macafeeReg->{'/' . $keys->[1]};
        $antivirus->{$property} = sprintf("%04d.%04d", hex2dec($major), hex2dec($minor))
            if defined $major && defined $minor;
    }
}

sub _setKasperskyInfos {
    my ($antivirus) = @_;

    my $regvalues = [ qw(LastSuccessfulUpdate LicKeyType LicDaysTillExpiration) ];

    my $kasperskyReg = _getSoftwareRegistryKeys('KasperskyLab\protected', $regvalues)
        or return;

    my $found = first {
        $_->{"Data/"} && $_->{"Data/"}->{"/LastSuccessfulUpdate"}
    } values(%{$kasperskyReg});

    if ($found) {
        my $lastupdate = hex2dec($found->{"Data/"}->{"/LastSuccessfulUpdate"});
        if ($lastupdate && $lastupdate != 0xFFFFFFFF) {
            my @date = localtime($lastupdate);
            # Format BASE_VERSION as YYYYMMDD
            $antivirus->{BASE_VERSION} = sprintf(
                "%04d%02d%02d",$date[5]+1900,$date[4]+1,$date[3]);
        }
        # Set expiration date only if we found a licence key type
        my $keytype = hex2dec($found->{"Data/"}->{"/LicKeyType"});
        if ($keytype) {
            my $expiration = hex2dec($found->{"Data/"}->{"/LicDaysTillExpiration"});
            if (defined($expiration)) {
                my @date = localtime(time+86400*$expiration);
                $antivirus->{EXPIRATION} = sprintf(
                    "%02d/%02d/%04d",$date[3],$date[4]+1,$date[5]+1900);
            }
        }
    }
}

sub _setESETInfos {
    my ($antivirus) = @_;

    my $esetReg = _getSoftwareRegistryKeys(
        'ESET\ESET Security\CurrentVersion\Info',
        [ qw(ProductVersion ScannerVersion) ]
    );
    return unless $esetReg;

    unless ($antivirus->{VERSION}) {
        $antivirus->{VERSION} = $esetReg->{"/ProductVersion"}
            if $esetReg->{"/ProductVersion"};
    }

    $antivirus->{BASE_VERSION} = $esetReg->{"/ScannerVersion"}
        if $esetReg->{"/ScannerVersion"};
}

sub _setAviraInfos {
    my ($antivirus) = @_;

    my ($aviraInfos) = getWMIObjects(
        moniker    => 'winmgmts://./root/CIMV2/Applications/Avira_AntiVir',
        class      => "License_Info",
        properties => [ qw/License_Expiration/ ]
    );
    if($aviraInfos && $aviraInfos->{License_Expiration}) {
        my ($expiration) = $aviraInfos->{License_Expiration} =~ /^(\d+\.\d+\.\d+)/;
        if ($expiration) {
            $expiration =~ s/\./\//g;
            $antivirus->{EXPIRATION} = $expiration;
        }
    }

    ($aviraInfos) = getWMIObjects(
        moniker    => 'winmgmts://./root/CIMV2/Applications/Avira_AntiVir',
        class      => "Product_Info",
        properties => [ qw/Product_Version VDF_Version/ ]
    );
    return unless $aviraInfos;

    unless ($antivirus->{VERSION}) {
        $antivirus->{VERSION} = $aviraInfos->{"Product_Version"}
            if $aviraInfos->{"Product_Version"};
    }

    $antivirus->{BASE_VERSION} = $aviraInfos->{"VDF_Version"}
        if $aviraInfos->{"VDF_Version"};
}

sub _getSoftwareRegistryKeys {
    my ($base, $values, $callback) = @_;

    my $reg;
    if (is64bit()) {
        $reg = getRegistryKey(
            path => 'HKEY_LOCAL_MACHINE/SOFTWARE/Wow6432Node/'.$base,
            wmiopts => { # Only used for remote WMI optimization
                values  => $values
            }
        );
        if ($reg) {
            if ($callback) {
                my $filter = &{$callback}($reg);
                return $filter if $filter;
            } else {
                return $reg;
            }
        }
    }

    $reg = getRegistryKey(
        path => 'HKEY_LOCAL_MACHINE/SOFTWARE/'.$base,
        wmiopts => { # Only used for remote WMI optimization
            values  => $values
        }
    );
    return ($callback && $reg) ? &{$callback}($reg) : $reg;
}

1;
