package FusionInventory::Agent::Task::Wmi;
use strict;
use warnings FATAL => 'all';
use base 'FusionInventory::Agent::Task';

use UNIVERSAL::require;
use English qw(-no_match_vars);
use Data::Dumper;

our $VERSION = '0.1';

sub isEnabled {
    my ($self) = @_;

    return 1
}

sub _connectToService {
    my ($hostname, $user, $pass) = @_;

    my $locator = Win32::OLE->CreateObject( 'WbemScripting.SWbemLocator' ) or
        warn;
    my $service = $locator->ConnectServer(
        $hostname,
        "root\\cimv2",
        "domain\\" . $user,
        $pass
    );

    return $service;
}

sub run {
    my ($self, %params) = @_;

    if ($REAL_USER_ID != 0) {
        $self->{logger}->warning(
            "You should execute this task as super-user"
        );
    }

    my $config = $self->{config};
    if (!$config->{wmi_hostname} || !$config->{wmi_user} || !$config->{wmi_pass}) {
        $self->{logger}->error('wmi connection parameters missing, be sure to give host, user and password.');
        return;
    } else {
        my $service = _connectToService($config->{wmi_hostname}, $config->{wmi_user}, $config->{wmi_pass});
        if ($service) {
            $self->{WMIService} = $service;
        } else {
            $self->{logger}->error("can't connect to WMI service");
            return;
        }
    }

    $self->getAntivirus($self->{WMIService});
}

sub getAntivirus {
    my ($self, $service) = @_;

    my $seen;
    foreach my $instance (qw/SecurityCenter SecurityCenter2/) {
        my $moniker = "winmgmts:{impersonationLevel=impersonate,(security)}!//./root/$instance";

        foreach my $object (getWMIObjects(
            WMIService => $service,
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
                my $bin = sprintf( "%b\n", $object->{productState});
                # http://blogs.msdn.com/b/alejacma/archive/2008/05/12/how-to-get-antivirus-information-with-wmi-vbscript.aspx?PageIndex=2#comments
                if ($bin =~ /(\d)\d{5}(\d)\d{6}(\d)\d{5}$/) {
                    $antivirus->{UPTODATE} = $1 || $2;
                    $antivirus->{ENABLED} = $3 ? 0 : 1;
                }
            }

            # avoid duplicates
            next if $seen->{$antivirus->{NAME}}->{$antivirus->{VERSION} || '_undef_'}++;

            my $dd = Data::Dumper->new([$antivirus]);
            my $output = $dd->Dump;
            $self->{logger}->debug2($output);
        }
    }
}

1;
