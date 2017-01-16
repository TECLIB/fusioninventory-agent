package FusionInventory::Agent::Task::Inventory::Win32::Users;

use strict;
use warnings;

use constant wbemFlagReturnImmediately => 0x10;
use constant wbemFlagForwardOnly => 0x20;

use English qw(-no_match_vars);
use Win32::OLE qw(in);
use Win32::OLE::Variant;
use Win32::TieRegistry (
    Delimiter   => '/',
    ArrayValues => 0,
    qw/KEY_READ/
);

Win32::OLE->Option(CP => Win32::OLE::CP_UTF8);

use FusionInventory::Agent::Tools::Win32;

sub isEnabled {
    my (%params) = @_;
    return 0 if $params{no_category}->{user};
    return 1;
}

sub doInventory {
    my (%params) = @_;

    my $inventory = $params{inventory};
    my $logger    = $params{logger};

    my $wmiParams = {};
    $wmiParams->{WMIService} = $params{inventory}->{WMIService} ? $params{inventory}->{WMIService} : undef;

    if (!$params{no_category}->{local_user}) {
        foreach my $user (_getLocalUsers(logger => $logger, %$wmiParams)) {
            $inventory->addEntry(
                section => 'LOCAL_USERS',
                entry   => $user
            );
        }
    }

    if (!$params{no_category}->{local_group}) {
        foreach my $group (_getLocalGroups(logger => $logger, %$wmiParams)) {
            $inventory->addEntry(
                section => 'LOCAL_GROUPS',
                entry   => $group
            );
        }
    }

    unless ($wmiParams) {
        foreach my $user (_getLoggedUsers(logger => $logger, %$wmiParams)) {
            $inventory->addEntry(
                section => 'USERS',
                entry   => $user
            );
        }
    }

    $inventory->setHardware({
        LASTLOGGEDUSER => _getLastUser(logger => $logger, %$wmiParams)
    });
}

sub _getLocalUsers {
    my (%params) = @_;

    my $wmiParams = {};
    if ($params{WMIService}) {
        $wmiParams = {
            WMIService => $params{WMIService}
        };
    }

    my @users = ();
    foreach my $object (getWMIObjects (
        moniker => "winmgmts:\\\\.\\root\\CIMV2",
        query => "SELECT * FROM Win32_UserAccount ".
            "WHERE LocalAccount='True' AND Disabled='False' and Lockout='False'",
        properties => [
            'Name',
            'SID'
        ],
        %$wmiParams
    )) {
        my $user = {
            NAME => $object->{Name},
            ID   => $object->{SID},
        };
        utf8::upgrade($user->{NAME});
        push @users, $user;
    }

    return @users;
}

sub _getLocalGroups {
    my (%params) = @_;

    my $wmiParams = {};
    if ($params{WMIService}) {
        $wmiParams = {
            WMIService => $params{WMIService}
        };
    }

    my @groups = ();
    foreach my $object (getWMIObjects (
        moniker => "winmgmts:\\\\.\\root\\CIMV2",
        query => "SELECT * FROM Win32_Group " .
            "WHERE LocalAccount='True'",
        properties => [
            'Name',
            'SID'
        ],
        %$wmiParams
    )) {
        my $group = {
            NAME => $object->{Name},
            ID   => $object->{SID},
        };
        utf8::upgrade($group->{NAME});
        push @groups, $group;
    }

    return @groups;
}

sub _getLoggedUsers {

    my $WMIService = Win32::OLE->GetObject("winmgmts:\\\\.\\root\\CIMV2")
        or die "WMI connection failed: " . Win32::OLE->LastError();

    my $processes = $WMIService->ExecQuery(
        "SELECT * FROM Win32_Process", "WQL",
        wbemFlagReturnImmediately | wbemFlagForwardOnly ## no critic (ProhibitBitwise)
    );

    my @users;
    my $seen;

    foreach my $process (in $processes) {
        next unless
            $process->{ExecutablePath} &&
            $process->{ExecutablePath} =~ /\\Explorer\.exe$/i;

        ## no critic (ProhibitBitwise)
        my $name = Variant(VT_BYREF | VT_BSTR, '');
        my $domain = Variant(VT_BYREF | VT_BSTR, '');

        $process->GetOwner($name, $domain);

        my $user = {
            LOGIN  => $name->Get(),
            DOMAIN => $domain->Get()
        };

        utf8::upgrade($user->{LOGIN});
        utf8::upgrade($user->{DOMAIN});

        next if $seen->{$user->{LOGIN}}++;

        push @users, $user;
    }

    return @users;
}

sub _getLastUser {
    my (%params) = @_;

    my @paths = (
        'SOFTWARE/Microsoft/Windows/CurrentVersion/Authentication/LogonUI/LastLoggedOnUser',
        'SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/DefaultUserName'
    );
    my $user;
    if ($params{WMIService}) {
        $user = _getLastUserFromRemoteRegistry(
            path => \@paths,
            WMIService => $params{WMIService}
        );
    } else {
        $user = _getLastUserFromLocalRegistry(
            path => \@paths
        )
    }
    return unless $user;

    $user =~ s,.*\\,,;
    return $user;
}

sub _getLastUserFromRemoteRegistry {
    my (%params) = @_;

    $DB::single = 1;
    my $user = encodeFromRegistry(
        getRegistryValueFromWMI(
            %params,
            path => 'HKEY_LOCAL_MACHINE/' . $params{path}->[0]
        )
    ) || encodeFromRegistry(
        getRegistryValueFromWMI(
            %params,
            path => 'HKEY_LOCAL_MACHINE/' . $params{path}->[1]
        )
    );
    return $user;
}

sub _getLastUserFromLocalRegistry {
    my (%params) = @_;

    # ensure native registry access, not the 32 bit view
    my $flags = is64bit() ? KEY_READ | KEY_WOW64_64 : KEY_READ;

    my $machKey = $Registry->Open('LMachine', {
        Access => $flags
    }) or die "Can't open HKEY_LOCAL_MACHINE key: $EXTENDED_OS_ERROR";

    my $user =
        encodeFromRegistry($machKey->{$params{path}->[0]}) ||
        encodeFromRegistry($machKey->{$params{path}->[1]});
    return $user;
}

1;
