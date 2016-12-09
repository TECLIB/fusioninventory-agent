package FusionInventory::Agent::Task::Inventory::Win32::OS;

use strict;
use warnings;
use integer;

use English qw(-no_match_vars);

use FusionInventory::Agent::Tools;
use FusionInventory::Agent::Tools::Hostname;
use FusionInventory::Agent::Tools::License;
use FusionInventory::Agent::Tools::Win32;

sub isEnabled {
    return 1;
}

sub doInventory {
    my (%params) = @_;

    my $inventory = $params{inventory};
    my $wmiParams = {};
    $wmiParams->{WMIService} = $params{inventory}->{WMIService} ? $params{inventory}->{WMIService} : undef;
    my ($operatingSystem) = getWMIObjects(
        class      => 'Win32_OperatingSystem',
        properties => [ qw/
            OSLanguage Caption Version SerialNumber Organization RegisteredUser
            CSDVersion TotalSwapSpaceSize LastBootUpTime
        / ],
        %$wmiParams
    );

    my ($computerSystem) = getWMIObjects(
        class      => 'Win32_ComputerSystem',
        properties => [ qw/
            Name Domain Workgroup PrimaryOwnerName TotalPhysicalMemory
        / ],
        %$wmiParams
    );

    my ($computerSystemProduct) = getWMIObjects(
        class      => 'Win32_ComputerSystemProduct',
        properties => [ qw/UUID/ ],
        %$wmiParams
    );

    $params{logger}->debug2('avant getRegistryValues');
    my $values = getRegistryValuesFromWMI(
        path => [
            'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows NT/CurrentVersion/DigitalProductId',
            'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows NT/CurrentVersion/DigitalProductId4',
            'HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/lanmanserver/Parameters/srvcomment'
        ],
        logger => $params{logger},
        %$wmiParams
    );
    my $raw1 = $values->[0];
    my $raw2 = $values->[1];
    my $raw3 = $values->[2];
    $params{logger}->debug2('après getRegistryValues');
    my $key =
        decodeMicrosoftKey($raw1) ||
        decodeMicrosoftKey($raw2);
    $params{logger}->debug2('après decode, avant encode');
    my $description = '';
    $description = encodeFromRegistry($raw3) if $raw3;
    $params{logger}->debug2('après encode');
    my $arch = is64bit(%$wmiParams) ? '64-bit' : '32-bit';
    $params{logger}->debug2('après is64bit');
    my $swap = $operatingSystem->{TotalSwapSpaceSize} ?
        int($operatingSystem->{TotalSwapSpaceSize} / (1024 * 1024)) : undef;

    my $memory = $computerSystem->{TotalPhysicalMemory} ?
        int($computerSystem->{TotalPhysicalMemory} / (1024 * 1024)) : undef;

    my $uuid = $computerSystemProduct->{UUID} !~ /^[0-]+$/ ?
        $computerSystemProduct->{UUID} : undef;

    my $boottime;
    if ($operatingSystem->{LastBootUpTime} =~
            /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/) {
        $boottime = getFormatedDate($1, $2, $3, $4, $5, $6);
    }
    $params{logger}->debug2('après getFormatDate');

    # get the name through native Win32::API, as WMI DB is sometimes broken
    my $hostname = $wmiParams->{WMIService} ? $computerSystem->{Name} : getHostname(short => 1);
    $params{logger}->debug2('après getHostname()');

    $inventory->setOperatingSystem({
        NAME           => "Windows",
        ARCH           => $arch,
        INSTALL_DATE   => _getInstallDate(%$wmiParams) || '',
        BOOT_TIME      => $boottime || '',
        KERNEL_VERSION => $operatingSystem->{Version},
        FULL_NAME      => $operatingSystem->{Caption},
        SERVICE_PACK   => $operatingSystem->{CSDVersion},
    });

    $inventory->setHardware({
        NAME        => $hostname,
        DESCRIPTION => $description,
        UUID        => $uuid,
        WINPRODKEY  => $key,
        WINLANG     => $operatingSystem->{OSLanguage},
        OSNAME      => $operatingSystem->{Caption},
        OSVERSION   => $operatingSystem->{Version},
        WINPRODID   => $operatingSystem->{SerialNumber},
        WINCOMPANY  => $operatingSystem->{Organization},
        WINOWNER    => $operatingSystem->{RegisteredUser} ||
                       $computerSystem->{PrimaryOwnerName},
        OSCOMMENTS  => $operatingSystem->{CSDVersion},
        SWAP        => $swap,
        MEMORY      => $memory,
        WORKGROUP   => $computerSystem->{Domain} ||
                       $computerSystem->{Workgroup},
    });
}

sub _getInstallDate {
    my (%params) = @_;
    my $installDate = getRegistryValue(
        path   => 'HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/InstallDate',
        %params
    );
    return unless $installDate;

    my $dec = hex2dec($installDate);
    return unless $dec;

    return getFormatedLocalTime($dec);
}

1;
