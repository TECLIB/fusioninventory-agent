package FusionInventory::Agent::Task::Wmi;
use strict;
use warnings FATAL => 'all';
use base 'FusionInventory::Agent::Task';

use UNIVERSAL::require;
use English qw(-no_match_vars);
use Data::Dumper;
use Win32::OLE qw(in);

use FusionInventory::Agent::Tools::Win32;

$| = 1;

Win32::OLE->Option( Warn => 9 );
use constant wbemFlagReturnImmediately => 0x10;
use constant wbemFlagForwardOnly => 0x20;

our $VERSION = '0.1';

my @formFactorVal = qw/
  Unknown
  Other
  SIP
  DIP
  ZIP
  SOJ
  Proprietary
  SIMM
  DIMM
  TSOP
  PGA
  RIMM
  SODIMM
  SRIMM
  SMD
  SSMP
  QFP
  TQFP
  SOIC
  LCC
  PLCC
  BGA
  FPBGA
  LGA
  /;

my @memoryTypeVal = qw/
  Unknown
  Other
  DRAM
  Synchronous DRAM
  Cache DRAM
  EDO
  EDRAM
  VRAM
  SRAM
  RAM
  ROM
  Flash
  EEPROM
  FEPROM
  EPROM
  CDRAM
  3DRAM
  SDRAM
  SGRAM
  RDRAM
  DDR
  DDR-2
  /;

my @memoryErrorProtection = (
    undef, 'Other', undef, 'None', 'Parity',
    'Single-bit ECC',
    'Multi-bit ECC', 'CRC',
);

sub isEnabled {
    my ($self) = @_;

    return 1;
}

sub _connectToService {
    my ( $hostname, $user, $pass ) = @_;

    my $locator = Win32::OLE->CreateObject('WbemScripting.SWbemLocator')
      or warn;
    my $service =
      $locator->ConnectServer( $hostname, "root\\cimv2", "domain\\" . $user,
        $pass );

    return $service;
}

sub run {
    my ( $self, %params ) = @_;

    if ( $REAL_USER_ID != 0 ) {
        $self->{logger}
          ->warning( "You should execute this task as super-user" );
    }

    my $config = $self->{config};
    if (   !$config->{wmi_hostname}
        || !$config->{wmi_user}
        || !$config->{wmi_pass} )
    {
        $self->{logger}->error(
'wmi connection parameters missing, be sure to give host, user and password.'
        );
        return;
    }
    else {
        my $service = _connectToService( $config->{wmi_hostname},
            $config->{wmi_user}, $config->{wmi_pass} );
        if ($service) {
            $self->{WMIService} = $service;
        }
        else {
            $self->{logger}->error("can't connect to WMI service");
            return;
        }
    }

    $self->getAntivirus( $self->{WMIService} );
    my $memories = getMemories( $self->{WMIService}, $self->{logger} );

    my $dd = Data::Dumper->new( [$memories] );
    $self->{logger}->debug2( $dd->Dump );
}

sub getAntivirus {
    my ( $self, $service ) = @_;

    my $seen;
    foreach my $instance (qw/SecurityCenter SecurityCenter2/) {
        my $moniker =
"winmgmts:{impersonationLevel=impersonate,(security)}!//./root/$instance";

        foreach my $object (
            getWMIObjects(
                WMIService => $service,
                moniker    => $moniker,
                class      => "AntiVirusProduct",
                properties => [
                    qw/
                      companyName displayName instanceGuid onAccessScanningEnabled
                      productUptoDate versionNumber productState
                      /
                ]
            )
          )
        {
            next unless $object;

            my $antivirus = {
                COMPANY  => $object->{companyName},
                NAME     => $object->{displayName},
                GUID     => $object->{instanceGuid},
                VERSION  => $object->{versionNumber},
                ENABLED  => $object->{onAccessScanningEnabled},
                UPTODATE => $object->{productUptoDate}
            };

            if ( $object->{productState} ) {
                my $bin = sprintf( "%b\n", $object->{productState} );

# http://blogs.msdn.com/b/alejacma/archive/2008/05/12/how-to-get-antivirus-information-with-wmi-vbscript.aspx?PageIndex=2#comments
                if ( $bin =~ /(\d)\d{5}(\d)\d{6}(\d)\d{5}$/ ) {
                    $antivirus->{UPTODATE} = $1 || $2;
                    $antivirus->{ENABLED} = $3 ? 0 : 1;
                }
            }

# avoid duplicates
#            next if $seen->{$antivirus->{NAME}}->{$antivirus->{VERSION} || '_undef_'}++;

            my $dd = Data::Dumper->new( [$antivirus] );
            my $output = $dd->Dump;
            $self->{logger}->debug2($output);
        }
    }
}

sub getMemories {
    my ( $service, $logger ) = @_;

    my $cpt = 0;
    my @memories;

    my @colItems = in($service->ExecQuery("SELECT * FROM Win32_PhysicalMemory"));

#    my $colItems = $service->InstancesOf('Win32_PhysicalMemory');

 #    foreach my $object (getWMIObjects(
 #        WMIService => $service,
 #        class      => 'Win32_PhysicalMemory',
 #        properties => [ qw/
 #            Capacity Caption Description FormFactor Removable Speed MemoryType
 #            SerialNumber
 #            / ]
 #    )) {
    foreach my $object ( @colItems ) {
        my $dd = Data::Dumper->new( [$object] );
        $logger->debug2( 'Win32_PhysicalMemory : ' . ref $object );
        #        $logger->debug2($dd->Dump);
        # Ignore ROM storages (BIOS ROM)
        $logger->debug2( join ( ' - ', keys %$object));
        $logger->debug2($obj->{Name});

        next unless $object->{MemoryType};
        my $type = $memoryTypeVal[ $object->{MemoryType} ];
        next if $type && $type eq 'ROM';
        next if $type && $type eq 'Flash';

        my $capacity;
        $capacity = $object->{Capacity} / ( 1024 * 1024 )
          if $object->{Capacity};

        push @memories,
          {
            CAPACITY     => $capacity,
            CAPTION      => $object->{Caption},
            DESCRIPTION  => $object->{Description},
            FORMFACTOR   => $formFactorVal[ $object->{FormFactor} ],
            REMOVABLE    => $object->{Removable} ? 1 : 0,
            SPEED        => $object->{Speed},
            TYPE         => $memoryTypeVal[ $object->{MemoryType} ],
            NUMSLOTS     => $cpt++,
            SERIALNUMBER => $object->{SerialNumber}
          };
    }

    foreach my $object (
        getWMIObjects(
            class      => 'Win32_PhysicalMemoryArray',
            properties => [
                qw/
                  MemoryDevices SerialNumber PhysicalMemoryCorrection
                  /
            ]
        )
      )
    {

        my $memory = $memories[ $object->{MemoryDevices} - 1 ];
        if ( !$memory->{SERIALNUMBER} ) {
            $memory->{SERIALNUMBER} = $object->{SerialNumber};
        }

        if ( $object->{PhysicalMemoryCorrection} ) {
            $memory->{MEMORYCORRECTION} =
              $memoryErrorProtection[ $object->{PhysicalMemoryCorrection} ];
        }

        if ( $memory->{MEMORYCORRECTION} ) {
            $memory->{DESCRIPTION} .= " (" . $memory->{MEMORYCORRECTION} . ")";
        }
    }

    return @memories;
}

1;
