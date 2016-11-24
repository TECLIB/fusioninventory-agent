package FusionInventory::Agent::Task::Wmi;
use strict;
use warnings FATAL => 'all';
use base 'FusionInventory::Agent::Task';

use UNIVERSAL::require;
use English qw(-no_match_vars);
use Data::Dumper;

use FusionInventory::Agent::Tools::Win32;
use FusionInventory::Agent::Task::Inventory::Win32::Memory;
use FusionInventory::Agent::Task::Inventory::Win32::Antivirus;
use FusionInventory::Agent::Task::Inventory::Win32::Bios;
use FusionInventory::Agent::Task::Inventory::Win32::Chassis;

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

    my %wmiParams = (
        WMIService => {
            hostname => $config->{wmi_hostname},
            user => $config->{wmi_user},
            pass => $config->{wmi_pass}
        }
    );
    my @memories = FusionInventory::Agent::Task::Inventory::Win32::Memory::getMemories(%wmiParams);
    my $dd = Data::Dumper->new( [\@memories] );
    $self->{logger}->debug2( $dd->Dump );

    my @antiviruses = FusionInventory::Agent::Task::Inventory::Win32::AntiVirus::getAntivirusesFromWMI(%wmiParams);
    $dd = Data::Dumper->new( [\@antiviruses] );
    $self->{logger}->debug2( $dd->Dump );

    my $bios = FusionInventory::Agent::Task::Inventory::Win32::Bios::appendBiosDataFromWMI(%wmiParams);
    $dd = Data::Dumper->new( [$bios] );
    $self->{logger}->debug2( $dd->Dump );

    my $chassis = FusionInventory::Agent::Task::Inventory::Win32::Chassis::getChassis(%wmiParams);
    $dd = Data::Dumper->new( [$chassis] );
    $self->{logger}->debug2( $dd->Dump );

    my $cpus = getCPUs(%wmiParams);
    $dd = Data::Dumper->new( [$cpus] );
    $self->{logger}->debug2( $dd->Dump );
}

sub getCPUs {
    my ( %wmiParams ) = @_;

    my $p = $wmiParams{WMIService};

    my @cpus = ();
    my $service = FusionInventory::Agent::Tools::Win32::_connectToService($p->{hostname}, $p->{user}, $p->{pass});
    foreach my $object (in($service->InstancesOf('Win32_Processor'))) {
        my $cpu = {};
        foreach my $prop (in $object->Properties_) {
            my $value;
            if (!($prop->Value)) {
                $value = 'NULL';
            } elsif ($prop->IsArray == 1) {
                my @values = ();
                foreach my $i ($prop) {
                    push @values, $prop->Value($i);
                }
                $value = join (' -|- ', @values);
            } else {
                $value = $prop->Value;
            }
            $cpu->{$prop->Name} = $value;
        }
        push @cpus, $cpu;
    }

    return @cpus;
}

sub getMemoriesUsingToolsFunction {
    my ( $host, $user, $pass, $logger ) = @_;

    my @list1 = getWMIObjects(
        WMIService => {
            hostname => $host,
            user => $user,
            pass => $pass
        },
        query      => [
            "SELECT * FROM Win32_PhysicalMemory"
        ],
        properties => [ qw/
            Capacity Caption Description FormFactor Removable Speed MemoryType
            SerialNumber
            / ]
    );
    my @list2 = getWMIObjects(
        WMIService => {
            hostname => $host,
            user => $user,
            pass => $pass
        },
        class      => 'Win32_PhysicalMemoryArray',
        properties => [
            qw/
                MemoryDevices SerialNumber PhysicalMemoryCorrection
                /
        ]
    );

    my @memories = FusionInventory::Agent::Task::Inventory::Win32::Memory::extractMemoriesFromWMIObjects(\@list1, \@list2);

    return @memories;
}



1;
