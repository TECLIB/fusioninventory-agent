package FusionInventory::Agent::Task::Wmi;
use strict;
use warnings FATAL => 'all';
use parent 'FusionInventory::Agent::Task::Inventory';

use UNIVERSAL::require;
use English qw(-no_match_vars);
use Data::Dumper;

use FusionInventory::Agent::Tools::Win32;

our $VERSION = '0.1';

sub isEnabled {
    my ($self) = @_;

    return 1;
}

sub getModules {
    #TODO : overwrite...
}

sub run {
    my ( $self, %params ) = @_;

    $self->{logger}->debug2('running Wmi');

    my $inventory = FusionInventory::Agent::Inventory->new(
        statedir => $self->{target}->getStorage()->getDirectory(),
        logger   => $self->{logger},
        tag      => $self->{config}->{'tag'},
        WMIService => {
            hostname => $self->{config}->{wmi_hostname},
            user     => $self->{config}->{wmi_user},
            pass     => $self->{config}->{wmi_pass}
        }
    );
    $params{inventory} = $inventory;
    $params{enabledModules} = [
        'FusionInventory::Agent::Task::Inventory::Generic',
        'FusionInventory::Agent::Task::Inventory::Win32',
#        'FusionInventory::Agent::Task::Inventory::Win32::AntiVirus',
#        'FusionInventory::Agent::Task::Inventory::Win32::Bios',
#        'FusionInventory::Agent::Task::Inventory::Win32::Chassis',
#        'FusionInventory::Agent::Task::Inventory::Win32::Controllers',
#        'FusionInventory::Agent::Task::Inventory::Win32::CPU',
#        'FusionInventory::Agent::Task::Inventory::Win32::Drives',
#        'FusionInventory::Agent::Task::Inventory::Win32::Environment',
#        'FusionInventory::Agent::Task::Inventory::Win32::Inputs',
#        'FusionInventory::Agent::Task::Inventory::Win32::License',
#        'FusionInventory::Agent::Task::Inventory::Win32::Memory',
#        'FusionInventory::Agent::Task::Inventory::Win32::Modems',
#        'FusionInventory::Agent::Task::Inventory::Win32::Networks',
#        'FusionInventory::Agent::Task::Inventory::Win32::OS',
#        'FusionInventory::Agent::Task::Inventory::Win32::Ports',
        'FusionInventory::Agent::Task::Inventory::Win32::Printers',
#        'FusionInventory::Agent::Task::Inventory::Win32::Registry'1,
#        'FusionInventory::Agent::Task::Inventory::Win32::Slots',
#        'FusionInventory::Agent::Task::Inventory::Win32::Softwares'
    ];
    $self->SUPER::run(%params);

    if (2==1) {
        if ( $REAL_USER_ID != 0 ) {
            $self->{logger}
              ->warning( "You should execute this task as super-user" );
        }

        my $config = $self->{config};
        if (!$config->{wmi_hostname}
            || !$config->{wmi_user}
            || !$config->{wmi_pass})
        {
            $self->{logger}->error(
                'wmi connection parameters missing, be sure to give host, user and password.'
            );
            return;
        }

        my %wmiParams = (
            WMIService => {
                hostname => $config->{wmi_hostname},
                user     => $config->{wmi_user},
                pass     => $config->{wmi_pass}
            }
        );
        my @memories = FusionInventory::Agent::Task::Inventory::Win32::Memory::getMemories(%wmiParams);
        my $dd = Data::Dumper->new( [ \@memories ] );
        $self->{logger}->debug2( $dd->Dump );

        my @antiviruses = FusionInventory::Agent::Task::Inventory::Win32::AntiVirus::getAntivirusesFromWMI(%wmiParams);
        $dd = Data::Dumper->new( [ \@antiviruses ] );
        $self->{logger}->debug2( $dd->Dump );

        my $bios = FusionInventory::Agent::Task::Inventory::Win32::Bios::appendBiosDataFromWMI(%wmiParams);
        $dd = Data::Dumper->new( [ $bios ] );
        $self->{logger}->debug2( $dd->Dump );

        my $chassis = FusionInventory::Agent::Task::Inventory::Win32::Chassis::getChassis(%wmiParams);
        $dd = Data::Dumper->new( [ $chassis ] );
        $self->{logger}->debug2( $dd->Dump );

        my @cpus = getCPU(%wmiParams);
        $dd = Data::Dumper->new( [ @cpus ] );
        $self->{logger}->debug2( $dd->Dump );

        my (@drives, @volumes) = FusionInventory::Agent::Task::Inventory::Win32::Drives::getDrives(%wmiParams);
        $dd = Data::Dumper->new( [ @drives, @volumes ] );
        $self->{logger}->debug2( $dd->Dump );

        my @envVars = FusionInventory::Agent::Task::Inventory::Win32::Environment::getEnvironmentValues(%wmiParams);
        $dd = Data::Dumper->new( [ \@envVars ] );
        $self->{logger}->debug2( $dd->Dump );
    }
}

sub getCPU {
    my @cpus = FusionInventory::Agent::Tools::Win32::getWMIObjects(
        class      => 'Win32_Processor',
        returnAllPropertiesValues => 1,
        @_
    );

    return @cpus;
}

1;
