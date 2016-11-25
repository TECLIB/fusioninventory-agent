package FusionInventory::Agent::Task::Wmi;
use strict;
use warnings FATAL => 'all';
use parent 'FusionInventory::Agent::Task::Inventory';

use UNIVERSAL::require;
use English qw(-no_match_vars);
use Data::Dumper;

use FusionInventory::Agent::Tools::Win32;
use FusionInventory::Agent::Task::Inventory::Win32::Memory;
use FusionInventory::Agent::Task::Inventory::Win32::Antivirus;
use FusionInventory::Agent::Task::Inventory::Win32::Bios;
use FusionInventory::Agent::Task::Inventory::Win32::Chassis;
use FusionInventory::Agent::Task::Inventory::Win32::Drives;
use FusionInventory::Agent::Task::Inventory::Win32::Environment;

our $VERSION = '0.1';

sub isEnabled {
    my ($self) = @_;

    return 1;
}

sub getModules {
    my ($class, $prefix) = @_;

    return getModules(SUPER, 'Win32');
}

sub run {
    my ( $self, %params ) = @_;

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
