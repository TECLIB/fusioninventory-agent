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
        'FusionInventory::Agent::Task::Inventory::Win32::AntiVirus',
        'FusionInventory::Agent::Task::Inventory::Win32::Bios',
        'FusionInventory::Agent::Task::Inventory::Win32::Chassis',
        'FusionInventory::Agent::Task::Inventory::Win32::Controllers',
        'FusionInventory::Agent::Task::Inventory::Win32::CPU',
        'FusionInventory::Agent::Task::Inventory::Win32::Drives',
        'FusionInventory::Agent::Task::Inventory::Win32::Environment',
        'FusionInventory::Agent::Task::Inventory::Win32::Inputs',
        'FusionInventory::Agent::Task::Inventory::Win32::License',
        'FusionInventory::Agent::Task::Inventory::Win32::Memory',
        'FusionInventory::Agent::Task::Inventory::Win32::Modems',
        'FusionInventory::Agent::Task::Inventory::Win32::Networks',
        'FusionInventory::Agent::Task::Inventory::Win32::OS',
        'FusionInventory::Agent::Task::Inventory::Win32::Ports',
        'FusionInventory::Agent::Task::Inventory::Win32::Printers',
        'FusionInventory::Agent::Task::Inventory::Win32::Registry',
        'FusionInventory::Agent::Task::Inventory::Win32::Slots',
#        'FusionInventory::Agent::Task::Inventory::Win32::Softwares',
        'FusionInventory::Agent::Task::Inventory::Win32::Sounds',
        'FusionInventory::Agent::Task::Inventory::Win32::Storages',
        'FusionInventory::Agent::Task::Inventory::Win32::USB',
        'FusionInventory::Agent::Task::Inventory::Win32::Users',
        'FusionInventory::Agent::Task::Inventory::Win32::Videos'
    ];
    $self->SUPER::run(%params);
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
