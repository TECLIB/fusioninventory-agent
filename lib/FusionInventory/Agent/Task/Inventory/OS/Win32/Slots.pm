package FusionInventory::Agent::Task::Inventory::OS::Win32::Slots;

use strict;
use warnings;

# Had never been tested. There is no slot on my virtal machine.
use FusionInventory::Agent::Tools::Win32;

sub isInventoryEnabled {
    return 1;
}

sub doInventory {
    my ($params) = @_;

    my $inventory = $params->{inventory};

    foreach my $Properties (getWmiProperties('Win32_SystemSlot', qw/
        Name Description SlotDesignation Status Shared
    /)) {

        $inventory->addSlot({
            NAME => $Properties->{Name},
            DESCRIPTION => $Properties->{Description},
            DESIGNATION => $Properties->{SlotDesignation},
            STATUS => $Properties->{Status},
            SHARED => $Properties->{Shared}
        });
    }

}

1;
