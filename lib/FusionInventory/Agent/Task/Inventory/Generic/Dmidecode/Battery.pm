package FusionInventory::Agent::Task::Inventory::Generic::Dmidecode::Battery;

use strict;
use warnings;

use parent 'FusionInventory::Agent::Task::Inventory::Module';

use FusionInventory::Agent::Tools;
use FusionInventory::Agent::Tools::Generic;
use FusionInventory::Agent::Tools::Batteries;

sub isEnabled {
    my (%params) = @_;
    return 0 if $params{no_category}->{battery};
    return 1;
}

sub doInventory {
    my (%params) = @_;

    my $inventory = $params{inventory};
    my $logger    = $params{logger};

    foreach my $battery (_getBatteries(logger => $logger)) {
        $inventory->addEntry(
            section => 'BATTERIES',
            entry   => $battery
        );
    }
}

sub _getBatteries {
    my $infos = getDmidecodeInfos(@_);

    return unless $infos->{22};

    my @batteries = ();
    foreach my $info (@{$infos->{22}}) {
        my $battery = _extractBatteryData($info);
        push @batteries, $battery if $battery;
    }

    return @batteries;
}

sub _extractBatteryData {
    my ($info) = @_;

    my $battery = {
        NAME         => $info->{'Name'},
        MANUFACTURER => getCanonicalManufacturer($info->{'Manufacturer'}),
        SERIAL       => sanitizeBatterySerial(
            $info->{'Serial Number'} || $info->{'SBDS Serial Number'}
        ),
        CHEMISTRY    => $info->{'Chemistry'} ||
            $info->{'SBDS Chemistry'},
    };

    if ($info->{'Manufacture Date'}) {
        $battery->{DATE} = _parseDate($info->{'Manufacture Date'});
    } elsif ($info->{'SBDS Manufacture Date'}) {
        $battery->{DATE} = _parseDate($info->{'SBDS Manufacture Date'});
    }

    if ($info->{'Design Capacity'} &&
        $info->{'Design Capacity'} =~ /(\d+) \s m[WA]h$/x) {
        $battery->{CAPACITY} = $1;
    }

    if ($info->{'Design Voltage'} &&
        $info->{'Design Voltage'} =~ /(\d+) \s mV$/x) {
        $battery->{VOLTAGE} = $1;
    }

    return $battery;
}

sub _parseDate {
    my ($string) = @_;

    my ($day, $month, $year);
    if ($string =~ /(\d{1,2}) [\/-] (\d{1,2}) [\/-] (\d{4})/x) {
        $month = $1;
        $day   = $2;
        $year  = $3;
        return "$day/$month/$year";
    } elsif ($string =~ /(\d{4}) [\/-] (\d{1,2}) [\/-] (\d{1,2})/x) {
        $year  = $1;
        $month = $2;
        $day   = $3;
        return "$day/$month/$year";
    } elsif ($string =~ /(\d{1,2}) [\/-] (\d{1,2}) [\/-] (\d{2})/x) {
        $month = $1;
        $day = $2;
        $year = ($3 > 90 ? "19" : "20" ).$3;
        return "$day/$month/$year";
    }
    return;
}

1;
