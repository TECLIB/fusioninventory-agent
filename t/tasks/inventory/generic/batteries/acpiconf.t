#!/usr/bin/perl
use strict;
use warnings;

use Test::Deep;
use Test::More;
use Test::NoWarnings;

use FusionInventory::Agent::Tools::Batteries;
use FusionInventory::Agent::Task::Inventory::Generic::Batteries::Acpiconf;
use FusionInventory::Agent::Task::Inventory::Generic::Dmidecode::Battery;

my %testAcpiconfInfos = (
    'infos_1.txt' => {
        NAME         => 'DELL 242WD6B',
        CAPACITY     => '6880 mAh',
        VOLTAGE      => '7600 mV',
        CHEMISTRY    => 'LION',
        SERIAL       => 58167,
    },
);

my %testAcpiconfMerged = (
    'freebsd-1' => {
        dmidecode   => 'dmidecode_1.txt',
        acpiconflist => [ 'infos_1.txt' ],
        step1 => [
            {
                CAPACITY        => '54990',
                CHEMISTRY       => 'LION',
                DATE            => '28/10/2016',
                MANUFACTURER    => 'Lg',
                NAME            => 'DELL 242WD6B',
                SERIAL          => 58167,
                VOLTAGE         => '7600'
            }
        ],
        merged => [
            {
                NAME         => 'DELL 242WD6B',
                CAPACITY     => '6880 mAh',
                VOLTAGE      => '7600 mV',
                CHEMISTRY    => 'LION',
                SERIAL       => 58167,
                MANUFACTURER => 'Lg',
                DATE         => '28/10/2016',
            }
        ],
    },
);

plan tests =>
    scalar (keys %testAcpiconfInfos) +
    2 * scalar (keys %testAcpiconfMerged) +
    1;

foreach my $test (keys %testAcpiconfInfos) {
    my $battery = FusionInventory::Agent::Task::Inventory::Generic::Batteries::Acpiconf::_getBatteryFromAcpiconf(
        file => 'resources/generic/batteries/acpiconf/' . $test
    );
    cmp_deeply(
        $battery,
        $testAcpiconfInfos{$test},
        "$test: _getBatteryFromAcpiconf()"
    );
}

foreach my $test (keys %testAcpiconfMerged) {
    my $list = Inventory::Batteries->new();
    my $dmidecode = $testAcpiconfMerged{$test}->{dmidecode};

    # Prepare batteries list like it should be after dmidecode passed
    map { $list->add($_) }
        FusionInventory::Agent::Task::Inventory::Generic::Dmidecode::Battery::_getBatteries(
            file => 'resources/generic/batteries/acpiconf/' . $dmidecode
        );
    cmp_deeply(
        [ $list->list() ],
        $testAcpiconfMerged{$test}->{step1},
        "test $test: merge step 1"
    );

    foreach my $file (@{$testAcpiconfMerged{$test}->{acpiconflist}}) {
        my $battery = FusionInventory::Agent::Task::Inventory::Generic::Batteries::Acpiconf::_getBatteryFromAcpiconf(
            file => 'resources/generic/batteries/acpiconf/' . $file
        );
        $list->merge($battery);
    };

    cmp_deeply(
        [ $list->list() ],
        $testAcpiconfMerged{$test}->{merged},
        "test $test: merged"
    );
}
