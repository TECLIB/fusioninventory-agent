#!/usr/bin/perl

use strict;
use warnings;

use lib './bin';
use setup;

use English qw(-no_match_vars) ;
use Getopt::Long;
use Pod::Usage;

use FusionInventory::Agent;

Getopt::Long::Configure( "no_ignorecase" );

my $options = {};

GetOptions(
    $options,
    'backend-collect-timeout=s',
    'conf-file=s',
    'config=s',
    'debug+',
    'host',
    'local|l=s',
    'logger=s',
    'logfile=s',
    'pass|p=s',
    'scan-homedirs',
    'server|s=s',
    'tag|t=s',
    'user|u=s',
    'version'
) or pod2usage(-verbose => 0);

pod2usage(-verbose => 0, -exitstatus => 0) if $options->{help};

if ($options->{version}) {
    my $PROVIDER = $FusionInventory::Agent::Version::PROVIDER;
    map { print $_."\n" }
        "fusioninventory-wmi $FusionInventory::Agent::Task::Wmi::VERSION",
        "based on $PROVIDER Agent v$FusionInventory::Agent::Version::VERSION",
        @{$FusionInventory::Agent::Version::COMMENTS};
    exit 0;
}

pod2usage(-verbose => 0) unless
    $options->{host}      and
        $options->{user}      and
        $options->{pass} and
        ($options->{local} or $options->{server});

if ($options->{'conf-file'}) {
    if ($options->{config}) {
        if ($options->{config} ne 'file') {
            print STDERR
                "don't use --conf-file with $options->{config} backend";
            exit 1;
        }
    } else {
        $options->{config} = 'file';
    }
}

if ($OSNAME eq 'MSWin32' && ! $options->{'no-win32-ole-workaround'}) {
    # From here we may need to avoid crashes due to not thread-safe Win32::OLE
    FusionInventory::Agent::Tools::Win32->require();
    FusionInventory::Agent::Tools::Win32::start_Win32_OLE_Worker();
}

my $agent = FusionInventory::Agent->new(%setup);

$options->{tasks} = 'wmi';

$options->{wmi_hostname} = $options->{host};
delete $options->{host};
$options->{wmi_user} = $options->{user};
delete $options->{user};
$options->{wmi_pass} = $options->{pass};
delete $options->{pass};

eval {

    $agent->init(options => $options);
    $agent->run();
};

if ($EVAL_ERROR) {
    print STDERR "Execution failure:.\n";
    print STDERR $EVAL_ERROR;
    exit 1;
}

exit(0);
