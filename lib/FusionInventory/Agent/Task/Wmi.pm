package FusionInventory::Agent::Task::Wmi;
use strict;
use warnings FATAL => 'all';

use UNIVERSAL::require;
use English qw(-no_match_vars);
use DBI;

sub isEnabled {
    my ($self) = @_;

    DBD::WMI->require();
    if ($EVAL_ERROR) {
        $self->{logger}->debug("cannot launch task WMI") if $self->{logger};
        return 0;
    }

    return 1
}

sub run {
    my ($self, %params) = @_;

    if ($REAL_USER_ID != 0) {
        $self->{logger}->warning(
            "You should execute this task as super-user"
        );
    }

    use DBI;
    my $dbh = DBI->connect('dbi:WMI:');

}

1;
