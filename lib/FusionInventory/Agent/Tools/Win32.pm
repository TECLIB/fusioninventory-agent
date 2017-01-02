package FusionInventory::Agent::Tools::Win32;

use strict;
use warnings;
use base 'Exporter';
use utf8;

use threads;
use threads 'exit' => 'threads_only';
use threads::shared;

#use sigtrap 'handler', \&errorHandler, 'error-signals';
#use sigtrap qw(handler errorHandler error-signals);
#use sigtrap qw(handler errorHandler old-interface-signals);
#use sigtrap qw(handler my_handler untrapped);
use sigtrap qw(handler errorHandler untrapped);

use UNIVERSAL::require();
use UNIVERSAL;

use Data::Dumper;

use constant KEY_WOW64_64 => 0x100;
use constant KEY_WOW64_32 => 0x200;


use Cwd;
use Encode;
use English qw(-no_match_vars);
use File::Temp qw(:seekable tempfile);
use File::Basename qw(basename);
use Win32::Job;
use Win32::TieRegistry (
    Delimiter   => '/',
    ArrayValues => 0,
    qw/KEY_READ REG_SZ REG_EXPAND_SZ REG_DWORD REG_BINARY REG_MULTI_SZ/
);

use constant REG_DWORD => Win32::TieRegistry::REG_DWORD;
use constant REG_BINARY => Win32::TieRegistry::REG_BINARY;
use constant REG_EXPAND_SZ => Win32::TieRegistry::REG_EXPAND_SZ;
use constant REG_MULTI_SZ => Win32::TieRegistry::REG_MULTI_SZ;
use constant REG_SZ => Win32::TieRegistry::REG_SZ;

use FusionInventory::Agent::Tools;
use FusionInventory::Agent::Tools::Network;

my $localCodepage;

our @EXPORT = qw(
    is64bit
    encodeFromRegistry
    KEY_WOW64_64
    KEY_WOW64_32
    getInterfaces
    getRegistryValue
    getRegistryValueFromWMI
    getRegistryKey
    getWMIObjects
    getLocalCodepage
    runCommand
    FileTimeToSystemTime
    getUsersFromRegistry
    isDefinedRemoteRegistryKey
    getRegistryKeyFromWMI
    getRegistryValuesFromWMI
    retrieveValuesNameAndType
);

my %wmiFailedCalls :shared;

sub _recordWmiCallAsFailed {
    my ($call) = @_;

    {
        lock(%wmiFailedCalls);
        $wmiFailedCalls{$call} = 1;
    }
    open(O, ">>" . 'hard_debug.log');
    print O '_recordWmiCallAsFailed ' . $call . "\n";
    close O;
}

sub _forgetWmiCall {
    my ($call) = @_;

    {
        lock(%wmiFailedCalls);
        delete $wmiFailedCalls{$call};
    }
    open(O, ">>" . 'hard_debug.log');
    print O '_forgetWmiCall ' . $call . "\n";
    close O;
}

sub _isWmiCallFailed {
    my ($call) = @_;

    return defined $wmiFailedCalls{$call};
}

sub my_handler {
    print "on s'en fout\n";
    print "Caught signal $_[0]!\n";
}

sub errorHandler {
    open(O, ">>" . 'hard_debug.log');
    print O 'sigtrap errorHandler now on untrapped, we trapped this signal !' . "\n";
    close O;
#    die('aïe aïe aïe, thread dying now...');
#    return 1;
#    die;
}

sub is64bit {
    return
        any { $_->{AddressWidth} eq 64 }
        getWMIObjects(
            class => 'Win32_Processor', properties => [ qw/AddressWidth/ ],
            @_
        );
}

sub getLocalCodepage {
    if (!$localCodepage) {
        $localCodepage =
            "cp" .
            getRegistryValue(
                path => 'HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/Nls/CodePage/ACP'
            );
    }

    return $localCodepage;
}

sub encodeFromRegistry {
    my ($string) = @_;

    ## no critic (ExplicitReturnUndef)
    return undef unless $string;

    return $string if Encode::is_utf8($string);

    return decode(getLocalCodepage(), $string);
}

sub getWMIObjects {
    my $win32_ole_dependent_api = {
        array => 1,
        funct => '_getWMIObjects',
        args  => \@_
    };

    return _call_win32_ole_dependent_api($win32_ole_dependent_api);
}

sub _getWMIObjects {
    my (%params) = (
        moniker => 'winmgmts:{impersonationLevel=impersonate,(security)}!//./',
        @_
    );

    Win32::OLE->use('in');
    my $WMIService;
    if ($params{WMIService}) {
        if (
            $params{WMIService}->{hostname}
            && $params{WMIService}->{user}
            && $params{WMIService}->{pass}
        ) {
            $WMIService = _connectToService(
                $params{WMIService}->{hostname},
                $params{WMIService}->{user},
                $params{WMIService}->{pass},
                "root\\cimv2"
            );
        } else {
            return;
        }
    } else {
        $WMIService = Win32::OLE->GetObject( $params{moniker} );
        # Support alternate moniker if provided and main failed to open
        unless (defined($WMIService)) {
            if ($params{altmoniker}) {
                $WMIService = Win32::OLE->GetObject( $params{altmoniker} );
            }
        }
    }
    return unless (defined($WMIService));

    my @objects;
    my $instances = $params{query} ?
        $WMIService->ExecQuery(@{$params{query}}) :
        $WMIService->InstancesOf($params{class});

    # eventually return all properties
    return extractAllPropertiesFromWMIObjects($instances) if $params{returnAllPropertiesValues};

    foreach my $instance (
        in(
            $instances
        )) {
        my $object;
        foreach my $property (@{$params{properties}}) {
            if (defined $instance->{$property} && !ref($instance->{$property})) {
                # string value
                $object->{$property} = $instance->{$property};
                # despite CP_UTF8 usage, Win32::OLE downgrades string to native
                # encoding, if possible, ie all characters have code <= 0x00FF:
                # http://code.activestate.com/lists/perl-win32-users/Win32::OLE::CP_UTF8/
                utf8::upgrade($object->{$property});
            } elsif (defined $instance->{$property}) {
                # list value
                $object->{$property} = $instance->{$property};
            } else {
                $object->{$property} = undef;
            }
        }
        push @objects, $object;
    }

    return @objects;
}

sub extractAllPropertiesFromWMIObjects {
    my ($instances) = @_;

    my @objects = ();
    foreach my $instance (in($instances)) {
        my $obj = {};
        foreach my $prop (in($instance->Properties_)) {
            my $value;
            if (!($prop->Value)) {
                $value = 'NULL';
            } elsif ($prop->IsArray == 1) {
                my @values = ();
                foreach my $i ($prop) {
                    push @values, $prop->Value( $i );
                }
                $value = join (' -|- ', @values);
            } else {
                $value = $prop->Value;
            }
            $obj->{$prop->Name} = $value;
        }
        push @objects, $obj;
    }

    return @objects;
}

sub getRegistryValue {
    my (%params) = @_;

    if ($params{WMIService}) {
        my $dd = Data::Dumper->new([\%params]);
        $params{logger}->debug2($dd->Dump) if $params{logger};
        return getRegistryValueFromWMI(%params);
    }

    my ($root, $keyName, $valueName);
    if ($params{path} =~ m{^(HKEY_\S+)/(.+)/([^/]+)} ) {
        $root      = $1;
        $keyName   = $2;
        $valueName = $3;
    } else {
        $params{logger}->error(
            "Failed to parse '$params{path}'. Does it start with HKEY_?"
        ) if $params{logger};
        return;
    }

    my $key = _getRegistryKey(
        logger  => $params{logger},
        root    => $root,
        keyName => $keyName
    );

    return unless (defined($key));

    if ($valueName eq '*') {
        my %ret;
        foreach (keys %$key) {
            s{^/}{};
            $ret{$_} = $params{withtype} ? [$key->GetValue($_)] : $key->{"/$_"} ;
        }
        return \%ret;
    } else {
        return $params{withtype} ? [$key->GetValue($valueName)] : $key->{"/$valueName"} ;
    }
}

sub getRegistryValueFromWMI {
    my (%params) = @_;
    $params{logger}->debug2('in getRegistryValueFromWMI()');
    my $win32_ole_dependent_api = {
        funct => '_getRegistryValueFromWMI',
        args  => \@_
    };

    return _call_win32_ole_dependent_api($win32_ole_dependent_api);
}

sub getRegistryValuesFromWMI {
    my $win32_ole_dependent_api = {
        funct => '_getRegistryValuesFromWMI',
        args  => \@_
    };

    return _call_win32_ole_dependent_api($win32_ole_dependent_api);
}

sub _getRegistryValuesFromWMI {
    my (%params) = @_;

    return unless ref($params{path}) eq 'ARRAY' || ref($params{path}) eq 'HASH';

    my $WMIService = _connectToService(
        $params{WMIService}->{hostname},
        $params{WMIService}->{user},
        $params{WMIService}->{pass},
        "root\\default"
    );
    return unless $WMIService;
    my $objReg = $WMIService->Get("StdRegProv");
    return unless $objReg;

    if (ref($params{path}) eq 'ARRAY') {
        my %hash = ();
        %hash = map { $_ => 1 } @{$params{path}};
        $params{path} = \%hash;
    }

    my $values = {};
    for my $path (keys %{$params{path}}) {
        next unless $path =~ m{^(HKEY_\S+)/(.+)/([ ^ /]+)};
        my $root = $1;
        my $keyName = $2;
        my $valueName = $3;
        $values->{$path} = _retrieveRemoteRegistryValueByType(
            %params,
            root => $root,
            keyName => $keyName,
            valueName => $valueName,
            objReg => $objReg,
            valueType => $params{path}->{$path}
        );
    }
    return $values;
}

sub _getRegistryValueFromWMI {
    my (%params) = @_;

    if ($params{path} =~ m{^(HKEY_\S+)/(.+)/([^/]+)} ) {
        $params{root}      = $1;
        $params{keyName}   = $2;
        $params{valueName} = $3;
    } else {
        return;
    }

    my $WMIService = _connectToService(
        $params{WMIService}->{hostname},
        $params{WMIService}->{user},
        $params{WMIService}->{pass},
        "root\\default"
    );
    if (!$WMIService) {
        return;
    }
    my $objReg = $WMIService->Get("StdRegProv");
    if (!$objReg) {
        return;
    }

    my $value;
    if ($params{valueType}) {
        $value = _retrieveRemoteRegistryValueByType(
            %params,
            objReg => $objReg
        );
    } else {
        $value = _retrieveValueFromRemoteRegistry(
            %params,
            objReg => $objReg
        );
    }
    return $value;
}

sub _retrieveValueFromRemoteRegistry {
    my (%params) = @_;

    my $hkey;
    if ($params{root} =~ /^HKEY_LOCAL_MACHINE(?:\\|\/)(.*)$/) {
        $hkey = $Win32::Registry::HKEY_LOCAL_MACHINE;
        my $keyName = $1 . '/' . $params{keyName};
        $keyName =~ tr#/#\\#;
        $params{keyName} = $keyName;
    } else {
        return;
    }

    return _retrieveRemoteRegistryValueByType(
        %params,
        valueType => REG_SZ,
    );
}

sub isDefinedRemoteRegistryKey {
    my (%params)  =@_;

    my $win32_ole_dependent_api = {
        funct => '_isDefinedRemoteRegistryKey',
        args  => \@_
    };

    $params{logger}->debug2('isDefinedRemoteRegistryKey() ');

    my $val = _call_win32_ole_dependent_api($win32_ole_dependent_api);

    $params{logger}->debug2($params{path} . ' : ' . $val);

    return $val;
}

sub _isDefinedRemoteRegistryKey {
    my (%params) = @_;

    return unless $params{WMIService};

    my ($root, $keyName);
    if ($params{path} =~ m{^(HKEY_\S+)/(.+)} ) {
        $root      = $1;
        $keyName   = $2;
    } else {
        $params{logger}->error(
            "Failed to parse '$params{path}'. Does it start with HKEY_?"
        ) if $params{logger};
        return;
    }

    my $WMIService = _connectToService(
        $params{WMIService}->{hostname},
        $params{WMIService}->{user},
        $params{WMIService}->{pass},
        "root\\default"
    );
    if (!$WMIService) {
        return;
    }
    my $objReg = $WMIService->Get("StdRegProv");
    if (!$objReg) {
        return;
    }

    my $hkey;
    if ($root =~ /^HKEY_LOCAL_MACHINE(?:\\|\/)(.*)$/) {
        $hkey = $Win32::Registry::HKEY_LOCAL_MACHINE;
        $keyName = $1 . '/' . $keyName;
        $keyName =~ tr#/#\\#;
    }

    my $keys = Win32::OLE::Variant->new(Win32::OLE::Variant::VT_BYREF() | Win32::OLE::Variant::VT_VARIANT());
    my $return = $objReg->EnumKey($hkey, $keyName, $keys);
    my $ret = defined $return && $return == 0 ? 1 : 0;

    return $ret;
}

sub getRegistryKey {
    my (%params) = @_;

    my ($root, $keyName);
    if ($params{path} =~ m{^(HKEY_\S+)/(.+)} ) {
        $root      = $1;
        $keyName   = $2;
    } else {
        $params{logger}->error(
            "Failed to parse '$params{path}'. Does it start with HKEY_?"
        ) if $params{logger};
        return;
    }

    if ($params{WMIService}) {
        return getRegistryKeyFromWMI(
            root => $root,
            keyName => $keyName,
            %params
        );
    }

    return _getRegistryKey(
        logger  => $params{logger},
        root    => $root,
        keyName => $keyName
    );
}

sub _getRegistryKey {
    my (%params) = @_;

    ## no critic (ProhibitBitwise)
    my $rootKey = is64bit() ?
        $Registry->Open($params{root}, { Access=> KEY_READ | KEY_WOW64_64 } ) :
        $Registry->Open($params{root}, { Access=> KEY_READ } )                ;

    if (!$rootKey) {
        $params{logger}->error(
            "Can't open $params{root} key: $EXTENDED_OS_ERROR"
        ) if $params{logger};
        return;
    }
    my $key = $rootKey->Open($params{keyName});

    return $key;
}

sub getRegistryKeyFromWMI {
    open(O, ">>".'hard_debug.log');
    print O 'starting getRegistryKeyFromWMI' . "\n";
    close O;

    my (%params) = @_;

    my $win32_ole_dependent_api = {
        funct => '_getRegistryKeyFromWMI',
        args  => \@_
    };

    my $f = sub {
        open(O, ">>".'hard_debug.log');
        print O 'eval captured end of thread !!!' . "\n";
        close O;
    };
    $DB::single = 1;
    my $keyNames = _call_win32_ole_dependent_api($win32_ole_dependent_api);

    if ($params{retrieveValuesForAllKeys}) {
        my %hash = map { $_ => 1 } @$keyNames;
        $keyNames = \%hash;
        for my $wantedKey (keys %$keyNames) {
            my $wantedKeyPath = $params{path} . '/' . $wantedKey;
            open(O, ">>".'hard_debug.log');
            print O 'on envoie retrieveValuesNameAndType '.$wantedKeyPath."\n";
            close O;
            my $eval = eval {
                $keyNames->{$wantedKey} = retrieveValuesNameAndType(
                    @_,
                    path => $wantedKeyPath
                );
            };
            &$f if $@ or !$eval;
        }
    }

    return $keyNames;
}

sub _getRegistryKeyFromWMI{
    my (%params) = @_;

    return unless $params{WMIService};

    my $WMIService = _connectToService(
        $params{WMIService}->{hostname},
        $params{WMIService}->{user},
        $params{WMIService}->{pass},
        "root\\default"
    );
    if (!$WMIService) {
        return;
    }
    my $objReg = $WMIService->Get("StdRegProv");
    if (!$objReg) {
        return;
    }

    if ($params{path} =~ m{^(HKEY_\S+)/(.+)} ) {
        $params{root}      = $1;
        $params{keyName}   = $2;
    } else {
        return;
    }

    return _retrieveSubKeyList(
        %params,
        objReg => $objReg
    );
}

sub _retrieveSubKeyList {
    my (%params) = @_;

    open(O, ">>" . 'hard_debug.log');
    print O '_retrieveSubKeyList() ' . $params{path} . "\n";
    close O;

    Win32::OLE->use('in');

    my $hkey;
    if ($params{root} =~ /^HKEY_LOCAL_MACHINE(?:\\|\/)(.*)$/) {
        $hkey = $Win32::Registry::HKEY_LOCAL_MACHINE;
        my $keyName = $1 . '/' . $params{keyName};
        $keyName =~ tr#/#\\#;
        $params{keyName} = $keyName;
    } else {
        return;
    }

    my $arr = Win32::OLE::Variant->new( Win32::OLE::Variant::VT_ARRAY() | Win32::OLE::Variant::VT_VARIANT() | Win32::OLE::Variant::VT_BYREF()  , [1,1] );
    # Do not use Die for this method

    my $func = sub {
        open (O, ">" . 'eval_return.log');
        print O '_retrieveSubKeyList() : eval is fatal error !!!' . "\n";
        close O;
    };
    my $return;
    my $subKeys;
#    open(O, ">" . 'debug_' . time());
#    print O 'avant eval' . "\n";

        open(O, ">>" . 'hard_debug.log');
        print O 'keyName : ' . $params{keyName} . "\n";
        close O;
        $return = $params{objReg}->EnumKey($hkey, $params{keyName}, $arr);
        open(O, ">>" . 'hard_debug.log');
        print O 'après EnumKey' . "\n";
        close O;
        if (defined $return && $return == 0 && $arr->Value) {
            open(O, ">>" . 'hard_debug.log');
            print O '$return : ' . $return . "\n";
            close O;
            $subKeys = [ ];
            foreach my $item (in( $arr->Value )) {
                push @$subKeys, $item;
            }
        }
#        if ($params{retrieveValuesForAllKeys}) {
#            $params{retrieveValuesForKeyName} = $subKeys;
#        }
#        if ($params{retrieveValuesForKeyName}
#            && ref($params{retrieveValuesForKeyName}) eq 'ARRAY') {
#            my %subKeysWithValues = map { $_ => 1 } @$subKeys;
#            for my $wantedKey (@{$params{retrieveValuesForKeyName}}) {
#                if ($subKeysWithValues{$wantedKey}) {
#                    my $wantedKeyPath = $params{keyName} . "\\" . $wantedKey;
#                    open(O, ">>" . 'hard_debug.log');
#                    print O 'on envoie _retrieveValuesNameAndType ' . $wantedKeyPath . "\n";
#                    close O;
#                    $subKeysWithValues{$wantedKey} = _retrieveValuesNameAndType(
#                        WMIService => $params{WMIService},
#                        objReg => $params{objReg},
#                        keyName   => $wantedKeyPath,
#                        hkey => 'HKEY_LOCAL_MACHINE'
#                    );
#                }
#            }
#            $subKeys = \%subKeysWithValues;
#        }

    &$func if $@;
#    print O 'après eval' . "\n";
#    print O 'mais heu' . "\n" if $@;
#    print O 'mais alors ! ' . "\n";
#    print O $@ if $@;
#    close O;
    return $subKeys;
}

sub retrieveValuesNameAndType {
    my $win32_ole_dependent_api = {
        funct => '_retrieveValuesNameAndType',
        args  => \@_
    };

    return _call_win32_ole_dependent_api($win32_ole_dependent_api);
}

sub _retrieveValuesNameAndType {
    my (%params) = @_;

    Win32::OLE->use('valof');

    my $truc = $params{path} ? $params{path} : $params{keyName} ? $params{keyName} : 'UNDEF';
    open(O, ">>" . 'hard_debug.log');
    print O '_retrieveValuesNameAndType() ' . $truc . "\n";
    close O;

    unless ($params{root}) {
        if ($params{path} && $params{path} =~ m{^(HKEY_\S+)/(.+)}) {
            $params{root} = $1;
            $params{keyName} = $2;
        } elsif (!($params{keyName})) {
            return;
        }
    }

    my $hkey;
    if ($params{root} && $params{root} =~ /^HKEY_LOCAL_MACHINE(?:\\|\/)(.*)$/) {
        $hkey = $Win32::Registry::HKEY_LOCAL_MACHINE;
        my $keyName = $1 . '/' . $params{keyName};
        $keyName =~ tr#/#\\#;
        $params{keyName} = $keyName;
    } elsif ($params{hkey} && $params{hkey} eq 'HKEY_LOCAL_MACHINE') {
        $hkey = $Win32::Registry::HKEY_LOCAL_MACHINE;
    } else {
        $params{logger}->error(
            "Failed to parse '$params{path}'. Does it start with HKEY_?"
        ) if $params{logger};
        return;
    }

    my $wmiCall = $params{WMIService}->{hostname} . '#' . $params{WMIService}->{user} . '#' . $params{keyName};
    return if _isWmiCallFailed($wmiCall);

    unless ($params{objReg}) {
        return unless $params{WMIService};
        my $WMIService = _connectToService(
            $params{WMIService}->{hostname},
            $params{WMIService}->{user},
            $params{WMIService}->{pass},
            "root\\default"
        );
        if (!$WMIService) {
            return;
        }
        my $objReg = $WMIService->Get("StdRegProv");
        if (!$objReg) {
            return;
        }
        $params{objReg} = $objReg;
    }

    my $func1 = sub {
        my $str = shift;
        # do nothing
        my $dd = Data::Dumper->new([\%SIG]);
        open(O, ">>" . 'hard_debug.log');
        print O 'eval() has died ' . $params{keyName} . " : $str\n";
        print O Win32::OLE->LastError() . "\n";
        print O $@ . "\n";
        print O $dd->Dump;
        close O;
        $SIG{SEGV} = &errorHandler;
        die('die because of SEGV');
    };
    my $values;

        my $types;
        my $arrValueTypes = Win32::OLE::Variant->new( Win32::OLE::Variant::VT_ARRAY() | Win32::OLE::Variant::VT_VARIANT() | Win32::OLE::Variant::VT_BYREF() , [1,1] );
        my $arrValueNames = Win32::OLE::Variant->new( Win32::OLE::Variant::VT_ARRAY() | Win32::OLE::Variant::VT_VARIANT() | Win32::OLE::Variant::VT_BYREF() , [1,1] );
        open(O, ">>" . 'hard_debug.log');
        print O 'avant EnumValues' . "\n";
        close O;
    # record call
    _recordWmiCallAsFailed($wmiCall);
#    eval {
    {
        $SIG{SEGV} = \&$func1;

        my $return = $params{objReg}->EnumValues($hkey, $params{keyName}, $arrValueNames, $arrValueTypes);
        print 'error : '.$return."\n";
        print Win32::OLE->LastError()."\n";
        my $sprintfError = '';
        if (Win32::OLE->LastError()) {
            open(O, ">>".'hard_debug.log');
            $sprintfError = sprintf("%s", Win32::OLE->LastError());
            print O $sprintfError."\n";
            close O;
        }
        open(O, ">>".'hard_debug.log');
        print O 'sprintfError : '.$sprintfError."\n";
        print O 'ref arrValueTypes '.(ref $arrValueTypes)."\n";
        print O 'arrValueTypes->IsNothing '.$arrValueTypes->IsNothing()."\n";
        print O 'arrValueTypes->IsNullString '.$arrValueTypes->IsNullString()."\n";
        print O 'arrValueTypes->Type '.$arrValueTypes->Type()."\n";
        close O;
        $DB::single = 1;
        sleep 1;
        my $f2 = sub {
            my $str = shift;
            open(O, ">>".'hard_debug.log');
            print O '_retrieveValuesNameAndType() : eval() has died '.$params{keyName}." : $str\n";
            print O Win32::OLE->LastError()."\n";
            print O $@."\n";
            close O;
        };
        open(O, ">>".'hard_debug.log');
        print O 'arrValueTypes->Value '.$arrValueTypes->Value()."\n";
        my $ddd = Data::Dumper->new([ $arrValueTypes ]);
        print O $ddd->Dump;
        close O;
        #    my $retEval = eval {
        #        local $SIG{SEGV} = 'IGNORE';
        if (defined $return && $return == 0) {
            $types = [ ];
            foreach my $item (in( $arrValueTypes->Value )) {
                push @$types, sprintf $item;
            }
            if (scalar (@$types) > 0) {
                my $i = 0;
                $values = { };
                foreach my $item (in( $arrValueNames->Value )) {
                    my $valueName = sprintf $item;
                    $values->{$valueName} = _retrieveRemoteRegistryValueByType(
                        valueType => $types->[$i],
                        keyName   => $params{keyName},
                        valueName => $valueName,
                        objReg    => $params{objReg},
                        hkey      => $hkey
                    );
                    $i++;
                }
            }
        }
        $SIG{SEGV} = 'DEFAULT';
    }
#    };
#    &$func1 if $@;

    _forgetWmiCall($wmiCall);
    return $values;
}

sub _retrieveRemoteRegistryValueByType {
    my (%params) = @_;
#    open (O, ">>" . 'eval_return.log');
#    print O 'in _retrieveRemoteRegistryValueByType' . "\n";
#    my $dd = Data::Dumper->new([\%params]);
#    print O $dd->Dump;
#    close O;
    return unless $params{valueType} && $params{objReg} && $params{keyName};

    open (O, ">>" . 'eval_return.log');
    print O 'return ' . $params{keyName} . ' ' . $params{valueName} . ' ' . $params{valueType} . "\n";
    close O;

    if ($params{root} && $params{root} =~ /^HKEY_LOCAL_MACHINE(?:\\|\/)(.*)$/) {
        $params{hkey} = $Win32::Registry::HKEY_LOCAL_MACHINE;
        my $keyName = $1 . '/' . $params{keyName};
        $keyName =~ tr#/#\\#;
        $params{keyName} = $keyName;
    } elsif ($params{hkey} && $params{hkey} eq 'HKEY_LOCAL_MACHINE') {
        $params{hkey} = $Win32::Registry::HKEY_LOCAL_MACHINE;
    }

    my $value;
    my $result = Win32::OLE::Variant->new(Win32::OLE::Variant::VT_BYREF() | Win32::OLE::Variant::VT_BSTR(), 0);
    if ($params{valueType} == REG_BINARY) {
        $value = $params{objReg}->GetBinaryValue($params{hkey}, $params{keyName}, $params{valueName}, $result);
        $value = sprintf($result);
    } elsif ($params{valueType} == REG_DWORD) {
        $result = Win32::OLE::Variant->new(Win32::OLE::Variant::VT_I4(), 0);
        my $return = $params{objReg}->GetDWORDValue($params{hkey}, $params{keyName}, $params{valueName}, $result);
        if (defined $return && $return == 0) {
            $value = $result->Date('yyyy-MM-dd') . ' ' . $result->Time('HH:mm:ss');
#            $value .= ' - ' . $result->As(Win32::OLE::Variant::VT_I4())->Value;
            $value .= ' - ' . $result->Number();
            $value .= ' - ' . $result->Value();
            $value .= ' - ' . sprintf($result);
        }
        $result = Win32::OLE::Variant->new(Win32::OLE::Variant::VT_I4(), 0);
#        $result = Win32::OLE::Variant->new(Win32::OLE::Variant::VT_BYREF() | Win32::OLE::Variant::VT_BSTR(), 0);
        $return = $params{objReg}->GetStringValue($params{hkey}, $params{keyName}, $params{valueName}, $result);
        $value .= sprintf($result);
    } elsif ($params{valueType} == REG_EXPAND_SZ) {
        $value = $params{objReg}->GetExpandedStringValue($params{hkey}, $params{keyName}, $params{valueName}, $result);
        $value = sprintf($result);
    } elsif ($params{valueType} == REG_MULTI_SZ) {
        $value = $params{objReg}->GetMultiStringValue($params{hkey}, $params{keyName}, $params{valueName}, $result);
        $value = sprintf($result);
    } elsif ($params{valueType} == REG_SZ) {
        $value = $params{objReg}->GetStringValue($params{hkey}, $params{keyName}, $params{valueName}, $result);
        $value = sprintf($result);
    } else		         {
        $params{logger}->error('_retrieveRemoteRegistryValueByType() : wrong valueType !') if $params{logger};
    }

    $value = '' if !$value;
    open (O, ">>" . 'eval_return.log');
    print O 'return ' . $params{keyName} . ' ' . $params{valueName} . ' : <' . sprintf($value) . '>' . "\n";
    close O;

    return $value;
}

sub getRegistryTreeFromWMI {
    my $win32_ole_dependent_api = {
        funct => '_getRegistryTreeFromWMI',
        args  => \@_
    };

    return _call_win32_ole_dependent_api($win32_ole_dependent_api);
}

sub _getRegistryTreeFromWMI {
    my (%params) = @_;

    return unless $params{WMIService};

    my $WMIService = _connectToService(
        $params{WMIService}->{hostname},
        $params{WMIService}->{user},
        $params{WMIService}->{pass},
        "root\\default"
    );
    if (!$WMIService) {
        return;
    }
    my $objReg = $WMIService->Get("StdRegProv");
    if (!$objReg) {
        return;
    }

    return _retrieveSubTreeRec(
        objReg => $objReg,
        %params
    );
}

sub _retrieveSubTreeRec {
    my (%params) = @_;

    open(O, ">>" . 'hard_debug.log');
    print O '_retrieveSubTreeRec() ' . $params{path} . "\n";
    close O;

    my @debug = ('in _retrieveSubTreeRec()');
    my $dd = Data::Dumper->new([\%params]);
    if ($params{path} =~ m{^(HKEY_\S+)/(.+)} ) {
        $params{root}      = $1;
        $params{keyName}   = $2;
    } else {
        return;
    }
    my $tree;
    $dd = Data::Dumper->new([\%params]);
    my $subKeys = _retrieveSubKeyList(%params);
    my $keyValues;
    $keyValues = _retrieveValuesNameAndType(%params);
    open(O, ">>" . 'hard_debug.log');
    print O 'done _retrieveValuesNameAndType' . "\n";
    $dd = Data::Dumper->new([$subKeys, $keyValues]);
    print O $dd->Dump;
    close O;
    if ($subKeys) {
        push @debug, 'subKeys found';
#        $params{logger}->debug2('found subKeys');
        $tree = {};
        for my $subKey (@$subKeys) {
#            $params{logger}->debug2('subKey : ' . $subKey);
#            $params{logger}->debug2('lauching _retrieveSubTreeRec in _retrieveSubTreeRec');
#            $tree->{$subKey} = 'value';
            open(O, ">>" . 'hard_debug.log');
            print O 'subKey : ' . $subKey . "\n";
            close O;
            $tree->{$subKey} = _retrieveSubTreeRec(
                %params,
                path => $params{path} . '/' . $subKey
            );
        }
    }
    if ($keyValues) {
        push @debug, 'found keyValues' . "\n";
        $tree = $keyValues;
    }
    if (!$subKeys && !$keyValues) {
        $tree = {};
        if ($params{path} =~ m{^(HKEY_\S+)/(.+)/([^/]+)} ) {
            $params{root}      = $1;
            $params{keyName}   = $2;
            $params{valueName} = $3;
            $tree->{VALUE} = 'value';#_retrieveValueFromRemoteRegistry(%params);
        }
#        $params{logger}->debug2("didn't find subKeys");
#        $params{logger}->debug2('lauching _retrieveValueFromRemoteRegistry');
    }
    $tree->{DEBUG} = \@debug;
    return $tree;
}



sub runCommand {
    my (%params) = (
        timeout => 3600 * 2,
        @_
    );

    my $job = Win32::Job->new();

    my $buff = File::Temp->new();

    my $winCwd = Cwd::getcwd();
    $winCwd =~ s{/}{\\}g;

    my ($fh, $filename) = File::Temp::tempfile( "$ENV{TEMP}\\fusinvXXXXXXXXXXX", SUFFIX => '.bat');
    print $fh "cd \"".$winCwd."\"\r\n";
    print $fh $params{command}."\r\n";
    print $fh "exit %ERRORLEVEL%\r\n";
    close $fh;

    my $args = {
        stdout    => $buff,
        stderr    => $buff,
        no_window => 1
    };

    $job->spawn(
        "$ENV{SYSTEMROOT}\\system32\\cmd.exe",
        "start /wait cmd /c $filename",
        $args
    );

    $job->run($params{timeout});
    unlink($filename);

    $buff->seek(0, SEEK_SET);

    my $exitcode;

    my ($status) = $job->status();
    foreach my $pid (%$status) {
        $exitcode = $status->{$pid}{exitcode};
        last;
    }

    return ($exitcode, $buff);
}

sub getInterfaces {

    my @configurations;

    foreach my $object (getWMIObjects(
        class      => 'Win32_NetworkAdapterConfiguration',
        properties => [ qw/Index Description IPEnabled DHCPServer MACAddress
                           MTU DefaultIPGateway DNSServerSearchOrder IPAddress
                           IPSubnet/  ],
        @_
    )) {
        $_{logger}->debug2('found Win32_NetworkAdapterConfiguration') if $_{logger};
        my $configuration = {
            DESCRIPTION => $object->{Description},
            STATUS      => $object->{IPEnabled} ? "Up" : "Down",
            IPDHCP      => $object->{DHCPServer},
            MACADDR     => $object->{MACAddress},
            MTU         => $object->{MTU}
        };

        if ($object->{DefaultIPGateway}) {
            $configuration->{IPGATEWAY} = $object->{DefaultIPGateway}->[0];
        }

        if ($object->{DNSServerSearchOrder}) {
            $configuration->{dns} = $object->{DNSServerSearchOrder}->[0];
        }

        if ($object->{IPAddress}) {
            foreach my $address (@{$object->{IPAddress}}) {
                my $prefix = shift @{$object->{IPSubnet}};
                push @{$configuration->{addresses}}, [ $address, $prefix ];
            }
        }

        $configurations[$object->{Index}] = $configuration;
    }

    my @interfaces;

    foreach my $object (getWMIObjects(
        class      => 'Win32_NetworkAdapter',
        properties => [ qw/Index PNPDeviceID Speed PhysicalAdapter
                           AdapterTypeId/  ],
        @_
    )) {
        # http://comments.gmane.org/gmane.comp.monitoring.fusion-inventory.devel/34
        next unless $object->{PNPDeviceID};

        $_{logger}->debug2('found Win32_NetworkAdapter') if $_{logger};

        my $pciid;
        if ($object->{PNPDeviceID} =~ /PCI\\VEN_(\w{4})&DEV_(\w{4})&SUBSYS_(\w{4})(\w{4})/) {
            $pciid = join(':', $1 , $2 , $3 , $4);
        }

        my $configuration = $configurations[$object->{Index}];

        if ($configuration->{addresses}) {
            foreach my $address (@{$configuration->{addresses}}) {

                my $interface = {
                    PNPDEVICEID => $object->{PNPDeviceID},
                    PCIID       => $pciid,
                    MACADDR     => $configuration->{MACADDR},
                    DESCRIPTION => $configuration->{DESCRIPTION},
                    STATUS      => $configuration->{STATUS},
                    MTU         => $configuration->{MTU},
                    dns         => $configuration->{dns},
                };

                if ($address->[0] =~ /$ip_address_pattern/) {
                    $interface->{IPADDRESS} = $address->[0];
                    $interface->{IPMASK}    = $address->[1];
                    $interface->{IPSUBNET}  = getSubnetAddress(
                        $interface->{IPADDRESS},
                        $interface->{IPMASK}
                    );
                    $interface->{IPDHCP}    = $configuration->{IPDHCP};
                    $interface->{IPGATEWAY} = $configuration->{IPGATEWAY};
                } else {
                    $interface->{IPADDRESS6} = $address->[0];
                    $interface->{IPMASK6}    = getNetworkMaskIPv6($address->[1]);
                    $interface->{IPSUBNET6}  = getSubnetAddressIPv6(
                        $interface->{IPADDRESS6},
                        $interface->{IPMASK6}
                    );
                }

                $interface->{SPEED}      = $object->{Speed} / 1_000_000
                    if $object->{Speed};
                $interface->{VIRTUALDEV} = _isVirtual($object, $configuration);

                push @interfaces, $interface;
            }
        } else {
            next unless $configuration->{MACADDR};

            my $interface = {
                PNPDEVICEID => $object->{PNPDeviceID},
                PCIID       => $pciid,
                MACADDR     => $configuration->{MACADDR},
                DESCRIPTION => $configuration->{DESCRIPTION},
                STATUS      => $configuration->{STATUS},
                MTU         => $configuration->{MTU},
                dns         => $configuration->{dns},
            };

            $interface->{SPEED}      = $object->{Speed} / 1_000_000
                if $object->{Speed};
            $interface->{VIRTUALDEV} = _isVirtual($object, $configuration);

            push @interfaces, $interface;
        }

    }

    return
        @interfaces;

}

sub _isVirtual {
    my ($object, $configuration) = @_;

    # PhysicalAdapter only work on OS > XP
    if (defined $object->{PhysicalAdapter}) {
        return $object->{PhysicalAdapter} ? 0 : 1;
    }

    # http://forge.fusioninventory.org/issues/1166
    if ($configuration->{DESCRIPTION} &&
        $configuration->{DESCRIPTION} =~ /RAS/ &&
        $configuration->{DESCRIPTION} =~ /Adapter/i
    ) {
          return 1;
    }

    return $object->{PNPDeviceID} =~ /^ROOT/ ? 1 : 0;
}

sub FileTimeToSystemTime {
    # Inspired by Win32::FileTime module
    my $time = shift;

    my $SystemTime = pack( 'SSSSSSSS', 0, 0, 0, 0, 0, 0, 0, 0 );

    # Load Win32::API as late as possible
    Win32::API->require() or return;

    my @times;
    eval {
        my $FileTimeToSystemTime = Win32::API->new(
            'kernel32',
            'FileTimeToSystemTime',
            [ 'P', 'P' ],
            'I'
        );

        $FileTimeToSystemTime->Call( $time, $SystemTime );
        @times = unpack( 'SSSSSSSS', $SystemTime );
    };

    return @times;
}

my $worker ;
my $worker_semaphore;

my @win32_ole_calls : shared;

sub start_Win32_OLE_Worker {

    unless (defined($worker)) {
        # Request a semaphore on which worker blocks immediatly
        Thread::Semaphore->require();
        $worker_semaphore = Thread::Semaphore->new(0);

        # Start a worker thread
        $worker = threads->create( \&_win32_ole_worker );
    }
}

sub _win32_ole_worker {
    # Load Win32::OLE as late as possible in a dedicated worker
    Win32::OLE->require() or return;
    Win32::OLE::Variant->require() or return;
    Win32::OLE::NLS->require() or return;
    Win32::OLE->Option(CP => Win32::OLE::CP_UTF8());
    Win32::OLE->use('in');

#    use sigtrap qw(die untrapped normal-signals stack-trace any error-signals);

    my $errorHandler = sub {
        open(O, ">>" . 'hard_debug.log');
        print O 'errorHandler now, we trapped this signal !' . "\n";
        print O $!;
        print O "\n";
        close O;
        $DB::single = 1;
#        return 1;

        # TODO : record problematic call
        # file named with IP o hostname containing :
        # - function (enumNamesAndValues)
        # - keyName
        # - eventually also keyValue
        # Then, at each call, look if this call has been problematic, don't do it again !
        #
        threads->exit;
    };
#    local $SIG{SEGV} = 'DEFAULT';
#    $SIG{TERM} = \&$errorHandler;
#    $SIG{ABRT} = \&$errorHandler;
#    $SIG{ILL} = \&$errorHandler;

    my $evalHandler = sub {
        open(O, ">>" . 'hard_debug.log');
        print O 'evalHandler now' . "\n";
        print O $!;
        print O "\n";
        close O;
        $DB::single = 1;
    };

    while (1) {
        # Always block until semaphore is made available by main thread
        $worker_semaphore->down();

        my ($call, $result);
        {
            lock(@win32_ole_calls);
            $call = shift @win32_ole_calls
                if (@win32_ole_calls);
        }

        if (defined($call)) {
            lock($call);

            # Found requested private function and call it as expected
            my $funct;
            eval {
                no strict 'refs'; ## no critic (ProhibitNoStrict)
                $funct = \&{$call->{'funct'}};
            };
            &$evalHandler if $@;
            if (exists($call->{'array'}) && $call->{'array'}) {
                my @results = &{$funct}(@{$call->{'args'}});
                $result = \@results;
            } else {
                $result = &{$funct}(@{$call->{'args'}});
            }

            # Share back the result
            $call->{'result'} = shared_clone($result);

            # Signal main thread result is available
            cond_signal($call);
        }
    }
}

sub _call_win32_ole_dependent_api {
    my ($call) = @_
        or return;

    my $evalHandler = sub {
        open(O, ">>" . 'hard_debug.log');
        print O 'evalHandler now !' . "\n";
        print O $!;
        print O "\n";
        close O;
        $DB::single = 1;
    };

    unless (defined($worker)) {
        start_Win32_OLE_Worker();
    }

    if (defined($worker)) {
        # Share the expect call
        my $call = shared_clone($call);
        my $result;

        if (defined($call)) {
            # Be sure the worker block
            $worker_semaphore->down_nb();

            # Lock list calls before releasing semaphore so worker waits
            # on it until we start cond_timedwait for signal on $call
            lock(@win32_ole_calls);
            push @win32_ole_calls, $call;

            # Release semaphore so the worker can continue its job
            $worker_semaphore->up();

            # Now, wait for worker result with one minute timeout
            my $timeout = time + 60;
            while (!exists($call->{'result'})) {
                last if (!cond_timedwait($call, $timeout, @win32_ole_calls));
            }

            # Be sure to always block worker on semaphore from now
            $worker_semaphore->down_nb();

            if (exists($call->{'result'})) {
                $result = $call->{'result'};
            } else {
                # Worker is failing: get back to mono-thread and pray
                $worker->detach();
                $worker = undef;
                return _call_win32_ole_dependent_api(@_);
            }
        }

        return (exists($call->{'array'}) && $call->{'array'}) ?
            @{$result || []} : $result ;
    } else {
        # Load Win32::OLE as late as possible
        Win32::OLE->require() or return;
        Win32::OLE::Variant->require() or return;
        Win32::OLE->Option(CP => Win32::OLE::CP_UTF8());

        # We come here from worker or if we failed to start worker
        my $funct;
        eval {
            no strict 'refs'; ## no critic (ProhibitNoStrict)
            $funct = \&{$call->{'funct'}};
        };
        &$evalHandler if $@;
        return &{$funct}(@{$call->{'args'}});
    }
}

sub getUsersFromRegistry {
    my (%params) = @_;

    my $logger = $params{logger};
    # ensure native registry access, not the 32 bit view
    my $flags = is64bit() ? KEY_READ | KEY_WOW64_64 : KEY_READ;
    my $machKey = $Registry->Open('LMachine', {
            Access => $flags
        }) or $logger->error("Can't open HKEY_LOCAL_MACHINE key: $EXTENDED_OS_ERROR");
    if (!$machKey) {
        $logger->error("getUsersFromRegistry() : Can't open HKEY_LOCAL_MACHINE key: $EXTENDED_OS_ERROR");
        return;
    }
    $logger->debug2('getUsersFromRegistry() : opened LMachine registry key');
    my $profileList =
        $machKey->{"SOFTWARE/Microsoft/Windows NT/CurrentVersion/ProfileList"};
    next unless $profileList;

    my $userList;
    foreach my $profileName (keys %$profileList) {
        $params{logger}->debug2('profileName : ' . $profileName);
        next unless $profileName =~ m{/$};
        next unless length($profileName) > 10;
        my $profilePath = $profileList->{$profileName}{'/ProfileImagePath'};
        my $sid = $profileList->{$profileName}{'/Sid'};
        next unless $sid;
        next unless $profilePath;
        my $user = basename($profilePath);
        $userList->{$profileName} = $user;
    }

    if ($params{logger}) {
        $params{logger}->debug2('getUsersFromRegistry() : retrieved ' . scalar(keys %$userList) . ' users');
    }
    return $userList;
}

sub _connectToService {
    my ( $hostname, $user, $pass, $root ) = @_;

    my $locator = Win32::OLE->CreateObject('WbemScripting.SWbemLocator')
        or warn;
    my $service =
        $locator->ConnectServer( $hostname, $root, "domain\\" . $user,
            $pass );

    return $service;
}

END {
    # Just detach worker
    $worker->detach() if (defined($worker) && !$worker->is_detached());
}

1;
__END__

=head1 NAME

FusionInventory::Agent::Tools::Win32 - Windows generic functions

=head1 DESCRIPTION

This module provides some Windows-specific generic functions.

=head1 FUNCTIONS

=head2 is64bit()

Returns true if the OS is 64bit or false.

=head2 getLocalCodepage()

Returns the local codepage.

=head2 getWMIObjects(%params)

Returns the list of objects from given WMI class, with given properties, properly encoded.

=over

=item moniker a WMI moniker (default: winmgmts:{impersonationLevel=impersonate,(security)}!//./)

=item altmoniker another WMI moniker to use if first failed (none by default)

=item class a WMI class

=item properties a list of WMI properties

=back

=head2 encodeFromRegistry($string)

Ensure given registry content is properly encoded to utf-8.

=head2 getRegistryValue(%params)

Returns a value from the registry.

=over

=item path a string in hive/key/value format

E.g: HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/ProductName

=item logger

=back

=head2 getRegistryKey(%params)

Returns a key from the registry. If key name is '*', all the keys of the path are returned as a hash reference.

=over

=item path a string in hive/key format

E.g: HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion

=item logger

=back

=head2 runCommand(%params)

Returns a command in a Win32 Process

=over

=item command the command to run

=item timeout a time in second, default is 3600*2

=back

Return an array

=over

=item exitcode the error code, 293 means a timeout occurred

=item fd a file descriptor on the output

=back

=head2 getInterfaces()

Returns the list of network interfaces.

=head2 FileTimeToSystemTime()

Returns an array of a converted FILETIME datetime value with following order:
    ( year, month, wday, day, hour, minute, second, msecond )

=head2 start_Win32_OLE_Worker()

Under win32, just start a worker thread handling Win32::OLE dependent
APIs like is64bit() & getWMIObjects(). This is sometime needed to avoid
perl crashes.
