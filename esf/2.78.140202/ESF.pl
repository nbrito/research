##
# $Id: ESF.pl,v 2.78 2014-02-02 11:01:47-02 nbrito Exp $
##
###########################################################################
#                      _________________  .____                           #
#                     /   _____/\_____  \ |    |                          #
#                     \_____  \  /  / \  \|    |                          #
#                     /        \/   \_/.  \    |___                       #
#                    /_______  /\_____\ \_/_______ \                      #
#                            \/        \__>       \/                      #
# ___________.__                                         .__        __    #
# \_   _____/|__| ____    ____   ________________________|__| _____/  |_  #
#  |    __)  |  |/    \  / ___\_/ __ \_  __ \____ \_  __ \  |/    \   __\ #
#  |     \   |  |   |  \/ /_/  >  ___/|  | \/  |_> >  | \/  |   |  \  |   #
#  \___  /   |__|___|  /\___  / \___  >__|  |   __/|__|  |__|___|  /__|   #
#      \/            \//_____/      \/      |__|                 \/       #
#                                                                         #
#                      _______                   __                       #
#                      \      \   ____ ___  ____/  |_                     #
#                      /   |   \_/ __ \\  \/  /\   __\                    #
#                     /    |    \  ___/ >    <  |  |                      #
#                     \____|__  /\___  >__/\_ \ |__|                      #
#                             \/     \/      \/                           #
#     ________                                   __  .__                  #
#    /  _____/  ____   ____   ________________ _/  |_|__| ____   ____     #
#   /   \  ____/ __ \ /    \_/ __ \_  __ \__  \\   __\  |/  _ \ /    \    #
#   \    \_\  \  ___/|   |  \  ___/|  | \// __ \|  | |  (  <_> )   |  \   #
#    \______  /\___  >___|  /\___  >__|  (____  /__| |__|\____/|___|  /   #
#           \/     \/     \/     \/           \/                    \/    #
#                                                                         #
#            Powered by Exploit Next Generation++ Technology              #
#                                                                         #
###########################################################################
# Author:         Nelson Brito <nbrito *NoSPAM* sekure.org>               #
# Release:        You Sh0t The Sheriff Seventh Edition                    #
# Version:        Version 2 (Next Generation)                             #
###########################################################################
# This file is part of SQL Fingerprint NG powered by ENG++ Technology.    #
#                                                                         #
# Copyright 2010-2014, Nelson Brito. All rights reserved worldwide.       #
###########################################################################
# This program is free software: you can redistribute it and/or modify it #
# under  the terms of the GNU General Public License  as published by the #
# Free Software Foundation,  either version 3 of the License, or (at your #
# option) any later version.                                              #
#                                                                         #
# This program  is  distributed in  the hope that  it will be useful, but #
# WITHOUT  ANY  WARRANTY;   without   even  the   implied   warranty   of #
# MERCHANTABILITY  or  FITNESS  FOR  A  PARTICULAR  PURPOSE.  See the GNU #
# General Public License for more details.                                #
#                                                                         #
# You  should have  received a copy of the  GNU  General  Public  License #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.   #
#                                                                         #
# Type "ESF.pl --manpage" for "Additional Terms and Conditions".          #
###########################################################################
#!/bin/sh -- # -*- perl -*-
eval 'exec `which perl` -x -S $0 ${1+"$@"} ;'
    if 0;

{(($^O=~/^[M]*$32/i)&&($0=~s!.*\\!!))||($0=~s!^.*/!!)};

BEGIN {
    my $subname = (caller (0))[3];
    eval ("require 5.012004;");
    eval ("require 5.010001;")
        if $@;
    die "$subname: Unsupported Perl version ($]).\nPlease, install Perl v5.10.1 or v5.12.4!\n"
        if $@;
}

use strict;
use Digest::MD5 qw (md5_hex);
use Getopt::Long qw (:config gnu_getopt no_ignore_case);
use IO::Select;
use IO::Socket::INET;
use IO::Socket::INET6;
use List::Util qw(max min);
use Pod::Usage;
use POSIX qw (strftime);
use Switch 'Perl5', 'Perl6';

##
# globals
##
my $rcsid   = q ($Id: ESF.pl,v 2.78 2014-02-02 11:01:47-02 nbrito Exp $);
my $major   = (split (/\./, (split (/ /, $rcsid))[2]))[0];
my $minor   = (split (/\./, (split (/ /, $rcsid))[2]))[1];
my @build   = (split (/\-/, (split (/ /, $rcsid))[3]));
$build[0]   =~ s/^20//;
my $release = "YSTS+GPL";
my $record  = 0;
my $start   = 0;
my $stop    = 0;

##
# version
##
my $version = "$major.$minor.$build[0]$build[1]$build[2]/$release";
my $script  = "SQL Fingerprint NG powered by ENG++ Technology [Version $version]";
my $author  = "Nelson Brito <nbrito\@sekure.org>";

##
# getoptions ()
##
my (
    $debug,
    $fingerdb,
    $ignore,
    $help,
    $highest,
    $database,
    $manpage,
    $prelogin,
    $timeout,
    $loop,
    $verbose
);

GetOptions (
    "d|debug"          => \$debug,
    "f|fingerdb=s"     => \$fingerdb,
    "h|?|help"         => \$help,
    "H|highest"        => \$highest,
    "i|ignore"         => \$ignore,
    "I|instance"       => \$database,
    "m|manpage"        => \$manpage,
    "P|prelogin"       => \$prelogin,
    "t|timeout=i"      => \$timeout,
    "T|loop-timeout=i" => \$loop,
    "v|verbose"        => \$verbose
) or die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n";

##
# $ARGV[0]
##
my $arguments = $#ARGV + 1;

##
# ESFDB[]
##
my %ESFDB     = ();

##
# FINGERED[]
##
my %FINGERED  = ();

##
# INSTANCE[]
##
my %INSTANCE  = ();

##
# MAJOR[]
##
my %MAJOR     = (
    "12", "Microsoft SQL Server 2014",
    "11", "Microsoft SQL Server 2012",
    "10", "Microsoft SQL Server 2008",
    "9",  "Microsoft SQL Server 2005",
    "8",  "Microsoft SQL Server 2000"
);

##
# MINOR[]
##
my %MINOR     = (
    "50", "R2"
);

##
# BUILT[]
##
my %BUILT     = (
    "Microsoft SQL Server 2014"    => {
        RTM => "2000"
    },
    "Microsoft SQL Server 2012"    => {
        RTM => "2100",
        SP1 => "3000"
    },
    "Microsoft SQL Server 2008 R2" => {
        RTM => "1600",
        SP1 => "2500",
        SP2 => "4000"
    },
    "Microsoft SQL Server 2008"    => {
        RTM => "1600",
        SP1 => "2531",
        SP2 => "4000",
        SP3 => "5500"
    },
    "Microsoft SQL Server 2005"    => {
        RTM => "1399",
        SP1 => "2047",
        SP2 => "3042",
        SP3 => "4035",
        SP4 => "5000"
    },
    "Microsoft SQL Server 2000"    => {
        RTM => "194",
        SP1 => "384",
        SP2 => "532",
        SP3 => "760",
        SP4 => "2039"
    }
);

##
# PACKETS[]
##
my %PACKETS   = (
    CLNT_UCAST_INST => {
        name       => "SSRP Client Unicast Instance Request",
        protocol   => "udp",
        connection => "1434",
        packet     => [
                        0x04
                      ]
    },
    PRELOGIN => {
        name       => "TDS Pre-Login Request",
        protocol   => "tcp",
        connection => "1433",
        packet     => [
                        #   <PacketHeader>
                        #       <Type>
                        0x12,
                        #       </Type>
                        #       <Status>
                        0x01,
                        #       </Status>
                        #       <Length>
                        0x00, 0x2F,
                        #       </Length>
                        #       <SPID>
                        0x00,
                        0x00,
                        #       </SPID>
                        #       <Packet>
                        0x01,
                        #       </Packet>
                        #       <Window>
                        0x00,
                        #       </Window>
                        #   </PacketHeader>
                        #   <PacketData>
                        #       <Prelogin>
                        #           <TokenType>
                        0x00,
                        #           </TokenType>
                        #           <TokenPosition>
                        0x00, 0x1A,
                        #           </TokenPosition>
                        #           <TokenLeng>
                        0x00, 0x06,
                        #           </TokenLeng>
                        #           <TokenType>
                        0x01,
                        #           </TokenType>
                        #           <TokenPosition>
                        0x00, 0x20,
                        #           </TokenPosition>
                        #           <TokenLeng>
                        0x00, 0x01,
                        #           </TokenLeng>
                        #           <TokenType>
                        0x02,
                        #           </TokenType>
                        #           <TokenPosition>
                        0x00, 0x21,
                        #           </TokenPosition>
                        #           <TokenLeng>
                        0x00, 0x01,
                        #           </TokenLeng>
                        #           <TokenType>
                        0x03,
                        #           </TokenType>
                        #           <TokenPosition>
                        0x00, 0x22,
                        #           </TokenPosition>
                        #           <TokenLeng>
                        0x00, 0x04,
                        #           </TokenLeng>
                        #           <TokenType>
                        0x04,
                        #           </TokenType>
                        #           <TokenPosition>
                        0x00, 0x26,
                        #           </TokenPosition>
                        #           <TokenLeng>
                        0x00, 0x01,
                        #           </TokenLeng>
                        #           <TokenType>
                        0xFF,
                        #           </TokenType>
                        #           <PreloginData>
                        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xB8, 0x0D, 0x00, 0x00, 0x01
                        #           </PreloginData>
                        #       </Prelogin>
                        #   </PacketData>
                      ]
    }
);

##
# PING[]
##
my %PING      = (
    CLNT_UCAST_EX => {
        name       => "SSRP Client Unicast Request",
        protocol   => "udp",
        connection => "1434",
        packet     => [
                        0x03
                      ]
    }
);

##
# VSAM[]
##
my %VSAM      = ();

##
# cidr ()
##
sub cidr {
    my ($subname, $address, $bits) = (
        (caller (0))[3],
        shift,
        shift
    );
    my ($all_bits_on, $netmask, $__1st_addr, $hostid) = (
        0xffffffff,
        0,
        0,
        0
    );

    (($bits >= 0)
        and ($bits <= 32))
            or die "\b\r$0:$subname [", __LINE__, "]: Unknown or invalid Classless Inter-Domain Routing [/$bits]!\n";

    $netmask    = ~($all_bits_on >> $bits);
    $hostid     = (1 << (32 - $bits)) - 1;
    $__1st_addr = ($address & $netmask);

    return ($__1st_addr, $hostid, $netmask);
}

##
# convert
##
sub convert {
    my ($subname, $conversion, $input) = (
        (caller (0))[3],
        shift,
        shift
        );

    given ($conversion) {
        when ("I2A") {
            return (join (".", unpack ("C4", (pack ("N", $input)))));
        }
        when ("A2I") {
            return (unpack ("N", pack ("C4", split (/\./, $input))));
        }
        default {
            die "\b\r$0:$subname [", __LINE__, "]: (ERROR) Unknown or invalid conversion [$conversion]!\n";
        }
    }
}

##
# ctrlc ()
##
sub ctrlc {
    my $subname = (caller (0))[3];

    $stop = time ();

    my $format_time = strftime ("%b %e %Y %H:%M:%S", localtime ());
    die "\b\r$0 execution elapsed time (dd:HH:MM:ss) [", evaluate ($stop - $start), "].\n",
        "\b\r$0 command interrupted on $format_time.\n";
}

##
# database ()
##
sub database {
    my ($subname, $hash, $mapped, $fingers, $start, $stop) = (
        (caller (0))[3],
        undef,
        undef,
        0,
        undef,
        undef
    );

    $start = time ();

    if (not (open (FINGERDB, "<@_"))) {
        print "\b\r$0::$subname(", __LINE__, "): (ERROR) $!!\n"
            if (not ($ignore));

        return (0);
    }

    foreach (<FINGERDB>) {
        chomp;

        next
            if (/^\s*#/
                or /^\s*$/);

        $fingers++;

        if (not ((($hash, $mapped) = split (/\s+\s*\s/, $_)) == 2)) {
            print "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid file format [line:$fingers]!\n"
                if (not ($ignore));

            return (0);
        }

        select (undef, undef, undef, 0.005);

        $stop = time ();

        print "\b\r$0 attempting launch unique versions [", evaluate ($stop - $start), "].";

        $ESFDB{$hash} = $mapped;
    }

    if (not (close (FINGERDB))) {
        print "\b\r$0::$subname(", __LINE__, "): (ERROR) $!!\n"
            if (not ($ignore));

        return (0);
    }

    return ($fingers);
}

##
# dumped ()
##
sub dumped {
    my ($subname, $buffer, $module, $direction, $counter, $line) = (
        (caller (0))[3],
        shift,
        shift,
        shift,
        0,
        0
    );
    my %packet = ();
    my @byte   = split (//, $buffer);

    print "\b\r[*] $0::$subname: $module: $direction: ", length ($buffer), " BYTE", (length ($buffer) > 1 ? "S" : ""), "\n";

    foreach (@byte) {
        $line++
            if ($counter == 0);

        $packet{$line}{hexa} .= unpack ("H*", $_) . " ";

        given ($_) {
            when (/[^\x21-\x7e]/) {
                $packet{$line}{ascii} .= ".";
            }
            default {
                $packet{$line}{ascii} .= $_;
            }
        }

        $counter++;

        $counter = 0
            if ($counter == 16);
    }

    $counter = 0;

    foreach my $bytes (1 .. scalar (keys %packet)) {
        $packet{$bytes}{hexa} .= " "
            while (length ($packet{$bytes}{hexa}) < 48);

        print unpack ("H*", pack ("n", $counter*16)), "\t", $packet{$bytes}{hexa}, "  ", $packet{$bytes}{ascii}, "\n";

        $counter++;
    }
}

##
# epoch ()
##
sub epoch {
    my ($subname, $input, $month, $day, $year, $hour, $minute, $second) =(
        (caller (0))[3],
        shift,
        undef,
        undef,
        undef,
        undef,
        undef,
        undef
    );
    my %months = (
        "01", "Jan", "02", "Feb", "03", "Mar",
        "04", "Apr", "05", "May", "06", "Jun",
        "07", "Jul", "08", "Aug", "09", "Sep",
        "10", "Oct", "11", "Nov", "12", "Dec"
    );

    ((($year, $month, $day) = split (/\-/, (split (/ /, $input))[3])) == 3)
        or die "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid date format!\n";

    ((($hour, $minute, $second) = split (/\:/, (split (/ /, $input))[4])) == 3)
        or die "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid date format!\n";

    $second = (split (/-/, $second))[0]
        if ($second =~ /-/);

    $day =~ s/^0/ /
        if ($day =~ /^0/);

    return ("$months{$month} $day $year $hour:$minute:$second");
}

##
# evaluate ()
##
sub evaluate {
    my ($subname, $message, %execution) = (
        (caller (0))[3],
        undef,
        ()
    );

    $execution{elapsed} = {
        seconds => @_,
        minutes => 0,
        hours   => 0,
        days    => 0
    };

    ($execution{elapsed}{minutes} = int ($execution{elapsed}{seconds}/60),
     $execution{elapsed}{seconds} = int ($execution{elapsed}{seconds}%60))
        if ($execution{elapsed}{seconds} >= 60);
    ($execution{elapsed}{hours}   = int ($execution{elapsed}{minutes}/60),
     $execution{elapsed}{minutes} = int ($execution{elapsed}{minutes}%60))
        if ($execution{elapsed}{minutes} >= 60);
    ($execution{elapsed}{days}    = int ($execution{elapsed}{hours}/24),
     $execution{elapsed}{hours}   = int ($execution{elapsed}{hours}%24))
        if ($execution{elapsed}{hours} >= 24);

    $execution{elapsed}{seconds} = "0$execution{elapsed}{seconds}"
        while (length ($execution{elapsed}{seconds}) < 2);
    $execution{elapsed}{minutes} = "0$execution{elapsed}{minutes}"
        while (length ($execution{elapsed}{minutes}) < 2);
    $execution{elapsed}{hours}   = "0$execution{elapsed}{hours}"
        while (length ($execution{elapsed}{hours}) < 2);
    $execution{elapsed}{days}    = "0$execution{elapsed}{days}"
        while (length ($execution{elapsed}{days}) < 2);

    $message .= "$execution{elapsed}{days}:$execution{elapsed}{hours}:";
    $message .= "$execution{elapsed}{minutes}:$execution{elapsed}{seconds}";

    return ($message);
}

##
# finger ()
##
sub finger {
    my ($subname, $target, $targets, $bits, $address, $succeeded, $fingers) = (
        (caller (0))[3],
        shift,
        undef,
        32,
        undef,
        0,
        0
    );

    $SIG{"HUP"}  = "ctrlc";
    $SIG{"PIPE"} = "ctrlc";
    $SIG{"INT"}  = "ctrlc";
    $SIG{"ILL"}  = "ctrlc";
    $SIG{"QUIT"} = "ctrlc";
    $SIG{"ABRT"} = "ctrlc";
    $SIG{"TRAP"} = "ctrlc";
    $SIG{"KILL"} = "ctrlc";
    $SIG{"TERM"} = "ctrlc";
    $SIG{"STOP"} = "ctrlc";
    $SIG{"TSTP"} = "ctrlc";
    $SIG{"SEGV"} = "ctrlc";

    ($0 =~ s/.pl$//)
        if ($0 =~ /.pl$/);

    if ($target =~ /\//) {
        die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n"
            unless ((($target, $bits) = split (/\//, $target)) == 2);

        die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n"
            unless ($bits =~ /^([+-]?)(?=\d|\.\d)\d*(\.\d)?([Ee]([+-]?\d+)+)?$/);

        die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n"
            if (($target eq undef)
                or ($bits eq undef));
    }

    $address = (gethostbyname ($target))[4]
        or die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n";

    $start   = time ();

    $timeout = $timeout ? $timeout : 30;
    $loop    = $loop    ? $loop    : 05;

    $verbose = 0
        if ($debug);

    print "\b\r$0 version $version built on ". epoch ($rcsid) . ".\n";

    $fingers = database ($fingerdb ? $fingerdb : "ESF.db");

    my $format_time = strftime ("%b %e %Y %H:%M:%S", localtime ());

    if ($fingers) {
        print "\b\r$0 successfuly launched $fingers unique versions on $format_time", ($debug ? " [DEBUG MODE]" : ""), ".\n";
    } else {
        %ESFDB = ();
        $ignore ?
            print "\b\r$0 successfuly launched on $format_time [IGNORE MODE", ($debug ? "+DEBUG MODE]" : "]"), ".\n"
        :
            goto FAILED;
    }

    my ($__1st_addr, $hostid, $netmask) = cidr (
        convert ("A2I", inet_ntoa ($address)),
        $bits
    );

    foreach ($__1st_addr .. ($__1st_addr + $hostid)) {
        my $progress = sprintf ("%.2f", 100); $succeeded = 0;

        $progress = sprintf ("%.2f", (($_ - $__1st_addr)*100)/$hostid)
            if (($__1st_addr + $hostid) > $__1st_addr);

        $progress = " $progress"
            while (length ($progress) < 6);

        $target   = convert ("I2A", $_);

        $verbose ?
            print "\b\r$0 attempting Microsoft SQL Version Fingerprinting [$target].\n"
        :
            $debug ?
                print "\b\r[+] $0::$subname: FINGERMARK: $target\n"
            :
                ($bits == 32) ?
                    print "\b\r$0 version fingerprinting: $target."
                :
                    print "\b\r$0 version fingerprinting: $target [$progress%].";

        $succeeded = rolled ($target, $verbose, $debug);

        if ($succeeded) {
            $targets++;

            if (not ($debug)) {
                print "\b\r$0 found Microsoft SQL Server running [$target].\n"
                    if (not ($verbose));

                vsam ($target)
                    if (scalar (keys %FINGERED));
            }
        }
 
        print "\b\r$0 finished Microsoft SQL Version Fingerprinting [$target].\n"
            if ($verbose);

        print "\b\r[-] $0::$subname: FINGERMARK: $target\n"
            if ($debug);
    }

    $stop = time ();

    print "\b\r$0 execution elapsed time (dd:HH:MM:ss) [", evaluate ($stop - $start), "].\n";

FAILED:
    $format_time = strftime ("%b %e %Y %H:%M:%S", localtime ());
    print "\b\r$0 ",  ($targets ? "successfully" : "unsuccessfully"), " finished on $format_time.\n";

    $succeeded ?
        exit (1)
    :
        exit (0);
}

##
# highest ()
##
sub highest {
    my ($subname, $module, %scored, %highest, $higher, $multiple) = (
        (caller (0))[3],
        shift,
        @_,
        (),
        0,
        undef
    );

    foreach (keys %scored) {
        if (not (defined $higher)
            or ($higher < $scored{$_}{scored})) {
            %highest = ();
            $higher  = $scored{$_}{scored};

            $highest{$_} = $scored{$_}{scored};
        } elsif ($higher == $scored{$_}{scored}) {
            $highest{$_} = $scored{$_}{scored};
        }
    }

    given ($module) {
        when ("VSAM") {
            $multiple .= substr ($scored{$_}{matched}, 21) . ","
                foreach (sort (keys %highest));
        }
        default {
            die "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid module [$module]!\n";
        }
    }

    $multiple =~ s/,$//;

    print "\b\r$0 found $module" . ((scalar (keys %highest) > 1) ? " MULTIPLE " : " ") . "HIGHEST Score: $multiple.\n";
}

##
# match ()
##
sub match {
    my ($subname, $version, $module, $digest, $matched) = (
        (caller (0))[3],
        shift,
        shift,
        undef,
        undef
    );

    $digest = md5_hex ($version);

    given ($ESFDB{$digest}) {
        when ("") {
            my ($major, $minor, $built, $service_pack) = (
                undef,
                undef,
                undef,
                "UNKNOWN SP"
            );

            ($major, $minor, $built) = split (/\./, $version);

            given ($MAJOR{$major}) {
                when (undef) {
                    $matched = "Microsoft SQL Server [$version]";
                }
                default {
                    $matched  = "$MAJOR{$major}";
                    $matched .= " $MINOR{$minor}"
                        if ((exists $MINOR{$minor})
                            and ($major eq "10"));

                    foreach (sort (keys (%{$BUILT{$matched}}))) {
                        $service_pack  = $_
                            if ($built >= $BUILT{$matched}{$_});
                        $service_pack .= "+UPDATES"
                            if ($built > $BUILT{$matched}{$_});
                    }

                    $matched  = "$matched $service_pack [$version]";
                }
            }
        }
        default {
            $matched = "$ESFDB{$digest}";
        }
    }

    return ($matched);
}

##
# parsed ()
##
sub parsed {
    my ($subname, $module, $buffer, $target, $instance, $failed, $version) = (
        (caller (0))[3],
        shift,
        shift,
        shift,
        shift,
        shift,
        undef
    );

    given ($module) {
        when ("CLNT_UCAST_EX") {
            my (@multiple, %sample, $message) = (
                undef,
                (),
                undef
            );

            $buffer =~ s/[^[:ascii:]]//g;

            @multiple = split (/\;;/, $buffer);

            if (scalar (@multiple) > 1) {
                my $instances = undef;

                $message .= "\b\r$0 found MULTIPLE SQL Server instances [";
                foreach (sort (@multiple)) {
                    %sample = split (/\;/, $_);
                    $instances .= $sample{InstanceName} . ",";
                }

                $instances =~ s/,$//;

                $message .= $instances;
                $message .= "].\n";

                print $message
                    if ($verbose);

                print "\b\r[*] $0::$subname: $module: INSTANCE", (scalar (@multiple) > 1 ? "S: " : ": "), "$instances\n"
                    if ($debug);
            }

            foreach (@multiple) {
                %sample = split (/\;/, $_);

                $INSTANCE{$sample{InstanceName}} = {
                    target     => $target,
                    server     => $sample{ServerName},
                    instance   => $sample{InstanceName},
                    cluster    => $sample{IsClustered},
                    version    => $sample{Version},
                    connection => $sample{tcp},
                    np         => $sample{np}
                };
            }
        }
        when ("CLNT_UCAST_INST") {
            my (%sample, $major, $minor, $built) = (
                undef,
                undef,
                undef,
                undef
            );

            $buffer =~ s/[^[:ascii:]]//g;

            %sample = split (/\;/, $buffer);

            ($major, $minor, $built) = split (/\./, $sample{Version});

            print "\b\r[*] $0::$subname: $module: VERSION: $major.$minor.$built\n"
                if ($debug);

            $minor = "0$minor"
                while (length ($minor) < 2);

            $version = "$major.$minor.$built";

            $FINGERED{$record} = {
                target     => $INSTANCE{$instance}{target},
                server     => $INSTANCE{$instance}{server},
                instance   => $INSTANCE{$instance}{instance},
                cluster    => $INSTANCE{$instance}{cluster},
                version    => $version,
                matched    => match ($version),
                protocol   => $PACKETS{$module}{protocol},
                connection => $INSTANCE{$instance}{connection},
                np         => $INSTANCE{$instance}{np},
                module     => $module
            }
                if (not ($debug));

            print "\b\r[*] $0::$subname: $module: MATCHED: ", uc (match ($version)), "\n"
                if ($debug);
        }
        when ("PRELOGIN") {
            my (@bytes, $offset, $major, $minor, $built) = (
                (),
                0,
                undef,
                undef,
                undef
            );

            @bytes = split (//, $buffer);

            $offset = index ($buffer, pack ("C*", 0xff)) + 1;

            $major = hex (unpack ("H*", $bytes[$offset++]));
            $minor = hex (unpack ("H*", $bytes[$offset++]));
            $built = hex (unpack ("H*", $bytes[$offset++].$bytes[$offset++]));

            print "\b\r[*] $0::$subname: $module: VERSION: $major.$minor.$built\n"
                if ($debug);

            $minor = "0$minor"
                while (length ($minor) < 2);

            $version = "$major.$minor.$built";

            $FINGERED{$record} = {
                target     => $INSTANCE{$instance}{target},
                instance   => $INSTANCE{$instance}{instance},
                cluster    => $INSTANCE{$instance}{cluster},
                version    => $version,
                matched    => match ($version),
                protocol   => $PACKETS{$module}{protocol},
                connection => $INSTANCE{$instance}{connection},
                np         => $INSTANCE{$instance}{np},
                module     => $module
            }
                if (not ($debug));

           print "\b\r[*] $0::$subname: $module: MATCHED: ", uc (match ($version)), "\n"
                if ($debug);
        }
        default {
            die "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid module [$module]!\n";
        }
    }
}

##
# rolled ()
##
sub rolled {
    my ($subname, $target, $verbose, $debug, $succeeded, $failed) = (
        (caller (0))[3],
        shift,
        shift,
        shift,
        0,
        0
    );
    my %packets = %PACKETS;
    my %ping    = %PING;

    $record     = 0;

    %FINGERED   = ();
    %INSTANCE   = ();

    foreach my $module (sort (keys %ping)) {
        my $buffer = undef;
        print "\b\r$0 attempting $ping{$module}{name} [$module].\n"
            if ($verbose);

        print "\b\r[>] $0::$subname: $module: $target: $ping{$module}{connection}/", uc ($ping{$module}{protocol}), "\n"
            if ($debug);

        select (undef, undef, undef, $loop)
            if (($debug)
                or ($verbose));

        $buffer = spread (
            $module,
            $ping{$module}{protocol},
            $ping{$module}{connection},
            pack("C*", @{$ping{$module}{packet}}),
            $target,
        );

        given ($buffer) {
            when (undef) {
                foreach (sort (keys %packets)) {
                    given ($packets{$_}{protocol}) {
                        when("udp") {
                            print "\b\r$0 deleting all attempts for $packets{$_}{name}.\n"
                                if (($verbose)
                                    and (not ($prelogin)));
                            
                            print "\b\r[!] $0::$subname: $module: DELETE: $_\n"
                                if (($debug)
                                    and (not ($prelogin)));

                            delete $packets{$_}
                                if (not ($prelogin));
                        }
                        when ("tcp") {
                            $INSTANCE{MSSQLSERVER} = {
                                target     => $target,
                                server     => "N/A",
                                instance   => "MSSQLSERVER",
                                cluster    => "N/A",
                                version    => "N/A",
                                connection => "1433",
                                np         => "N/A"
                            };
                        }
                    }
                }
 
                print "\b\r$0 failed to perform version fingerprinting over [$module].\n"
                    if ($verbose);
                
                print "\b\r[<] $0::$subname: $module: $target: $ping{$module}{connection}/", uc ($ping{$module}{protocol}), "\n"
                    if ($debug);
                
            }
            default {
                my $message = $ping{$module}{name};
                $message =~ s/Request/Response/;

                if (not (valid ($ping{$module}{protocol}, $buffer))) {
                    dumped ($buffer, $module, "REQUEST");

                    die "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid $message [$module]!\n";
                }

                parsed ($module, $buffer, $target, undef, undef);

                print "\b\r$0 finished $ping{$module}{name} [$module].\n"
                    if ($verbose);

                print "\b\r[<] $0::$subname: $module: $target: $ping{$module}{connection}/", uc ($ping{$module}{protocol}), "\n"
                    if ($debug);
            }
        }
    }

    foreach (sort (keys %packets)) {
        delete $packets{$_}
            if (($prelogin)
                and ($packets{$_}{protocol} eq "udp"));
    }

    foreach my $module (sort (keys %packets)) {
        foreach my $instance (sort (keys %INSTANCE)) {
            my ($protocol, $connection, $packet, $buffer) = (
                undef,
                undef,
                undef,
                undef
            );

            $protocol   = $packets{$module}{protocol};
            $connection = $packets{$module}{connection};

            given ($protocol) {
                when ("tcp") {
                    $connection = $INSTANCE{$instance}{connection};
                    $packet     = pack ("C*", @{$packets{$module}{packet}});
                }
                when ("udp") {
                    $packet  = pack ("C*", @{$packets{$module}{packet}});
                    $packet .= $instance;
                }
                default {
                    die "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid protocol [$protocol]!\n";
                }
            }

            print "\b\r$0 attempting $packets{$module}{name} [$module].\n"
                if ($verbose);

            print "\b\r[>] $0::$subname: $module: $instance: $connection/", uc ($protocol), "\n"
                if ($debug);

            select (undef, undef, undef, $loop)
                if (($debug)
                    or ($verbose));

            $buffer = spread (
                $module,
                $protocol,
                $connection,
                $packet,
                $target
            );

            given ($buffer) {
                when (undef) {
                    print "\b\r$0 failed to perform version fingerprinting over [$module].\n"
                        if ($verbose);

                    print "\b\r[<] $0::$subname: $module: $instance: $connection/", uc ($protocol), "\n"
                        if ($debug);
                }
                default {
                    my $message = $packets{$module}{name};
                    $message =~ s/Request/Response/;

                    if (not (valid ($protocol, $buffer))) {
                            dumped ($buffer, $module, "REQUEST");

                            die "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid $message [$module]!\n";
                    }

                    $succeeded++; $record++;

                    parsed ($module, $buffer, $target, $instance, $failed);

                    if ($packets{$module}{protocol} eq "tcp") {
                        given ($INSTANCE{$instance}{connection}) {
                            when ($packets{$module}{connection}) {
                                print "\b\r$0 found DEFAULT SQL Server TCP connection [$instance\@$target:$INSTANCE{$instance}{connection}].\n"
                                    if ($verbose);
                            }
                            default {
                                print "\b\r$0 found DYNAMIC SQL Server TCP connection [$instance\@$target:$INSTANCE{$instance}{connection}].\n"
                                    if ($verbose);
                            }
                        }
                    }

                    print "\b\r$0 finished $packets{$module}{name} [$module].\n"
                        if ($verbose);

                    print "\b\r[<] $0::$subname: $module: $instance: $connection/", uc ($protocol), "\n"
                        if ($debug);
                }
            }
        }
    }

    return ($succeeded);
}

##
# spread ()
##
sub spread {
    my ($subname, $module, $protocol, $connection, $packet, $address, $buffer) = (
        (caller (0))[3],
        shift,
        shift,
        shift,
        shift,
        shift,
        undef
    );
    my ($start, $stop) = (
        0,
        0
    );

    $start = time ();

    dumped ($packet, $module, "REQUEST")
        if ($debug);

    my $sock = IO::Socket::INET->new (
        Blocking => 1,
        Proto    => $protocol,
        PeerPort => $connection,
        PeerAddr => $address,
        Timeout  => $timeout,
        Type     => ($protocol eq "tcp") ? SOCK_STREAM : SOCK_DGRAM
    );

    $sock->send ($packet)
        if ($sock ne undef);

    given ($protocol) {
        when ("tcp") {
            $sock->recv ($buffer, 5000)
                if (($sock ne undef)
                    and (IO::Select->new ($sock)->can_read ($timeout)));
        }
        when ("udp") {
            eval {
                local $SIG{"ALRM"} = sub { die "timeout\n" };

                alarm $timeout;

                $sock->recv ($buffer, 5000)
                    if ($sock ne undef);

                alarm 0;
                1;
            };
            alarm 0;

            if ($@) {
                return (undef)
                    unless ($@ eq "timeout\n");
            }
        }
        default {
            die "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid protocol [$protocol]!\n";
        }
    }

    $sock->close ()
        if ($sock ne undef);

    if (not (valid ($protocol, $buffer))) {
        if ($debug) {
            $stop    = time ();

            print "\b\r[!] $0::$subname: $module: RESPONSE: NOT VALID AFTER ", evaluate ($stop - $start), "\n";
        }

        return (undef);
    } else {
        dumped ($buffer, $module, "RESPONSE")
            if ($debug);
    }

    return ($buffer);
}

##
# valid () -- EXTREMELY LIMITED DUE TO PUBLIC RELEASE
##
sub valid {
    my ($subname, $protocol, $buffer, @bytes, $type) = (
        (caller (0))[3],
        shift,
        shift,
        ()
    );

    return (0)
        unless (length ($buffer) > 0);

    return (0)
        unless ($buffer ne undef);

    @bytes = split (//, $buffer);

    $type  = unpack ("H*", $bytes[0]);

    given ($protocol) {
        when ("tcp") {
            return (0)
                unless ($type eq "04");

        }
        when ("udp") {
            return (0)
                unless ($type eq "05");

        }
        default {
            die "\b\r$0::$subname(", __LINE__, "): (ERROR) Unknown or invalid protocol [$protocol]!\n";
        }
    }

    return (1);
}

##
# vsam ()
##
sub vsam {
    my ($subname, $target, $percentage, $higher) = (
        (caller (0))[3],
        shift,
        0,
        ()
    );

    %VSAM = ();

    print "\b\r$0 attempting Version Scoring Algorithm Mechanism [VSAM].\n"
        if ($verbose);

    foreach (sort (keys %FINGERED)) {
        $VSAM{$FINGERED{$_}{version}} = {
            version  => $FINGERED{$_}{version},
            matched  => $FINGERED{$_}{matched},
            instance => [],
            scored   => 0
        };
   }

    foreach (sort (keys %FINGERED)) {
        foreach my $versions (sort (keys %VSAM)) {
            if ($versions eq $FINGERED{$_}{version}) {
                push (@{$VSAM{$versions}{istance}}, $FINGERED{$_}{instance});
                $VSAM{$versions}{scored}++;
            }
        }
    }

    foreach (sort (keys %VSAM)) {
        if (int ($VSAM{$_}{scored}) > 0) {
            my ($scored, $instances, %uniques)  = (
                undef,
                undef,
                ()
            );

            $percentage = int (($VSAM{$_}{scored}*100)/scalar (keys %FINGERED));
            $scored     = int ($percentage/10);

            $percentage = " $percentage"
                while (length ($percentage) < 3);
            $scored     = " $scored"
                while (length ($scored) < 2);

            if ($database) {
                %uniques = map {$_, 1} @{$VSAM{$_}{istance}};
            
                if ((scalar (keys %INSTANCE) == scalar (keys %uniques))
                    and (scalar (keys %INSTANCE) > 1)) {
                    $instances  = "ALL-INSTANCES";
                } else {
                    $instances .= $_ . ","
                        foreach (sort (keys %uniques));
                    $instances =~ s/,$//;
                }
            }

            print "\b\r$0 found VSAM($scored): $percentage% $VSAM{$_}{matched}", ($instances ne undef) ? " [$instances]" : "", ".\n";
        } else {
            $highest = 0
                if ($highest);
        }
    }

    highest ("VSAM", %VSAM)
        if ($highest);

    print "\b\r$0 finished Version Scoring Algorithm Mechanism [VSAM].\n"
        if ($verbose);
}

##
# help ()
##
pod2usage (
    -message  => "$script\n$author\n",
    -verbose  => 99,
    -sections => ["USAGE|OPTIONS|COPYRIGHT|LEGAL NOTICE"]
)
    if $help;

##
# man ()
##
pod2usage (-verbose => 2)
    if $manpage;

##
# usage ()
##
die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n"
    if ($arguments < 1);

##
# main ()
##
select (STDOUT); $|=1;
finger ($ARGV[0]);

##
# POD (Plain Old Documentation) for ESF.pl.
##
=pod

=head1 NAME

B<ESF.pl> - B<SQL Fingerprint NG> powered by B<ENG++ Technology>

=head1 VERSION

This document describes the B<Version 2> of B<SQL Fingerprint NG> (C<B<YouSh0t The Sheriff + GNU General Public License>>), which applies the most reliable and accurate technique, based on its sophisticated algorithm, to identify B<Microsoft SQL Server> versions.

If you are interested on the B<Version 4> of B<SQL Fingerprint NG> (C<B<TECHNOLOGY PREVIEW>>), which applies sophisticated algorithm to also identify vulnerabilities, please, contact the L<AUTHOR|/"AUTHOR">.

=head1 USAGE

C<ESF.pl host[E<sol>CIDR] [options]>

=head1 DESCRIPTION

B<Microsoft SQL Server> fingerprinting can be a time consuming process, because it involves trial and error methods to determine the exact version. Intentionally inserting an invalid input to obtain a typical error message or using certain alphabets that are unique for certain server are two of the many ways to possibly determine the version, but most of them require authentication, permissions and/or privileges on B<Microsoft SQL Server> to succeed.

Instead, B<SQL Fingerprint NG> uses a combination of crafted packets for B<SQL Server Resolution Protocol> (L<SSRP|/"SSRP">) and B<Tabular Data Stream Protocol> (L<TDS|/"TDS">) (protocols natively used by B<Microsoft SQL Server>) to accurately perform version fingerprinting and determine the exact B<Microsoft SQL Server> version. B<SQL Fingerprint NG> also applies a sophisticated B<Version Scoring Algorithm Mechanism> (L<VSAM|/"VERSION SCORING ALGORITHM MECHANISM">) powered by B<Exploit Next Generation++ Technology>, which is a much more reliable technique to determine the B<Microsoft SQL Server> version. It is a tool intended to be used by:

=over 4
 
=item * Database Administrators

=item * Database Auditors

=item * Database Owners

=item * Penetration Testers

=back

Having over C<SIX HUNDRED> unique versions within its fingerprint database, B<SQL Fingerprint NG> currently supports fingerprinting for:

=over 4

=item * Microsoft SQL Server 2000

=item * Microsoft SQL Server 2005

=item * Microsoft SQL Server 2008

=item * Microsoft SQL Server 2008 R2

=item * Microsoft SQL Server 2012

=item * Microsoft SQL Server 2014

=back

B<SQL Fingerprint NG> re-invented the techniques used by several public tools (B<SQLPing Tool> by I<Chip Andrews>, I<Rajiv Delwadia> and I<Michael Choi>, and B<SQLVer Tool> by I<Chip Andrews>) (see L<SEE ALSO|/"SEE ALSO"> for further information). B<SQL Fingerprint NG> shows the C<MAPPED VERSION> and C<PATCH LEVEL> (i.e., B<Microsoft SQL Server 2008 SP1 (CU-5)>) instead of showing only the C<RAW VERSION> (i.e., B<Microsoft SQL Server 10.0.2746>). B<SQL Fingerprint NG> also has the ability to show the I<HIGHEST Score> version -- based on its sophisticated L<VSAM|/"VERSION SCORING ALGORITHM MECHANISM"> powered by B<Exploit Next Generation++ Technology> -- and allows to determine C<vulnerable> and C<unpatched> B<Microsoft SQL Server> -- based on its sophisticated B<Exploit Scoring Algorithm Mechanism> (L<ESAM|/"EXPLOIT SCORING ALGORITHM MECHANISM">) powered by B<Exploit Next Generation++ Technology>. Both L<VSAM|/"VERSION SCORING ALGORITHM MECHANISM"> and L<ESAM|/"EXPLOIT SCORING ALGORITHM MECHANISM"> make the B<SQL Fingerprint NG> the most comprehensive B<Microsoft SQL Server> fingerprinting tool.

This version is a completely rewritten version in B<Perl>, making B<SQL Fingerprint NG> much more portable than the previous binary version for B<Microsoft Windows> OS (see L<HISTORY|/"HISTORY"> for further information), and its original purpose is to be used as a tool to perform automated penetration test.

=over 4

I<NOTE: B<SQL Fingerprint NG> C<IS NOT> a SQLi tool, and has no ability to perform such task.>

=back

=head2 Fingerprinting Steps

As described in L<DESCRIPTION|/"DESCRIPTION">, B<SQL Fingerprint NG> uses a combination of crafted packets for L<SSRP|/"SSRP"> and L<TDS|/"TDS"> to accurately perform version fingerprintfing. To achieve an accurate and much more reliable version fingerprinting, B<SQL Fingerprint NG> employes the following steps, mimicking a valid negotiation between the B<CLIENT> and the B<SERVER>:

=over 4

=item 1) C<L<SSRP|/"SSRP"> Client Unicast Request> (CLNT_UCAST_EX)

This STEP attempts to gather the B<Microsoft SQL Server> single B<instance> or even B<multiple instances> (see L<MULTIPLE SQL Server instances|/"MULTIPLE SQL Server instances"> for further information), and the respective L<TDS|/"TDS"> communication port(s) -- the L<TDS|/"TDS"> communication port for each B<instance> can be dynamic or default (see L<DYNAMIC SQL Server TCP port|/"DYNAMIC SQL Server TCP port"> and L<DEFAULT SQL Server TCP port|/"DEFAULT SQL Server TCP port"> for further information).

=over 4

I<NOTE: If this C<STEP> fails and C<-b,--brute-force> has not been configured, the C<STEP 2> is not performed and the C<STEP 3> will use L<TDS|/"TDS"> default communication port only.>

=back

=item 2) C<L<SSRP|/"SSRP"> Client Unicast Instance Request> (CLNT_UCAST_INST)

This STEP attempts to use the information gathered by I<STEP 1> to collect, parse and match information for a single B<instance> or for B<multiple instances> (see L<MULTIPLE SQL Server instances|/"MULTIPLE SQL Server instances"> for further information). Once the collecting, parsing and matching is done, the fingerprinting data is stored to be validated by the sophisticated L<VSAM|/"VERSION SCORING ALGORITHM MECHANISM"> and L<ESAM|/"EXPLOIT SCORING ALGORITHM MECHANISM"> powered by B<Exploit Next Generation++ Technology>.

=over 4
 
I<NOTE: If the C<STEP 1> fails or C<-P,--prelogin> has been configured, this C<STEP> is not performed.>
 
=back

=item 3) C<L<TDS|/"TDS"> Pre-Login Request> (PRELOGIN)
 
This STEP attempts to use the information gathered by I<STEP 1> to collect, parse and match information for a single B<instance> running on L<TDS|/"TDS"> default coommunication port (see L<DEFAULT SQL Server TCP port|/"DEFAULT SQL Server TCP port"> for further information) or for B<multiple instances> (see L<MULTIPLE SQL Server instances|/"MULTIPLE SQL Server instances"> for further information) running on L<TDS|/"TDS"> dynamic communication port(s) (see L<DYNAMIC SQL Server TCP port|/"DYNAMIC SQL Server TCP port"> for further information). Once the collecting, parsing and matching is done, the fingerprinting data is stored to be validated by the sophisticated L<VSAM|/"VERSION SCORING ALGORITHM MECHANISM"> and L<ESAM|/"EXPLOIT SCORING ALGORITHM MECHANISM"> powered by B<Exploit Next Generation++ Technology>.

=over 4
 
I<NOTE: If C<STEP 1> fails and C<-b,--brute-force> has not been configured, this C<STEP> will use L<TDS|/"TDS"> default communication port only.>
 
=back

=back

=head2 SSRP

As described in C<[MS-SQLR]: SQL Server Resolution Protocol> specification document (see L<SEE ALSO|/"SEE ALSO"> for further information).

=over 4

=item 1) C<1.3 Overview>

C<The first case is used for the purpose of determining the communication endpoint information of a particular database instance, whereas the second case is used for enumeration of database instances in the network and to obtain the endpoint information of each instance.> (I<page 8>)

C<The SQL Server Resolution Protocol does not include any facilities for authentication, protection of data, or reliability. The SQL Server Resolution Protocol is always implemented on top of the UDP Transport Protocol [RFC768].> (I<page 8>)

=item 2) C<1.9 Standards Assignments>

C<The client always sends its request to UDP port 1434 of the server or servers.> (I<page 10>)

=item 3) C<2.2.2 CLNT_UCAST_EX>

C<The CLNT_UCAST_EX packet is a unicast request that is generated by clients that are trying to determine the list of database instances and their network protocol connection information installed on a single machine. The client generates a UDP packet with a single byte, as shown in the following diagram.> (I<page 11>)

=item 4) C<2.2.3 CLNT_UCAST_INST>

C<The CLNT_UCAST_INST packet is a request for information related to a specific instance. The structure of the request is as follows.> (I<page 12>)

=back

According to the previous quotes, the L<SSRP|/"SSRP"> C<is used for the purpose of determining the communication endpoint information of a particular database instance>, which C<does not include any facilities for authentication>, and both C<L<SSRP|/"SSRP"> CLNT_UCAST_EX Request> and C<L<SSRP|/"SSRP"> CLNT_UCAST_INST Request> can be used C<for the purpose of determining the communication endpoint information>.

Based on this analysis, it is possible to determine the B<Microsoft SQL Server> version  using the C<L<SSRP|/"SSRP"> CLNT_UCAST_EX Request> andE<sol>or C<L<SSRP|/"SSRP"> CLNT_UCAST_INST Request>. The version is available within the C<L<SSRP|/"SSRP"> CLNT_UCAST_EX Response> andE<sol>or C<L<SSRP|/"SSRP"> CLNT_UCAST_INST Response>, and it is a C<valuable> information sent from B<SERVER> to B<CLIENT> to ensure they will establish a communication correctly, using the correct database B<instance> and the same dialect by both B<CLIENT> and B<SERVER>.

Here is a C<L<SSRP|/"SSRP"> CLNT_UCAST_INST Request> and C<L<SSRP|/"SSRP"> CLNT_UCAST_INST Response> sample traffic dump between the B<SQL Fingerprint NG> and a B<Microsoft SQL Server 2012 SP1>:

=over 4

=item C<L<SSRP|/"SSRP"> CLNT_UCAST_INST Request>

 0000   04 4d 53 53 51 4c 53 45 52 56 45 52              .MSSQLSERVER

=item C<L<SSRP|/"SSRP"> CLNT_UCAST_INST Response>

 0000	05 61 00 53 65 72 76 65 72 4e 61 6d 65 3b 57 49   .a.ServerName;WI
 0010	4e 2d 44 41 43 4b 47 37 4e 4a 37 31 4d 3b 49 6e   N-DACKG7NJ71M;In
 0020	73 74 61 6e 63 65 4e 61 6d 65 3b 4d 53 53 51 4c   stanceName;MSSQL
 0030	53 45 52 56 45 52 3b 49 73 43 6c 75 73 74 65 72   SERVER;IsCluster
 0040	65 64 3b 4e 6f 3b 56 65 72 73 69 6f 6e 3b 31 31   ed;No;Version;11
 0050	2e 30 2e 33 30 30 30 2e 30 3b 74 63 70 3b 31 34   .0.3000.0;tcp;14
 0060	33 33 3b 3b                                       33;;

=back

As seen above, the information within the C<L<SSRP|/"SSRP"> CLNT_UCAST_EX Response> represents the version for B<Microsoft SQL Server 2012 SP1> (I<11.0.3000>), as well as many interesting information.

=over 4
 
I<NOTE: No authentication and C<valuable> information.>
 
=back

=head2 TDS

As described in C<B<[MS-TDS]: Tabular Data Stream Protocol>> specification document (see L<SEE ALSO|/"SEE ALSO"> for further information).

=over 4 

=item 1) C<2.2.1.1 Pre-Login>

C<Before a login occurs, a handshake denominated pre-login occurs between client and server, setting up contexts such as encryption and MARS-enabled.> (I<page 17>)

=item 2) C<2.2.2.1 Pre-Login Response>

C<The pre-login response is a tokenless packet data stream. The data stream consists of the response to the information requested by the client pre-login message.> (I<page 18>)

=item 3) C<2.2.4.1 Tokenless Stream>

C<As shown in the previous section, some messages do not use tokens to describe the data portion of the data stream. In these cases, all the information required to describe the packet data is contained in the packet header. This is referred to as a tokenless stream and is essentially just a collection of packets and data.> (I<page 24>)

=item 4) C<2.2.6.4 PRELOGIN>

C<A message sent by the client to set up context for login. The server responds to a client PRELOGIN message with a message of packet header type 0x04 and the packet data containing a PRELOGIN structure.> (I<page 59>)

C<[TERMINATOR] [0xFF] [Termination token.]> (I<page 61>)

C<TERMINATOR is a required token, and it MUST be the last token of PRELOGIN_OPTION. TERMINATOR does not include length and bits specifying offset.> (I<page 61>)

=back

According to the previous quotes, the C<L<TDS|/"TDS"> Pre-Login> is just C<a handshake>, i.e., the C<L<TDS|/"TDS"> Pre-Login> is a C<tokenless packet data stream> of the C<pre-authentication state> to establish the negotiation between the B<CLIENT> and the B<SERVER> -- as described in C<Figure 3: Pre-login to post-login sequence> (I<page 103>).

Based on this analysis, it is possible to determine the B<Microsoft SQL Server> version  during the C<L<TDS|/"TDS"> Pre-Login> handshake. It is an undocumented feature, but it is not a bug or a leakage, in fact, it is more likely to be an C<AS IS> embedded feature that allows B<CLIENT> to establish a negotiation with B<SERVER>. The version is available within the C<L<TDS|/"TDS"> Pre-Login Response> packet data stream, and it is a C<valuable> information sent from B<SERVER> to B<CLIENT> to ensure they will establish a communication correctly, using the correct database B<instance> and the same dialect by both B<CLIENT> and B<SERVER>.

Here is a C<tokenless packet data stream> sample traffic dump of a C<L<TDS|/"TDS"> Pre-Login> handshake between the B<SQL Fingerprint NG> and a B<Microsoft SQL Server 2012 SP1>:
 
=over 4

=item C<L<TDS|/"TDS"> Pre-Login Request>
 
 0000	12 01 00 2f 00 00 01 00 00 00 1a 00 06 01 00 20   .../............
 0010	00 01 02 00 21 00 01 03 00 22 00 04 04 00 26 00   ....!...."....&.
 0020	01 ff 09 00 00 00 00 00 01 00 b8 0d 00 00 01      ...............

=item C<L<TDS|/"TDS"> Pre-Login Response>

 0000	04 01 00 2b 00 00 01 00 00 00 1a 00 06 01 00 20   ...+............
 0010	00 01 02 00 21 00 01 03 00 22 00 00 04 00 22 00   ....!...."....".
 0020	01 ff 0b 00 0b b8 00 00 01 00 01                  ...........

=back

As seen above, there are four bytes following the C<TERMINATOR> (I<FFh> at the B<OFFSET> I<34>), and they represent the version for B<Microsoft SQL Server 2012 SP1> (I<11.0.3000>):

=over 4

=item 1) B<OFFSET> I<35> represents the Major Version (I<0Bh> = I<11>)

=item 2) B<OFFSET> I<36> represents the Minor Version (I<00h> = I<0>)

=item 3) B<OFFSETS> I<37>E<sol>I<38> represent the Build Version (I<0BB8h> = I<3000>)

=back

Also, note that the C<L<TDS|/"TDS"> Pre-Login Request> does not need to include the instance name, as well as B<Microsoft SQL Server 2000> has an unique C<L<TDS|/"TDS"> Pre-Login Response> size, which differentiates it from B<Microsoft SQL Server 2005>, B<2008>, B<2008 R2> and B<2012> and above:

=over 4

=item 1) C<L<TDS|/"TDS"> Pre-Login Response> on B<Microsoft SQL Server 2000> is always 37 bytes.

=item 2) C<L<TDS|/"TDS"> Pre-Login Response> on B<Microsoft SQL Server 2005>, B<2008>, B<2008 R2> and B<2012> is always 43 bytes.

=back

=over 4

I<NOTE: No authentication and C<valuable> information.>

=back

=head2 L<SSRP|/"SSRP"> and L<TDS|/"TDS"> Considerations

=over 4

=item 1) C<Microsoft Security Bulletin MS02-039>

C<SQL Server 2000 introduces the ability to host multiple instances of SQL Server on a single physical computer. Each instance operates for all intents and purposes as though it was a separate server. However, the multiple instances cannot all use the standard SQL Server session port (TCP 1433). While the default instance listens on TCP port 1433, named instances listen on any port assigned to them. The SQL Server Resolution Service, which operates on UDP port 1434, provides a way for clients to query for the appropriate network endpoints to use for a particular instance of SQL Server.>

=back

As seen above, and in previous sections, both L<SSRP|/"SSRP"> and L<TDS|/"TDS"> can be used to determine the B<Microsoft SQL Server> version. However, there are two caveats to be considered:

=over 4

=item * The L<SSRP|/"SSRP"> returns the base version instead of the real version on Microsoft SQL Server 2000, i.e., the L<SSRP|/"SSRP"> returns inaccurate version if the Microsoft SQL Server 2000 is installed.

=item * The L<SSRP|/"SSRP"> returns the base version instead of the real version on Microsoft SQL Server 2005, 2008, 2008 R2 and 2012 for GDR and QFE updates, otherwise L<SSRP|/"SSRP"> returns the real version, i.e., the L<SSRP|/"SSRP"> returns inaccurate version if the GDR and QFE updates are applied, which does not happen with Service Packs and Cumulative Updates.

=over 4

I<NOTE: To avoid inaccurate version fingerprinting, it is recommended to use C<-P,--prelogin> (see L<OPTIONS|/"OPTIONS"> for further information).>

=back

=back

=head2 CIDR

To support this feature B<SQL Fingerprint NG> applies the same B<algorithm> used by L<T50|http://t50.sourceforge.net>, and this B<algorithm> is based on three code lines (I<the smallest algorithm ever>), as following:

=over 4

=item 1) C<$netmask = ~($all_bits_on E<gt>E<gt> $bits);>

Calculate the network mask.

=over 4

=item * Bitwise B<SHIFT RIGHT> (E<gt>E<gt>) C<FFFFFFFFh> using given L<CIDR|/"CIDR">, resulting in the number of bits to calculate the network mask.

=item * Bitwise logic B<NOT> (~) turns off the bits that are on and turns on the bits that are off, resulting in the network mask.

=back

=item 2) C<$hostid = (1 E<lt>E<lt> (32 - $bits)) - 1;>

Calculate the number of available IPv4 addresses.

=over 4

=item * Subtract given L<CIDR|/"CIDR"> from 32, resulting in the host identifier's (bits) portion for the given IPv4 address.

=item * Bitwise B<SHIFT LEFT> (E<lt>E<lt>) C<1> and decrementing C<1>, resulting in the total number of IPv4 addresses available for the given L<CIDR|/"CIDR">.

=back

=item 3) C<$__1st_addr = ($address & $netmask);>

Calculate the first available IPv4 address.

=over 4

=item * Bitwise logic B<AND> (&) given IPv4 address and network mask, resulting in the first available IPv4 address for given L<CIDR|/"CIDR">.

=back

=back

The smallest allowed value is C<E<sol>0>, which performs version fingerprinting for the whole Internet, and the largest value is C<E<sol>32>, which performs version fingerprinting for a single host.

=head1 BRUTE FORCE MODE

Description is not available on public releases.

=head1 WARNING MESSAGES

=head2 DEFAULT SQL Server TCP port

Warns the availability of C<Default Instances> running on L<TDS|/"TDS"> default communication port(s) . This information is collected and parsed by C<STEP 1>, validated by C<STEP 2> and used by C<STEP 3> (see L<Fingerprinting Steps|/"Fingerprinting Steps"> for further information).

=over 4
 
I<NOTE: Only in C<-v,--verbose> and not available in C<-b,--brute-force> (see L<OPTIONS|/"OPTIONS"> for further information).>
 
=back

=head2 DYNAMIC SQL Server TCP port

Warns the availability of B<multiple instances> (C<Default Instances> as well as C<Named Instances>) running on L<TDS|/"TDS"> dynamic communication port(s). This information is collected and parsed by C<STEP 1> , validated by C<STEP 2> and used by C<STEP 3> (see L<Fingerprinting Steps|/"Fingerprinting Steps"> for further information).

=over 4
 
I<NOTE: Only in C<-v,--verbose> and not available in C<-b,--brute-force> (see L<OPTIONS|/"OPTIONS"> for further information).>
 
=back
 
=head2 HIGHEST Score

Warns the L<HIGHEST Score|/"HIGHEST Score"> for a single version, i.e., B<SQL Fingerprint NG> found a higher probability of a single version among the B<instance(s)>.

=over 4

I<NOTE: Only in C<-H,--highest> (see L<OPTIONS|/"OPTIONS"> for further information).>

=back

=head2 MULTIPLE HIGHEST Score

Warns the L<HIGHEST Score|/"HIGHEST Score"> for multiple versions, i.e., B<SQL Fingerprint NG> found a higher probability of multiple version among the B<instance(s)>.

=over 4

I<NOTE: Only in C<-H,--highest> (see L<OPTIONS|/"OPTIONS"> for further information).>

=back

=head2 MULTIPLE SQL Server instances

Warns the availability of B<multiple instances> (C<Default Instances> as well as C<Named Instances>). This information is collected and parsed by C<STEP 1> and used and validated by C<STEP 3> (see L<Fingerprinting Steps|/"Fingerprinting Steps"> for further information).

=over 4

I<NOTE: Only in C<-v,--verbose> and not available in C<-b,--brute-force> (see L<OPTIONS|/"OPTIONS"> for further information).>

=back

=head1 OPTIONS

=over 4

=item C<E<sol>CIDR>
 
Configures the L<CIDR|/"CIDR"> (I<Classless Inter-Domain Routing>), which builds a range of IPv4 addresses (see L<CIDR|/"CIDR"> for further information).
 
=item C<-b,--brute-force> B<(default OFF)>
 
Configures the B<BRUTE FORCE MODE>, which drives B<SQL Fingerprint NG> to perform B<PROTOCOL GATHERING> on pre-defined TCP ports (C<-p,--ports>), by checking for a valid C<L<TDS|/"TDS"> Pre-Login Response> (see L<BRUTE FORCE MODE|/"BRUTE FORCE MODE"> for further information).

=over 4

I<NOTE: This option is not available on public releases.>

=back

=item C<-d,--debug> B<(default OFF)>
 
Configures the B<DEBUG MODE>, which gives further detailed information about the fingerprinting tasks.

=over 4

I<NOTE: This option disables both L<VSAM|/"VERSION SCORING ALGORITHM MECHANISM"> and L<ESAM|/"EXPLOIT SCORING ALGORITHM MECHANISM">.>

=back

=item C<-f,--fingerdb FILE> B<(default C<ESF.db>)>

Configures an optional B<SQL Fingerprint NG> Database file.


=item C<-h,-?,--help>

Displays the help and usage message.

=item C<-H,--highest> B<(default OFF)>
 
Displays L<HIGHEST Score|/"HIGHEST Score"> and L<MULTIPLE HIGHEST Score|/"MULTIPLE HIGHEST Score"> messages for both L<VSAM|/"VERSION SCORING ALGORITHM MECHANISM"> and L<ESAM|/"EXPLOIT SCORING ALGORITHM MECHANISM"> (see L<HIGHEST Score|/"HIGHEST Score"> and L<MULTIPLE HIGHEST Score|/"MULTIPLE HIGHEST Score"> for further information).
 
=item C<-i,--ignore> B<(default OFF)>
 
Configures the B<IGNORE MODE>, which forces B<SQL Fingerprint NG> to ignore missing B<SQL Fingerprint NG> Database file, as well as corrupted andE<sol>or invalid B<SQL Fingerprint NG> Database file.

=item C<-I,--instance> B<(default OFF)>
 
Displays B<instance(s)> name (C<Default Instances> as well as C<Named Instances>) for both L<VSAM|/"VERSION SCORING ALGORITHM MECHANISM"> and L<ESAM|/"EXPLOIT SCORING ALGORITHM MECHANISM">.

=item C<-m,--manpage>

Displays the manual page embedded in B<SQL Fingerprint NG>, which is the manual page in POD (Plain Old Documentation) format.

=item C<-p,--ports NUM:NUM> B<(default 1024:65535)>
 
Configures TCP ports, which are the TCP ports used by B<BRUTE FORCE MODE>.
 
=over 4

I<NOTE: This option is not available on public releases.>

=back
 
=item C<-P,--prelogin> B<(default OFF)>
 
Configures C<L<TDS|/"TDS"> Pre-Login Request> only, which avoids C<L<SSRP|/"SSRP"> Client Unicast Instance Request>.
 
=item C<-s,--suppress> B<(default OFF)>
 
Configures the B<SUPPRESS MODE>, which suppresses the L<VSAM|/"VERSION SCORING ALGORITHM MECHANISM"> messages.

=over 4

I<NOTE: This option is not available on public releases.>

=back
 
=item C<-S,--scan> B<(default OFF)>
 
Configures the B<SCAN MODE>, which uses the L<ESAM|/"EXPLOIT SCORING ALGORITHM MECHANISM"> to score the vulnerabilities and their exploitability.

=over 4

I<NOTE: This option is not available on public releases.>

=back
 
=item C<-t,--timeout NUM> B<(default 30)>

Configures a specific connection timeout (seconds), which allows B<SQL Fingerprint NG> to wait until close the connection.

=item C<-T,--loop-timeout NUM> B<(default 5)>

Configures a specific timeout (seconds), which allows B<SQL Fingerprint NG> to wait until execute the next C<STEP> in the C<LOOP>.

=item C<-v,--verbose> B<(default OFF)>

Configures the B<VERBOSE MODE>, which gives detailed information about the fingerprinting tasks.

=back

=head1 DEPENDENCIES

=over 4

=item C<Digest::MD5(3)>

See C<L<Getopt::Long's Perl Documentation|Digest::MD5/"DESCRIPTION">> for further information.

=item C<Getopt::Long(3)>

See C<L<Getopt::Long's Perl Documentation|Getopt::Long/"DESCRIPTION">> for further information.

=item C<IO::Select(3)>

See C<L<IO::Select's Perl Documentation|IO::Select::INET/"DESCRIPTION">> for further information.

=item C<IO::Socket::INET(3)>

See C<L<IO::Socket::INET's Perl Documentation|IO::Socket::INET/"DESCRIPTION">> for further information.

=item C<IO::Socket::INET6(3)>

See C<L<IO::Socket::INET6's Perl Documentation|IO::Socket::INET6/"DESCRIPTION">> for further information.

=item C<List::Util(3)> 

See C<L<List::Util's Perl Documentation|List::Util/"DESCRIPTION">> for further information.

=item C<Pod::Usage(3)>

See C<L<Pod::Usage's Perl Documentation|Pod::Usage/"DESCRIPTION">> for further information.

=item C<POSIX(1)>

See C<L<POSIX's Perl Documentation|POSIX/"DESCRIPTION">> for further information.

=item C<Switch(3)>

See C<L<Switch's Perl Documentation|Switch/"DESCRIPTION">> for further information.

=item C<PERL(1)> v5.10.1 or v5.12.4

B<SQL Fingerprint NG> has been widely tested under B<Perl> v5.10.1 (Ubuntu 10.04 LTS) and B<Perl> v5.12.4 (OS X Mountain Lion). Due to this, B<SQL Fingerprint NG> requires one of the mentioned versions to be executed. The following tests will be performed to ensure its capabilities:

 BEGIN {
    my $subname = (caller (0))[3];
    eval ("require 5.012004;");
    eval ("require 5.010001;") if $@;
    die "$subname: Unsupported Perl version ($]).\n" if $@;
 }

=over 4

I<NOTE: If you are confident that your B<Perl> version is capable to execute the B<SQL Fingerprint NG>, please, remove the above tests and send a feedback to L<AUTHOR|/"AUTHOR">>.

=back

See C<L<PERL's Perl Documentation|PERL/"DESCRIPTION">> for further information.

=back

=head1 SEE ALSO

L<Digest::MD5(3)|Digest::MD5>, L<Getopt::Long(3)|Getopt::Long>, L<IO::Select(3)|IO::Select>, L<IO::Socket::INET(3)|IO::Socket::INET>, L<IO::Socket::INET6(3)|IO::Socket::INET6>, L<List::Util(3)|List::Util>, L<Pod::Usage(3)|Pod::Usage>, L<POSIX(1)|POSIX>, L<Switch(3)|Switch>, PERL(1), L<[RFC793]|http://www.ietf.org/rfc/rfc793.txt>, L<[RFC768]|http://www.ietf.org/rfc/rfc768.txt>, L<TDS|http://msdn.microsoft.com/en-us/library/dd304523.aspx>, L<SSRP|http://msdn.microsoft.com/en-us/library/cc219703.aspx>, L<SQLPing & SQLVer Tools|http://www.sqlsecurity.com/downloads>, L<C<TOUCHING THE UNTOUCHABLE>|http://www.slideshare.net/nbrito01/touching-the-untouchable-ysts-seventh-edition>

=head1 HISTORY

=over 4

=item B<2008>

Exploit Next Generation Tool (B<PRIVATE RELEASE>)

=item B<2009>
 
H2HC Sixth Edition Talk (B<November 28>)
 
=item B<2010>

MSSQLFP BETA-3 (B<January 5>)

MSSQLFP BETA-4 (B<January 18>)

ESF 1.00.0006 (B<February 10>)

ESF 1.10.101008/CTP (B<October 8>)

=item B<2012>

ESF 1.12.120115/RC0 (B<January 15>)

ESF 1.42.24-102144 Perl Version (B<December 24>)

=item B<2013>

YSTS Seventh Edition Talk (B<May 20>)

=item B<2014>

ESF 2.78.140202/YSTS+GPL (B<February 2>)
 
=back

=head1 TODO

=over 4

=item 1) Include IPv6 address support.

=item 2) Include L<SSRP|/"SSRP"> CLNT_BCAST_EX support -- a.k.a. Passive Mode.

=item 3) Include B<EXPLOIT MODE>.

=back

=head1 BUGS AND LIMITATIONS

Report B<SQL Fingerprint NG> bugs and limitations directly to the L<AUTHOR|/"AUTHOR">.

=head1 LEGAL NOTICE

Be aware that the use of B<SQL Fingerprint NG> may be forbidden in some countries. There may be rules and laws prohibiting any unauthorized user from launching a port scanning and/or fingerprinting services. These actions may be considered illegal.

The L<AUTHOR|/"AUTHOR"> B<VEHEMENTLY DENIES> the malicious use of B<SQL Fingerprint NG>, as well as its use for illegal purposes.

Use B<SQL Fingerprint NG> at your own risk!

=over 4

I<NOTE: This is a very limited version for public releases, which does not introduce the advanced and sophisticated algorithms demonstrated during the L<You Sh0t The Sheriff|http://www.ysts.org> Seventh Edition.>
 
=back

=head1 AUTHOR

B<Nelson Brito> L<mailto:nbrito@sekure.org>.

=head1 COPYRIGHT NOTICE

Copyright 2010-2014, B<Nelson Brito>. All rights reserved worldwide.

B<ENG++ Technology> and other noted B<Exploit Next Generation++> and/or B<ENG++> related products contained herein are registered trademarks or trademarks of L<AUTHOR|/"AUTHOR">. Any other non-B<Exploit Next Generation++> related products, registered and/or unregistered trademarks contained herein is only by reference and are the sole property of their respective owners.
 
B<Exploit Next Generation++ Technology>, innovating since 2010.

B<MICROSOFT SQL SERVER VERSION FINGERPRINTING TOOL. MADE IN BRAZIL.>

=head1 MICROSOFT SQL SERVER (REGISTERED TRADEMARKS OR TRADEMARKS)

=head2 Microsoft SQL Server 2000 Copyright

Copyright 1988-2003 Microsoft Corporation. All rights reserved.

Active Directory, ActiveX, BackOffice, CodeView, Developer Studio, FoxPro, JScript, Microsoft, Microsoft Press, Microsoft SQL Server, MSDN, MS-DOS, Outlook, PivotChart, PivotTable, PowerPoint, Visual Basic, Visual C++, Visual Studio, Win32, Windows 2000, Windows, and Windows NT are either registered trademarks or trademarks of Microsoft Corporation in the United States and/or other countries. The names of actual companies and products mentioned herein may be the trademarks of their respective owners.

=head2 Microsoft SQL Server 2005 Copyright

Copyright 1998-2007 Microsoft Corporation. All rights reserved.

Microsoft, MS DOS, Windows, Windows NT, ActiveX, Developer Studio, FoxPro, JScript, MSDN, Visual Basic, Visual C++, Visual InterDev, Visual J++, Visual Studio, and Win32 are either registered trademarks or trademarks of Microsoft Corporation in the United States and/or other countries. All other trademarks are property of their respective owners.

=head2 Microsoft SQL Server 2008 (R2) Copyright

Copyright 1998-2009 Microsoft Corporation. All rights reserved.

Microsoft, MS DOS, Windows, Windows NT, ActiveX, Developer Studio, FoxPro, JScript, MSDN, Visual Basic, Visual C++, Visual InterDev, Visual J++, Visual Studio, and Win32 are either registered trademarks or trademarks of Microsoft Corporation in the United States and/or other countries. All other trademarks are property of their respective owners.

=head2 Microsoft SQL Server 2012 Copyright

Copyright 1998-2012 Microsoft Corporation. All rights reserved.

Microsoft, Active Directory, ActiveX, Bing Maps, Excel, IntelliSense, MSDN, MS-DOS, PivotChart, PivotTable, PowerPoint, SharePoint, SQL Server, Visual Basic, Visual C#, Visual C++, Visual Studio, Windows, Windows NT, Windows Server, and Windows Vista are trademarks of the Microsoft group of companies. SAP NetWeaver is the registered trademark of SAP AG in Germany and in several other countries. All other trademarks are property of their respective owners.

=head1 LICENSE

This program is free software: you can redistribute it and/or modify it under the terms of the I<GNU General Public License> as published by the B<Free Software Foundation>, either version 3 of the License, or (at your option) any later version.

You should have received a copy of the L<GNU General Public License|http://www.gnu.org/licenses/> along with this program. If not, see L<GNU General Public License|http://www.gnu.org/licenses/>.

The following text was taken borrowed and adapted from L<NMap|http://www.nmap.org/> License:

=head2 Additional Terms and Conditions

Note that the GPL places important restrictions on C<derived works>, yet it does not provide a detailed definition of that term. To avoid misunderstandings, the L<AUTHOR|/"AUTHOR"> considers an application to constitute a "derivative work" for the purpose of this license if it does any of the following:

=over 4

=item 1) Integrates source code from B<SQL Fingerprint NG>.

=item 2) Reads or includes B<SQL Fingerprint NG> copyrighted data files, such: version database and configuration files, any code extraction (partial or total), any algorith (partial or toal), etc...

=item 3) Integrates, includes or aggregates B<SQL Fingerprint NG> (partial or total) into a proprietary executable installer, such as those produced by InstallShield.

=item 4) Links to a library or executes a program that does any of the above.

=back

The term C<B<SQL Fingerprint NG>> should be taken to also include any portions or derived works of B<SQL Fingerprint NG>. This list is not exclusive, but is meant to clarify the L<AUTHOR|/"AUTHOR">'s interpretation of C<derived works> with some common examples. The L<AUTHOR|/"AUTHOR">'s interpretation applies only to B<SQL Fingerprint NG> -- he doesn't speak for other people's GPL works.
 
If you have any questions about the GPL licensing restrictions on using B<SQL Fingerprint NG> in non-GPL works, the L<AUTHOR|/"AUTHOR"> would be happy to help. As mentioned above, the L<AUTHOR|/"AUTHOR"> also offers alternative license to integrate B<SQL Fingerprint NG> into proprietary applications and appliances. These licenses generally include a perpetual license as well as providing for priority support and updates as well as helping to fund the continued development of B<SQL Fingerprint NG> technology. Please email the L<AUTHOR|/"AUTHOR"> for further information.
 
If you received these files with a written license agreement or contract stating terms other than the terms above, then that alternative license agreement takes precedence over these comments.
 
Source is provided to this software because the L<AUTHOR|/"AUTHOR"> believes users have a right to know exactly what a program is going to do before they run it. This also allows you to audit the software for security holes, but none have been found so far.
 
Source code also allows you to port B<SQL Fingerprint NG> to new platforms, fix bugs, and add new features and new protocol modules. You are highly encouraged to send your changes to the L<AUTHOR|/"AUTHOR"> for possible incorporation into the main distribution. By sending these changes to L<AUTHOR|/"AUTHOR">, it is assumed that you are offering the B<SQL Fingerprint NG> Project, and its L<AUTHOR|/"AUTHOR">, the unlimited, non-exclusive right to reuse, modify, and relicense the code. B<SQL Fingerprint NG> will always be available Open Source, but this is important because the inability to relicense code has caused devastating problems for other Free Software projects (such as KDE and NASM). The L<AUTHOR|/"AUTHOR"> also occasionally relicense the code to third parties as discussed above. If you wish to specify special license conditions of your contributions, just say so when you send them.

=head1 DISCLAIMER OF WARRANTY

This program is distributed in the hope that it will be useful, but B<WITHOUT ANY WARRANTY>; without even the implied warranty of B<MERCHANTABILITY> or B<FITNESS FOR A PARTICULAR PURPOSE> (see the L<GNU General Public License|http://www.gnu.org/licenses/> for more details).

=cut
