#!/usr/local/bin/perl
#
# Checks a host.equiv file to see what it trusted
#
#  trust.he [-h host.equiv] [-d]
#
#  options specify alternate data files, except the -d, which is the debug flag.
#
#  Originally written by me, but then tim tessin grabbed it and optimized
# it.  This is one of the building blocks for SATAN, BTW.  You'll see
# more of this later...
#
#  - d
#
#  routine tjt hack job - 10/28/91
#  - deleted netgroup file specifcation.  netgroups is always gotten 
#    from yp maps, never from the file.
#  - simplified and optimized second pass, store intermediate values
#    avoiding second open.  Code runs in 1/3 the time. 
#  - make the %trusted array hold individual hostnames, so we can subtract
#    more easily.
#  - implemented subtract option.
#  - fixed a bug or two adding single hosts.
#  - output one per line so I can sort and diff it to test it.
#  - Wow! Total rethink of algorithm.  Need to tag untrusted as well
#    as trusted cuz 1st match either way causes access search to 
#    terminate. 
#  - single entries can have - as per spec
#  - lots of error checking bypassed.  Do we need it?  If there are
#    syntax errors will system allow access? In what cases?
#

# Process the command args...
require 'getopts.pl';
$usage = "Usage: $0  [-h host.equiv] [-n netgroup] [-d]\n";
die $usage unless &Getopts('h:n:d');

if (!defined($opt_h)) { $hosts_equiv = "/etc/hosts.equiv"; }
else { $hosts_equiv = $opt_h; }

&init_net_group;

open (HE, $hosts_equiv) || die "Can't open $hosts_equiv\n";
while (<HE>) {
	chop;
	/^\s*#/ && next;
	/^\s*$/ && next; 		# trash garbage
	/^\+\s*$/ && do {		# + in hosts.equiv is trouble
		print "Trust WORLD\n";
		exit 0;
		};

	($sign,$at,$name) = /^([+-])?(@)?(.*)/;
	print "sign: $sign at: $at name: $name\n" if $opt_d;
	unless ($at) {
		if ($sign eq "-") {
			$untrusted{$name} = $name unless ($trusted{$name});
			}
		else {
			$trusted{$name} = $name unless ($untrusted{$name});
			}
		}
	# handle netgroups now...
	else {
		# add
		if ($sign ne "-") {
			for (split(/\s+/,$members{$name})) {
				$trusted{$_} = $_ unless $untrusted{$_};
				}
			print "Add $name:\n", $members{$name},"\n" if $opt_d;
			}
		# delete
		else {
			for (split(/\s+/,$members{$name})) {
				$untrusted{$_} = $_ unless $trusted{$_};
				}
			print "Subtract $name:\n", $members{$name},"\n" if $opt_d;
			}
		}	# end of netgroup stuff
	}
close(HE);

for $trust (values %trusted) {
	print "$trust\n";
	}

#############################
sub init_net_group {

#   Make two passes through netgroup file -- first pass grabs all the
# groupnames for expansion when parsing the triples

#  1st Pass:
#
# get the net groups for the 2nd pass:
if (defined($opt_n)) { open (NG, $opt_n) || die "Can't open $opt_n\n"; }
else { open (NG, "ypcat -k netgroup |") || die "Can't open netgroups\n";}
while (<NG>) {
	chop;
	push(@lines,$_);
	($group, @members) = split(/\s+/, $_);
	$member = pop(@members);
	for (@members) { $member .= " $_"; }

	if ($second_pass{$group} eq "") {
		$second_pass{$group} = $member;
		}
	else { warn "Duplicate net-group found: $group\n"; }

	$member = "";
	}
close NG;

#  2nd Pass:
#
foreach $line (@lines) {
	($group, @members) = split(/\s+/, $line);

	print "\n===>: $group\nMembers: @members\n\n" if ($opt_d);

	$wild1 = $wild2 = $wild3 = 0;
	for (@members) {
		unless ( ($machine,$name,$domain) = /\((.*),(.*),(.*)\)/ ) {
			$netgrp = $_;
			}

		if ($machine || $name || $domain) {
			print "line: ($machine,$name,$domain)\n" if ($opt_d);
			$wild1 = 1 unless $machine;
			$wild2 = 1 unless $name;
			$wild3 = 1 unless $domain;

			$wild1 = -1 if ( $machine && $machine =~ /^\W/ );
			$wild2 = -1 if ( $name && $name =~ /^\W/ );
			$wild3 = -1 if ( $domain && $domain =~ /^\W/ );

			# wildcards or not; no action if $wild1 == -1:
			if ($wild1 > 0) {
				$members{$group} = "WILDCARD";
				}
			elsif (!$wild1) {
				if ($members{$group} eq "") {
					$members{$group} = $machine; }
				elsif ($members{$group} ne "WILDCARD") {
					$members{$group} .= " $machine"; }
				}
			}
		else {
			print "line: $netgrp\n" if ($opt_d);
			print "PUSHING $netgrp: $second_pass{$netgrp}\n" if $opt_d;
			# what if groups instead of (,,) stuff?
			@stuff = split(/\s+/, $second_pass{$netgrp});
			for $i (@stuff) {
				next if ($i eq "");
				print "PUSH $i\n" if $opt_d;
				push(@members, $i);
				}
			}
		}

	print "\nSAVED:",  $group, " ", $members{$group}, "\n" if $opt_d;
	$line = "";
	}

}	# end of netgroup stuff
