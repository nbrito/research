#!/usr/unsup/bin/perl
'true' || eval 'exec perl -S $0 $argv:q';
eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
& eval 'exec /usr/local/bin/perl -S $0 $argv:q'
        if 0;

$me=$ENV{"USER"};
$end_code=0; 
$networkgrps="";
while (<>) {
	chop;
	@F = split(' ');
	if (/^[ \t]*\+@/) { 
		$networkgrps=$networkgrps . $F[0] . " ";
	}
	elsif ($#F > 0) {
		$machine=$F[0];
		shift(@F);
		while ( $#F > -1 ) {
			if ( $F[0] ne $me )  {
				$holes{$machine}=$holes{$machine} . $F[0] . " ";
			}
			shift(@F);
		}
     	}
}
if ( $networkgrps ne "" )  {
	printf "\nAll users in network group(s) (%s) can login to your account\n",$networkgrps;
	printf "without a password.\n";
	$end_code=1;
}
for ( keys %holes )  {
	printf "\nThese users at %s are allowed to login to your account\n",$_;
	printf "without a password: %s\n", $holes{$_};
	$end_code=1;
}
exit $end_code;
