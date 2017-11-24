#!/bin/sh  # need to mention perl here to avoid recursion
# NOTE:
#   If you know where perl is and your system groks #!, put its
# pathname at the top to make this a tad faster.
#
# the following magic is from the perl man page
# and should work to get us to run with perl 
# even if invoked as an sh or csh or foosh script.
# notice we don't use full path cause we don't
# know where the user has perl on their system.
#
eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}' 
& eval 'exec perl -S $0 $argv:q'
    if $running_under_some_stupid_shell_instead_of_perl;

#  Target shell scripts in question:
$COPS_CONFIG="pathconf.pl";

#  Potential directories to find commands:
@all_dirs=("/bin",
	   "/usr/bin",
	   "/usr/ucb",
	   "/usr/local/bin",  # scary
	   "/usr/bsd");

# uncomment next line if you want your own current path used instead
#
# @all_dirs = split(/:/, $ENV{'PATH'});

#  Target commands in question, sans those checked above:
@all_commands= ("cc", "awk", "cat",
		"chmod", "cmp", "comm", "cp",
		"date", "diff", "echo", "egrep", "expr",
		"find", "grep", "ls", "mail",
		"mkdir", "mv", "rm", "sed",
		"sh", "sort", "test", "tftp", "touch",
		"uudecode", "uniq", "ypcat");

@want{@all_commands} = ();

%exceptions=   ('strings', 'chk_strings',
                'tftp', 'misc.chk',
		'cmp', 'ftp.chk',
                'uudecode', 'misc.chk');

# grab the current values:
open COPS_CONFIG || die "Can't open $COPS_CONFIG: $!\n";

$new = "$COPS_CONFIG.$$";
open(NEW_CONFIG, ">$new") || die "Can't open $new: $!\n";

while (<COPS_CONFIG>) {
    unless (/\$(\w+)\s*=\s*(['"])(\S*)\2/) {
	print NEW_CONFIG;
	next;
    } 
    ($cap_command, $path) = ($1, $3);
    ($command = $cap_command) =~ tr/A-Z/a-z/;
    unless (($newpath = &getpath($command)) || $command =~ /^yp/) {
	warn "Warning!  no path for $command!\n";
	warn "          $exceptions{$command} will not work as planned!\n"
		     if $exceptions{$command};
	$errors++;
    } else {
	delete $want{$command};
    } 
    print "old $path now in $newpath\n" if $newpath ne $path;
    print NEW_CONFIG "\$$cap_command = '$newpath';\n";

}

for (sort keys %want) {
    delete $want{$_} if $path = &getpath($_);
    tr/a-z/A-Z/;
    print NEW_CONFIG '$', $_, " = '", $path, "';\n";
} 

close(COPS_CONFIG) || die "can't close $COPS_CONFIG: $!\n";
close(NEW_CONFIG) || die "can't close $new: $!\n";

if (@missing = keys %want) {
     warn "Warning!   missing paths for @missing!\n";
     warn "The shell version may not work right!\n";
} 


if ($errors) {
    print STDERR "Not all paths were found: write anyway? ";
    # what about removing NEW_CONFIG, $new ??
    exit 1 if <STDIN> !~ /^\s*y/i;
    print STDERR "Ok, but this might not be right...\n";
} 

$old = "$COPS_CONFIG.old";

rename($COPS_CONFIG, $old)
    || die "can't rename $COPS_CONFIG to $old: $!\n";

rename($new, $COPS_CONFIG)
    || die "can't rename $new to $COPS_CONFIG: $!\n";


open COPS_CONFIG || die "can't re-open $COPS_CONFIG: $!\n";
($SH_CONF = $COPS_CONFIG) =~ s/\.pl$/.sh/;
open (SH_CONF, ">$SH_CONF") || die "can't create $SH_CONF: $!\n";

while (<COPS_CONFIG>) {
    s/^\$//;
    print SH_CONF;
} 
close SH_CONF || die "can't close $SH_CONF: $!\n";

exit 0;

#############

sub getpath {
    local($cmd) = @_;
    local($path);

    for (@all_dirs) {
	return $path if -x ($path = "$_/$cmd");
    } 
    '';
} 
