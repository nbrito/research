#
#  (This takes the place of the C program is_able.c, BTW.)
# 
#  is_able filename {w|g|s|S}       {r|w|B|b|s}
#      (world/group/SUID/SGID   read/write/{read&write}/{suid&write}/s[ug]id)
# 
#     The second arg of {r|w} determines whether a file is (group or world
#   depending on the first arg of {w|g}) writable/readable, or if it is
#   SUID/SGID (first arg, either s or S, respectively), and prints out a
#   short message to that effect.
# 
#  So:
#     is_able w w		# checks if world writable
#     is_able g r		# checks if group readable
#     is_able s s		# checks if SUID
#     is_able S b		# checks if world writable and SGID

package main;
require 'file_mode.pl';

package is_able;

# package statics
#
%wg = ( 
	'w', 00006,
	'g', 00060,
	's', 04000,
	'S', 02000,
       );

%rwb= (
	'r', 00044,
	'w', 00022,
	'B', 00066,
	'b', 04022,
	's', 06000,
      );

$silent = 0;  # for suppressing diagnostic messages


sub main'is_able {
    local($file, $wg, $rwb) = @_;

    local ( 
	   $mode, 			# file mode
           $piece,			# 1 directory component
	   @pieces, 			# all the pieces
	   @dirs, 			# all the directories
	   $p, 				# punctuation; (*) mean writable
	   				#       due to writable parent
	   $retval,			# true if vulnerable
	   $[				# paranoia
	  );

    &usage, return undef	if @_ != 3 || $file eq '';

    &usage, return undef	unless defined $wg{$wg} && defined $rwb{$rwb};

    if (&'Mode($file) eq 'BOGUS' && $noisy) {
	warn "is_able: can't stat $file: $!\n";
	return undef;
    }

    $retval = 0;

    if ($rwb{$rwb} & $rwb{'w'}) {
	@pieces = split(m#/#, $file);
	for ($i = 1; $i <= $#pieces; $i++) {
	    push(@dirs, join('/', @pieces[0..$i]));
	}
    } else {
	@dirs = ( $file );
    } 

    for $piece ( reverse @dirs ) {

	next unless $mode = &'Mode($piece);
	next if $mode eq 'BOGUS';

	next unless $mode &= 07777 & $wg{$wg} & $rwb{$rwb};

	$retval = 1;

	$p = $piece eq $file ? '!' : '! (*)';

	$parent_is_writable = $p eq '! (*)'; # for later

	next if $silent; # for &is_writable

	print "Warning!  $file is group readable$p\n"	if $mode & 00040; 
	print "Warning!  $file is _World_ readable$p\n"	if $mode & 00004; 
	print "Warning!  $file is group writable$p\n"	if $mode & 00020; 
	print "Warning!  $file is _World_ writable$p\n"	if $mode & 00002; 
	print "Warning!  $file is SUID!\n"		if $mode & 04000; 
	print "Warning!  $file is SGID!\n"		if $mode & 02000; 

	last if $piece ne $file;  # only complain on first writable parent
    }
    $retval;
}

sub main'is_writable {
    local($silent) = 1;
    &'is_able($_[0], 'w', 'w') 
	? $parent_is_writable 
	     ? "writable (*)"
	     : "writable" 
	: 0;
} 

sub main'is_readable {
    local($silent) = 1;
    &'is_able($_[0], 'w', 'r');
}

sub usage { 
    warn <<EOF;
Usage: is_able file {w|g|S|s} {r|w|B|b|s}
 (not: is_able @_)
EOF
}

1;
