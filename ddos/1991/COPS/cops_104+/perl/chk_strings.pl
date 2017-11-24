#
#  This is a big one.  Support routines to check for strings 
# that look like pathnames and make sure they're not writable.
# Will recurse if $recurse is set.  the shell version can't do
# this (yet).  call &ignore with list of regexps that you don't
# care about.  (or set @ignores)
#
# originally by Tom Christiansen <tchrist@convex.com>
# since hacked on by parties various and sundry.

require 'is_able.pl';
require 'file_mode.pl';
require 'pathconf.pl';

package chk_strings;


$'STRINGS = $'STRINGS || '/usr/ucb/strings';

for ( '/dev/null', '/dev/tty' ) {
    $seen{$_}++;
} 

sub main'chk_strings {
    local($ARGV) = @_;
    local($_);
    local($word);
    local(*STRINGS);  # XXX: might run out of fd's on deep recursion!  -tchrist
    local(%paths, $text); 
    local($STRINGS) = "$'STRINGS $ARGV |";

    &ignore(@ignores) if defined @ignores && !$already_ignored;

    $STRINGS="< $ARGV", $text=1 if -T $ARGV;
    print "Opening via: $STRINGS\n" if $debug;

    open (STRINGS, $STRINGS); 
    while (<STRINGS>) { 
	next unless m#/#;   # was m#/.*/#;
#---------------------------------------------------------------------------
# Comments and modifications by Martin Foord (maf%dbsm.oz.au@munnari.oz.au).
	#s/#.*$// if $text;  # strip out comments if -T file
	# Comments start in the shell at the beginning of a word or at the
	# beggining of a line
	if ($text) {
		s/\s+#.*$//;
		s/^#.*$//;
	}

	# Get rid of semicolons, they can hang around on filenames ...
	s/;//g;
#---------------------------------------------------------------------------

	s/"([^"]*)"/ $1 /g;
	s/'([^']*)'/ $1 /g;
	# See my comments below on how to deal with this stuff ... (line 64).
	#s/`([^`]*)`/ $1 /g;


	s!([<>])\s+/!$1/!g;  # "> /foo" goes to ">/foo";

	s/=/ /g;  # warning -- mangled files with = in them
	for $word (split) {
	    if ($word =~ m#:/#) {
		print "push $word (split on the colons)\n" if $debug;
		@paths{split(/:/, $word)} = ();
	    } elsif ($word =~ m#^[<>]?/#) {
		print "push $word\n" if $debug;
		$paths{$word}++;
	    }
	}
    }
    close (STRINGS);
    push(@files, $ARGV);

    for (keys %paths) {
	s/\)$//;
	s/^\(//;
	s#^/+#/#;
	s#^(/.*)/$#$1#;	    # get rid of trailing slash

#---------------------------------------------------------------------------
# Comments and modifications by Martin Foord (maf%dbsm.oz.au@munnari.oz.au).
	# It's best to evaluate what's in backquotes rather than remove them
	# as in the substitution above, due to files which
	# look like this /var/yp/`domainname` (eg in my /etc/rc.local).
	s`\`(.+)\``$1`; # eval what's in backquotes.
	chop if /\n$/;	# fang off \n if there ...
#---------------------------------------------------------------------------
	next if &ignored($_);
	s/^[<>]//;
	next if $_ eq '';
	next unless !$seen{$_}++ && -e && !-S _;
	print "checking $_\n" if $debug;
	if ($how = &'is_writable($_)) {
	    print "Warning!  File $_ (inside ",
			join(' inside ', reverse @files), ") is _World_ $how!\n";
	} elsif ($recurse && (&'Mode($_) & 0111) && -f _) {
	     print "recursing $_\n" if $debug;
	     &'chk_strings($_);   
	} 
    }
     pop(@files);
} 

sub ignore {
    local($_);
    local($prog);

    $already_ignored = 1;

    $prog = <<'EOCODE';

sub ignored {
    local($return) = 1;
    local($prog);
    local($_) = @_;
    {
EOCODE
    for (@_) {
	$prog .= "\tlast if m\201${_}\201;\n";
    } 
    $prog .= <<'EOCODE';
	$return = 0;
    }
    print "$_ IGNORED\n" if $debug && $return;
    $return;
}
EOCODE
    
    print $prog if $debug;
    eval $prog;
    die $@ if $@;
} 

sub ignored {}; # in case they never ignore anything

1;
