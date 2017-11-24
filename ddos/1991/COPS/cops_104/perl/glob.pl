#
#  This does shell or perl globbing without resorting
# to the shell -- we were having problems with the shell blowing
# up with extra long pathnames and lots of file names.  set $glob'debug 
# for trace information.
#
# tom christiansen <tchrist@convex.com>

package glob;

sub main'glob { 
    local($expr) = @_;
    local(@files);

    $? = 0;
    open(SAVERR, ">&STDERR"); close(STDERR);  # suppress args too long
    @files = <${expr}>;
    if ($?) {
	print SAVERR "shell glob blew up on $expr\n" if $debug;
	@files = &SHglob($expr);
    }
    open (STDERR, ">&SAVERR");
    # if (@files == 1 && $files[0] eq $expr) { @files = ''; } # sh foo
    @files;
}

sub main'SHglob {
    local($expr) = @_;
    local(@retlist) = ();
    local($dir);

    print "SHglob: globbing $expr\n" if $debug;

    $expr =~ s/([.{+\\])/\\$1/g;
    $expr =~ s/\*/.*/g;
    $expr =~ s/\?/./g;

    for $dir (split(' ',$expr)) {
	push(@retlist, &main'REglob($dir));
    } 

    return sort @retlist;
} 

sub main'REglob {
    local($path) = @_;
    local($_);
    local(@retlist) = ();
    local($root,$expr,$pos);
    local($relative) = 0;
    local(@dirs);
    local($user);

    $haveglobbed = 0;

    @dirs = split(/\/+/, $path);

    if ($dirs[$[] =~ m!~(.*)!) {
	$dirs[$[] = &homedir($1);
	return @retlist unless $dirs[$[];
    } elsif ($dirs[$[] eq '') {
	$dirs[$[] = '/' unless $dirs[$[] =~ m!^\.{1,2}$!;
    } else {
	unshift(@dirs, '.');
	$relative = 1;
    } 

    printf "REglob: globbing %s\n", join('/',@dirs) if $debug;

    @retlist = &expand(@dirs);

    for (@retlist) {
	if ($relative) {
	    s!^\./!!o;
	}
	s!/{2,}!/!g;
    } 

    return sort @retlist;
}

sub expand {
    local($dir, $thisdir, @rest) = @_;
    local($nextdir);
    local($_);
    local(@retlist) = ();
    local(*DIR);

    unless ($haveglobbed || $thisdir =~ /([^\\]?)[?.*{[+\\]/ && $1 ne '\\') {
	@retlist = ($thisdir);
    } else {
	unless (opendir(DIR,$dir)) {
	    warn "glob: can't opendir $dir: $!\n" if $debug;
	} else {
		@retlist = grep(/^$thisdir$/,readdir(DIR));
		@retlist = grep(!/^\./, @retlist) unless $thisdir =~ /^\\\./;
		$haveglobbed++;
	} 
	closedir DIR;
    } 

    for (@retlist) {
	$_ = $dir . '/' . $_;
    }

    if ($nextdir = shift @rest) {
	local(@newlist) = ();
	for (@retlist) {
	    push(@newlist,&expand($_,$nextdir,@rest));
	} 
	@retlist = @newlist;
    } 

    return @retlist;
} 

sub homedir {
    local($user) = @_;
    local(@pwent);
    # global %homedir

    if (!$user) {
	return $ENV{'HOME'} 		if $ENV{'HOME'};
	($user = $ENV{'USER'})  	|| 
	    ($user = getlogin) 		|| 
	    (($user) = getpwnam($>));
	warn "glob'homedir: who are you, user #$>?\n" unless $user;
	return '/';
    } 
    unless (defined $homedir{$user}) {
	if (@pwent = getpwnam($user)) {
	    $homedir{$user} = $pwent[$#pwent - 1];
	} else {
	    warn "glob'homedir: who are you, user #$>?\n" unless $user;
	    $homedir{$user} = '/';
	}
    }
    return $homedir{$user};
} 


1;
