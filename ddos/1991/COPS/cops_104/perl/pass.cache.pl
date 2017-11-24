#
#   Routines for reading and caching user and group information.  These
# are used in multiple programs... it caches the info once, then hopefully
# won't be used again.
#
#  Steve Romig, May 1991.
#
# Provides a bunch of routines and a bunch of arrays.  Routines 
# (and their usage):
#
#    load_passwd_info($use_getent, $file_name)
#
#	loads user information into the %uname* and %uid* arrays 
#	(see below).  
#
#	If $use_getent is non-zero:
#	    get the info via repeated 'getpwent' calls.  This can be
#	    *slow* on some hosts, especially if they are running as a
#	    YP (NIS) client.
#	If $use_getent is 0:
#	    if $file_name is "", then get the info from reading the 
#	    results of "ypcat passwd" and from /etc/passwd.  Otherwise, 
#	    read the named file.  The file should be in passwd(5) 
#	    format.
#
#    load_group_info($use_gentent, $file_name)
#
#	is similar to load_passwd_info.
#
# Information is stored in several convenient associative arrays:
#
#   %uname2shell	Assoc array, indexed by user name, value is 
#			shell for that user name.
#
#   %uname2dir		Assoc array, indexed by user name, value is
#			home directory for that user name.
#
#   %uname2uid		Assoc array, indexed by name, value is uid for 
#			that uid.
#			
#   %uname2passwd	Assoc array, indexed by name, value is password
#			for that user name.
#
#   %uid2names		Assoc array, indexed by uid, value is list of
#			user names with that uid, in form "name name
#			name...". 
#
#   %gid2members	Assoc array, indexed by gid, value is list of
#			group members in form "name name name..."
#
#   %gname2gid		Assoc array, indexed by group name, value is
#			matching gid.
#
#   %gid2names		Assoc array, indexed by gid, value is the
#			list of group names with that gid in form 
#			"name name name...".
#
# You can also use routines named the same as the arrays - pass the index 
# as the arg, get back the value.  If you use this, get{gr|pw}{uid|gid|nam} 
# will be used to lookup entries that aren't found in the cache.
#
# To be done:
#    probably ought to add routines to deal with full names.
#    maybe there ought to be some anal-retentive checking of password 
#	and group entries.
#    probably ought to cache get{pw|gr}{nam|uid|gid} lookups also.
#    probably ought to avoid overwriting existing entries (eg, duplicate 
#       names in password file would collide in the tables that are 
#	indexed by name).
#
# Disclaimer:
#    If you use YP and you use netgroup entries such as 
#	+@servers::::::
#	+:*:::::/usr/local/utils/messages
#    then loading the password file in with &load_passwd_info(0) will get 
#    you mostly correct YP stuff *except* that it won't do the password and 
#    shell substitutions as you'd expect.  You might want to use 
#    &load_passwd_info(1) instead to use getpwent calls to do the lookups, 
#    which would be more correct.
#

package main;

$PASSWD = '/etc/passwd' unless defined $PASSWD;

require 'pathconf.pl';

%uname2shell = ();
%uname2dir = ();
%uname2uid = ();
%uname2passwd = ();
%uid2names = ();
%gid2members = ();
%gname2gid = ();
%gid2names = ();

$DOMAINNAME = "/bin/domainname" unless defined $DOMAINNAME;
$YPCAT = "/bin/ypcat" unless defined $YPCAT;

$yptmp = "./yptmp.$$";

$passwd_loaded = 0;		# flags to use to avoid reloading everything
$group_loaded = 0;		# unnecessarily...

#
# We provide routines for getting values from the data structures as well.
# These are named after the data structures they cache their data in.  Note 
# that they will all generate password and group file lookups via getpw* 
# and getgr* if they can't find info in the cache, so they will work
# "right" even if load_passwd_info and load_group_info aren't called to 
# preload the caches.
#
# I should point out, however, that if you don't call load_*_info to preload
# the cache, uid2names, gid2names and gid2members *will not* be complete, since 
# you must read the entire password and group files to get a complete picture.
# This might be acceptable in some cases, so you can skip the load_*_info
# calls if you know what you are doing...
#
sub uname2shell {
    local($key) = @_;

    if (! defined($uname2shell{$key})) {
	&add_pw_info(getpwnam($key));
    }

    return($uname2shell{$key});
}

sub uname2dir {
    local($key) = @_;
    local(@pw_info);

    if (! defined($uname2dir{$key})) {
	&add_pw_info(getpwnam($key));
    }

    return($uname2dir{$key});
}

sub uname2uid {
    local($key) = @_;
    local(@pw_info);

    if (! defined($uname2uid{$key})) {
	&add_pw_info(getpwnam($key));
    }

    return($uname2uid{$key});
}

sub uname2passwd {
    local($key) = @_;
    local(@pw_info);

    if (! defined($uname2passwd{$key})) {
	&add_pw_info(getpwnam($key));
    }

    return($uname2passwd{$key});
}

sub uid2names {
    local($key) = @_;
    local(@pw_info);

    if (! defined($uid2names{$key})) {
	&add_pw_info(getpwuid($key));
    }

    return($uid2names{$key});
}

sub gid2members {
    local($key) = @_;
    local(@gr_info);

    if (! defined($gid2members{$key})) {
	&add_gr_info(getgrgid($key));
    }

    return($gid2members{$key});
}

sub gname2gid {
    local($key) = @_;
    local(@gr_info);

    if (! defined($gname2gid{$key})) {
	&add_gr_info(getgrnam($key));
    }

    return($gname2gid{$key});
}

sub gid2names {
    local($key) = @_;
    local(@gr_info);

    if (! defined($gid2names{$key})) {
	&add_gr_info(getgrgid($key));
    }

    return($gid2names{$key});
}

#
# Update user information for the user named $name.  We cache the password, 
# uid, login group, home directory and shell.
#

sub add_pw_info {
    local($name, $passwd, $uid, $gid) = @_;
    local($dir, $shell);

#
# Ugh!  argh...yech...sigh.  If we use getpwent, we get back 9 elts, 
# if we parse /etc/passwd directly we get 7.  Pick off the last 2 and 
# assume that they are the $directory and $shell.  
#
    $num = ( $#_ >= 7 ? 8 : 6 );
    $dir = $_[$num - 1];
    $shell = $_[$num] || '/bin/sh';


    if ($name ne "") {
	$uname2shell{$name} = $shell;
	$uname2dir{$name} = $dir;
	$uname2uid{$name} = $uid;
	$uname2passwd{$name} = $passwd;

	if ($gid ne "") {
	    # fixme: should probably check for duplicates...sigh

	    if (defined($gid2members{$gid})) {
		$gid2members{$gid} .= " $name";
	    } else {
		$gid2members{$gid} = $name;
	    }
	}

	if ($uid ne "") {
	    if (defined($uid2names{$uid})) {
		$uid2names{$uid} .= " $name";
	    } else {
		$uid2names{$uid} = $name;
	    }
	}
    }
}

#
# Update group information for the group named $name.  We cache the gid 
# and the list of group members.
#

sub add_gr_info {
    local($name, $passwd, $gid, $members) = @_;

    if ($name ne "") {
	$gname2gid{$name} = $gid;

	if ($gid ne "") {
	    if (defined($gid2names{$gid})) {
		$gid2names{$gid} .= " $name";
	    } else {
		$gid2names{$gid} = $name;
	    }

	    # fixme: should probably check for duplicates

	    $members = join(' ', split(/[, \t]+/, $members));

	    if (defined($gid2members{$gid})) {
		$gid2members{$gid} .= " " . $members;
	    } else {
		$gid2members{$gid} = $members;
	    }
	}
    }
}

#
# We need to suck in the entire group and password files so that we can 
# make the %uid2names, %gid2members and %gid2names lists complete.  Otherwise,
# we would just read the entries as needed with getpw* and cache the results.
# Sigh.
#
# There are several ways that we might find the info.  If $use_getent is 1, 
# then we just use getpwent and getgrent calls to read the info in.
#
# That isn't real efficient if you are using YP (especially on a YP client), so
# if $use_getent is 0, we can use ypcat to get a copy of the passwd and
# group maps in a fairly efficient manner.  If we do this we have to also read
# the local /etc/{passwd,group} files to complete our information.  If we aren't 
# using YP, we just read the local pasword and group files.
#
sub load_passwd_info {
    local($use_getent, $file_name) = @_;
    local(@pw_info);

    if ($passwd_loaded) {
	return;
    }

    $passwd_loaded = 1;

    if ($'GET_PASSWD) {
	open(GFILE, "$'GET_PASSWD|") || die "can't $'GET_PASSWD";
	while (<GFILE>) {
		chop;
		&add_pw_info(split(/:/));
		}
	close(GFILE);
	}
    else {

    if ($use_getent) {
	#
	# Use getpwent to get the info from the system, and add_pw_info to 
	# cache it.
	#
	while (@pw_info = getpwent) {
	    &add_pw_info(@pw_info);
	}

	endpwent;

	return;
    } elsif ($file_name eq "") {
	chop($has_yp = `$DOMAINNAME`);
	if ($has_yp) {
	    #
	    # If we have YP (NIS), then use ypcat to get the stuff from the 
	    # map.@
	    #
	    system("$YPCAT passwd > $yptmp 2> /dev/null");
	    if (-s $yptmp) {
	    	open(FILE, "$YPCAT passwd|") ||
	      	die "can't 'ypcat passwd'";
	    	while (<FILE>) {
			chop;
			&add_pw_info(split(/:/));
	    		}
	    	}
	    close(FILE);
	}

	#
	# We have to read /etc/passwd no matter what...
	#
	$file_name = "/etc/passwd";
    }

    open(FILE, $file_name) ||
      die "can't open $file_name";

    while (<FILE>) {
	chop;
	    
	if ($_ !~ /^\+/) {
	    &add_pw_info(split(/:/));
	}

	# fixme: if the name matches +@name, then this is a wierd 
	# netgroup thing, and we aren't dealing with it right.  might want
	# to warn the poor user...suggest that he use the use_getent 
	# method instead.
    }
    }

    close(FILE);
}

sub load_group_info {
    local($use_getent, $file_name) = @_;
    local(@gr_info);

    if ($group_loaded) {
	return;
    }

    $group_loaded = 1;

    if ($use_getent) {
	#
	# Use getgrent to get the info from the system, and add_gr_info to 
	# cache it.
	#
	while ((@gr_info = getgrent()) != 0) {
	    &add_gr_info(@gr_info);
	}

	endgrent();

	return();
    } elsif ($file_name eq "") {
	chop($has_yp = `$DOMAINNAME`);
	if ($has_yp) {
	    #
	    # If we have YP (NIS), then use ypcat to get the stuff from the 
	    # map.
	    #
	    system("$YPCAT passwd > $yptmp 2> /dev/null");
	    if (-s $yptmp) {
	    	open(FILE, "$YPCAT group|") ||
	      	die "can't 'ypcat group'";
	    	while (<FILE>) {
			chop;
			&add_gr_info(split(/:/));
	    		}
	    	close(FILE);
		}
	}

	#
	# We have to read /etc/group no matter what...
	#
	$file_name = "/etc/group";
    }

    open(FILE, $file_name) ||
      die "can't open $file_name";

    while (<FILE>) {
	chop;
	if ($_ !~ /^\+/) {
	    &add_gr_info(split(/:/));
	}

	# fixme: if the name matches +@name, then this is a wierd 
	# netgroup thing, and we aren't dealing with it right.  might want
	# to warn the poor user...suggest that he use the use_getent 
	# method instead.
    }

    close(FILE);
}

# Load the password stuff -- Do NOT take this out!
&'load_passwd_info(0,$PASSWD);

unlink $yptmp;

1;
