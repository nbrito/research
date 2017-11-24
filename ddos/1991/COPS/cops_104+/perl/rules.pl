sub apply_rules {
    local($op, $value, @plan) = @_;

    printf("eval($op $value): %s\n", &ascii_plan(@plan)) if $opt_d;

    #
    # apply UID attack rules...
    #
    if ($op eq "u") {
	#
	# If we can replace /etc/passwd or /usr/lib/aliases, we can grant 
	# any uid. 
	#
	&addto("r", "/etc/passwd", @plan);
        &addto("r", "/usr/lib/aliases", @plan);
        &addto("r", "/etc/aliases", @plan);

	#
	# Check CF's for all usernames with this uid.
	#
uname_loop:
    foreach $uname (split(/ /, $uid2names{$value})) {
	    $home = $uname2dir{$uname};

	    next uname_loop unless $home;

	    if ($home eq "/") {
		$home = "";
	    }
	    &addto("r", "$home/.rhosts", @plan);
	    &addto("r", "$home/.login", @plan);
	    &addto("r", "$home/.logout", @plan);
	    &addto("r", "$home/.cshrc", @plan);
	    &addto("r", "$home/.profile", @plan);
	}

	#
	# Controlling files for root...
	#
	@rootlist = ( 
		"/etc/rc", "/etc/rc.boot", "/etc/rc.single", 
		"/etc/rc.config", "/etc/rc.local", "/usr/lib/crontab",
		"/usr/spool/cron/crontabs",
		);

	if ($value eq "0") {
	    foreach $file (@rootlist) {
		    &addto("r", $file, @plan);
	    }
	    # Experimental!
	    # you can remove this if desired - tjt
	    #do "rc.prog";
	}

	#
	# Other CFs for non-root folks...
	#
	if ($value ne "0") {
	    &addto("r", "/etc/hosts.equiv", @plan);
	    if (-s "/etc/hosts.equiv") {
		&addto("r", "/etc/hosts", @plan);
	    }
	}

    #
    # Plans for attacking GIDs...
    #
    } elsif ($op eq "g") {	# apply gid attack rules

	#
	# If we can replace /etc/group we can become any group
	#				  
        &addto("r", "/etc/group", @plan);

	#
	# If we can grant any member of a group we can grant that group
	#
member_loop:
	foreach $uname (split(/ /, $gid2members{$value})) {
	    if (! defined($uname2uid{$uname})) {
		printf(stderr "group '%s' member '%s' doesn't exist.\n",
			$value,
			$uname);
		next member_loop;
	    }

	    &addto("u", $uname2uid{$uname}, @plan);
	}

    #
    # Plans for attacking files...
    #

    } elsif ($op eq "r" || $op eq "w") {

        ($owner, $group, $other) = &filewriters($value);

	&addto("u", $owner, @plan) if ($owner ne "");
	&addto("g", $group, @plan) if ($group ne "");
	&addto("u", "-1", @plan) if ($other);

	#
	# If the goal is to replace the file, check the parent directory...
	#
	if ($op eq "r") {
	    $parent = $value;
	    $parent =~ s#/[^/]*$##;     # strip last / and remaining stuff

	    if ($parent eq "") {
		$parent = "/";
	    }

	    if ($parent ne $value) {
		&addto("r", $parent, @plan);
	    }
	}

    } else {			# wow, bad $type of object!
	printf(stderr "kuang: bad op in apply_rules!\n");
	printf(stderr "op '%s' value '%s' plan '%s'\n",
		$op,
		$value,
		&ascii_plan(@plan));
	exit(1);
    }
}

1;

