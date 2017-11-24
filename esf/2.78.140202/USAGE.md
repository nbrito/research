```
SQL Fingerprint NG powered by ENG++ Technology [Version 2.78.140202/YSTS+GPL]
Nelson Brito <nbrito@sekure.org>

Usage:
    "ESF.pl host[/CIDR] [options]"

Options:
    "/CIDR"
        Configures the CIDR (*Classless Inter-Domain Routing*), which builds
        a range of IPv4 addresses (see CIDR for further information).

    "-b,--brute-force" (default OFF)
        Configures the BRUTE FORCE MODE, which drives SQL Fingerprint NG to
        perform PROTOCOL GATHERING on pre-defined TCP ports ("-p,--ports"),
        by checking for a valid "TDS Pre-Login Response" (see BRUTE FORCE
        MODE for further information).

            *NOTE: This option is not available on public releases.*

    "-d,--debug" (default OFF)
        Configures the DEBUG MODE, which gives further detailed information
        about the fingerprinting tasks.

            *NOTE: This option disables both VSAM and ESAM.*

    "-f,--fingerdb FILE" (default "ESF.db")
        Configures an optional SQL Fingerprint NG Database file.

    "-h,-?,--help"
        Displays the help and usage message.

    "-H,--highest" (default OFF)
        Displays HIGHEST Score and MULTIPLE HIGHEST Score messages for both
        VSAM and ESAM (see HIGHEST Score and MULTIPLE HIGHEST Score for
        further information).

    "-i,--ignore" (default OFF)
        Configures the IGNORE MODE, which forces SQL Fingerprint NG to
        ignore missing SQL Fingerprint NG Database file, as well as
        corrupted and/or invalid SQL Fingerprint NG Database file.

    "-I,--instance" (default OFF)
        Displays instance(s) name ("Default Instances" as well as "Named
        Instances") for both VSAM and ESAM.

    "-m,--manpage"
        Displays the manual page embedded in SQL Fingerprint NG, which is
        the manual page in POD (Plain Old Documentation) format.

    "-p,--ports NUM:NUM" (default 1024:65535)
        Configures TCP ports, which are the TCP ports used by BRUTE FORCE
        MODE.

            *NOTE: This option is not available on public releases.*

    "-P,--prelogin" (default OFF)
        Configures "TDS Pre-Login Request" only, which avoids "SSRP Client
        Unicast Instance Request".

    "-s,--suppress" (default OFF)
        Configures the SUPPRESS MODE, which suppresses the VSAM messages.

            *NOTE: This option is not available on public releases.*

    "-S,--scan" (default OFF)
        Configures the SCAN MODE, which uses the ESAM to score the
        vulnerabilities and their exploitability.

            *NOTE: This option is not available on public releases.*

    "-t,--timeout NUM" (default 30)
        Configures a specific connection timeout (seconds), which allows SQL
        Fingerprint NG to wait until close the connection.

    "-T,--loop-timeout NUM" (default 5)
        Configures a specific timeout (seconds), which allows SQL
        Fingerprint NG to wait until execute the next "STEP" in the "LOOP".

    "-v,--verbose" (default OFF)
        Configures the VERBOSE MODE, which gives detailed information about
        the fingerprinting tasks.

Legal Notice:
    Be aware that the use of SQL Fingerprint NG may be forbidden in some
    countries. There may be rules and laws prohibiting any unauthorized user
    from launching a port scanning and/or fingerprinting services. These
    actions may be considered illegal.

    The AUTHOR VEHEMENTLY DENIES the malicious use of SQL Fingerprint NG, as
    well as its use for illegal purposes.

    Use SQL Fingerprint NG at your own risk!

        *NOTE: This is a very limited version for public releases, which
        does not introduce the advanced and sophisticated algorithms
        demonstrated during the You Sh0t The Sheriff <http://www.ysts.org>
        Seventh Edition.*

Copyright Notice:
    Copyright 2010-2014, Nelson Brito. All rights reserved worldwide.

    ENG++ Technology and other noted Exploit Next Generation++ and/or ENG++
    related products contained herein are registered trademarks or
    trademarks of AUTHOR. Any other non-Exploit Next Generation++ related
    products, registered and/or unregistered trademarks contained herein is
    only by reference and are the sole property of their respective owners.

    Exploit Next Generation++ Technology, innovating since 2010.

    MICROSOFT SQL SERVER VERSION FINGERPRINTING TOOL. MADE IN BRAZIL.

```
