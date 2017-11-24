```
ESF(1)                User Contributed Perl Documentation               ESF(1)



NAME
       ESF.pl - SQL Fingerprint NG powered by ENG++ Technology

VERSION
       This document describes the Version 2 of SQL Fingerprint NG ("You Sh0t
       The Sheriff + GNU General Public License"), which applies the most
       reliable and accurate technique, based on its sophisticated algorithm,
       to identify Microsoft SQL Server versions.

       If you are interested on the Version 4 of SQL Fingerprint NG
       ("TECHNOLOGY PREVIEW"), which applies sophisticated algorithm to also
       identify vulnerabilities, please, contact the AUTHOR.

USAGE
       "ESF.pl host[/CIDR] [options]"

DESCRIPTION
       Microsoft SQL Server fingerprinting can be a time consuming process,
       because it involves trial and error methods to determine the exact
       version. Intentionally inserting an invalid input to obtain a typical
       error message or using certain alphabets that are unique for certain
       server are two of the many ways to possibly determine the version, but
       most of them require authentication, permissions and/or privileges on
       Microsoft SQL Server to succeed.

       Instead, SQL Fingerprint NG uses a combination of crafted packets for
       SQL Server Resolution Protocol (SSRP) and Tabular Data Stream Protocol
       (TDS) (protocols natively used by Microsoft SQL Server) to accurately
       perform version fingerprinting and determine the exact Microsoft SQL
       Server version. SQL Fingerprint NG also applies a sophisticated Version
       Scoring Algorithm Mechanism (VSAM) powered by Exploit Next Generation++
       Technology, which is a much more reliable technique to determine the
       Microsoft SQL Server version. It is a tool intended to be used by:

       o   Database Administrators

       o   Database Auditors

       o   Database Owners

       o   Penetration Testers

       Having over "SIX HUNDRED" unique versions within its fingerprint
       database, SQL Fingerprint NG currently supports fingerprinting for:

       o   Microsoft SQL Server 2000

       o   Microsoft SQL Server 2005

       o   Microsoft SQL Server 2008

       o   Microsoft SQL Server 2008 R2

       o   Microsoft SQL Server 2012

       o   Microsoft SQL Server 2014

       SQL Fingerprint NG re-invented the techniques used by several public
       tools (SQLPing Tool by Chip Andrews, Rajiv Delwadia and Michael Choi,
       and SQLVer Tool by Chip Andrews) (see SEE ALSO for further
       information). SQL Fingerprint NG shows the "MAPPED VERSION" and "PATCH
       LEVEL" (i.e., Microsoft SQL Server 2008 SP1 (CU-5)) instead of showing
       only the "RAW VERSION" (i.e., Microsoft SQL Server 10.0.2746). SQL
       Fingerprint NG also has the ability to show the HIGHEST Score version
       -- based on its sophisticated VSAM powered by Exploit Next Generation++
       Technology -- and allows to determine "vulnerable" and "unpatched"
       Microsoft SQL Server -- based on its sophisticated Exploit Scoring
       Algorithm Mechanism (ESAM) powered by Exploit Next Generation++
       Technology. Both VSAM and ESAM make the SQL Fingerprint NG the most
       comprehensive Microsoft SQL Server fingerprinting tool.

       This version is a completely rewritten version in Perl, making SQL
       Fingerprint NG much more portable than the previous binary version for
       Microsoft Windows OS (see HISTORY for further information), and its
       original purpose is to be used as a tool to perform automated
       penetration test.

           NOTE: SQL Fingerprint NG "IS NOT" a SQLi tool, and has no ability
           to perform such task.

   Fingerprinting Steps
       As described in DESCRIPTION, SQL Fingerprint NG uses a combination of
       crafted packets for SSRP and TDS to accurately perform version
       fingerprintfing. To achieve an accurate and much more reliable version
       fingerprinting, SQL Fingerprint NG employes the following steps,
       mimicking a valid negotiation between the CLIENT and the SERVER:

       1) "SSRP Client Unicast Request" (CLNT_UCAST_EX)
           This STEP attempts to gather the Microsoft SQL Server single
           instance or even multiple instances (see MULTIPLE SQL Server
           instances for further information), and the respective TDS
           communication port(s) -- the TDS communication port for each
           instance can be dynamic or default (see DYNAMIC SQL Server TCP port
           and DEFAULT SQL Server TCP port for further information).

               NOTE: If this "STEP" fails and "-b,--brute-force" has not been
               configured, the "STEP 2" is not performed and the "STEP 3" will
               use TDS default communication port only.

       2) "SSRP Client Unicast Instance Request" (CLNT_UCAST_INST)
           This STEP attempts to use the information gathered by STEP 1 to
           collect, parse and match information for a single instance or for
           multiple instances (see MULTIPLE SQL Server instances for further
           information). Once the collecting, parsing and matching is done,
           the fingerprinting data is stored to be validated by the
           sophisticated VSAM and ESAM powered by Exploit Next Generation++
           Technology.

               NOTE: If the "STEP 1" fails or "-P,--prelogin" has been
               configured, this "STEP" is not performed.

       3) "TDS Pre-Login Request" (PRELOGIN)
           This STEP attempts to use the information gathered by STEP 1 to
           collect, parse and match information for a single instance running
           on TDS default coommunication port (see DEFAULT SQL Server TCP port
           for further information) or for multiple instances (see MULTIPLE
           SQL Server instances for further information) running on TDS
           dynamic communication port(s) (see DYNAMIC SQL Server TCP port for
           further information). Once the collecting, parsing and matching is
           done, the fingerprinting data is stored to be validated by the
           sophisticated VSAM and ESAM powered by Exploit Next Generation++
           Technology.

               NOTE: If "STEP 1" fails and "-b,--brute-force" has not been
               configured, this "STEP" will use TDS default communication port
               only.

   SSRP
       As described in "[MS-SQLR]: SQL Server Resolution Protocol"
       specification document (see SEE ALSO for further information).

       1) "1.3 Overview"
           "The first case is used for the purpose of determining the
           communication endpoint information of a particular database
           instance, whereas the second case is used for enumeration of
           database instances in the network and to obtain the endpoint
           information of each instance." (page 8)

           "The SQL Server Resolution Protocol does not include any facilities
           for authentication, protection of data, or reliability. The SQL
           Server Resolution Protocol is always implemented on top of the UDP
           Transport Protocol [RFC768]." (page 8)

       2) "1.9 Standards Assignments"
           "The client always sends its request to UDP port 1434 of the server
           or servers." (page 10)

       3) "2.2.2 CLNT_UCAST_EX"
           "The CLNT_UCAST_EX packet is a unicast request that is generated by
           clients that are trying to determine the list of database instances
           and their network protocol connection information installed on a
           single machine. The client generates a UDP packet with a single
           byte, as shown in the following diagram." (page 11)

       4) "2.2.3 CLNT_UCAST_INST"
           "The CLNT_UCAST_INST packet is a request for information related to
           a specific instance. The structure of the request is as follows."
           (page 12)

       According to the previous quotes, the SSRP "is used for the purpose of
       determining the communication endpoint information of a particular
       database instance", which "does not include any facilities for
       authentication", and both "SSRP CLNT_UCAST_EX Request" and "SSRP
       CLNT_UCAST_INST Request" can be used "for the purpose of determining
       the communication endpoint information".

       Based on this analysis, it is possible to determine the Microsoft SQL
       Server version  using the "SSRP CLNT_UCAST_EX Request" and/or "SSRP
       CLNT_UCAST_INST Request". The version is available within the "SSRP
       CLNT_UCAST_EX Response" and/or "SSRP CLNT_UCAST_INST Response", and it
       is a "valuable" information sent from SERVER to CLIENT to ensure they
       will establish a communication correctly, using the correct database
       instance and the same dialect by both CLIENT and SERVER.

       Here is a "SSRP CLNT_UCAST_INST Request" and "SSRP CLNT_UCAST_INST
       Response" sample traffic dump between the SQL Fingerprint NG and a
       Microsoft SQL Server 2012 SP1:

       "SSRP CLNT_UCAST_INST Request"
            0000   04 4d 53 53 51 4c 53 45 52 56 45 52              .MSSQLSERVER

       "SSRP CLNT_UCAST_INST Response"
            0000   05 61 00 53 65 72 76 65 72 4e 61 6d 65 3b 57 49   .a.ServerName;WI
            0010   4e 2d 44 41 43 4b 47 37 4e 4a 37 31 4d 3b 49 6e   N-DACKG7NJ71M;In
            0020   73 74 61 6e 63 65 4e 61 6d 65 3b 4d 53 53 51 4c   stanceName;MSSQL
            0030   53 45 52 56 45 52 3b 49 73 43 6c 75 73 74 65 72   SERVER;IsCluster
            0040   65 64 3b 4e 6f 3b 56 65 72 73 69 6f 6e 3b 31 31   ed;No;Version;11
            0050   2e 30 2e 33 30 30 30 2e 30 3b 74 63 70 3b 31 34   .0.3000.0;tcp;14
            0060   33 33 3b 3b                                       33;;

       As seen above, the information within the "SSRP CLNT_UCAST_EX Response"
       represents the version for Microsoft SQL Server 2012 SP1 (11.0.3000),
       as well as many interesting information.

           NOTE: No authentication and "valuable" information.

   TDS
       As described in "[MS-TDS]: Tabular Data Stream Protocol" specification
       document (see SEE ALSO for further information).

       1) "2.2.1.1 Pre-Login"
           "Before a login occurs, a handshake denominated pre-login occurs
           between client and server, setting up contexts such as encryption
           and MARS-enabled." (page 17)

       2) "2.2.2.1 Pre-Login Response"
           "The pre-login response is a tokenless packet data stream. The data
           stream consists of the response to the information requested by the
           client pre-login message." (page 18)

       3) "2.2.4.1 Tokenless Stream"
           "As shown in the previous section, some messages do not use tokens
           to describe the data portion of the data stream. In these cases,
           all the information required to describe the packet data is
           contained in the packet header. This is referred to as a tokenless
           stream and is essentially just a collection of packets and data."
           (page 24)

       4) "2.2.6.4 PRELOGIN"
           "A message sent by the client to set up context for login. The
           server responds to a client PRELOGIN message with a message of
           packet header type 0x04 and the packet data containing a PRELOGIN
           structure." (page 59)

           "[TERMINATOR] [0xFF] [Termination token.]" (page 61)

           "TERMINATOR is a required token, and it MUST be the last token of
           PRELOGIN_OPTION. TERMINATOR does not include length and bits
           specifying offset." (page 61)

       According to the previous quotes, the "TDS Pre-Login" is just "a
       handshake", i.e., the "TDS Pre-Login" is a "tokenless packet data
       stream" of the "pre-authentication state" to establish the negotiation
       between the CLIENT and the SERVER -- as described in "Figure 3:
       Pre-login to post-login sequence" (page 103).

       Based on this analysis, it is possible to determine the Microsoft SQL
       Server version  during the "TDS Pre-Login" handshake. It is an
       undocumented feature, but it is not a bug or a leakage, in fact, it is
       more likely to be an "AS IS" embedded feature that allows CLIENT to
       establish a negotiation with SERVER. The version is available within
       the "TDS Pre-Login Response" packet data stream, and it is a "valuable"
       information sent from SERVER to CLIENT to ensure they will establish a
       communication correctly, using the correct database instance and the
       same dialect by both CLIENT and SERVER.

       Here is a "tokenless packet data stream" sample traffic dump of a "TDS
       Pre-Login" handshake between the SQL Fingerprint NG and a Microsoft SQL
       Server 2012 SP1:

       "TDS Pre-Login Request"
            0000   12 01 00 2f 00 00 01 00 00 00 1a 00 06 01 00 20   .../............
            0010   00 01 02 00 21 00 01 03 00 22 00 04 04 00 26 00   ....!...."....&.
            0020   01 ff 09 00 00 00 00 00 01 00 b8 0d 00 00 01      ...............

       "TDS Pre-Login Response"
            0000   04 01 00 2b 00 00 01 00 00 00 1a 00 06 01 00 20   ...+............
            0010   00 01 02 00 21 00 01 03 00 22 00 00 04 00 22 00   ....!...."....".
            0020   01 ff 0b 00 0b b8 00 00 01 00 01                  ...........

       As seen above, there are four bytes following the "TERMINATOR" (FFh at
       the OFFSET 34), and they represent the version for Microsoft SQL Server
       2012 SP1 (11.0.3000):

       1) OFFSET 35 represents the Major Version (0Bh = 11)
       2) OFFSET 36 represents the Minor Version (00h = 0)
       3) OFFSETS 37/38 represent the Build Version (0BB8h = 3000)

       Also, note that the "TDS Pre-Login Request" does not need to include
       the instance name, as well as Microsoft SQL Server 2000 has an unique
       "TDS Pre-Login Response" size, which differentiates it from Microsoft
       SQL Server 2005, 2008, 2008 R2 and 2012 and above:

       1) "TDS Pre-Login Response" on Microsoft SQL Server 2000 is always 37
       bytes.
       2) "TDS Pre-Login Response" on Microsoft SQL Server 2005, 2008, 2008 R2
       and 2012 is always 43 bytes.

           NOTE: No authentication and "valuable" information.

   SSRP and TDS Considerations
       1) "Microsoft Security Bulletin MS02-039"
           "SQL Server 2000 introduces the ability to host multiple instances
           of SQL Server on a single physical computer. Each instance operates
           for all intents and purposes as though it was a separate server.
           However, the multiple instances cannot all use the standard SQL
           Server session port (TCP 1433). While the default instance listens
           on TCP port 1433, named instances listen on any port assigned to
           them. The SQL Server Resolution Service, which operates on UDP port
           1434, provides a way for clients to query for the appropriate
           network endpoints to use for a particular instance of SQL Server."

       As seen above, and in previous sections, both SSRP and TDS can be used
       to determine the Microsoft SQL Server version. However, there are two
       caveats to be considered:

       o   The SSRP returns the base version instead of the real version on
           Microsoft SQL Server 2000, i.e., the SSRP returns inaccurate
           version if the Microsoft SQL Server 2000 is installed.

       o   The SSRP returns the base version instead of the real version on
           Microsoft SQL Server 2005, 2008, 2008 R2 and 2012 for GDR and QFE
           updates, otherwise SSRP returns the real version, i.e., the SSRP
           returns inaccurate version if the GDR and QFE updates are applied,
           which does not happen with Service Packs and Cumulative Updates.

               NOTE: To avoid inaccurate version fingerprinting, it is
               recommended to use "-P,--prelogin" (see OPTIONS for further
               information).

   CIDR
       To support this feature SQL Fingerprint NG applies the same algorithm
       used by T50 <http://t50.sourceforge.net>, and this algorithm is based
       on three code lines (the smallest algorithm ever), as following:

       1) "$netmask = ~($all_bits_on >> $bits);"
           Calculate the network mask.

           o   Bitwise SHIFT RIGHT (>>) "FFFFFFFFh" using given CIDR,
               resulting in the number of bits to calculate the network mask.

           o   Bitwise logic NOT (~) turns off the bits that are on and turns
               on the bits that are off, resulting in the network mask.

       2) "$hostid = (1 << (32 - $bits)) - 1;"
           Calculate the number of available IPv4 addresses.

           o   Subtract given CIDR from 32, resulting in the host identifier's
               (bits) portion for the given IPv4 address.

           o   Bitwise SHIFT LEFT (<<) 1 and decrementing 1, resulting in the
               total number of IPv4 addresses available for the given CIDR.

       3) "$__1st_addr = ($address & $netmask);"
           Calculate the first available IPv4 address.

           o   Bitwise logic AND (&) given IPv4 address and network mask,
               resulting in the first available IPv4 address for given CIDR.

       The smallest allowed value is "/0", which performs version
       fingerprinting for the whole Internet, and the largest value is "/32",
       which performs version fingerprinting for a single host.

BRUTE FORCE MODE
       Description is not available on public releases.

WARNING MESSAGES
   DEFAULT SQL Server TCP port
       Warns the availability of "Default Instances" running on TDS default
       communication port(s) . This information is collected and parsed by
       "STEP 1", validated by "STEP 2" and used by "STEP 3" (see
       Fingerprinting Steps for further information).

           NOTE: Only in "-v,--verbose" and not available in
           "-b,--brute-force" (see OPTIONS for further information).

   DYNAMIC SQL Server TCP port
       Warns the availability of multiple instances ("Default Instances" as
       well as "Named Instances") running on TDS dynamic communication
       port(s). This information is collected and parsed by "STEP 1" ,
       validated by "STEP 2" and used by "STEP 3" (see Fingerprinting Steps
       for further information).

           NOTE: Only in "-v,--verbose" and not available in
           "-b,--brute-force" (see OPTIONS for further information).

   HIGHEST Score
       Warns the HIGHEST Score for a single version, i.e., SQL Fingerprint NG
       found a higher probability of a single version among the instance(s).

           NOTE: Only in "-H,--highest" (see OPTIONS for further information).

   MULTIPLE HIGHEST Score
       Warns the HIGHEST Score for multiple versions, i.e., SQL Fingerprint NG
       found a higher probability of multiple version among the instance(s).

           NOTE: Only in "-H,--highest" (see OPTIONS for further information).

   MULTIPLE SQL Server instances
       Warns the availability of multiple instances ("Default Instances" as
       well as "Named Instances"). This information is collected and parsed by
       "STEP 1" and used and validated by "STEP 3" (see Fingerprinting Steps
       for further information).

           NOTE: Only in "-v,--verbose" and not available in
           "-b,--brute-force" (see OPTIONS for further information).

OPTIONS
       "/CIDR"
           Configures the CIDR (Classless Inter-Domain Routing), which builds
           a range of IPv4 addresses (see CIDR for further information).

       "-b,--brute-force" (default OFF)
           Configures the BRUTE FORCE MODE, which drives SQL Fingerprint NG to
           perform PROTOCOL GATHERING on pre-defined TCP ports ("-p,--ports"),
           by checking for a valid "TDS Pre-Login Response" (see BRUTE FORCE
           MODE for further information).

               NOTE: This option is not available on public releases.

       "-d,--debug" (default OFF)
           Configures the DEBUG MODE, which gives further detailed information
           about the fingerprinting tasks.

               NOTE: This option disables both VSAM and ESAM.

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

               NOTE: This option is not available on public releases.

       "-P,--prelogin" (default OFF)
           Configures "TDS Pre-Login Request" only, which avoids "SSRP Client
           Unicast Instance Request".

       "-s,--suppress" (default OFF)
           Configures the SUPPRESS MODE, which suppresses the VSAM messages.

               NOTE: This option is not available on public releases.

       "-S,--scan" (default OFF)
           Configures the SCAN MODE, which uses the ESAM to score the
           vulnerabilities and their exploitability.

               NOTE: This option is not available on public releases.

       "-t,--timeout NUM" (default 30)
           Configures a specific connection timeout (seconds), which allows
           SQL Fingerprint NG to wait until close the connection.

       "-T,--loop-timeout NUM" (default 5)
           Configures a specific timeout (seconds), which allows SQL
           Fingerprint NG to wait until execute the next "STEP" in the "LOOP".

       "-v,--verbose" (default OFF)
           Configures the VERBOSE MODE, which gives detailed information about
           the fingerprinting tasks.

DEPENDENCIES
       Digest::MD5(3)
           See "Getopt::Long's Perl Documentation" for further information.

       Getopt::Long(3)
           See "Getopt::Long's Perl Documentation" for further information.

       IO::Select(3)
           See "IO::Select's Perl Documentation" for further information.

       IO::Socket::INET(3)
           See "IO::Socket::INET's Perl Documentation" for further
           information.

       IO::Socket::INET6(3)
           See "IO::Socket::INET6's Perl Documentation" for further
           information.

       List::Util(3)
           See "List::Util's Perl Documentation" for further information.

       Pod::Usage(3)
           See "Pod::Usage's Perl Documentation" for further information.

       POSIX(1)
           See "POSIX's Perl Documentation" for further information.

       Switch(3)
           See "Switch's Perl Documentation" for further information.

       PERL(1) v5.10.1 or v5.12.4
           SQL Fingerprint NG has been widely tested under Perl v5.10.1
           (Ubuntu 10.04 LTS) and Perl v5.12.4 (OS X Mountain Lion). Due to
           this, SQL Fingerprint NG requires one of the mentioned versions to
           be executed. The following tests will be performed to ensure its
           capabilities:

            BEGIN {
               my $subname = (caller (0))[3];
               eval ("require 5.012004;");
               eval ("require 5.010001;") if $@;
               die "$subname: Unsupported Perl version ($]).\n" if $@;
            }

               NOTE: If you are confident that your Perl version is capable to
               execute the SQL Fingerprint NG, please, remove the above tests
               and send a feedback to AUTHOR.

           See "PERL's Perl Documentation" for further information.

SEE ALSO
       Digest::MD5(3), Getopt::Long(3), IO::Select(3), IO::Socket::INET(3),
       IO::Socket::INET6(3), List::Util(3), Pod::Usage(3), POSIX(1),
       Switch(3), PERL(1), [RFC793] <http://www.ietf.org/rfc/rfc793.txt>,
       [RFC768] <http://www.ietf.org/rfc/rfc768.txt>, TDS
       <http://msdn.microsoft.com/en-us/library/dd304523.aspx>, SSRP
       <http://msdn.microsoft.com/en-us/library/cc219703.aspx>, SQLPing &
       SQLVer Tools <http://www.sqlsecurity.com/downloads>, "TOUCHING THE
       UNTOUCHABLE" <http://www.slideshare.net/nbrito01/touching-the-
       untouchable-ysts-seventh-edition>

HISTORY
       2008
           Exploit Next Generation Tool (PRIVATE RELEASE)

       2009
           H2HC Sixth Edition Talk (November 28)

       2010
           MSSQLFP BETA-3 (January 5)

           MSSQLFP BETA-4 (January 18)

           ESF 1.00.0006 (February 10)

           ESF 1.10.101008/CTP (October 8)

       2012
           ESF 1.12.120115/RC0 (January 15)

           ESF 1.42.24-102144 Perl Version (December 24)

       2013
           YSTS Seventh Edition Talk (May 20)

       2014
           ESF 2.78.140202/YSTS+GPL (February 2)

TODO
       1) Include IPv6 address support.
       2) Include SSRP CLNT_BCAST_EX support -- a.k.a. Passive Mode.
       3) Include EXPLOIT MODE.

BUGS AND LIMITATIONS
       Report SQL Fingerprint NG bugs and limitations directly to the AUTHOR.

LEGAL NOTICE
       Be aware that the use of SQL Fingerprint NG may be forbidden in some
       countries. There may be rules and laws prohibiting any unauthorized
       user from launching a port scanning and/or fingerprinting services.
       These actions may be considered illegal.

       The AUTHOR VEHEMENTLY DENIES the malicious use of SQL Fingerprint NG,
       as well as its use for illegal purposes.

       Use SQL Fingerprint NG at your own risk!

           NOTE: This is a very limited version for public releases, which
           does not introduce the advanced and sophisticated algorithms
           demonstrated during the You Sh0t The Sheriff <http://www.ysts.org>
           Seventh Edition.

AUTHOR
       Nelson Brito <mailto:nbrito@sekure.org>.

COPYRIGHT NOTICE
       Copyright 2010-2014, Nelson Brito. All rights reserved worldwide.

       ENG++ Technology and other noted Exploit Next Generation++ and/or ENG++
       related products contained herein are registered trademarks or
       trademarks of AUTHOR. Any other non-Exploit Next Generation++ related
       products, registered and/or unregistered trademarks contained herein is
       only by reference and are the sole property of their respective owners.

       Exploit Next Generation++ Technology, innovating since 2010.

       MICROSOFT SQL SERVER VERSION FINGERPRINTING TOOL. MADE IN BRAZIL.

MICROSOFT SQL SERVER (REGISTERED TRADEMARKS OR TRADEMARKS)
   Microsoft SQL Server 2000 Copyright
       Copyright 1988-2003 Microsoft Corporation. All rights reserved.

       Active Directory, ActiveX, BackOffice, CodeView, Developer Studio,
       FoxPro, JScript, Microsoft, Microsoft Press, Microsoft SQL Server,
       MSDN, MS-DOS, Outlook, PivotChart, PivotTable, PowerPoint, Visual
       Basic, Visual C++, Visual Studio, Win32, Windows 2000, Windows, and
       Windows NT are either registered trademarks or trademarks of Microsoft
       Corporation in the United States and/or other countries. The names of
       actual companies and products mentioned herein may be the trademarks of
       their respective owners.

   Microsoft SQL Server 2005 Copyright
       Copyright 1998-2007 Microsoft Corporation. All rights reserved.

       Microsoft, MS DOS, Windows, Windows NT, ActiveX, Developer Studio,
       FoxPro, JScript, MSDN, Visual Basic, Visual C++, Visual InterDev,
       Visual J++, Visual Studio, and Win32 are either registered trademarks
       or trademarks of Microsoft Corporation in the United States and/or
       other countries. All other trademarks are property of their respective
       owners.

   Microsoft SQL Server 2008 (R2) Copyright
       Copyright 1998-2009 Microsoft Corporation. All rights reserved.

       Microsoft, MS DOS, Windows, Windows NT, ActiveX, Developer Studio,
       FoxPro, JScript, MSDN, Visual Basic, Visual C++, Visual InterDev,
       Visual J++, Visual Studio, and Win32 are either registered trademarks
       or trademarks of Microsoft Corporation in the United States and/or
       other countries. All other trademarks are property of their respective
       owners.

   Microsoft SQL Server 2012 Copyright
       Copyright 1998-2012 Microsoft Corporation. All rights reserved.

       Microsoft, Active Directory, ActiveX, Bing Maps, Excel, IntelliSense,
       MSDN, MS-DOS, PivotChart, PivotTable, PowerPoint, SharePoint, SQL
       Server, Visual Basic, Visual C#, Visual C++, Visual Studio, Windows,
       Windows NT, Windows Server, and Windows Vista are trademarks of the
       Microsoft group of companies. SAP NetWeaver is the registered trademark
       of SAP AG in Germany and in several other countries. All other
       trademarks are property of their respective owners.

LICENSE
       This program is free software: you can redistribute it and/or modify it
       under the terms of the GNU General Public License as published by the
       Free Software Foundation, either version 3 of the License, or (at your
       option) any later version.

       You should have received a copy of the GNU General Public License
       <http://www.gnu.org/licenses/> along with this program. If not, see GNU
       General Public License <http://www.gnu.org/licenses/>.

       The following text was taken borrowed and adapted from NMap
       <http://www.nmap.org/> License:

   Additional Terms and Conditions
       Note that the GPL places important restrictions on "derived works", yet
       it does not provide a detailed definition of that term. To avoid
       misunderstandings, the AUTHOR considers an application to constitute a
       "derivative work" for the purpose of this license if it does any of the
       following:

       1) Integrates source code from SQL Fingerprint NG.
       2) Reads or includes SQL Fingerprint NG copyrighted data files, such:
       version database and configuration files, any code extraction (partial
       or total), any algorith (partial or toal), etc...
       3) Integrates, includes or aggregates SQL Fingerprint NG (partial or
       total) into a proprietary executable installer, such as those produced
       by InstallShield.
       4) Links to a library or executes a program that does any of the above.

       The term "SQL Fingerprint NG" should be taken to also include any
       portions or derived works of SQL Fingerprint NG. This list is not
       exclusive, but is meant to clarify the AUTHOR's interpretation of
       "derived works" with some common examples. The AUTHOR's interpretation
       applies only to SQL Fingerprint NG -- he doesn't speak for other
       people's GPL works.

       If you have any questions about the GPL licensing restrictions on using
       SQL Fingerprint NG in non-GPL works, the AUTHOR would be happy to help.
       As mentioned above, the AUTHOR also offers alternative license to
       integrate SQL Fingerprint NG into proprietary applications and
       appliances. These licenses generally include a perpetual license as
       well as providing for priority support and updates as well as helping
       to fund the continued development of SQL Fingerprint NG technology.
       Please email the AUTHOR for further information.

       If you received these files with a written license agreement or
       contract stating terms other than the terms above, then that
       alternative license agreement takes precedence over these comments.

       Source is provided to this software because the AUTHOR believes users
       have a right to know exactly what a program is going to do before they
       run it. This also allows you to audit the software for security holes,
       but none have been found so far.

       Source code also allows you to port SQL Fingerprint NG to new
       platforms, fix bugs, and add new features and new protocol modules. You
       are highly encouraged to send your changes to the AUTHOR for possible
       incorporation into the main distribution. By sending these changes to
       AUTHOR, it is assumed that you are offering the SQL Fingerprint NG
       Project, and its AUTHOR, the unlimited, non-exclusive right to reuse,
       modify, and relicense the code. SQL Fingerprint NG will always be
       available Open Source, but this is important because the inability to
       relicense code has caused devastating problems for other Free Software
       projects (such as KDE and NASM). The AUTHOR also occasionally relicense
       the code to third parties as discussed above. If you wish to specify
       special license conditions of your contributions, just say so when you
       send them.

DISCLAIMER OF WARRANTY
       This program is distributed in the hope that it will be useful, but
       WITHOUT ANY WARRANTY; without even the implied warranty of
       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE (see the GNU
       General Public License <http://www.gnu.org/licenses/> for more
       details).



perl v5.18.2                      2014-02-02                            ESF(1)
```
