```
ESF(1)                User Contributed Perl Documentation               ESF(1)



NAME
       ESF.pl - SQL Fingerprint powered by ENG++ Technology

VERSION
       This document describes ESF.pl [Version 1].

USAGE
       "ESF.pl host [options]"

DESCRIPTION
       Microsoft SQL Server fingerprinting can be a time consuming process,
       because it involves trial and error methods to determine the exact
       version. Intentionally inserting an invalid input to obtain a typical
       error message or using certain alphabets that are unique for certain
       server are two of the many ways to possibly determine the version, but
       most of them require authentication, permissions and/or privileges on
       Microsoft SQL Server to succeed.

       Instead, ESF.pl uses a combination of crafted packets for SQL Server
       Resolution Protocol ("SSRP") and Tabular Data Stream Protocol ("TDS")
       (protocols natively used by Microsoft SQL Server) to accurately perform
       version fingerprinting and determine the exact Microsoft SQL Server
       version. ESF.pl also applies a sophisticated Scoring Algorithm
       Mechanism (powered by Exploit Next Generation++ Technology), which is a
       much more reliable technique to determine the Microsoft SQL Server
       version. It is a tool intended to be used by:

       o   Database Administrators

       o   Database Auditors

       o   Database Owners

       o   Penetration Testers

       Having over "FIVE HUNDRED" unique versions within its fingerprint
       database, ESF.pl currently supports fingerprinting for:

       o   Microsoft SQL Server 2000

       o   Microsoft SQL Server 2005

       o   Microsoft SQL Server 2008

       o   Microsoft SQL Server 2012

       ESF.pl re-invented the techniques used by several public tools (SQLPing
       Tool by Chip Andrews, Rajiv Delwadia and Michael Choi, and SQLVer Tool
       by Chip Andrews) (see "SEE ALSO" for further information). ESF.pl shows
       the "MAPPED VERSION" and "PATCH LEVEL" (i.e., Microsoft SQL Server 2008
       SP1 (CU5)) instead of showing only the "RAW VERSION" (i.e., Microsoft
       SQL Server 10.0.2746). ESF.pl also has the ability to show the MOST
       LIKELY version, based on its sophisticated Scoring Algorithm Mechanism,
       and allows to determine "vulnerable" and "unpatched" Microsoft SQL
       Server better than many of public and commercial tools.

       This version is a completely rewritten version in Perl, making ESF.pl
       much more portable than the previous binary version (Win32), and its
       original purpose is to be used as a tool to perform automated
       penetration test. This version also includes the following Microsoft
       SQL Server versions to its fingerprint database:

       o   Microsoft SQL Server 2012 SP1 (CU1)

       o   Microsoft SQL Server 2012 SP1

       o   Microsoft SQL Server 2012 SP1 CTP4

       o   Microsoft SQL Server 2012 SP1 CTP3

       o   Microsoft SQL Server 2012 SP0 (CU4)

       o   Microsoft SQL Server 2012 SP0 (MS12-070)

       o   Microsoft SQL Server 2012 SP0 (CU3)

       o   Microsoft SQL Server 2012 SP0 (CU2)

       o   Microsoft SQL Server 2012 SP0 (CU1)

       o   Microsoft SQL Server 2012 SP0 (MS12-070)

       o   Microsoft SQL Server 2012 SP0 (KB2685308)

       o   Microsoft SQL Server 2012 RTM

           NOTE: ESF.pl "IS NOT" a SQLi tool, and has no ability to perform
           such task.

   Fingerprinting Steps
       As described in "DESCRIPTION", ESF.pl uses a combination of crafted
       packets for "SSRP" and "TDS" to accurately perform version
       fingerprintfing. To achieve an accurate and much more reliable version
       fingerprinting, ESF.pl employes the following steps, mimicking a valid
       negotiation between the CLIENT and the SERVER:

       1) "SSRP" "Client Unicast Request" (CLNT_UCAST_EX)
           This step attempts to gather the Microsoft SQL Server single
           instance or even multiple instances (see "MULTIPLE SQL SERVER
           INSTANCES WARNING" for further information), and the respective
           "TDS" communication port(s) - the "TDS" communication port for each
           instances can be dynamic or default (see "DYNAMIC SQL SERVER TCP
           PORT WARNING" and "DEFAULT SQL SERVER TCP PORT WARNING" for further
           information).

               NOTE: If this step fails, the "STEP 2" is not performed and the
               "STEP 3" will use "TDS" default communication port only.

       2) "SSRP" "Client Unicast Instance Request" (CLNT_UCAST_INST)
           This step attempts to use the information gathered by step 1 to
           collect, parse and match information for a single instances or for
           multiple instances (see "MULTIPLE SQL SERVER INSTANCES WARNING" for
           further information). Once the collecting, parsing and matching is
           done, the fingerprinting data is stored to be validated by the
           sophisticated Scoring Algorithm Mechanism (powered by Exploit Next
           Generation++ Technology).

               NOTE: If the "STEP 1" fails, this step is not performed.

       3) "TDS" "Pre-Login Request" (PRELOGIN)
           This step attempts to use the information gathered by step 1 to
           collect, parse and match information for a single instances running
           on "TDS" default coommunication port (see "DEFAULT SQL SERVER TCP
           PORT WARNING" for further information) or for multiple instances
           (see "MULTIPLE SQL SERVER INSTANCES WARNING" for further
           information) running on "TDS" dynamic communication port(s) (see
           "DYNAMIC SQL SERVER TCP PORT WARNING" for further information. Once
           the collecting, parsing and matching is done, the fingerprinting
           data is stored to be validated by the sophisticated Scoring
           Algorithm Mechanism (powered by Exploit Next Generation++
           Technology).

               NOTE: If "STEP 1" fails, this step will use "TDS" default
               communication port only.

 SSRP
       As described in "[MS-SQLR]: SQL Server Resolution Protocol"
       specification document (see "SEE ALSO" for further information).

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

       According to the previous quotes, the "SSRP" is used for the purpose of
       determining the communication endpoint information of a particular
       database instance, which does not include any facilities for
       authentication, and both "SSRP" "CLNT_UCAST_EX Request" and "SSRP"
       "CLNT_UCAST_INST Request" can be used for the purpose of determining
       the communication endpoint information.

       Based on this analysis, it is possible to determine the Microsoft SQL
       Server version  using the "SSRP" "CLNT_UCAST_EX Request" and/or "SSRP"
       "CLNT_UCAST_INST Request". The version is available within the "SSRP"
       "CLNT_UCAST_EX Response" and/or "SSRP" "CLNT_UCAST_INST Response", and
       it is a gratuitous information sent from SERVER to CLIENT to ensure
       they will establish a communication correctly, using the correct
       database instance and the same dialect by both CLIENT and SERVER.

       Here is a "SSRP" "CLNT_UCAST_INST Request" and "SSRP" "CLNT_UCAST_INST
       Response" sample traffic dump between the ESF.pl and a Microsoft SQL
       Server 2008 SP1:

       "SSRP" "CLNT_UCAST_INST Request"
            0000   04 4d 53 53 51 4c 53 45 52 56 45 52              .MSSQLSERVER

       "SSRP" "CLNT_UCAST_INST Response"
            0000   05 77 00 53 65 72 76 65 72 4e 61 6d 65 3b 53 45  .w.ServerName;SE
            0010   52 56 45 52 30 34 3b 49 6e 73 74 61 6e 63 65 4e  RVER04;InstanceN
            0020   61 6d 65 3b 4d 53 53 51 4c 53 45 52 56 45 52 3b  ame;MSSQLSERVER;
            0030   49 73 43 6c 75 73 74 65 72 65 64 3b 4e 6f 3b 56  IsClustered;No;V
            0040   65 72 73 69 6f 6e 3b 31 30 2e 30 2e 32 35 33 31  ersion;10.0.2531
            0050   2e 30 3b 74 63 70 3b 31 34 33 33 3b 6e 70 3b 5c  .0;tcp;1433;np;\
            0060   5c 53 45 52 56 45 52 30 34 5c 70 69 70 65 5c 73  \SERVER04\pipe\s
            0070   71 6c 5c 71 75 65 72 79 3b 3b                    ql\query;;

       As demonstrated above, the information within the "SSRP" "CLNT_UCAST_EX
       Response" represents the version for Microsoft SQL Server 2008 SP1
       (10.0.2531), as well as many interesting information.

           NOTE: no authentication and gratuitous information.

   TDS
       As described in "[MS-TDS]: Tabular Data Stream Protocol" specification
       document (see "SEE ALSO" for further information).

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

       According to the previous quotes, the "TDS" "Pre-Login" is just a
       handshake, i.e., the "TDS" "Pre-Login" is a tokenless packet data
       stream of the pre-authentication state to establish the negotiation
       between the CLIENT and the SERVER - as described in "Figure 3:
       Pre-login to post-login sequence" (page 103).

       Based on this analysis, it is possible to determine the Microsoft SQL
       Server version  during the "TDS" "Pre-Login" handshake. It is an
       undocumented feature, but it is not a bug or a leakage, in fact, it is
       more likely to be an "AS IS" embedded feature that allows CLIENT to
       establish a negotiation with SERVER. The version is available within
       the "TDS" "Pre-Login Response" packet data stream, and it is a
       gratuitous information sent from SERVER to CLIENT to ensure they will
       establish a communication correctly, using the correct database
       instance and the same dialect by both CLIENT and SERVER.

       Here is a tokenless packet data stream sample traffic dump of a "TDS"
       "Pre-Login" handshake between the ESF.pl and a Microsoft SQL Server
       2008 SP1:

       "TDS" "Pre-Login Request"
            0000   12 01 00 2f 00 00 01 00 00 00 1a 00 06 01 00 20
            0010   00 01 02 00 21 00 01 03 00 22 00 04 04 00 26 00
            0020   01 ff 09 00 00 00 00 00 01 00 b8 0d 00 00 01

       "TDS" "Pre-Login Response"
            0000   04 01 00 2b 00 00 01 00 00 00 1a 00 06 01 00 20
            0010   00 01 02 00 21 00 01 03 00 22 00 00 04 00 22 00
            0020   01 ff 0a 00 09 e3 00 00 01 00 01

       As demonstrated above, there are four bytes following the "TERMINATOR"
       (0xFF at the OFFSET 34), and they represent the version for Microsoft
       SQL Server 2008 SP1 (10.0.2531):

       1) OFFSET 35 represents the Major Version (0x0a = 10)
       2) OFFSET 36 represents the Minor Version (0x00 = 0)
       3) OFFSETS 37/38 represent the Build Version ([0x09*256]+0xe3 = 2531)

           NOTE: no authentication and gratuitous information.

   MULTIPLE SQL SERVER INSTANCES WARNING
       Warns the availability of multiple instances ("Default Instances" as
       well as "Named Instances"). This information is collected and parsed by
       "STEP 1" and used and validated by "STEP 3" (see "Fingerprinting Steps"
       for further information).

           NOTE: Only in "verbose" mode (see "OPTIONS" for further
           information).

   DYNAMIC SQL SERVER TCP PORT WARNING
       Warns the availability of multiple instances ("Default Instances" as
       well as "Named Instances") running on "TDS" dynamic communication
       port(s). This information is collected and parsed by "STEP 1" and used
       and validated by "STEP 3" (see "Fingerprinting Steps" for further
       information).

           NOTE: Only in "verbose" mode (see "OPTIONS" for further
           information).

   DEFAULT SQL SERVER TCP PORT WARNING
       Warns the availability of "Default Instances" running on "TDS" default
       communication port(s) . This information is collected and parsed by
       "STEP 1" and used and validated by "STEP 3" (see "Fingerprinting Steps"
       for further information).

           NOTE: Only in "verbose" mode (see "OPTIONS" for further
           information).

   MOST LIKELY WARNING
       ADD DESCRIPTION HERE

OPTIONS
       "-d,--debug" (default OFF)
           Configure the debug mode, giving much more information details
           about the fingerprinting tasks.

       "-f,--fingerdb FILE" (default "ESF.db")
           Configure an optional file for SQL Fingerprint Database.

       "-t,--timeout NUM" (default 30)
           Configure a specific connection timeout (seconds), allowing ESF.pl
           to wait until close the connection.

       "-T,--TIMEOUT NUM" (default 5)
           Configure a specific timeout (seconds), allowing ESF.pl to wait
           until execute the next subroutine.

       "-v,--verbose" (default OFF)
           Configure the verbose mode, giving information details about the
           fingerprinting tasks.

       "-m,--manpage"
           Display the manual page embedded in ESF.pl, being the manual page
           in POD (Plain Old Documentation) format.

       "-h,-?,--help"
           Display the help and usage message.

DEPENDENCIES
       Digest::MD5(3)
           See "Getopt::Long's Perl Documentation" for further information.

       Getopt::Long(3)
           See "Getopt::Long's Perl Documentation" for further information.

       IO::Socket(3)
           See "IO::Socket's Perl Documentation" for further information.

       Pod::Usage(3)
           See "Pod::Usage's Perl Documentation" for further information.

       POSIX(1)
           See "POSIX's Perl Documentation" for further information.

       Switch(3)
           See "Switch's Perl Documentation" for further information.

       PERL(1) v5.10.1 or v5.12.4
           ESF.pl has been widely tested under Perl v5.10.1 (Ubuntu 10.04 LTS)
           and Perl v5.12.4 (OS X Mountain Lion). Due to this, ESF.pl requires
           one of the mentioned versions to be executed. The following tests
           will be performed to ensure its capabilities:

            BEGIN {
               my $subname = (caller (0))[3];
               eval ("require 5.012004;");
               eval ("require 5.010001;") if $@;
               die "$subname: Unsupported Perl version ($]).\n" if $@;
            }

               NOTE: If you are confident that your Perl version is capable to
               execute the ESF.pl, please, remove the above tests and send
               feedback to the author.

           See "PERL's Perl Documentation" for further information.

SEE ALSO
       Digest::MD5(3), IO::Socket(3), Getopt::Long(3), Pod::Usage(3),
       POSIX(1), Switch(3), PERL(1), [RFC793]
       <http://www.ietf.org/rfc/rfc793.txt>, [RFC768]
       <http://www.ietf.org/rfc/rfc768.txt>, TDS
       <http://msdn.microsoft.com/en-us/library/dd304523.aspx>, SSRP
       <http://msdn.microsoft.com/en-us/library/cc219703.aspx>, SQLPing &
       SQLVer Tools <http://www.sqlsecurity.com/downloads>

HISTORY
       2008
           Private Release (Late 2008)

       2009
           H2HC Talk (November 28)

       2010
           MSSQLFP BETA-3 (January 5)

           MSSQLFP BETA-4 (January 18)

           ESF 1.00.0006 (February 10)

           ESF 1.10.101008/CTP (October 8)

       2012
           ESF 1.12.120115/RC0 (January 15)

BUGS AND LIMITATIONS
       Report ESF.pl bugs and limitations directly to the author.

AUTHOR
       Nelson Brito <mailto:nbrito@prontonmail.com>.

COPYRIGHT
       Copyright(c) 2010-2012 Nelson Brito. All rights reserved worldwide.

       Exploit Next Generation++ Technology and/or other noted Exploit Next
       Generation++ and/or ENG++ related products contained herein are
       registered trademarks or trademarks of Nelson Brito. Any other non-
       Exploit Next Generation++ related products, registered and/or
       unregistered trademarks contained herein is only by reference and are
       the sole property of their respective owners.

       Exploit Next Generation++ Technology, innovating since 2010.

LICENSE
       This program is free software: you can redistribute it and/or modify it
       under the terms of the GNU General Public License as published by the
       Free Software Foundation, either version 3 of the License, or (at your
       option) any later version.

       You should have received a copy of the GNU General Public License along
       with this program. If not, see <http://www.gnu.org/licenses/>.

DISCLAIMER OF WARRANTY
       This program is distributed in the hope that it will be useful, but
       WITHOUT ANY WARRANTY; without even the implied warranty of
       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
       General Public License for more details.



perl v5.18.2                      2012-12-25                            ESF(1)
```
