        Internet Security Scanner, v1.3

	Copyright (c) Christopher Klaus, 1992, 1993, 1994, 1995.

This version is a freely working available demo version with many features
lacking from the commercial version.  The commercial version checks for
All known vulnerabilities including Firewall checking and Denial of
Service Attacks (being able to crash machines and networks remotely).
For more information about updates, please check the following:

	http://iss.net/iss
	ftp ftp.iss.net:/pub/iss
	mail info@iss.net  "send index" in body of message.

For more information on how to protect your network, how to securely set up
FTP, what patches to install, possible compromise and who to contact at various
vendors, Internet Security Systems, Inc provides resources such as 
Security FAQes (Frequently Asked Questions). These are available on
comp.answers, comp.security.unix, comp.security.misc, alt.security, 
comp.unix.admin, and alt.answers.

  Internet Security Scanner (ISS) is the first multi-level security
scanners available to the public.  It was designed to be flexible and easily
portable to many unix platforms and do its job in a reasonable amount of
time.  It provides information to the administrator that will fix obvious
security misconfigurations. 

  ISS does a multi-level scan of security, not just searching for one
weakness in the system.  To provide this to the public or at least to the
security conscious crowd may cause people to think that it is too dangerous
for the public, but many of the (cr/h)ackers are already aware of these
security holes and know how to exploit them. 

  These security holes are not deep in some OS routines, but standard
misconfigurations that many domains on Internet tend to show.  Many of these
holes are warned about in CERT and CIAC advisories.  This is the first
release of ISS and there is still much room for improvement. 

  ISS is a project that I started as I became interested in security.  As I
heard about (cr/h)ackers breaking into NASA and universities around the
world, I wanted to find out the deep secrets of security and how these people
were able to gain access to expensive machines that I would think were
secure.  I searched Internet for relative information, such as Phrack and
CERT advisories. 

  Most information was vague and did not explain how intruders were able to
gain access to most systems.  At most the information told administrators to
make password security tighter and to apply the vendor's security patches. 
They lacked real information on how an intruder would look at a site to try
to gain access.  Having talked with security experts and reading CERT
advisories, I started trying to look for various security holes within my
domain.

  To my surprise, I noticed that many of machines were adequately secured,
but within a domain there remained enough machines with obvious holes that
anyone wanted into any machine could attack the weak 'trusted' machine and
from there could gain access to the rest of the domain. From this project, I
have not learned any new deep secret to cracking systems, but with the right
tools that most domains on Internet are insecure.  These holes will not be a
surprise to any advanced intruder, but with this tool administrators will be
able to quickly search for obvious holes and prepare to fix them.

  ISS will scan a domain sequentially looking for connections.  When it finds
a host it will try to connect to various ports.  For starters, it tries the
telnet port. When it connects to the telnet port, it logs any information
that the host displays.  

	With the -d option, ISS ignores trying default accounts.  By default,
ISS will then try to log in as 'sync' which is a common account name for
SunOS and other Unixes.  It in itself is not a big hole other than giving
more information about type of OS, version number of OS, and  displaying the
MOTD.   But 'sync' with no password can become a security hole as someone
with a regular account on that host can divert the 'sync' privileges and
ultimately become root.  The 'sync' account should be passworded or disabled.

  With the -m option, ISS ignores the mail port. By default, ISS tries the
mail port. Connecting to this provides information regarding the hostname,
type of OS it is, and even the version number of sendmail. 

  With the -v option, ISS wont check for mail aliases. By default, it will
check for various users and aliases.  The obvious aliases to search for is
decode and uudecode.  With these aliases, you are able to send mail to
decode@hostname with a file that has been uuencoded to overwrite a systems
file, such as .rhosts.  Some of the users it looks for is 'bbs', 'guest',
'lp', and the well known debug and wiz backdoors within sendmail.  'bbs',
'guest', and 'lp' are known to have weak passwords or no passwords at all.

  With the -f option, ISS wont check the FTP port. By default, it will
connect to the ftp port and check to see if a person can log into anonymous.
 Many systems such as Macs let anyone log in and look around other users'
private information.  If it succeeds logging in as anonymous, it will then
attempt to create a directory.  If it does that successfully, the main
directory of the FTP site is writeable and open to attack.  Many anonymous
ftp sites have security holes.  Such weaknesses is being able to write to
the main directory of the ftp directory, thus an intruder could write a
.rhost file and log in as ftp.  Plus, the anonymous ftp site may contain the
actual host's password file and not just a dummy password file. 

  With the -r option, ISS ignores checking for rpc. By default, ISS will
look for holes that most systems are more prone to have open.  It uses rpc
information to find security weaknesses.  It will do a 'rpcinfo -p
hostname'. With this information gained, it finds which hosts are running
NIS, rexd, bootparam, whose on the host, selection_svc, and NFS. 

  If a system shows YPServ, it is likely that it has not been patched yet and
with the proper domainname, ypserv will provide the password file to any
remote host asking for it.  To fix this, apply the proper ypserv patch from
your vendor.  ISS will attempt to guess the domainname and that will provide
information as to which machine is the NIS server is.   The domainname should
be changed if it can easily be guessed so that it will slow people from
grabbing the password file.  Another attempt to fix this problem is
to make sure that if the password file does get out, none of the
passwords can easily be cracked.  Crack (by Alec Muffett alecm@sun.com) does
a fine job of finding weak passwords. Also shadowing the password file will
help correct this weakness.

  With the -y option and a program called Ypx (by Rob Nautu
rob@wzv.win.tue.nl), ISS will try to grab the password file from ypserv.

  If a system shows Select_svr, selection_svr is running on the machine and
there are known holes that let anyone remotely read any file on the system,
even the password file.  Selection_svr should be disabled.

  When Rexd is running on a remote system, anyone with a small C program can
emulate the 'on' command spoofing any user on the remote machine, thus
gaining access to the password file and adding .rhosts files. Rexd should be
disabled.

  If a machine is running Bootparam, it is likely a server to diskless
clients.  One problem with bootparam is that if it is running and someone
can guess which machines the client and servers are, they are able to get
the domainname from bootparam, which goes back to the YPServ problem.   

  The -e option will only log exports that everyone can mount.  To
usually find out which machines are its clients, by default, log all the
exportable directories.  'showmount -e hostname' shows the exports on a
remote host.  If the exported directories look like:

	/usr 		   (everyone)
	/export/placebo    placebo
	/export/spiff      spiff

  Anyone can mount /usr and possible replace files and do other damage.
Placebo and spiff appear to be clients to this server.

  ISS also does a 'rusers -l hostname' searching for users on the system.
That provides how busy is the machine and possible login entries to try.

  ISS with option -p will support scanning all the ports on a certain host,
thus looking for possible access entries, such as gophers, muds, and other
applications ran by local users.  It also can be used to show which ports
are blocked by a firewall.

  ISS will quickly scan the domain. It does not try to connect to every
address, but rather scans through doing a name lookup for each address.  And
if that address has a name, it will then do a more thorough lookup of
information on that host. With the -q option, it will try to connect to hosts
even without names.  

  Option -o will allow you to send output to another log file rather than
the regular ISS.log.  Output to "-" is to stdout, allowing for quicker
debugging and testing.

  To sum it up, ISS will scan a domain grabbing essential information for
administrators to easily sort through and give themselves a chance to secure
the open machines on their network.

  Some additional notes about this program.  You can find patches and
additional information from cert@cert.org and their anonymous FTP site 
cert.org (192.88.209.5).  They have an advisory about the security flaws
found with ISS that may be beneficial in closing the flaws.

----- Compilation Notes

If you find that ISS is taking a long time scanning a single machine,
#define sun
in iss.c because it may not be handling the alarm signals correctly.

Ports for ISS are found on ftp.iss.net pub/iss/ports


nfsbug.shar is a package from Leendert un Doorn.  It checks for many
		NFS vulnerabilities.

ypx.shar is a package from Rob Nauta.  It checks for YP NIS vulnerability.

strobe.tar is a package by Julian Assange.  This allows quick and fast checking
		of TCP ports.

------

Acknowledgements
  I would like to thank the following people for ideas, suggestions, and help:
Scott Miles, Dan Farmer, Wietse Venema, Alec Muffett, Scott Yelich, Darren
Reed, Tim Newsham, H. Morrow Long (for port scan routines), Jim Morton, and
Billy Barron.

 Please send suggestions to

 cklaus@iss.net

 Copyright C Klaus, 1993, 1994, 1995
