/*
 * Internet Security Scannner v1.3
 *
 * Purpose: Check the Security of your Domain
 *
 *
 * program_name -options #1 #2
 * #1 is the inetnet network to start searching on
 * #2 is the inetnet network to end searching on
 *
 *
 * This software is Copyright (c) 1992, 1993, 1994, 1995 by Christopher Klaus
 *
 * Permission is hereby granted to copy, distribute or otherwise
 * use any part of this package as long as you do not try to make
 * money from it or pretend that you wrote it.  This copyright
 * notice must be maintained in any copy made.
 *
 * Use of this software constitutes acceptance for use in an AS IS
 * condition. There are NO warranties with regard to this software.
 * In no event shall the author be liable for any damages whatsoever
 * arising out of or in connection with the use or performance of this
 * software.  Any use of this software is at the user's own risk.
 *
 *  If you make modifications to this software that you feel
 *  increases it usefulness for the rest of the community, please
 *  email the changes, enhancements, bug fixes as well as any and
 *  all ideas to me. This software is going to be maintained and
 *  enhanced as deemed necessary by the community.
 *
 *              Christopher Klaus (cklaus@iss.net)
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <arpa/nameser.h>
#include "telnet.h"
#include <sys/stat.h>
#ifndef pyr
#include <string.h>
#endif
#ifdef pyr
#include <strings.h>
#endif



#define TELOPTS
#define TELCMDS
#define BUFSIZE 16
#include <resolv.h>

/* Set to Appropriate Paths For Various Unixes */
#define SHOWMOUNT "/usr/etc/showmount"
#define RUSERS "/usr/ucb/rusers"
#define RPCINFO "/usr/etc/rpcinfo"
#define YPWHICH "/usr/bin/ypwhich"

struct sockaddr_in a;
/* struct of socket */
int x, i, thirty = 30, sd;
int r;
/*  range values to scan */
struct in_addr first, second, myaddr;

int sec = 0, port = 0;
/* Check to see when function is done */
int done;
/* Conditions to check scan for in each host */
int mail = 0, acctcheck = 0, ypx = 0, rpcinfo = 0, scanports = 0;
int quick = 0, export = 0, ftp = 0, login = 0;

int mnt = 0, width = 0;
char hname[200], testname[200], smtpname[200], addr[100], *progname, c;
char tryname[200], res[10][200], buf[200], temp1[200], temp2[200];

FILE *fp = NULL;
donothing()			/* Signal sets done variable to tell program
				 * to quit */
{
    done = 1;
#ifdef sun
    siginterrupt(SIGALRM, 1);
#endif
    signal(SIGALRM, donothing);
}
getname(addr)
    struct sockaddr_in *addr;
{
    struct hostent *hoste;
    hoste = gethostbyaddr((char *) &addr->sin_addr, sizeof(struct in_addr),
			  addr->sin_family);
    if (hoste)
    {
	sprintf(hname, "%s", hoste->h_name);
	return (1);
    } else
    {
	sprintf(hname, "NoName");	/* May be interesting */
	return (0);
    }
}
ctos()				/* Connect to Socket */
{
    int soc;
    soc = socket(AF_INET, SOCK_STREAM, 0);
    if (soc < 0)
    {
	sleep(5);
	(void) setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &thirty, sizeof(thirty));
	soc = socket(AF_INET, SOCK_STREAM, 0);
	printf("Retrying Socket.\n");
	if (soc < 0)
	{
	    printf("Socket is locked\n");
	}
    }
    a.sin_port = htons((port == 0) ? 23 : port);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(x);
    r = connect(soc, &a, sizeof(a));
    return (soc);
}
/* Give usage message */
void
usage()
{
    printf("\n\nISS v1.3  (Internet Security Scanner)\n");
    printf("Usage: %s -msrdyvpqefo #1 #2 \n", progname);
    printf(" -m Ignores checking for mail port.\n");
    printf(" -s xx number of seconds max to wait\n");
    printf(" -r Ignores Checking for RPC calls\n");
    printf(" -d Ignores Checking Default Logins such as sync\n");
    printf(" -y Try to get pw via Ypx\n");
    printf(" -v Ignores finding Mail Aliases for decode, guest, bbs, lp\n");
    printf(" -p Scans one Host for all open TCP ports (disables all");
    printf(" other options)\n");
    printf(" -q Turns off Quick Scan so it finds hosts even with no name.\n");
    printf(" -e Only logs directories that can be mounted by everyone\n");
    printf(" -f Ignores Checking FTP port for logging in as anonymous\n");
    printf(" -o <file> send output to non ISS.log file, \"-\" is stdout\n");
    printf("#1 is the inetnet network to start searching on\n");
    printf("#2 is the inetnet network to end searching on\n");
    printf("(ie. 128.128.128.1 128.128.128.25 will scan all hosts from \n");
    printf(" 128.128.128.1 to 128.128.128.25).\n");

    printf("\nWritten By Christopher Klaus (cklaus@iss.net)\n");
    printf(" Send me suggestions, bugs, fixes, and ideas.	Send flames > /dev/null\n");
    exit(1);
}
clrlog()			/* clear log buffer */
{
    for (i = 0; i < 190; i++)
    {
	temp1[i] = ' ';
	temp2[i] = ' ';
    }
    temp1[0] = '\0';
}
fmt(buff1, buff2)		/* Format string for log */
    char buff1[200], buff2[200];
{

    int y, r;
    y = 0;

    r = 0;
    while ((buff1[y] != NULL) && (r < width))
    {
	if (iscntrl(buff1[y]))
	    buff1[y] = ' ';

	if (y != 0)
	    if ((buff1[y] == buff2[r - 1]) && (ispunct(buff1[y]) || isspace(buff1[y])))
		y++;
	    else
	    {
		buff2[r] = buff1[y];
		y++;
		r++;
	    }
	else
	{
	    buff2[r] = buff1[y];
	    y++;
	    r++;
	}
    }
    buff2[r] = NULL;

}


do_log(s)			/* Records the telnet session and tries
				 * defaults */
    int s;
{
    unsigned char c, buf[5];
    int a, count, cnt;
    alarm(0);
    alarm(9);
    width = 78;
    clrlog();
    cnt = 0;
    count = 0;
    (void) write(s, '\n', 1);
    while (!done && (count != 250))
    {
	a = read(s, &c, 1);
	if (a < 0)
	    return;
	if (a == 0)
	    continue;
	if (c == IAC)
	{
	    read(s, buf, 2);
	    respond(s, buf[0], buf[1]);
	} else
	{
	    if (c == 0)
		continue;
	    if (c == '\n')
	    {
		temp1[cnt] = c;
		cnt++;
		count++;
		continue;
	    }
	    if (isprint(c) || isspace(c))
	    {
		temp1[cnt] = c;
		count++;
		cnt++;
	    }
	}
    }
    fmt(temp1, temp2);
    fflush(fp);
    if (login != 1)
    {
	(void) writeln(s, "sync");
	alarm(0);
	alarm(3);
	cnt = 0;
	for (count = 0; count < 3; count++)
	{
	    c = 0;
	    while ((c != '\n') && !done)
	    {
		c = 0;
		if (!(read(sd, &c, 1)) && (c != 0))
		{
		    fprintf(fp, "%c", c);
		    fflush(fp);
		}
	    }
	}

	fflush(fp);
    }
}




/* Our Policy is always say *NO* to telnet negotations */
respond(s, com, opt)
    int s;
    unsigned int com, opt;
{
    unsigned char buf[10];
    buf[0] = IAC;
    buf[2] = opt;
    switch (com)
    {
	/* will and wont get do and dont as reply */
    case WILL:
    case WONT:
	buf[1] = DONT;
	(void) write(s, buf, 3);
	break;
	/* do and dont get will and wont as reply  */
    case DO:
    case DONT:
	buf[1] = WONT;
	(void) write(s, buf, 3);
	break;
    default:
	fprintf(stderr, "(%d)(%d)", com, opt);
    }
}
 /* Takes a Name and uses parts of it to guess domainname */
domainguess()
{
    int l, l1, i;
    l = 0;
    l1 = 0;
    for (i = 0; i <= (strlen(hname)); i++)
    {

	res[l][l1] = hname[i];
	l1++;
	if (hname[i] == '.')
	{
	    res[l][l1 - 1] = NULL;
	    l1 = 0;
	    l++;
	}
    }
    sprintf(tryname, "NoName");
    testdomain();
    sprintf(tryname, "noname");
    testdomain();
    sprintf(tryname, "Noname");
    testdomain();
    for (i = 0; i <= l; i++)
    {
	sprintf(tryname, "%s", res[i]);
	testdomain();
    }
    for (i = 0; i < l; i++)
    {
	sprintf(tryname, "%s.%s", res[i], res[i + 1]);
	testdomain();
    }
    if (l >= 2)
    {
	sprintf(tryname, "%s.%s.%s", res[l - 2], res[l - 1], res[l]);
	testdomain();
    }
    if (l >= 3)
    {
	sprintf(tryname, "%s.%s.%s.%s", res[l - 3], res[l - 2], res[l - 1], res[l]);
	testdomain();
    }
    if (l >= 4)
    {
	sprintf(tryname, "%s.%s.%s.%s.%s", res[l - 4], res[l - 3], res[l - 2], res[l - 1], res[l]);
	testdomain();
    }
}
testdomain()			/* Check each guess to see if it matched
				 * domainname */
{
    FILE *nis;			/* pointer to nis domainname log file */


    (void) sprintf(buf, "%s -d %s %s > %s.dom 2>/dev/null", YPWHICH, tryname, hname, addr);
    (void) system(buf);
    (void) sprintf(buf, "%s.dom", addr);
    if ((nis = fopen(buf, "r")) == NULL)
    {
	printf("\nError Opening File\n");
	return (1);
    }
    while (!feof(nis))
    {
	buf[0] = NULL;
	fgets(buf, sizeof(buf), nis);
	if ((strstr(buf, "Domain") == NULL) && (buf[0] != NULL))
	{
	    fprintf(fp, "\nDomainname: %s NIS Server: %s", tryname, buf);
	}
    }
    (void) fclose(nis);
    (void) sprintf(buf, "rm %s.dom", addr);
    (void) system(buf);

}
getsmtpname()
{
    int l, lp1, i;
    l = 0;
    lp1 = 0;
    for (i = 0; i <= (strlen(temp1)); i++)
    {
	if ((temp1[i] == ' '))
	    l++;

	if (l == 1)
	{
	    if (lp1 != 0)
	    {
		smtpname[lp1 - 1] = temp1[i];
	    }
	    lp1++;
	}
    }
}



checksmtp()			/* Check Sendmail Port */
{
    int count = 0;
    int t = 0;
    alarm((sec == 0) ? 8 : sec);
    port = 25;
    done = 0;
    c = 0;
    sd = ctos();
    if (r != -1)
    {
	/* Read & Write Here */
	(void) setsockopt(sd, SOL_SOCKET, SO_LINGER, &thirty, sizeof(thirty));
	fcntl(sd, F_SETFL, O_NDELAY);
	while ((c != '\n') && !done)
	{
	    read(sd, &c, 1);
	    if ((c != 0) && (t < 200))
	    {
		temp1[t] = c;
		t++;
	    }
	}
	width = 75;
	fmt(temp1, temp2);
	fprintf(fp, "\nSMTP:%s\n", temp2);
	getsmtpname();
	clrlog();
	if (!acctcheck)
	{
	    (void) writeln(sd, "VRFY guest");
	    (void) writeln(sd, "VRFY decode");
	    (void) writeln(sd, "VRFY bbs");
	    (void) writeln(sd, "VRFY lp");
	    (void) writeln(sd, "VRFY uudecode");
	    (void) writeln(sd, "wiz");
	    (void) writeln(sd, "debug");
	    (void) writeln(sd, "QUIT");
	    alarm(0);
	    alarm(10);
	    for (count = 0; count < 9; count++)
	    {
		c = 0;
		while ((c != '\n') && !done)
		{
		    read(sd, &c, 1);
		    if (c != 0)
		    {
			fprintf(fp, "%c", c);
			fflush(fp);
		    }
		}
	    }
	}
    } else
    {
	fprintf(fp, "\n NoSMTP");
    }

    alarm(0);
    (void) close(sd);
    done = 0;
}
checkftp()			/* Check FTP Port for anonymous */
{
    int count = 0;
    int t = 0;
    alarm((sec == 0) ? 5 : sec);
    port = 21;
    sd = ctos();
    if (r != -1)
    {
	(void) setsockopt(sd, SOL_SOCKET, SO_LINGER, &thirty, sizeof(thirty));
	done = 0;
	c = 0;
	t = 0;
	fcntl(sd, F_SETFL, O_NDELAY);
	fflush(fp);
	clrlog();
	while ((c != '\n') && !done && (t < 200))
	{
	    read(sd, &c, 1);
	    if (c != 0)
	    {
		temp1[t] = c;
		t++;
	    }
	}
	width = 75;
	fmt(temp1, temp2);
	fprintf(fp, "\nFTP:%s\n", temp2);
	clrlog();
	(void) writeln(sd, "user anonymous");
	(void) writeln(sd, "pass -iss@iss.iss.iss");	/* turns off messages
							 * with dash */
	(void) writeln(sd, "pwd");	/* PWD shows current directory */
	(void) writeln(sd, "mkd test");	/* Tries to make a directory */
	(void) writeln(sd, "rmd test");	/* Tries to remove the directory */
	(void) writeln(sd, "QUIT");
	alarm(0);
	alarm(10);
	for (count = 0; count < 30; count++)
	{
	    c = 0;
	    while ((c != '\n') && !done)
	    {
		read(sd, &c, 1);
		if (c != 0)
		{
		    fprintf(fp, "%c", c);
		}
	    }
	}
    } else
    {
	fprintf(fp, "\n NoFTP");
    }

    alarm(0);
    (void) close(sd);
}
checkrpc()
{
    FILE *rpc;			/* pointer to rpcinfo log file */

    int rusr, yp, rex, name, boot, x25, sels;
    /* Flags for rusers,ypserv,rexd,x25,select_svr,bootparam and named server */

    yp = 0;
    mnt = 0;
    rex = 0;
    boot = 0;
    sels = 0;
    x25 = 0;
    rusr = 0;
    name = 0;

    (void) sprintf(buf, "%s.log", addr);
    if ((rpc = fopen(buf, "r")) == NULL)
    {
	(void) printf("\nError Opening File\n");
	return (1);
    }
    while (!feof(rpc))
    {
	fgets(buf, sizeof(buf), rpc);
	if (strstr(buf, "ypserv") != NULL)
	{
	    if (!yp)
		fprintf(fp, " YPSERV");
	    yp = 1;
	}
	if (strstr(buf, "mount") != NULL)
	{
	    if (!mnt)
		fprintf(fp, " MOUNT");
	    mnt = 1;
	}
	if (strstr(buf, "name") != NULL)
	{
	    if (!name)
		fprintf(fp, " NAME");
	    name = 1;
	}
	if (strstr(buf, "x25") != NULL)
	{
	    if (!x25)
		fprintf(fp, " X25");
	    x25 = 1;
	}
	if (strstr(buf, "boot") != NULL)
	{
	    if (!boot)
		fprintf(fp, " BOOT");
	    boot = 1;
	}
	if (strstr(buf, "selec") != NULL)
	{
	    if (!sels)
		fprintf(fp, " SELECT");
	    sels = 1;
	}
	if (strstr(buf, "rexd") != NULL)
	{
	    if (!rex)
		fprintf(fp, " REXD");
	    rex = 1;
	}
	if (strstr(buf, "rusers") != NULL)
	{
	    if (!rusr)
		fprintf(fp, " RUSERS");
	    rusr = 1;
	}
    }
    (void) fclose(rpc);
/* Try to guess domain name if ypserv was found */
    if (yp)
    {
	(void) strcpy(testname, hname);
	domainguess();
	if (smtpname[0] != NULL)
	{
	    (void) strcpy(testname, smtpname);
	    domainguess();
	    smtpname[0] = NULL;
	}
    }
/*  Check Mount List for directories */
    if (mnt == 1)
    {
	sprintf(buf, "%s -e %s > %s.log 2>/dev/null", SHOWMOUNT, addr, addr);
	system(buf);
	sprintf(buf, "%s.log", addr);
	if ((rpc = fopen(buf, "r")) == NULL)
	{
	    (void) printf("\nError Opening File\n");
	    return (1);
	}
	fprintf(fp, "\n");
	while (!feof(rpc))
	{
	    fgets(buf, sizeof(buf), rpc);
	    if (!export == 1)
	    {
		fprintf(fp, "%s", buf);
		sprintf(buf, " ");
	    } else
	    {
		if (strstr(buf, "every") != NULL)
		{
		    fprintf(fp, "ALL:%s", buf);
		    (void) sprintf(buf, " ");
		}
	    }
	}
	(void) fclose(rpc);
    }
/* Tries to get password file via ypserv, need ypx in local directory */
/* Plan to add my own code that grabs the password file */
    if ((yp == 1) && (ypx == 1))
    {
	sprintf(buf, "./ypx -dgs -o %s.yp %s", addr, hname);
	system(buf);
    }
    if (rusr == 1)
    {
	sprintf(buf, "%s -l %s > %s.log 2> /dev/null", RUSERS, hname, addr);
	system(buf);
	sprintf(buf, "%s.log", addr);
	if ((rpc = fopen(buf, "r")) == NULL)
	{
	    (void) printf("\nError Opening File\n");
	    return (1);
	}
	fprintf(fp, "\n");
	sprintf(buf, "NoOne Online");
	while (!feof(rpc))
	{
	    fgets(buf, sizeof(buf), rpc);
	    {
		fprintf(fp, "%s", buf);
	    }
	}
	(void) fclose(rpc);

    }
    (void) sprintf(buf, "rm %s.log", addr);
    (void) system(buf);
}
checkall()
{
    alarm((sec == 0) ? 6 : sec);
    /* Set Alarm to def 6 seconds */
    port = 23;
    sd = ctos();
    if (r != -1)
    {
	do_log(sd);
    }
    /* Try to Connect */
    alarm(0);
    (void) close(sd);
    if (r != -1)
    {
	if (!rpcinfo)
	{
	    (void) sprintf(buf, "%s -p %s > %s.log 2> /dev/null", RPCINFO, addr, addr);
	    (void) system(buf);
	}
	(void) getname(&a);
	fprintf(fp, "%s %s", addr, hname);
	fprintf(fp, "\n>%s", temp2);
	clrlog();
	if (!mail)
	{
	    checksmtp();	/* Try to Read The SendMail Port */
	}
	if (ftp != 1)
	{
	    checkftp();
	}
	if (!rpcinfo)
	{
	    (void) checkrpc();
	}
	fprintf(fp, "\n\n");
	fflush(fp);
    }
#ifdef notdef
    else
    {
	if (quick == 1)
	{
	    fprintf(fp, "Host %s would not connect.\n", hname);
	}
    }
#endif
}
open_logfile(file)
    char *file;
{
    if (!fp)
    {
	if (fp = fopen(file, "r"))
	{
	    (void) fclose(fp);
	    fp = fopen(file, "a");
	} else
	    fp = fopen(file, "a");
	fprintf(fp, "       -->    Inet Sec Scanner Log By Christopher Klaus (C) 1995    <--\n");
	fprintf(fp, "              Email: cklaus@iss.net Web: http://iss.net/iss\n");
	fprintf(fp, "       ================================================================\n");

    }
}
writeln(pd, string)
    int pd;
    char *string;
{
    (void) write(pd, string, strlen(string));
    (void) write(pd, "\n", 1);
}
/* Thanks to H.Morrow Long,Manager of Development,Yale U CS Computing Facility
   INET: Long-Morrow@CS.Yale.EDU
   for the following routines taken from probe_tcp_ports.c,v 1.3 93/10/01 */

Probe_TCP_Ports(Name)
    char *Name;
{
    unsigned Port;
    char *Host;
    struct hostent *HostEntryPointer;
    struct sockaddr_in SocketInetAddr;
    struct hostent TargetHost;
    struct in_addr TargetHostAddr;
    char *AddressList[1];
    char NameBuffer[128];

    extern int inet_addr();
    extern char *rindex();
    if (Name == NULL)
	return (1);
    Host = Name;
    if (Host == NULL)
	return (1);
    HostEntryPointer = gethostbyname(Host);
    if (HostEntryPointer == NULL)
    {
	TargetHostAddr.s_addr = inet_addr(Host);
	if (TargetHostAddr.s_addr == -1)
	{
	    (void) fprintf(fp, "unknown host: %s\n", Host);
	    return (1);
	}
	(void) strcpy(NameBuffer, Host);
	TargetHost.h_name = NameBuffer;
	TargetHost.h_addr_list = AddressList, TargetHost.h_addr =
	    (char *) &TargetHostAddr;
	TargetHost.h_length = sizeof(struct in_addr);
	TargetHost.h_addrtype = AF_INET;
	TargetHost.h_aliases = 0;
	HostEntryPointer = &TargetHost;
    }
    SocketInetAddr.sin_family = HostEntryPointer->h_addrtype;
    bcopy(HostEntryPointer->h_addr, (char *) &SocketInetAddr.sin_addr,
	  HostEntryPointer->h_length);


    for (Port = 1; Port < 65536; Port++)
	(void) Probe_TCP_Port(Port, HostEntryPointer, SocketInetAddr);
    return (0);
}
Probe_TCP_Port(Port, HostEntryPointer, SocketInetAddr)
    unsigned Port;
    struct hostent *HostEntryPointer;
    struct sockaddr_in SocketInetAddr;
{
    int SocketDescriptor;
    struct servent *ServiceEntryPointer;


    SocketInetAddr.sin_port = htons(Port);
    SocketDescriptor = socket(AF_INET, SOCK_STREAM, 6);
    if (SocketDescriptor < 0)
    {
	perror("socket");
	return (1);
    }
    if (!(connect(SocketDescriptor, (char *) &SocketInetAddr,
		  sizeof(SocketInetAddr)) < 0))
    {
	(void) fprintf(fp, "Host %s, Port %d ",
		       HostEntryPointer->h_name, Port);
	if ((ServiceEntryPointer = getservbyport(Port, "tcp")) !=
	    (struct servent *) NULL)
	    (void) fprintf(fp, " (\"%s\" service) ",
			   ServiceEntryPointer->s_name);
	(void) fprintf(fp, "opened.\n");
	(void) fflush(fp);
    }
    (void) close(SocketDescriptor);
    return (0);
}
main(argc, argv)
    int argc;
    char **argv;
{
    char line[512];
    char *logfile = "ISS.log", *arg;
    sethostent(1);
    progname = argv[0];
    first.s_addr = 0;
    second.s_addr = 0;

    if (argc == 1)
	usage();

    while ((arg = *++argv))
    {
	if (*arg == '-')
	    for (arg++; *arg; arg++)
		switch (*arg)
		{
		case 'h':
		    usage();
		    exit(0);
		    break;
		case 'd':
		    login++;
		    break;
		case 'v':
		    acctcheck++;
		    break;
		case 'y':
		    ypx++;
		    break;
		case 'f':
		    ftp++;
		    break;
		case 'm':
		    mail++;
		    break;
		case 'o':
		    if (argv[1] && *argv[1])
			if (!strcmp(argv[1], "-"))
			    fp = stdout;
			else
			    logfile = *++argv;
		    break;
		case 'r':
		    rpcinfo++;
		    break;
		case 'q':
		    quick++;
		    break;
		case 'e':
		    export++;
		    break;
		case 'p':
		    scanports++;
		    open_logfile(logfile);
		    logfile = *++argv;
		    break;
		case 's':
		    sec = atoi(arg + 1);
		    if (sec == 0)
		    {
			if (!*++argv)
			{
			    (void) printf("Parse error! missing parameter\n");
			    exit(1);
			}
			sec = atoi(*argv);
		    }
		    break;
		}
	else
	{
	    if (!first.s_addr)
		first.s_addr = inet_addr(*argv);
	    else if (!second.s_addr)
		second.s_addr = inet_addr(*argv);
	}
    }
    if (scanports)
    {
	Probe_TCP_Ports(logfile);
	(void) fclose(fp);
	return (0);
    }
    if (!first.s_addr)
    {
	(void) printf("Enter address to probe : ");
	(void) gets(line);
	first.s_addr = inet_addr(line);
    }
    if (!second.s_addr)
    {
	second.s_addr = first.s_addr;
    }
    if (first.s_addr == -1 || second.s_addr == -1)
    {
	(void) printf("Out of range.\n");
	exit(1);
    }
    open_logfile(logfile);
#ifdef sun
    siginterrupt(SIGALRM, 1);
#endif
    signal(SIGALRM, donothing);
    fprintf(fp, "\nScanning from %s", inet_ntoa(first));
    fprintf(fp, " to %s\n", inet_ntoa(second));
    fflush(fp);

    for (x = ntohl(first.s_addr); x <= ntohl(second.s_addr); x++)
    {
	if ((x & 0xff) == 255)
	    x++;
	if ((x & 0xff) == 0)
	    x++;
	myaddr.s_addr = htonl(x);
	(void) strcpy(addr, inet_ntoa(myaddr));
	if (quick == 1)
	{
	    a.sin_port = htons((port == 0) ? 23 : port);
	    a.sin_family = AF_INET;
	    a.sin_addr.s_addr = myaddr.s_addr;
	    if (getname(&a) == 1)	/* Look For Names */
		checkall();	/* Try for addresses with names */
	} else
	    checkall();		/* Try for each address */
    }
    endhostent();
    (void) fclose(fp);
    return (0);
}
