/*
 *  -=[Nemesis Packet Injection Suite]=-
 *          icmp.c  by obecian 
 *
 */

#include "icmp.h"

int
main (int argc, char **argv)
{
    int i, j, m;
    int opt;
    char *file = NULL;
    char buff[512];
    FILE *pay = NULL;
    extern char *optarg;
    extern int opterr;

	int bindata = 0;

	got_link = 0;	
	got_options = 0;
	got_payload = 0;

    if (argc < 2)
        usage (argv[0]);

    if (geteuid () != 0)
    {
        printf ("user '%s' does not have an euid of 0\n", getlogin ());
        exit (1);
    }

    defaults ();

    opterr = 0;
    while ((opt = getopt (argc, argv, "S:D:H:M:d:I:T:O:t:s:i:c:m:C:G:P:bv")) != EOF)
    {
        switch (opt)
        {
		case 'v':
            verbose = 1;
            for (i = 0; i < 78; i++)
                putchar ('*');
            putchar ('\n');
            i = (78 - sizeof (VERSION " " CODERS)) >> 1;
            for (j = 0; j <= i; j++)
                putchar (' ');
            puts (VERSION " " CODERS);
            for (i = 0; i < 78; i++)
                putchar ('*');
            putchar ('\n');
			putchar ('\n');
			break;
        case 'S':
            if (!(source = libnet_name_resolve (optarg, 0)))
            {
                fprintf (stderr, "Invalid source IP address: %s\n", optarg);
                exit (1);
            }
			if (verbose)
				printf ("Source IP %s\n", optarg);
            break;
        case 'D':
            if (!(dest = libnet_name_resolve (optarg, 0)))
            {
                fprintf (stderr, "Invalid destination IP address: %s\n", optarg);
                exit (1);
            }
			if (verbose)
				printf ("Destination IP %s\n", optarg);
            break;
        case 'd':
            device = optarg;
			got_link = 1;
            break;
		case 'H':
			if (got_link)
				sscanf (optarg, "%x:%x:%x:%x:%x:%x", &enet_src[0], &enet_src[1], &enet_src[2], &enet_src[3], &enet_src[4], &enet_src[5]);
			break;
		case 'M':
			if (got_link)
				sscanf (optarg, "%x:%x:%x:%x:%x:%x", &enet_dst[0], &enet_dst[1], &enet_dst[2], &enet_dst[3], &enet_dst[4], &enet_dst[5]);
			break;
        case 'I':
            id = atoi (optarg);
            break;
        case 'T':
            ttl = atoi (optarg);
            break;
        case 't':
            tos = strtoul (optarg, NULL, 0);
            break;
        case 'C':
            switch (*optarg)
            {
            case 'o':
                otime = atoi (optarg);
                break;
            case 'r':
                rtime = atoi (optarg);
                break;
            case 't':
                ttime = atoi (optarg);
                break;
            }
            break;
        case 'G':
            if (!(gwy = libnet_name_resolve (optarg, 0)))
			{
				fprintf (stderr, "Invalid gateway IP address: %s\n", optarg);
				exit (1);
			}
			if (verbose)
				printf ("Preferred Gateway %s\n", optarg);
            break;
        case 's':
            seq = atoi (optarg);
            break;
        case 'i':
            type = atoi (optarg);
            break;
        case 'c':
            code = atoi (optarg);
            break;
        case 'm':
            mask = strtoul (optarg, NULL, 0);
            break;
		case 'b':
			bindata = 1;
			break;
        case 'P':
            file = optarg;
			got_payload = 1;
            if ((pay = fopen (file, "r")) == NULL)
            {
                printf ("Payload file \"%s\"\n", file);
                exit (1);
            }
            break;
		case 'O':
			got_options = 1;
			(u_char)*options = strtoul (optarg, NULL, 0);
			break;
        case '?':
            usage (argv[0]);
            break;
        }
    }
	
	if (verbose)
	{
		if (got_link)
        {
			printf ("Source MAC Address: ");
			printf ("%x:%x:%x:%x:%x:%x\n", enet_src[0], enet_src[1], enet_src[2], enet_src[3], enet_src[4], enet_src[5]);
			printf ("Destination MAC Address: ");
			printf ("%x:%x:%x:%x:%x:%x\n", enet_dst[0], enet_dst[1], enet_dst[2], enet_dst[3], enet_dst[4], enet_dst[5]);
        }   
	printf ("ICMP Packet:\n\n");
	}
	
	switch (type)
	{
		case 0:
			if (verbose)
				printf ("Type: ECHO REPLY\n");
			break;
		case 3:
			if (verbose)
				printf ("Type: DESTINATION UNREACHABLE\n");
			switch (code)
			{
				case 0:
					if (verbose)
						printf ("Code: NETWORK UNREACHABLE\n");
					break;
				case 1:
					if (verbose)
						printf ("Code: HOST UNREACHABLE\n");
					break;
				case 2:
					if (verbose)
						printf ("Code: PROTOCOL UNREACHABLE\n");
					break;
				case 3:
					if (verbose)
						printf ("Code: PORT UNREACHABLE\n");
					break;
				case 4:
					if (verbose)
						printf ("Code: FRAGMENTATION NEEDED\n");
					break;
				case 5:	
					if (verbose)
						printf ("Code: SOURCE ROUTE FAILED\n");
					break;
				case 6:
					if (verbose)
						printf ("Code: DESTINATION NETWORK UNKNOWN\n");
					break;
				case 7:
					if (verbose)
						printf ("Code: DESTINATION HOST UNKNOWN\n");
					break;
				case 8:
					if (verbose)
						printf ("Code: SOURCE HOST ISOLATED (obsolete)\n");
					break;	
				case 9:
					if (verbose)
						printf ("Code: DESTINATION NETWORK ADMINISTRATIVELY PROHIBITED\n");
					break;
				case 10:
					if (verbose)
						printf ("Code: DESTINATION HOST ADMINISTRATIVELY PROHIBITED\n");
					break;
				case 11:
					if (verbose)
						printf ("Code: NETWORK UNREACHABLE FOR TOS\n");
					break;
				case 12:
					if (verbose)
						printf ("Code: HOST UNREACHABLE FOR TOS\n");
					break;
				case 13: /* useful for firewall discovery */
					if (verbose)	
						printf ("Code: COMMUNICATION ADMINISTRATIVELY PROHIBITED BY FILTERING\n");
					break;
				case 14:
					if (verbose)
						printf ("Code: HOST PRECEDENCE VIOLATION\n");
					break;
				case 15:
					if (verbose)
						printf ("Code: PRECEDENCE CUTOFF IN EFFECT\n");
					break;
			}
			break;
		case 4:
			if (verbose)
				printf ("Type: SOURCE QUENCH\n");
			break;
		case 5:
			if (verbose)
				printf ("Type: REDIRECT\n");
			switch (code)
			{
				case 0:
					if (verbose)
						printf ("Code: REDIRECT FOR NETWORK\n");
					break;
				case 1:
					if (verbose)
						printf ("Code: REDIRECT FOR HOST\n");
					break;
				case 2:
					if (verbose)
						printf ("Code: REDIRECT FOR TOS AND NETWORK\n");
					break;
				case 3:
					if (verbose)
						printf ("Code: REDIRECT FOR TOS AND HOST\n");
					break;
			}
			break;
		case 8:
			if (verbose)
				printf ("Type: ECHO REQUEST\n");
			break;
		case 9:
			if (verbose)
				printf ("Type: ROUTER ADVERTISEMENT\n");
			break;
		case 10:
			if (verbose)
				printf ("Type: ROUTER SOLICITATION\n");
			break;
		case 11:
			if (verbose)
				printf ("Type: TIME EXCEEDED\n");
			switch (code)
			{
				case 0:
					if (verbose)
						printf ("Code: TTL = 0 DURING TRANSMIT\n");
					break;
				case 1:
					if (verbose)
						printf ("Code: TTL = 0 DURING REASSEMBLY\n");
					break;
			}
			break;
		case 12:
			if (verbose)
				printf ("Type: PARAMETER PROBLEM\n");
			switch (code)
			{
				case 0:
					if (verbose)
						printf ("Code: IP HEADER BAD (catchall error)\n");
					break;
				case 1:
					if (verbose)
						printf ("Code: REQUIRED OPTION MISSING\n");
					break;
			}
			break;
		case 13:
			if (verbose)
				printf ("Type: TIMESTAMP REQUEST\n");
			break;
		case 14:
			if (verbose)
				printf ("Type: TIMESTAMP REPLY\n");
			break;
		case 15:
			if (verbose)
				printf ("Type: INFORMATION REQUEST\n");
			break;
		case 16:
			if (verbose)
				printf ("Type: INFORMATION REPLY\n");
			break;
		case 17:
			if (verbose)
				printf ("Type: ADDRESS MASK REQUEST\n");
			break;
		case 18:
			if (verbose)
				printf ("Type: ADDRESS MASK REPLY\n");
			break;
	}

	if (verbose)
	{
    	printf ("Sequence number: %d\n", seq);
		if ((type == ICMP_MASKREQ) || (type == ICMP_MASKREPLY))
    		printf ("Mask: 0x%x\n", mask);
    
		printf ("IP ID: %d\n", id);
    	printf ("IP TTL: %d\n", ttl);
    	printf ("IP TOS: 0x%x\n\n", tos);
	}
    
	if (got_payload)
    {
        if (bindata)
        {
            while (!feof(pay))
            {
                fread(&buff, sizeof (buff), 1, pay);
                payload = malloc (sizeof (buff));
                strncpy (payload, buff, strlen (buff));
                if (verbose)
				{ 
					printf ("BINARY Payload:\n");
                	for (m=0; m<strlen(payload); m++)
                    	printf("%x ", payload[m]);
                	printf ("\n");
				}
                if (buildicmp () >= 0)
					if (verbose)
                    	printf ("\nWrote ICMP packet successfully\n");
                else
					if (verbose)
                    	printf ("\nUnable to write packet successfully\n");
            }
        }
        else
        {
            while (fgets(buff, sizeof (buff), pay))
            {
                payload = malloc (sizeof (buff));
                strncpy (payload, buff, strlen (buff));
				if (verbose)
				{
                	printf ("ASCII Payload:\n");
                	printf ("%s\n", payload);
				}
                if (buildicmp () >= 0)
					if (verbose)
                    	printf ("\nWrote ICMP packet successfully\n");
                else
					if (verbose)
                    	printf ("\nUnable to write packet successfully\n");
            }
        }
    }
    else
    {
        if (buildicmp () >= 0)
			if (verbose)
            	printf ("\nWrote ICMP packet successfully\n");
        else
			if (verbose)
            	printf ("\nUnable to write packet successfully\n");
    }
}

void
usage (char *arg)
{
    printf ("\nUsage:\n  %s [-v] [options]\n\n", arg);
	printf ("ICMP options: \n"
			"  -i <ICMP Type>\n"
			"  -c <ICMP Code>\n"
			"  -s <Sequence Number>\n"
			"  -m <ICMP Mask>\n"
			"  -G <Preferred Gateway>\n"
			"  -Co <Time of Originating request>\n"
			"  -Cr <Time request was Received>\n"
			"  -Ct <Time reply was Transmitted>\n"
            "  -P <Payload File (Binary or ASCII)>\n"
            "  -b (Enable Binary Payload)\n"
			"  (-v VERBOSE - packet struct to stdout)\n\n");
	printf ("IP options: \n"
            "  -S <Source IP Address>\n"
            "  -D <Destination IP Address>\n"
			"  -I <IP ID>\n"
			"  -T <IP TTL>\n"
			"  -t <IP tos>\n"
			"  -o <IP Options>\n\n");
	printf ("Data Link Options: \n"
			"  -d <Ethernet Device>\n"
			"  -H <Source MAC Address>\n"
			"  -M <Destination MAC Address>\n\n");


    printf ("You must define a Source, Destination, Protocol & its dependent"
            " options.\n");
    exit (1);
}

void
defaults ()
{
    sport = 42069;
    dport = 23;
    id = 0;
	tos = IPTOS_LOWDELAY | IPTOS_THROUGHPUT;
    ttl = 254;
    seq = 0;
    type = 8;
    code = 0;
    mask = 0xffffff00;
	payload = NULL;
	payload_s = 0;
	*options = NULL;
	option_s = 0;
}
