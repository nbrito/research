/*
 * THE NEMESIS PROJECT (c) obecian 1999
 *
 * tcp.c (TCP Packet Injector)
 * 
 */

#include "tcp.h"

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
    while ((opt = getopt (argc, argv, "S:D:x:y:d:H:M:i:O:f:w:q:a:t:P:I:T:u:bv")) != EOF)
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
				fprintf (stderr, "Invalid Destination IP address: %s\n", optarg);
				exit (1);
			}
			if (verbose)
				printf ("Destination IP %s\n", optarg); 
			break;
        case 'x':
            sport = atoi (optarg);
			break;
        case 'y':
            dport = atoi (optarg);
			break;
        case 'd':
			got_link = 1;
            device = optarg;
            break;
		case 'H':
			if (got_link)
				sscanf (optarg, "%x:%x:%x:%x:%x:%x", &enet_src[0], &enet_src[1], &enet_src[2], &enet_src[3], &enet_src[4], &enet_src[5]);
			break;
		case 'M':
			if (got_link)
				sscanf (optarg, "%x:%x:%x:%x:%x:%x", &enet_dst[0], &enet_dst[1], &enet_dst[2], &enet_dst[3], &enet_dst[4], &enet_dst[5]);
            break;
		case 'u':
			urgp = atoi (optarg);
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
        case 'f':
            switch (*optarg)
            {
            	case 'S':
                	fl_opt |= SYN;
                	flags |= TH_SYN;
                	break;
            	case 'A':
                	fl_opt |= ACK;
                	flags |= TH_ACK;
                	break;
            	case 'R':
                	fl_opt |= RST;
                	flags |= TH_RST;
                	break;
            	case 'P':
                	fl_opt |= PSH;
                	flags |= TH_PUSH;
                	break;
            	case 'U':
                	fl_opt |= URG;
                	flags |= TH_URG;
                	break;
            	case 'F':
                	fl_opt |= FIN;
                	flags |= TH_FIN;
                	break;
            }
            break;
        case 'w':
            win = atoi (optarg);
            break;
        case 'q':
            seq = atoi (optarg);
            break;
        case 'a':
            ack = atoi (optarg);
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
		case 'b':
			bindata = 1;
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
		printf ("Source port: %d  ", sport);
    	printf ("Destination port: %d\n", dport);

		if (got_link)
		{
			printf ("Source MAC Address: ");
			printf ("%x:%x:%x:%x:%x:%x\n", enet_src[0], enet_src[1], enet_src[2] , enet_src[3], enet_src[4], enet_src[5]);
			printf ("Destination MAC Address: ");
			printf ("%x:%x:%x:%x:%x:%x\n", enet_dst[0], enet_dst[1], enet_dst[2] , enet_dst[3], enet_dst[4], enet_dst[5]);
		}

		printf ("Flags: ");
    	if (fl_opt & SYN)
      		printf ("SYN ");
    	if (fl_opt & ACK)
      		printf ("ACK ");
    	if (fl_opt & RST)
      		printf ("RST ");
    	if (fl_opt & PSH)
      		printf ("PSH ");
    	if (fl_opt & URG)
      		printf ("URG ");
    	if (fl_opt & FIN)
      		printf ("FIN ");
		printf ("\nTCP Urgent Pointer: %d\n", urgp);
    	printf ("Window Size: %d\n", win);
    	if (fl_opt & ACK)
      		printf ("ACK number: %d\n", ack);
    	if (fl_opt & SYN)
      		printf ("Sequence number: %d\n", seq);
   
    	printf ("IP ID: %d\n", id);
    	printf ("IP TTL: %d\n", ttl);
    	printf ("IP TOS: 0x%x\n\n", tos);
		printf ("IP Options: %s\n", options);
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
				if (buildtcp () != -1)
					if (verbose)	
						printf ("\nWrote TCP packet successfully\n");
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

				if (buildtcp () != -1)
					if (verbose)
						printf ("\nWrote TCP packet successfully\n");
				else
					if (verbose)
						printf ("\nUnable to write packet successfully\n");
			}
		}
	}
	else
	{
		if (buildtcp () != -1)
			if (verbose)
				printf ("\nWrote TCP packet successfully\n");
		else
			if (verbose)
				printf ("\nUnable to write packet successfully\n");
	}
}

void
usage (char *arg)
{
    printf ("\nTCP usage:\n  %s [-v] [options]\n\n", arg);
    printf ("TCP options: \n"
			"  [-x <Source Port>]\n"
			"  [-y <Destination Port>]\n"
			"  -f <TCP Flag Options>\n"
			"     -fS SYN, -fA ACK, -fR RST, -fP PSH, -fF FIN, -fU URG\n"
			"  -w <Window Size>\n"
			"  -s <SEQ Number>\n"
			"  -a <ACK Number>\n"
            "  -u <TCP Urgent Pointer>\n"
			"  -P <Payload File (Binary or ASCII)>\n"
			"  -b (Enable Binary Payload)\n"
			"  (-v VERBOSE - packet struct to stdout)\n\n");
	printf ("IP options: \n"
            "  -S <Source IP Address>\n"
            "  -D <Destination IP Address>\n"
			"  -I <IP ID>\n"
			"  -T <IP TTL>\n"
			"  -t <IP tos>\n"
			"  -O <IP Options>\n\n");
	printf ("Data Link Options: \n"
            "  -d <Ethernet Device>\n"
			"  -H <Source MAC Address>\n"
			"  -M <Destination MAC Address>\n\n");
    printf ("You must define a Source, Destination and Protocol Options\n");
    exit (1);
}

void
defaults ()
{

    enet_src[0] = 0x02;
    enet_src[1] = 0x0f;
    enet_src[2] = 0x0a;
    enet_src[3] = 0x0d;
    enet_src[4] = 0x0e;
    enet_src[5] = 0x0d;

    enet_dst[0] = 0x0d;
    enet_dst[1] = 0x0e;
    enet_dst[2] = 0x0a;
    enet_dst[3] = 0x0d;
    enet_dst[4] = 0x00;
    enet_dst[5] = 0x01;
	
    fl_opt = 0;
    sport = 42069;
    dport = 23;
    id = 0;
	urgp = 2048;
    tos = IPTOS_LOWDELAY | IPTOS_THROUGHPUT;
    ttl = 254;
    seq = 420;
    ack = 420;
    win = 512;
    payload = NULL;
    payload_s = 0;
	*options = NULL;
	option_s = 0;
	frag = IP_DF;
}
