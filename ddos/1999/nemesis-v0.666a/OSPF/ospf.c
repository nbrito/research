/*
 * THE NEMESIS PROJECT (c) obecian 1999
 * 
 * ospf.c (OSPF Packet Injector)
 *
 */

#include "ospf.h"

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
    while ((opt = getopt (argc, argv, "S:D:r:s:L:R:A:g:n:i:l:o:O:P:m:I:T:t:p:bv")) != EOF)
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
		case 'p':
			switch (*optarg)
			{
				case 'H':
					ospftype = 1;
					break;
				case 'L':
					ospftype = 2;
					break;
				case 'R':
					ospftype = 3;
					break;
			}
		case 'L':
			rtrid = atoi (optarg);
			break;
		case 's':
			seqnum = atoi (optarg);
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
        case 'm':
            mask = strtoul (optarg, NULL, 0);
            break;
		case 'b':
			bindata = 1;
			break;
        case 'P':
            file = optarg;
            if ((pay = fopen (file, "r")) == NULL)
            {
                printf ("Payload file \"%s\"\n", file);
                exit (1);
            }
            break;
		case 'O':
			ooptions = strtoul (optarg, NULL, 0);
			break;
		case 'o':
			(u_char)*options = strtoul (optarg, NULL, 0);
			break;
		case 'l':
			interval = atoi (optarg);
			break;
		case 'r': 
        	if (!(router = libnet_name_resolve (optarg, 0)))
            {
            	fprintf (stderr, "Invalid advertising router address: %s\n", optarg);
            	exit (1);
            }
            if (verbose)
                printf ("Advertising Router IP: %s\n", optarg);
            break;
		case 'n':
        	if (!(neighbor = libnet_name_resolve (optarg, 0)))
            {
            	fprintf (stderr, "Invalid neighbor address: %s\n", optarg);
            	exit (1);
            }
            break;
		case 'i':
			dead_int = atoi (optarg);
			break;
		case 'R':
			addrid = strtoul (optarg, NULL, 0);
			break;
		case 'A':
			addaid = strtoul (optarg, NULL, 0);
			break;
		case 'g':
			ospf_age = atoi (optarg);
			break;
        case '?':
            usage (argv[0]);
            break;
        }
    }
	
	if (ospftype == -1) 
	{
		printf ("\nOSPF Packet type not supplied.\n");
        exit (1);
	}

	if (verbose)
	{
		printf ("\nOSPF Options: 0x%x\n", ooptions);
		printf ("Priority: %d\n", priority);
		printf ("Advertising Router ID: 0x%x\n", addrid);
       	printf ("Advertising Area ID: 0x%x\n", addaid);

	}

	if (ospftype == 1)
	{
		if (verbose)
			printf ("Dead router interval: %d\n", dead_int);
	}
	else if (ospftype == 2)
	{
		if (verbose)
		{
			printf ("Netmask: %x\n", mask);
			printf ("Sequence Number: %d\n", seqnum);
			printf ("Router Advertisement Age: %d\n", ospf_age);
			printf ("Link State ID: %d\n", rtrid);
		}
	}
	else if (ospftype == 3)
	{
		if (verbose) 
			printf ("Link State ID:	%d\n", rtrid);
	}	

	if (verbose)
	{
		printf ("IP ID: %d\n", id);
    	printf ("IP TTL: %d\n", ttl);
    	printf ("IP TOS: 0x%x\n", tos);
		printf ("IP Frag: %d\n", frag);
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
				if (buildospf () != -1)
					if (verbose)
						printf ("\nWrote OSPF packet successfully\n\n");
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

           		if (buildospf () != -1)
					if (verbose)
            			printf ("\nWrote OSPF packet successfully\n\n");
            	else
					if (verbose)
               			printf ("\nUnable to write packet successfully\n");
			}
		}
	}
	else
	{
		if (buildospf () != -1)
			if (verbose)
				printf ("\nWrote OSPF packet successfully\n\n");
		else
			if (verbose)
				printf ("\nUnable to write packet successfully\n");
	}
}

void
usage (char *arg)
{
    printf ("\nOSPF usage:\n  %s [-v] [optlist]\n\n", arg);
    printf ("OSPF options: \n"
            "  -p <OSPF Protocol>\n"
			"     -pH HELLO, -pL LSA, -pR LSR\n"
			"  -n <Neighbor Router Address>\n"
			"  -i <Dead Router Interval>\n"
			"  -L <router id (LSA)>\n"
            "  -s <sequence number>\n"
            "  -r <Advertising Router Address>\n"
            "  -g <OSPF LSA age>\n"
            "  -m <OSPF netmask>\n"
            "  -O <OSPF options>\n"
            "  -l <OSPF interval>\n"
            "  -R <OSPF router id>\n"
            "  -A <OSPF area id>\n\n"
			"  -P <Payload File (Binary or ASCII)>\n"
			"  -b (Enable Binary Payload)\n"
			"  (-v VERBOSE - packet struct to stdout)\n\n");
	printf ("IP Options\n"
            "  -S <Source Address>\n"
            "  -D <Destination Address>\n"
			"  -I <IP ID>\n"
            "  -T <IP TTL>\n"
            "  -t <IP tos>\n"
            "  -o <IP Options>\n\n");
    printf ("You must define a Source, Destination, Protocol & its dependent"
            " options.\n\n");
    exit (1);
}

void
defaults ()
{
    id = 0;
	tos = IPTOS_LOWDELAY | IPTOS_THROUGHPUT;
    ttl = 254;
    mask = 0xffffff00;
	addrid = 0xff00ff00;
	addaid = 0xd00dd00d;
	rtrid = 42;
	ospf_age = 40;
	ooptions = 0x00;
	priority = 0x00;
	dead_int = 30;
	payload = NULL;
	payload_s = 0;
	*options = NULL;
	option_s = 0;
	interval = 2;
	seqnum = 420;
	frag = IP_DF;
	ospftype = -1;
}
