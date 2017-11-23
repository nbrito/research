/*
 * THE NEMESIS PROJECT (c) obecian 1999
 *
 * udp.c (UDP Packet Injector)
 *
 */
	
#include "udp.h"

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
	
	verbose = 0;

    if (argc < 2)
        usage (argv[0]);

    if (geteuid () != 0)
    {
        printf ("user '%s' does not have an euid of 0\n", getlogin ());
        exit (1);
    }

    defaults ();

    opterr = 0;
    while ((opt = getopt (argc, argv, "S:D:x:y:I:T:t:O:P:bv")) != EOF)
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
        case 'x':
            sport = atoi (optarg);
			break;
        case 'y':
            dport = atoi (optarg);
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

    if (source == 0 || dest == 0)
    {
    	printf ("source and/or destination address missing.\n");
    	exit (1);
    }

	if (verbose)
	{
    	printf ("Protocol: ");

		printf ("UDP Packet:\n\n");
    	printf ("Source port: %i\n", sport);
    	printf ("Destination port: %i\n", dport);
    
		printf ("IP ID: %d\n", id);
    	printf ("IP TTL: %d\n", ttl);
    	printf ("IP TOS: 0x%x\n", tos);
		printf ("IP Options: %s\n\n", options);
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
                if (buildudp () == 0)
					if (verbose)
                    	printf ("\nWrote UDP packet successfully\n");
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
                if (buildudp () == 0)
					if (verbose)
                    	printf ("\nWrote UDP packet successfully\n");
                else
					if (verbose)
                    	printf ("\nUnable to write packet successfully\n");
            }
        }
    }
    else
    {
        if (buildudp () == 0)
			if (verbose)
            	printf ("\nWrote UDP packet successfully\n");
        else
			if (verbose)
            	printf ("\nUnable to write packet successfully\n");
    }
}

void
usage (char *arg)
{
    printf ("\nUDP usage:\n  %s [-v] [options]\n\n", arg);
    printf ("options: \n"
            "  [-x <Source Port>]\n"
            "  [-y <Destination Port>]\n"
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
    printf ("You must define a Source, Destination and Protocol Options.\n");
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
	payload = NULL;
	payload_s = 0;
	*options = NULL;
	option_s = 0;
}
