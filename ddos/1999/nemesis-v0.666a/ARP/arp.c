/*
 * THE NEMESIS PROJECT (c) obecian 1999
 *
 * arp.c (ARP Packet Injector)
 *
 */

#include "arp.h"

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
    while ((opt = getopt (argc, argv, "S:D:d:P:bH:M:v")) != EOF)
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
			printf ("%x:%x:%x:%x:%x:%x\n", enet_src[0], enet_src[1], enet_src[2] , enet_src[3], enet_src[4], enet_src[5]);
			printf ("Destination MAC Address: ");
			printf ("%x:%x:%x:%x:%x:%x\n", enet_dst[0], enet_dst[1], enet_dst[2] , enet_dst[3], enet_dst[4], enet_dst[5]);
		}	
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
                if (buildarp () != -1)
					if (verbose)
                    	printf ("\nWrote ARP packet successfully\n");
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
                if (buildarp () != -1)
					if (verbose)
                    	printf ("\nWrote ARP packet successfully\n");
                else
					if (verbose)
                    	printf ("\nUnable to write packet successfully\n");
            }
        }
    }
    else
    {
        if (buildarp () != -1)
			if (verbose)
            	printf ("\nWrote ARP packet successfully\n");
        else
			if (verbose)
            	printf ("\nUnable to write packet successfully\n");
    }
}

void
usage (char *arg)
{
    printf ("\nUsage:\n  %s [-v] [optlist]\n\n", arg);
    printf ("ARP Options: \n"
            "  -S <Source IP Address>\n"
            "  -D <Destination IP Address>\n"
			"  -P <Payload File (Binary or ASCII)>\n"
			"  -b (Enable Binary Payload)\n"
    		"  (-v VERBOSE - packet struct to stdout)\n\n");
	printf ("Data Link Options: \n"
			"  -d <Ethernet Device>\n"
			"  -H <Source MAC Address>\n"
			"  -M <Destination MAC Address>\n\n");
    printf ("You must define a Source, Destination, Protocol Options\n");
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

	payload = NULL;
	payload_s = 0;
}
