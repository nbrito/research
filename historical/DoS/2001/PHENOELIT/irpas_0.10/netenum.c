#include <stdio.h>
#include <stdlib.h>
#include "enum.h"

int main(int argc,char **argv) {
    int		n=0;

    if (argc>1) {
	if ((n=enumerate(argv[1],
			argc>2?atoi(argv[2]):0,
			argc>3?atoi(argv[3]):0))<0) {
	    printf("error in enumerate\n");
	} else {
	    if ((argc>3)&&(atoi(argv[3])>0)) printf("%d targets found\n",n);
	    enum_print();
	}
    } else {
	fprintf(stderr,"Netenum\n%s <destination> [timeout] [verbosity]\n"
		"if timeout is >0, pings are used to enum\n",
		argv[0]);
    }

    enum_free();
    return n;
}
