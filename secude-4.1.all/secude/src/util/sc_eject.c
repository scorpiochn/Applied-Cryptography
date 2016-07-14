#include <stdio.h>
#include "secure.h"


int             verbose = 0;



main(cnt, parm)
	int             cnt;
	char          **parm;
{
	extern char    *optarg;
	extern int      optind, opterr;
	char           *cmd = *parm, opt;


	optind = 1;
	opterr = 0;


	if ((opt = getopt(cnt, parm, "v")) != -1)  {
		switch (opt) {
			case 'v':
				verbose = 1;
				break;

			default:
				break;
		}
	}


#ifdef SCA

	if ((sec_sc_eject(CURRENT_SCT)) == -1) {
		if (err_stack) {
			if (verbose) aux_fprint_error(stderr, 0);
			else aux_fprint_error(stderr, TRUE);
		}
		else	fprintf(stderr, "%s: unable to eject smartcard\n", cmd);
		exit(-1);
	}


#endif
	exit(0);
}
