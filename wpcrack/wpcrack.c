/*----------------------------------------------------------------------
**  WPCRACK - Copyright (c) 1990, 91 Ron Dippold 10/11/91
**  rdippold@qualcomm.com
**
**  Attempt to crack a Word Perfect 5.x file through some massive
**  security holes.
**
**  This source code is hereby released for public use.  All I ask is
**  that if you make some cool new additions or enhancements that you
**  mail me the update.  And if you use the program or source code,
**  give me a little credit.
**
**  There's at least one major enhancement that could be made to this
**  that I can think of at the moment - frequency analysis on the
**  actual document text.  Once you know the format, it's pretty easy.
**
**  I'm not claiming this is the best code you've ever seen, it's just
**  a fast hack, but it works.  I tried to be generic as possible so
**  that it will compile on almost any platform.  It was written under
**  Borland C.
**----------------------------------------------------------------------*/

#include <stdio.h>

#define MAX 18        /* Max number of chars to look for */
#define N 5           /* Max number of repeats */

FILE *f;              /* File name */

typedef unsigned char byte;
typedef unsigned int  word;

byte buf1[48];
byte *buf;

word csum1, csum, missing, mi;

/* bytes in the plaintext we think we know - 0x00 means we don't know */
byte known[32] = {
	0xfb, 0xff, 0x05, 0x00, 0x32, 0x00, 0x99, 0x99,
	0x00, 0x00, 0x99, 0x99, 0x99, 0x00, 0x00, 0x00,
	0x42, 0x00, 0x00, 0x00, 0x99, 0x00, 0x99, 0x00,
	0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0x99, 0x99 };

byte source[MAX][N][MAX];   /* source table from known bytes */
char pass[MAX][N][MAX];     /* possible passwords */
char tots[MAX][MAX];        /* totals and matches for each password position */
char mats[MAX][MAX];
int  conf[MAX];             /* confidence for each length */

char chr[N];                /* character and count for each char */
byte cnt[N];

char fmt[N][MAX];           /* characters for output */
byte cnts[N][MAX];

int order[MAX];             /* order by confidence */
int thresh=80;              /* threshold of confidence */
int num=0;                  /* number of lengths that beat threshold */

byte pp;
char c;

byte idx[MAX];              /* current guess */
char cur[MAX];

int i, j, k, l, t, len, tot, match, deep;
int do_dec=0, do_table=0;

void docs() {
	printf( " To attempt to crack a Word Perfect 5.x file, the syntax is:\n\n" );
	printf( "   WPCRACK (-d) (-t) <filename> ( <threshold> )\n\n" );
	printf( " <filename> is the Word Perfect file to crack.\n" );
	printf( " <threshold> is the percentage confidence threshold over which\n" );
  printf( "    a length is considered to be a possibility.\n" );
	printf( "    From 0 (all) to 100 (exact match), default 80.\n" );
	printf( " The -d switch will force WPCRACK to the decimal values of\n");
	printf( "    each character of an answer as well.  Not pretty.\n");
	printf( " The -t switch will force WPCRACK to print all answers in table\n");
	printf( "    form with all possibilities, ignoring checksums.\n");
	printf( "\n\n To decrypt the file with the password, run WPUNCRYP on it.\n");
	exit( 1 );
}

void main( int argc, char **argv )
{
	printf( "\nWPCRACK 1.0 - Copyright (c) 1990,91 Ron Dippold\n\n" );

	if( argc < 2 || argc > 5 ) {
		docs();
	}

	i=1;

	while( i<argc && argv[i][0] == '-' ) {
		if( argv[i][1] == 'd' ) {
			do_dec = 1;
		} else {
			if( argv[i][1] == 't' ) {
				do_table = 1;
			} else {
				docs();
			}
		}
		i++;
	}

	if( i>= argc ) {
		docs();
	}

	if( i == argc-2  ) {
		sscanf( argv[i+1], "%d", &thresh );
		if( thresh<0 || thresh>100 ) {
			docs();
		}
	}

	if( !( f = fopen( argv[i], "rb" ))) {
		printf( "  Could not open file %s\n", argv[i] );
		exit( 2 );
	}

	fseek( f, 0L, SEEK_SET );
	if( fread( buf1, 1, 4, f ) != 4) {
		fclose( f );
		printf( "  Couldn't read 4 bytes from file %s!\n", argv[i] );
		exit( 3 );
	}

	if( buf1[0]!=0xff || buf1[1]!=0x57 || buf1[2]!=0x50 || buf1[3]!=0x43 ) {
		printf( "%x, %x, %x, %x\n", buf1[0], buf1[1], buf1[2], buf1[3] );
		fclose( f );
		printf( "  The identification bytes in this file are not those of a\n" );
		printf( "  Word Perfect 5.x file.\n" );
		exit( 4 );
	}

	if( fread( &buf1[4], 1, 44, f ) != 44 ) {
		fclose( f );
		printf( "  Couldn't read the first 48 bytes of the file - garbaged!\n" );
		exit( 5 );
	}
	fclose( f );

	if( buf1[12]==0 && buf1[13]==0 ) {
		printf( "  The file claims it is not encrypted.\n" );
		printf( "  We'll continue anyway, but take note!\n\n%c",7 );
	}

	csum1 = (buf1[12]<<8) + buf1[13];

	buf = &buf1[16];

/*  printf( "Building known text table.\n" ); */
	for( i=1; i<MAX; i++ ) {
		for( j=0; j<N; j++ ) {
			for( k=0; k<i; k++ ) {
				pp = j*i+k;
				while ( pp<= 31 ) {
					if( known[pp] == 0x99 ) {
						pp+=i; continue;
					}
					tot = 0;
					if( j>0 ) for( l=j-1; l>=0; l-- ) {
						if( pp == source[i][l][k] ) {
							tot++;
						}
					}
					if( tot ) {
						pp+=i;
					} else {
						break;
					}
				}
				if ( pp>31 ) pp = 0xFF;
				source[i][j][k] = pp;
			}
		}
	}

/*  printf("Trying password lengths from 1 to %d\n", MAX-1 ); */
	for( len=1; len<MAX; len++ ) {
/* printf( "Len %2d:\n", len ); */
    for( j=0; j<N; j++ ) {
			for( k=0; k<len; k++ ) {
				l = source[len][j][k];
				if( l != 0xFF && known[l] != 0x99 ) {
					pp = ( len+l+1 ) ^ known[l] ^ buf[l];
					if( pp>127 || (pp>='a' && pp<='z')) pp = 0;
/* putchar( pp ); */
				} else {
					pp = 0;
/* putchar( '_'); */
				}
				pass[len][j][k] = pp;
			}
/* printf( "\n" ); */
		}

    /* move all good choices to the top */
		for( k=0; k<len; k++ ) {
			for( j=0; j<N-1; j++ ) {
				if( pass[len][j][k] == 0 ) {
					for( l=j; l<N-1; l++ ) {
						pass[len][l][k] = pass[len][l+1][k];
					}
					pass[len][N-1][k] = 0;
				}
			}
		}

		tot=match=0;
		for( k=0; k<len; k++ ) {
			tots[len][k] = mats[len][k] = 0;
			for( j=1; j<N; j++ ) {
				if( pass[len][j][k] != 0 ) {
					tots[len][k]+=j;
					for( i=0; i<j; i++ ) {
						if( pass[len][j][k] == pass[len][i][k] ) {
							mats[len][k]++;
						}
					}
				}
			}
			tot+=tots[len][k];
			match+=mats[len][k];
		}

		if( tot ) {
			conf[len] = match*100 / tot ;
		} else {
			conf[len]=0;
		}
	}

/*  printf( "Sorting results\n\n" ); */
	for( i=0; i<MAX; i++ ) {
		order[i] = i;
	}

  /* so it's a bubble sort.  It's small.  Deal with it. */
	for( i=MAX-1; i>0; i-- ) {
		for( j=1; j<i; j++ ) {
			if( conf[order[j]] < conf[order[j+1]] ) {
				k = order[j]; order[j] = order[j+1]; order[j+1] = k;
			}
		}
	}

	for( num=MAX-1; num>0; num-- ) {
		if( conf[order[num]]>=thresh ) {
			break;
		}
	}

	printf( "%d length%c meet%c the %d%% initial confidence threshold.\n",
		num, num==1 ? ' ':'s', num==1 ? 's':' ', thresh );

	if( num == 0 ) {
		printf( "  Try lowering the threshold.\n");
		printf( "  Or maybe you need a new version of this to match a Word Perfect change.\n" );
		exit( 2 );
	}

	for( l=1; l<=num; l++ ) {
		len = order[l];
		printf( "\nPassword length of %d with %d%% confidence level:\n\n",
			len, conf[len] );

		deep=0;
    /* for each character */
		for( k=0; k<len; k++ ) {
			for( j=0; j<N; j++ ) {
				fmt[j][k]=' ';
				cnts[j][k]=0;
			}

      /* run a character vote */
			for( j=0; j<N; j++ ) {
				chr[j]=cnt[j]=0;
			}
			for( j=0; j<N; j++ ) {
				if( pass[len][j][k] != 0 ) for(i=0; i<N; i++ ) {
					if( !chr[i] ) {
						chr[i] = pass[len][j][k];
					}
					if( pass[len][j][k] == chr[i] ) {
						cnt[i]++;
						break;
					}
				}
			}
      for( i=N-1; i>0; i-- ) {      /* sort to find most popular */
				for( j=0; j<i; j++ ) {
					if( cnt[j] < cnt[j+1] ) {
						t = cnt[j]; cnt[j] = cnt[j+1]; cnt[j+1] = t;
						t = chr[j]; chr[j] = chr[j+1]; chr[j+1] = t;
					}
				}
			}

      if( cnt[0] == 0 ) {           /* no letters */
				fmt[0][k]='_';
				cnts[0][k]=0;
			} else {
				for( j=0; j<N; j++ ) {
					if( cnt[j] ) {
						cnts[j][k]=cnt[j];
						fmt[j][k]=chr[j];
						if( deep<j) deep = j;
					}
				}
			}
		}

    /* Find any missing letters */
		missing = 0; mi=-1;
		for( k=0; k<len; k++ ) {
			if( !cnts[0][k] ) {
				missing++;
				mi = k;
			}
		}

		if( missing > 1 || do_table ) {
			if( missing > 1) {
				printf("  More than one letter is missing - showing all possibilities.\n");
			} else {
				printf("  Displaying table form as requested\n");
			}

      /* show in table form */
			for( j=0; j<=deep; j++ ) {
				printf( "   # of matches: " );
				for( k=0; k<len; k++ ) {
					putchar( cnts[j][k] ? cnts[j][k]+'0' : '0' );
				}
				if( j==0 ) {
					printf( "\n  Primary Guess: " );
				} else {
					printf( "\n     Alternates: " );
				}
				csum = 0;
				for( k=0; k<len; k++ ) {
					putchar( cnts[j][k] ? fmt[j][k] : ' ' );
					if( cnts[j][k] ) {
						csum = ( (csum >> 1) | ( csum << 15) ) ^ ( fmt[j][k]<<8 );
					}
				}
        if( j==0 ) {
					if (missing) {
						printf("  (Incomplete!)");
					} else {
						if( csum == csum1 ) {
							printf("  Checksum good!");
						} else {
							printf("  Checksum bad!");
						}
					}
				}

				if( do_dec ) {
					printf( "\n                 " );
					for(k=0; k<len; k++) {
						printf("%d ", cnts[j][k] ? fmt[j][k] : 0);
					}
				}

        /* if only one missing character, extrapolate */
				if( missing == 1 && j==0 ) {
					for( i=0; i<128; i++ ) {
						csum = 0;
						fmt[0][mi] = i;
						for( k=0; k<len; k++ ) {
							csum = ( (csum >> 1) | ( csum << 15) ) ^ ( fmt[0][k]<<8 );
						}
						if( csum == csum1 && ( i<'a' || i>='z' )) {
							printf( "\n   Extrapolated: " );
							for( k=0; k<len; k++ ) putchar( fmt[j][k] );
							printf( "   -- Good Checksum");
							if( do_dec ) {
								printf( "\n                 " );
								for(k=0; k<len; k++) printf("%d ", fmt[j][k]);
							}
						}
					}
				}

				printf( "\n\n" );
			}
		} else {

			for( k=0; k<len; k++ ) {
				idx[k]=0;
				cur[k]=fmt[0][k];
			}

			if( missing == 1 ) {
				cur[mi] = ' ';
				printf( "  " );
				for( k=0; k<len; k++ ) putchar( cur[k] );
				printf( "\n  ");
				for( k=0; k<len; k++ )
					putchar( k == mi ? '^' : ' ');
				printf( "\n The missing character will be extrapolated from the checksum\n\n");
			} else {
				printf( " Only possibilities with good checksums will be listed.\n\n");
			}

			do {
				if( missing == 0 ) {

          /* none missing - generate,  check checksum */
					csum = 0;
					for( k=0; k<len; k++ ) {
						csum = ( (csum >> 1) | ( csum << 15) ) ^ ( cur[k]<<8 );
					}
					if( csum == csum1 ) {
						printf( "  " );
						for( k=0; k<len; k++ ) {
							putchar( cur[k] );
						}
						printf( "   -- Good Checksum\n");
						if( do_dec ) {
							printf( "   Dec: " );
							for( k=0; k<len; k++ ) {
								printf( "%d ", cur[k] );
							}
							printf( "\n");
						}
					}
				} else {

          /* checksum missing - generate */
					tot = 0;
					for( i=0; i<128; i++ ) {
						csum = 0;
						cur[mi] = i;
						for( k=0; k<len; k++ ) {
							csum = ( (csum >> 1) | ( csum << 15) ) ^ ( cur[k]<<8 );
						}
						if( csum == csum1 && ( i<'a' || i>='z' )) {
							tot++;
							printf( "  " );
							for( k=0; k<len; k++ ) putchar( cur[k] );
							printf( "   -- Good Checksum\n");
							if( do_dec) {
								printf("  ");
								for( k=0; k<len; k++ ) printf("%d ",cur[k]);
								printf("\n");
							}
						}
					}
					if( !tot ) {
						printf("  No valid passwords found\n" );
					}
				}

        /* next combination */
				k=len-1;
				while( k>=0 ) {
					if( cnts[idx[k]+1][k]==0 || cur[k]== N-1 ) {
            idx[k]=0;
						k--;
					} else {
						idx[k]++;
						break;
					}
				}

			} while( k>=0 );
		} /* table or checksum */
	}
}

