/*----------------------------------------------------------------------
**  WPUNCRPY - Copyright (c) 1990, 91 Ron Dippold 10/11/91
**  rdippold@qualcomm.com
**
**  Attempt to decrypt a Word Perfect file once you know the password.
**  This is just so that Word Perfect isn't needed.
**
**  This source code is hereby released for public use.  All I ask is
**  that if you make some cool new additions or enhancements that you
**  mail me the update.  And if you use the program or source code,
**  give me a little credit.
**
**  I'm not claiming this is the best code you've ever seen, it's just
**  a fast hack, but it works.  I tried to be generic as possible so
**  that it will compile on almost any platform.  It was written under
**  Borland C.
**----------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>

FILE *fin, *fout;
char *inname, *outname, *pass;

typedef unsigned char byte;
typedef unsigned int  word;

word ver5 = 0;								/* version 4 or 5 */
word override = 0;            /* override checksum */
word pause = 0;               /* pause on screen */
word text = 0;                /* text mode */
word soft = 0;                /* translate CR as a space in text mode */

long tstart;									/* start of text position */
long pos;                     /* position in file */
word lines, chars;            /* lines of text */

word plen;                    /* password length */
word csum, csum1;             /* checksum */

word len;                     /* bytes to read */
word idx;                     /* index into buffer */

byte buf[4096], c;

word pidx;                    /* index down password */
byte xmask;                   /* XOR mask */

int i, j, k;

void docs() {
	printf( " To uncrypt a Word Perfect 4.x or 5.x file, the syntax is:\n\n");
	printf("    WPUNCRYP (-o) (-p) (-b) w|t \"password\" <input file> (<output file>) \n\n");
	printf("  Use the 'w' command to decrypt <input file> into <output file>\n");
	printf("    in Word Perfect format.  This option is meaningless if <output\n");
	printf("    file> is not given.\n");
	printf("  Use the 't' command to decrypt the text portion of <input file>.\n");
	printf("    This will not remove any embedded formatting codes, you can do\n");
	printf("    that yourself!\n");
	printf(" If <output file> is not given, the decrypted text will be shown to\n");
	printf("    the screen.\n");
	printf(" The optional -o switch will force the decrpytion even if the checksum\n");
	printf("    of the password doesn't match the checksum of the file.\n");
	printf(" The optional -p switch will make the make WPUNCRYP attempt to pause\n");
	printf("    after every screen of output to the screen.\n");
  printf(" In text output mode, both hard and soft line breaks are output as a\n");
  printf("    CR/LF.  The optional -b will translate the soft break as a space.\n");
	exit(1);
}

void main( int argc, char **argv )
{
	printf( "\nWPUNCRYP 1.0 - Copyright (c) 1990,91 Ron Dippold\n\n" );

	if( argc <4 || argc > 7 ) {
		docs();
	}

	i=1;
  override = pause = text = soft = 0;

	while( i<argc && argv[i][0] == '-' ) {
    switch( argv[i][1] ) {
      case 'o':
      case 'O':
			  override = 1;
        break;
      case 'p':
      case 'P':
				pause = 1;
        break;
      case 'b':
      case 'B':
        soft = 1;
        break;
      default:
				docs();
		}
		i++;
	}

	if( i>= argc-2 ) {
		docs();
	}

  if( argv[i][1]!='\0' ) docs();
  if( argv[i][0]=='t' ) {
    text = 1;
  } else {
		if( argv[i][0]=='w' ) {
      text = 0;
		} else {
      docs();
    }
	}
  i++;

	pass = argv[i++];
  plen = strlen( pass );

  inname = argv[i++];

  if( i< argc ) {
		outname = argv[i];
		pause = 0;
	} else {
		outname = NULL;
		text = 1;
	}

	if( i > argc ) {
		docs();
	}

  if( !text ) {
    soft = 0;
  }


	if( !( fin = fopen( inname, "rb" ))) {
		printf( "  Could not open file %s\n", inname );
		exit( 2 );
	}

	fseek( fin, 0L, SEEK_SET );
	if( fread( buf, 1, 4, fin ) != 4) {
		fclose( fin );
		printf( "  Couldn't read 4 bytes from file %s!\n", inname );
		exit( 3 );
	}

	if( buf[0]==0xff && buf[1]==0x57 && buf[2]==0x50 && buf[3]==0x43 ) {
		printf( "  This is a Word Perfect 5.x file.\n");
		ver5 = 1;
	} else {
		if( buf[0]==0xfe && buf[1]==0xff && buf[2]==0x61 && buf[3]==0x61 ) {
			printf( " This is a Word Perfect 4.1 encrypted file.\n");
		} else {
			fclose( fin );
			printf( "  The identification bytes in this file are not those of a\n" );
			printf( "  Word Perfect 5.x or 4.x encrpyted file.\n" );
			exit( 4 );
		}
	}

  if( ver5 ) {
	  if( fread( &buf[4], 1, 12, fin ) != 12 ) {
		  fclose( fin );
			printf( "  Couldn't read the first 16 bytes of the file - garbaged!\n" );
		  exit( 5 );
	  }

		if( buf[12]==0 && buf[13]==0 ) {
			printf( "  The file claims it is not encrypted.\n" );
			fclose( fin ); exit( 6 );
	  }
	}

  /* Now read the checksum */
  if( ver5 ) {
		csum1 = (buf[12]<<8) + buf[13];
	} else {
	  if( fread( &buf, 1, 2, fin ) != 2) {
      printf( "  Couldn't read checksum - short file!\n");
			fclose( fin ); exit( 7 );
    }
		csum1 = (buf[4]<<8) + buf[5];
  }

  csum = 0;
  for( i=0; i<plen; i++ ) {
    if( pass[i]>='a' && pass[i]<='z') {   /* convert to upper case */
			pass[i] -= 'a'-'A';
		}
		csum = ( (csum >> 1) | ( csum << 15) ) ^ ( pass[i]<<8 );
	}

	if( csum != csum1 ) {
		if( override ) {
			printf( "  Warning!  Password checksum does not match file checksum!\n");
			printf( "  Any output is suspect.\n");
		} else {
			printf( "  The password checksum does not match the checksum in the file.\n");
			printf( "  If you are convinced it is right, check the docs for the -o option.\n");
			fclose( fin ); exit( 8 );
		}
	}

	/* get start of text */
	if( ver5) {
		tstart = *((long *) (&buf[4]));
    pos = 16;
	} else {
		tstart = pos = 6;
	}

	if( outname ) {
		if( !( fout = fopen( outname, text ? "wt":"wb" ))) {
			printf( "  Could not open file %s\n", outname );
			exit( 2 );
		}
	  fseek( fout, 0L, SEEK_SET );
	} else {
		fout = NULL;
	}

	if( ver5 && fout && !text ) {
		buf[12] = buf[13] = 0;        /* write out first part of WP5.1 file */
		fwrite( &buf[0], 1, 16, fout );
	}

	pidx = 0;                       /* start of password */
	xmask = plen+1;                 /* start at password length+1 */

	if( ver5 ) {                    /* get rid of printer info, etc. */
		while( pos<tstart ) {
			if( tstart-pos > 4096 ) {
				len = 4096;
			} else {
				len = tstart-pos;
			}
			if( fread( buf, 1, len, fin ) !=len ) {
				printf( "\n  Unexpected end of file for %s.\n", inname );
				fclose( fin ); fclose( fout ); exit( 20 );
			}
			for( idx=0; idx<len; idx++ ) {      /* now decrypt */
				buf[idx] ^= pass[pidx++] ^ xmask++;
				if( pidx == plen ) pidx = 0;
			}
			if( fout && !text ) {
				if( fwrite( buf, 1, len, fout ) !=len ) {
					printf( "\n  Couldn't write %d bytes to %s.\n", len, outname );
					fclose( fin ); fclose( fout ); exit( 20 );
				}
			}
			pos += len;
		} /* while */
	} /* ver5 */

	idx = len = 0;                  /* no data yet */
	lines = chars = 0;              /* no lines shown */

	do {

		/* read from file as necessary */
		if( idx>=len ) {
			if( len>0 && fout ) {
				if( fwrite( buf, 1, len, fout ) !=len ) {
					printf( "\n  Couldn't write %d bytes to %s.\n", len, outname );
					fclose( fin ); fclose( fout ); exit( 20 );
				}
			}
			len = fread( buf, 1, 4096, fin );
			pos += len;
			if( len == 0 ) {
				break;                    /* all done with file */
			}
			idx = 0;
		}

		c = buf[idx] ^= pass[pidx++] ^ xmask++;
		if( pidx == plen ) pidx = 0;

		if( text ) {
			if( c == 0xA9 ) buf[idx] = '-'; /* translate annoying dashes */
			if( c == 0x0D ) {           /* handle soft break */
				if( soft ) {
					buf[idx] = ' ';
				} else {
					buf[idx] = '\n';
				}
			}
		}


		if( !fout ) {
			printf( "%c",c = buf[idx] );
			if( c == '\n' || ++chars == 80) {
				lines++; chars=0;
				if( lines == 24 && pause) {
					getch();
					lines = 0;
				}
			}
		}

		idx++;

	} while( 1 );

	fclose( fin );
	if( fout) fclose( fout );
}
