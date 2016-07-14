/*
 * lucifer.c
 *
 * C implementation of IBM lucifer cipher
 * extensive rewrite of FORTRAN code given by Sorkin of LLNL:
 * %A Arthur Sorkin
 * %T Lucifer: A cryptographic algorithm
 * %J Cryptologia
 * %V 8
 * %N 1
 * %D January 1984
 * %P 22-42
 * 
 * original comments and variable names
 * supported where possible in Sorkin subroutines.
 * have used better C bit-op support to eliminate need for
 * bit vector style storage
 *
 * This version: 3/16/91, Jonathan M. Smith
 * 
 * Modification history:
 *
 * 3/17/91 - switched back to bit-vector storage - eased manipulations
 * Does slightly over 12,000 characters/sec. on RS/6000 model 320
 */

#include <stdio.h>

#define ENCIPHER 0
#define DECIPHER 1

#define L_BLOCK 128				/* bits in a lucifer block */
#define BPB 8					/* bits per byte */

int m[L_BLOCK];					/* message vector */
int k[L_BLOCK];					/* key vector */

int o[8] = { 7, 6, 2, 1, 5, 0, 3, 4 };		/* diffusion pattern */
int pr[8] = { 2, 5, 4, 0, 3, 1, 7, 6 };		/* inverse of fixed permutation */

/* S-box permutations */
int s0[16] = { 12, 15, 7, 10, 14, 13, 11, 0, 2, 6, 3, 1, 9, 4, 5, 8 };
int s1[16] = { 7, 2, 14, 9, 3, 11, 0, 4, 12, 13, 1, 10, 6, 15, 8, 5 };

lucifer( direction )
int direction;
{
	int tcbindex, tcbcontrol; /* transfer control byte indices */
	int round, hi, lo, h_0, h_1;
	register int bit, temp1;
	int byte, index, v, tr[BPB];

	h_0 = 0;
	h_1 = 1;

	if( direction == DECIPHER )
		tcbcontrol = 8;
	else
		tcbcontrol = 0;


	for( round=0; round<16; round += 1 )
	{
		if( direction == DECIPHER )
			tcbcontrol = (tcbcontrol+1) & 0xF;
		tcbindex = tcbcontrol;
		for( byte = 0; byte < 8; byte +=1 )
		{
			lo = (m[(h_1*64)+(BPB*byte)+7])*8
				+(m[(h_1*64)+(BPB*byte)+6])*4
				+(m[(h_1*64)+(BPB*byte)+5])*2
				+(m[(h_1*64)+(BPB*byte)+4]);
			hi = (m[(h_1*64)+(BPB*byte)+3])*8
				+(m[(h_1*64)+(BPB*byte)+2])*4
				+(m[(h_1*64)+(BPB*byte)+1])*2
				+(m[(h_1*64)+(BPB*byte)+0]);

			v = (s0[lo]+16*s1[hi])*(1-k[(BPB*tcbindex)+byte])
				+(s0[hi]+16*s1[lo])*k[(BPB*tcbindex)+byte];

			for( temp1 = 0; temp1 < BPB; temp1 += 1 )
			{
				tr[temp1] = v & 0x1;
				v = v>>1;
			}

			for( bit = 0; bit < BPB; bit += 1 )
			{
				index = (o[bit]+byte) & 0x7;
				temp1 = m[(h_0*64)+(BPB*index)+bit]
					+k[(BPB*tcbcontrol)+pr[bit]]
					+tr[pr[bit]];
				m[(h_0*64)+(BPB*index)+bit] = temp1 & 0x1;
			}
		
			if( byte<7 || direction == DECIPHER )
				tcbcontrol = (tcbcontrol+1) & 0xF;
		}

		temp1 = h_0;
		h_0 = h_1;
		h_1 = temp1;
	}

	/* final swap */
	for( byte = 0; byte < 8; byte += 1 )
	{
		for( bit = 0; bit < BPB; bit += 1 )
		{
			temp1 = m[(BPB*byte)+bit];
			m[(BPB*byte)+bit] = m[64+(BPB*byte)+bit];
			m[64+(BPB*byte)+bit] = temp1;
		}
	}

	return;

}

/*
 * mygetpw()
 * essentially getpass() with modifiable length parms
 */

#include <sys/ioctl.h>
#include <termio.h>
#include <fcntl.h>

#ifndef EOS
#define EOS '\0'
#endif

#ifndef EOL
#define EOL '\n'
#endif

mygetpw( buf, len, prompt )
char *buf, *prompt;
int len;
{
	int i, fd;
	struct termio t;
	unsigned short save;

	fd = open( "/dev/tty", O_RDWR );
	if( fd >= 0 )
	{
		write( fd, prompt, strlen( prompt ) );
		ioctl( fd, TCGETA, &t );
		save = t.c_lflag;
		t.c_lflag &= ~ECHO;
		ioctl( fd, TCSETAW, &t );
	
		for( i = 0; i < len; i += 1 )
		{
			if( read( fd, &buf[i], sizeof(char) ) < sizeof(char) )
				break;
			if( buf[i] == EOL )
			{
				write( fd, &buf[i], sizeof(char) );
				break;
			}
		}
		for( ; i < len; i += 1 )
			buf[i] = EOS;
	
		t.c_lflag = save;
		ioctl( fd, TCSETAF, &t );
		close( fd );
	}
	else
	{
		fprintf( stderr, "Can't open /dev/tty. Exiting!\n" );
		exit( 1 );
	}

	return;
}


/*
 * this front-end uses mygetpw() to get a key, and then
 * loads the key into k, 
 * and then operates on the message 128 bits at a time,
 * by putting it in "m" and calling lucifer().
 * encryption/decryption controlled by a command line argument.
 */


main( argc, argv )
int argc;
char *argv[];
{
	int i, c, output, counter, direction;
	char buf[16];

	if( argc != 2 )
		usage();
	if( argv[1][0] != '-' || argv[1][2] != '\0' )
		usage();
	if( argv[1][1] == 'd' )
		direction = DECIPHER;
	else if( argv[1][1] == 'e' )
		direction = ENCIPHER;
	else
		usage();

	mygetpw( buf, 16, "Password: " );
	for( counter = 0; counter < 16; counter += 1 )
	{
		c = buf[counter] & 0xFF;
		for( i = 0; i < BPB; i += 1 )
		{
			k[(BPB*counter)+i] = c & 0x1;
			c = c>>1;
		}
	}

	counter = 0;

	while( (c=getchar()) != EOF )
	{
		if( counter == 16 )
		{
			lucifer( direction );
			for( counter = 0; counter < 16; counter += 1 )
			{
				output = 0;
				for( i = BPB-1; i >= 0; i -= 1 )
				{
					output = (output<<1) + m[(BPB*counter)+i];
				}
				putchar( output );
			}
			counter = 0;

		}

		for( i = 0; i < BPB; i += 1 )
		{
			m[(BPB*counter)+i] = c & 0x1;
			c = c>>1;
		}
		counter += 1;
	}
	for( ;counter < 16; counter += 1 )
		for( i = 0; i < BPB; i += 1 )
			m[(BPB*counter)+i] = 0;

	lucifer( direction );
	for( counter = 0; counter < 16; counter += 1 )
	{
		output = 0;
		for( i = BPB-1; i >= 0; i -= 1 )
		{
			output = (output<<1) + m[(BPB*counter)+i];
		}
		putchar( output );
	}

	exit( 0 );

}

usage()
{
	fprintf( stderr, "Usage: lucifer -[e|d]\n" );
	exit( 1 );
}


