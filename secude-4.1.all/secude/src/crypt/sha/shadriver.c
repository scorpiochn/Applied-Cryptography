#include "sha.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


/* Size of buffer for SHS speed test data */

#define TEST_BLOCK_SIZE     ( SHS_DIGESTSIZE * 100 )

/* Number of bytes of test data to process */

#define TEST_BYTES          10000000L
#define TEST_BLOCKS         ( TEST_BYTES / TEST_BLOCK_SIZE )

void main()
    {
    SHS_INFO shsInfo;
    time_t endTime, startTime;
    BYTE data[ 1000000 ];
    int shsinput, i; 
	

    /* Test output data (this is the only test data given in the SHS
       document, but chances are if it works for this it'll work for
       anything) */
    shsInit( &shsInfo );
    shsUpdate( &shsInfo, ( BYTE * ) "abc", 3 );
    shsFinal( &shsInfo );
    if( shsInfo.digest[ 0 ] != 0x0164B8A9L || 
	shsInfo.digest[ 1 ] != 0x14CD2A5EL || 
	shsInfo.digest[ 2 ] != 0x74C4F7FFL || 
	shsInfo.digest[ 3 ] != 0x082C4D97L || 
	shsInfo.digest[ 4 ] != 0xF1EDF880L )
	{
	puts( "Error in SHS implementation" );
	exit( -1 );
	}

    /* Now perform time trial, generating MD for 10MB of data.  First,
       initialize the test data */
    memset( data, 0, TEST_BLOCK_SIZE );

    /* Get start time */
    printf( "SHS time trial.  Processing %ld characters...\n", TEST_BYTES);
/*
    time( &startTime );
*/

    /* Calculate SHS message digest in TEST_BLOCK_SIZE byte blocks */
    shsInit( &shsInfo );
    i = read(0, data, TEST_BYTES);
    shsUpdate( &shsInfo, data, i );
    shsFinal( &shsInfo );

    for (i = 0; i < 5; i++) printf("%04Xl ", shsInfo.digest[ i ]);
    printf("\n");

    /* Get finish time and time difference */
/*
    time( &endTime );
    printf( "Seconds to process test input: %ld\n", endTime - startTime );
    printf( "Characters processed per second: %ld\n", TEST_BYTES / ( endTime - startTime ) );
*/
}

