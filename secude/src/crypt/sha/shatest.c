/* Size of buffer for SHS speed test data */
 
#define TEST_BLOCK_SIZE	( SHS_DIGESTSIZE * 100 )
 
/* Number of bytes of test data to process */
 
#define TEST_BYTES      10000000L
#define TEST_BLOCKS     ( TEST_BYTES / TEST_BLOCK_SIZE )
 
void main( void )
{
        SHS_INFO shsInfo;
        BYTE data[ TEST_BLOCK_SIZE ];
        time_t endTime, startTime;
        long i;
 
        /* Test output data (this is the only test data given in the SHS
           document, but chances are if it works for this it'll work for
           anything) */
        shsInit( &shsInfo );
        shsUpdate( &shsInfo, (BYTE *)"abc", 3 );
        shsFinal( &shsInfo );
        if( shsInfo.digest[ 0 ] != 0x0164B8A9L || \
            shsInfo.digest[ 1 ] != 0x14CD2A5EL || \
            shsInfo.digest[ 2 ] != 0x74C4F7FFL || \
            shsInfo.digest[ 3 ] != 0x082C4D97L || \
            shsInfo.digest[ 4 ] != 0xF1EDF880L )
        {
                puts( "Error in SHS implementation: Test 1 failed" );
                exit( -1 );
        }
        puts("Test 1 passed");
 
        shsInit( &shsInfo );
        shsUpdate( &shsInfo, (BYTE *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56 );
        shsFinal( &shsInfo );
        if( shsInfo.digest[ 0 ] != 0xD2516EE1L || \
            shsInfo.digest[ 1 ] != 0xACFA5BAFL || \
            shsInfo.digest[ 2 ] != 0x33DFC1C4L || \
            shsInfo.digest[ 3 ] != 0x71E43844L || \
            shsInfo.digest[ 4 ] != 0x9EF134C8L )
        {
                puts( "Error in SHS implementation: Test 2 failed" );
                exit( -1 );
        }
        puts("Test 2 passed");
 
        shsInit( &shsInfo );
        for( i = 0; i < 15625; i++ )
                shsUpdate( &shsInfo, (BYTE *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64 );
        shsFinal( &shsInfo );
        if( shsInfo.digest[ 0 ] != 0x3232AFFAL || \
            shsInfo.digest[ 1 ] != 0x48628A26L || \
            shsInfo.digest[ 2 ] != 0x653B5AAAL || \
            shsInfo.digest[ 3 ] != 0x44541FD9L || \
            shsInfo.digest[ 4 ] != 0x0D690603L )
        {
                puts( "Error in SHS implementation: Test 3 failed" );
                exit( -1 );
        }
        puts("Test 3 passed");
 
        shsInit( &shsInfo );
        for( i = 0; i < 40000; i++ )
                shsUpdate( &shsInfo, (BYTE *)"aaaaaaaaaaaaaaaaaaaaaaaaa", 25 );
        shsFinal( &shsInfo );
        if( shsInfo.digest[ 0 ] != 0x3232AFFAL || \
            shsInfo.digest[ 1 ] != 0x48628A26L || \
            shsInfo.digest[ 2 ] != 0x653B5AAAL || \
            shsInfo.digest[ 3 ] != 0x44541FD9L || \
            shsInfo.digest[ 4 ] != 0x0D690603L )
        {
                puts( "Error in SHS implementation: Test 4 failed" );
                exit( -1 );
        }
        puts("Test 4 passed");
 
        shsInit( &shsInfo );
        for( i = 0; i < 8000; i++ )
                shsUpdate( &shsInfo, (BYTE *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 125 );
        shsFinal( &shsInfo );
        if( shsInfo.digest[ 0 ] != 0x3232AFFAL || \
            shsInfo.digest[ 1 ] != 0x48628A26L || \
            shsInfo.digest[ 2 ] != 0x653B5AAAL || \
            shsInfo.digest[ 3 ] != 0x44541FD9L || \
            shsInfo.digest[ 4 ] != 0x0D690603L )
        {
                puts( "Error in SHS implementation: Test 5 failed" );
                exit( -1 );
        }
        puts("Test 5 passed");
 
        /* Now perform time trial, generating MD for 10MB of data.  First,
           initialize the test data */
        memset( data, 0, TEST_BLOCK_SIZE );
 
        /* Get start time */
        printf( "SHS time trial.  Processing %ld characters...\n", TEST_BYTES );
        time( &startTime );
 
        /* Calculate SHS message digest in TEST_BLOCK_SIZE byte blocks */
        shsInit( &shsInfo );
        for( i = TEST_BLOCKS; i > 0; i-- )
                shsUpdate( &shsInfo, data, TEST_BLOCK_SIZE );
        shsFinal( &shsInfo );
 
        /* Get finish time and time difference */
        time( &endTime );
        printf( "Seconds to process test input: %ld\n", endTime - startTime );
        printf( "Characters processed per second: %ld\n", TEST_BYTES / ( endTime - startTime ) );
}
