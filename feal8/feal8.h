/*
Version of 20 September 1989.
*/

typedef unsigned char ByteType ;

void SetKey( ByteType * ) ;
void Encrypt( ByteType *Plain, ByteType *Cipher ) ;
void Decrypt( ByteType *Cipher, ByteType *Plain ) ;
