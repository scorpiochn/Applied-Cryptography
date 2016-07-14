/*--- ripemglo.h -- Header file for global variables ----------- */

#define LINEBUFSIZE  200

DEF char ErrMsgTxt[LINEBUFSIZE];

DEF FILE *DebugStream
#ifdef MAIN
 = stderr
#endif
;

DEF FILE *CertinfoStream
#ifdef MAIN
 = stderr
#endif
;

DEF int Debug
#ifdef MAIN
=FALSE
#endif
;

DEF char *KeyToPrivKey
#ifdef MAIN
=NULL
#endif
;

DEF char *NewKeyToPrivKey
#ifdef MAIN
=NULL
#endif
;
