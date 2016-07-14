/*
   crypt.h (full version) by Info-ZIP.       Last revised:  8 Jan 94

   This header file is not copyrighted and may be distributed without
   restriction.
 */

#ifndef __crypt_h   /* don't include more than once */
#define __crypt_h

#ifndef CRYPT
#  define CRYPT     /* full version */
#endif

#define PWLEN  80   /* input buffer size for reading encryption key */
#define RAND_HEAD_LEN  12    /* length of encryption random header */

/* encode byte c, using temp t.  Warning: c must not have side effects. */
#define zencode(c,t)  (t=decrypt_byte(), update_keys(c), t^(c))

/* decode byte c in place */
#define zdecode(c)   update_keys(c ^= decrypt_byte())

int  decrypt_byte OF((void));
int  update_keys OF((int c));
void init_keys OF((char *passwd));
void crypthead OF((char *, ulg, FILE *));
char *getp OF((char *m, char *p, int n));
int  decrypt OF((void));

#ifdef UTIL
   int zipcloak OF((struct zlist far *, FILE *, FILE *, char *));
   int zipbare OF((struct zlist far *, FILE *, FILE *, char *));
#else /* !UTIL */
   unsigned zfwrite OF((voidp *, extent, extent, FILE *));
   extern char *key;
#endif /* ?UTIL */

#ifdef UNZIP
   extern int newzip;
#endif

#ifdef FUNZIP
   extern int encrypted;
#  ifdef NEXTBYTE
#    undef NEXTBYTE
#  endif
#  define NEXTBYTE (encrypted? update_keys(getc(in)^decrypt_byte()) : getc(in))
#endif /* FUNZIP */

#ifdef VMS
#  define echoff(f)  echo(0)
#  define echon()    echo(1)
   int echo OF((int));
#else
   void echoff OF((int));
   void echon OF((void));
#endif

#if defined(MSDOS) || defined(OS2) || defined(__human68k__) || defined(WIN32)
#  ifndef DOS_NT_OS2
#    define DOS_NT_OS2
#  endif
#endif

#ifdef TOPS20
#  define decrypt_byte   dcrbyt
#endif

#ifdef AMIGA
#  ifndef SIGBREAKF_CTRL_C
#    define SIGBREAKF_CTRL_C (1L << 12)
#  endif
#  if (defined(UNZIP) && !defined(CLIB_EXEC_PROTOS_H))
     void Signal(void *, long), *FindTask(void *);
#  endif
#  ifndef EPIPE
#    define EPIPE  9999     /* (errno == EPIPE) always false */
#  endif
   /* Note: getpid() is only used for random number seeding */
#  define getpid()  (long) FindTask(NULL)       /* more secure than pi */
#  ifdef __SASC_60
#    define echoff(f)  /* rawcon(1) */
#    define echon()    /* rawcon(0) */
#    define ECHO_NEWLINE()   putc('\n', stderr)
#  else
#    define getch getchar
#    ifdef AZTEC_C
#      define echoff(f)      set_raw()
#      define echon()        set_con()
#      define ECHO_NEWLINE() putc('\n', stderr)
#    else
#      define echoff(f)      { fputs("\033[30;40m",stderr);fflush(stderr); }
#      define echon()        { fputs("\033[31;40m",stderr);fflush(stderr); }
#      define ECHO_NEWLINE()
#    endif
#  endif
#endif

#ifdef MACOS
#  define getpid()     3141592654L   /* return PI for PID */
#endif

#endif /* !__crypt_h */
