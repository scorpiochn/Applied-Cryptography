/*
   crypt.c (full version) by Info-ZIP.        Last revised:  15 Aug 94

   This code is not copyrighted and is put in the public domain.  The
   encryption/decryption parts (as opposed to the non-echoing password
   parts) were originally written in Europe; the whole file can there-
   fore be freely distributed from any country except the USA.  If this
   code is imported into the USA, it cannot be re-exported from from
   there to another country.  (This restriction might seem curious, but
   this is what US law requires.)
 */

/* This encryption code is a direct transcription of the algorithm from
   Roger Schlafly, described by Phil Katz in the file appnote.txt.  This
   file (appnote.txt) is distributed with the PKZIP program (even in the
   version without encryption capabilities).
 */

#include "zip.h"
#include "crypt.h"

#ifndef PUTC
#  define PUTC putc
#endif

#ifndef UNZIP
#  ifdef BSD
#    define TEMP_BSD BSD
#    undef BSD
#  endif
#  include <sys/param.h>   /* this gets BSD4_4 on NET/2 and 4.4BSD systems */
#  if (defined(TEMP_BSD) && !defined(BSD))
#    define BSD TEMP_BSD
#    undef TEMP_BSD
#  endif
#  include <time.h>   /* time.h already included in unzip's zip.h */
#  if (defined(DOS_NT_OS2) && !defined(__GO32__))
#    include <process.h>
#  else
#    if !defined(BSD4_4) && !defined(SYSV)  /* getpid() in unistd.h */
       int  getpid OF((void));
#    endif
#  endif
#  ifndef __GNUC__
     void srand OF((unsigned int));
#  endif
   int rand OF((void));
#endif /* !UNZIP */

#if defined(LINUX) || defined(BSD4_4)  /* POSIX termio */
#  define TERMIOS
#else
#  if (defined(DIRENT) || defined(SYSV) || defined(CRAY))
     /* for now, assume DIRENT implies System V implies TERMIO */
#    if (!defined(NO_TERMIO) && !defined(TERMIO) && !defined(__MINT__))
#      define TERMIO
#    endif
#  endif
#endif /* LINUX || BSD4_4 */

#if (!defined(AMIGA) && !defined(MACOS))      /* (see crypt.h) */
#  if (defined(DOS_NT_OS2) || defined(VMS))
#    ifndef MSVMS
#      define MSVMS
#    endif
#    ifdef DOS_NT_OS2
#      ifdef __EMX__
#        define getch() _read_kbd(0, 1, 0)
#      else
#        ifdef __GO32__
#          include <pc.h>
#          define getch() getkey()
#        else /* !__GO32__ */
#          include <conio.h>
#        endif /* ?__GO32__ */
#      endif
#    else /* !DOS_NT_OS2 */
#      ifdef PASSWD_FROM_STDIN
#        define getch() getc(stdin)
#      else
#        define getch() getc(stderr)
#      endif
#      include <descrip.h>
#      include <iodef.h>
#      include <ttdef.h>
#      include <starlet.h>
#      if !defined(SS$_NORMAL)
#        define SS$_NORMAL 1   /* only thing we need from <ssdef.h> */
#      endif
#    endif /* ?DOS_NT_OS2 */
#  else /* !(DOS_NT_OS2 || VMS) */
#    ifdef TERMIOS
#      include <termios.h>
#      define sgttyb termios
#      define sg_flags c_lflag
#      define GTTY(f, s) tcgetattr(f, (voidp *) s)
#      define STTY(f, s) tcsetattr(f, TCSAFLUSH, (voidp *) s)
#    else /* !TERMIOS */
#       ifdef TERMIO       /* Amdahl, Cray, all SysV? */
#         ifdef COHERENT
#           include <termio.h>
#         else
#             include <sys/termio.h>
#         endif /* ?COHERENT */
#         define sgttyb termio
#         define sg_flags c_lflag
#         ifndef SYSV
            int ioctl OF((int, int, voidp *)); /* already in unistd.h */
#         endif
#         define GTTY(f,s) ioctl(f,TCGETA,(voidp *)s)
#         define STTY(f,s) ioctl(f,TCSETAW,(voidp *)s)
#       else /* !TERMIO */
#         ifndef MINIX
#           include <sys/ioctl.h>
#         endif /* !MINIX */
#         include <sgtty.h>
#         define GTTY gtty
#         define STTY stty
          int gtty OF((int, struct sgttyb *));
          int stty OF((int, struct sgttyb *));
#       endif /* ?TERMIO */
#    endif /* ?TERMIOS */
#    if defined(BSD4_4) || defined(SYSV) || defined(__convexc__)
#      ifndef UNZIP
#        include <fcntl.h>
#      endif
#    else
       char *ttyname OF((int));
#    endif
#  endif /* ?(DOS_NT_OS2 || VMS) */
#endif /* !AMIGA && !MACOS */

#ifdef UNZIP
   char *key = (char *)NULL;  /* password with which to decrypt data, or NULL */
#  ifndef FUNZIP
     local int testp OF((uch *h));
#  endif
#endif /* UNZIP */

local ulg keys[3]; /* keys defining the pseudo-random sequence */

#ifndef Trace
#  ifdef CRYPT_DEBUG
#    define Trace(x) fprintf x
#  else
#    define Trace(x)
#  endif
#endif

/***********************************************************************
 * Return the next byte in the pseudo-random sequence
 */
int decrypt_byte()
{
   ush temp;

   temp = (ush)keys[2] | 2;
   return (int)(((ush)(temp * (temp ^ 1)) >> 8) & 0xff);
}

/***********************************************************************
 * Update the encryption keys with the next byte of plain text
 */
int update_keys(c)
    int c;                  /* byte of plain text */
{
    keys[0] = CRC32(keys[0], c);
    keys[1] += keys[0] & 0xff;
    keys[1] = keys[1] * 134775813L + 1;
    keys[2] = CRC32(keys[2], (int)(keys[1] >> 24));
    return c;
}


/***********************************************************************
 * Initialize the encryption keys and the random header according to
 * the given password.
 */
void init_keys(passwd)
    char *passwd;             /* password string with which to modify keys */
{
    keys[0] = 305419896L;
    keys[1] = 591751049L;
    keys[2] = 878082192L;
    while (*passwd != '\0') {
        update_keys((int)*passwd);
        passwd++;
    }
}


#ifndef UNZIP

/***********************************************************************
 * Write encryption header to file zfile using the password passwd
 * and the cyclic redundancy check crc.
 */
void crypthead(passwd, crc, zfile)
    char *passwd;                /* password string */
    ulg crc;                     /* crc of file being encrypted */
    FILE *zfile;                 /* where to write header */
{
    int n;                       /* index in random header */
    int t;                       /* temporary */
    int c;                       /* random byte */
    int ztemp;                   /* temporary for zencoded value */
    uch header[RAND_HEAD_LEN-2]; /* random header */
    static unsigned calls = 0;   /* ensure different random header each time */

    /* First generate RAND_HEAD_LEN-2 random bytes. We encrypt the
     * output of rand() to get less predictability, since rand() is
     * often poorly implemented.
     */
    if (++calls == 1) {
        srand((unsigned)time(NULL) ^ getpid());
    }
    init_keys(passwd);
    for (n = 0; n < RAND_HEAD_LEN-2; n++) {
        c = (rand() >> 7) & 0xff;
        header[n] = (uch)zencode(c, t);
    }
    /* Encrypt random header (last two bytes is high word of crc) */
    init_keys(passwd);
    for (n = 0; n < RAND_HEAD_LEN-2; n++) {
        ztemp = zencode(header[n], t);
        putc(ztemp, zfile);
    }
    ztemp = zencode((int)(crc >> 16) & 0xff, t);
    putc(ztemp, zfile);
    ztemp = zencode((int)(crc >> 24) & 0xff, t);
    putc(ztemp, zfile);
}


#ifdef UTIL

/***********************************************************************
 * Encrypt the zip entry described by z from file source to file dest
 * using the password passwd.  Return an error code in the ZE_ class.
 */
int zipcloak(z, source, dest, passwd)
    struct zlist far *z;    /* zip entry to encrypt */
    FILE *source, *dest;    /* source and destination files */
    char *passwd;           /* password string */
{
    int c;                  /* input byte */
    int res;                /* result code */
    ulg n;                  /* holds offset and counts size */
    ush flag;               /* previous flags */
    int t;                  /* temporary */
    int ztemp;              /* temporary storage for zencode value */

    /* Set encrypted bit, clear extended local header bit and write local
       header to output file */
    if ((n = ftell(dest)) == -1L) return ZE_TEMP;
    z->off = n;
    flag = z->flg;
    z->flg |= 1,  z->flg &= ~8;
    z->lflg |= 1, z->lflg &= ~8;
    z->siz += RAND_HEAD_LEN;
    if ((res = putlocal(z, dest)) != ZE_OK) return res;

    /* Initialize keys with password and write random header */
    crypthead(passwd, z->crc, dest);

    /* Skip local header in input file */
    if (fseek(source, (long)(4 + LOCHEAD + (ulg)z->nam + (ulg)z->ext),
              SEEK_CUR)) {
        return ferror(source) ? ZE_READ : ZE_EOF;
    }

    /* Encrypt data */
    for (n = z->siz - RAND_HEAD_LEN; n; n--) {
        if ((c = getc(source)) == EOF) {
            return ferror(source) ? ZE_READ : ZE_EOF;
        }
        ztemp = zencode(c, t);
        putc(ztemp, dest);
    }
    /* Skip extended local header in input file if there is one */
    if ((flag & 8) != 0 && fseek(source, 16L, SEEK_CUR)) {
        return ferror(source) ? ZE_READ : ZE_EOF;
    }
    if (fflush(dest) == EOF) return ZE_TEMP;
    return ZE_OK;
}

/***********************************************************************
 * Decrypt the zip entry described by z from file source to file dest
 * using the password passwd.  Return an error code in the ZE_ class.
 */
int zipbare(z, source, dest, passwd)
    struct zlist far *z;  /* zip entry to encrypt */
    FILE *source, *dest;  /* source and destination files */
    char *passwd;         /* password string */
{
    int c0, c1;           /* last two input bytes */
    ulg offset;           /* used for file offsets */
    ulg size;             /* size of input data */
    int r;                /* size of encryption header */
    int res;              /* return code */
    ush flag;             /* previous flags */

    /* Save position and skip local header in input file */
    if ((offset = ftell(source)) == -1L ||
        fseek(source, (long)(4 + LOCHEAD + (ulg)z->nam + (ulg)z->ext),
              SEEK_CUR)) {
        return ferror(source) ? ZE_READ : ZE_EOF;
    }
    /* Initialize keys with password */
    init_keys(passwd);

    /* Decrypt encryption header, save last two bytes */
    c1 = 0;
    for (r = RAND_HEAD_LEN; r; r--) {
        c0 = c1;
        if ((c1 = getc(source)) == EOF) {
            return ferror(source) ? ZE_READ : ZE_EOF;
        }
        Trace((stdout, " (%02x)", c1));
        zdecode(c1);
        Trace((stdout, " %02x", c1));
    }
    Trace((stdout, "\n"));

    /* If last two bytes of header don't match crc (or file time in the
     * case of an extended local header), back up and just copy. For
     * pkzip 2.0, the check has been reduced to one byte only.
     */
#ifdef ZIP10
    if ((ush)(c0 | (c1<<8)) !=
        (z->flg & 8 ? (ush) z->tim & 0xffff : (ush)(z->crc >> 16))) {
#else
    c0++; /* avoid warning on unused variable */
    if ((ush)c1 != (z->flg & 8 ? (ush) z->tim >> 8 : (ush)(z->crc >> 24))) {
#endif
        if (fseek(source, offset, SEEK_SET)) {
            return ferror(source) ? ZE_READ : ZE_EOF;
        }
        if ((res = zipcopy(z, source, dest)) != ZE_OK) return res;
        return ZE_MISS;
    }

    /* Clear encrypted bit and local header bit, and write local header to
       output file */
    if ((offset = ftell(dest)) == -1L) return ZE_TEMP;
    z->off = offset;
    flag = z->flg;
    z->flg &= ~9;
    z->lflg &= ~9;
    z->siz -= RAND_HEAD_LEN;
    if ((res = putlocal(z, dest)) != ZE_OK) return res;

    /* Decrypt data */
    for (size = z->siz; size; size--) {
        if ((c1 = getc(source)) == EOF) {
            return ferror(source) ? ZE_READ : ZE_EOF;
        }
        zdecode(c1);
        putc(c1, dest);
    }
    /* Skip extended local header in input file if there is one */
    if ((flag & 8) != 0 && fseek(source, 16L, SEEK_CUR)) {
        return ferror(source) ? ZE_READ : ZE_EOF;
    }
    if (fflush(dest) == EOF) return ZE_TEMP;

    return ZE_OK;
}


#else /* !UTIL */

/***********************************************************************
 * If requested, encrypt the data in buf, and in any case call fwrite()
 * with the arguments to zfwrite().  Return what fwrite() returns.
 */
unsigned zfwrite(buf, item_size, nb, f)
    voidp *buf;                /* data buffer */
    extent item_size;          /* size of each item in bytes */
    extent nb;                 /* number of items */
    FILE *f;                   /* file to write to */
{
    int t;                    /* temporary */

    if (key != (char *)NULL) { /* key is the global password pointer */
        ulg size;              /* buffer size */
        char *p = (char*)buf;  /* steps through buffer */

        /* Encrypt data in buffer */
        for (size = item_size*(ulg)nb; size != 0; p++, size--) {
            *p = (char)zencode(*p, t);
        }
    }
    /* Write the buffer out */
    return fwrite(buf, item_size, nb, f);
}

#endif /* ?UTIL */
#endif /* !UNZIP */


#ifdef VMS

/***********************************************************************
 * Turn keyboard echoing on or off (VMS).  Loosely based on VMSmunch.c
 * and hence on Joe Meadows' file.c code.
 */
int echo(opt)
    int opt;
{
    /*
     * For VMS v5.x:
     *   IO$_SENSEMODE/SETMODE info:  Programming, Vol. 7A, System Programming,
     *     I/O User's: Part I, sec. 8.4.1.1, 8.4.3, 8.4.5, 8.6
     *   sys$assign(), sys$qio() info:  Programming, Vol. 4B, System Services,
     *     System Services Reference Manual, pp. sys-23, sys-379
     *   fixed-length descriptor info:  Programming, Vol. 3, System Services,
     *     Intro to System Routines, sec. 2.9.2
     * GRR, 15 Aug 91
     */

    static struct dsc$descriptor_s DevDesc =
        {9, DSC$K_DTYPE_T, DSC$K_CLASS_S, "SYS$INPUT"};
     /* {dsc$w_length, dsc$b_dtype, dsc$b_class, dsc$a_pointer}; */
    static short           DevChan, iosb[4];
    static long            i, status;
    static unsigned long   oldmode[2], newmode[2];   /* each = 8 bytes */
  

    /* assign a channel to standard input */
    status = sys$assign(&DevDesc, &DevChan, 0, 0);
    if (!(status & 1))
        return status;

    /* use sys$qio and the IO$_SENSEMODE function to determine the current
     * tty status (for password reading, could use IO$_READVBLK function
     * instead, but echo on/off will be more general)
     */
    status = sys$qio(0, DevChan, IO$_SENSEMODE, &iosb, 0, 0,
                     oldmode, 8, 0, 0, 0, 0);
    if (!(status & 1))
        return status;
    status = iosb[0];
    if (!(status & 1))
        return status;

    /* copy old mode into new-mode buffer, then modify to be either NOECHO or
     * ECHO (depending on function argument opt)
     */
    newmode[0] = oldmode[0];
    newmode[1] = oldmode[1];
    if (opt == 0)   /* off */
        newmode[1] |= TT$M_NOECHO;                      /* set NOECHO bit */
    else
        newmode[1] &= ~((unsigned long) TT$M_NOECHO);   /* clear NOECHO bit */

    /* use the IO$_SETMODE function to change the tty status */
    status = sys$qio(0, DevChan, IO$_SETMODE, &iosb, 0, 0,
                     newmode, 8, 0, 0, 0, 0);
    if (!(status & 1))
        return status;
    status = iosb[0];
    if (!(status & 1))
        return status;

    /* deassign the sys$input channel by way of clean-up */
    status = sys$dassgn(DevChan);
    if (!(status & 1))
        return status;

    return SS$_NORMAL;   /* we be happy */

} /* end function echo() */


#else /* !VMS */
#if (!defined(DOS_NT_OS2) && !defined(AMIGA) && !defined(MACOS))

static int echofd=(-1);       /* file descriptor whose echo is off */

/***********************************************************************
 * Turn echo off for file descriptor f.  Assumes that f is a tty device.
 */
void echoff(f)
    int f;                    /* file descriptor for which to turn echo off */
{
    struct sgttyb sg;         /* tty device structure */

    echofd = f;
    GTTY(f, &sg);             /* get settings */
    sg.sg_flags &= ~ECHO;     /* turn echo off */
    STTY(f, &sg);
}

/***********************************************************************
 * Turn echo back on for file descriptor echofd.
 */
void echon()
{
    struct sgttyb sg;         /* tty device structure */

    if (echofd != -1) {
        GTTY(echofd, &sg);    /* get settings */
        sg.sg_flags |= ECHO;  /* turn echo on */
        STTY(echofd, &sg);
        echofd = -1;
    }
}

#endif /* !(DOS_NT_OS2 || AMIGA || MACOS) */
#endif /* ?VMS */

#ifdef AMIGA

/***********************************************************************
 * Get a password of length n-1 or less into *p using the prompt *m.
 * The entered password is not echoed. 
 *
 * On AMIGA, SAS/C 6.x provides raw console input via getch().  This is
 * also available in SAS/C 5.10b, if the separately chargeable ANSI
 * libraries are used.
 *
 * Aztec C provides functions set_raw() and set_con() which we use for
 * echoff() and echon().
 *
 * Code for other compilers needs to provide routines or macros for
 * echoff() and echon() to either send ACTION_SET_CONSOLE packets or
 * provice "pseudo non-echo" input by setting the background and
 * foreground colors the same.  Then, only spaces visibly echo.  This
 * approach is the default in crypt.h.  Unfortunately, the cursor
 * cannot be held stationary during input because the standard getc()
 * and getchar() system routines buffer input until CR entered (due to
 * the lack of switchable raw I/O).  This may be considered an
 * advantage since it allows feedback for backspacing errors.
 *
 * Simulating true raw I/O on systems without getch() introduces
 * undesirable complexity and overhead, so we'll live with this 
 * simpler method for those compilers.  
 */
char *getp(m, p, n)

    char *m,*p;
    int n;
{
    int i;
    int c;

    fputs (m,stderr);                      /* display prompt and flush */
    fflush(stderr);

    echoff(2);

    i = 0;
    while ( i <= n ) {
       c=getch();
       if ( (c == '\n') || (c == '\r')) break;   /* until user hits CR */
       if (c == 0x03) {  /* ^C in input */
           Signal(FindTask(NULL), SIGBREAKF_CTRL_C);
           break;
       }
       if (i < n) p[i++]=(char)c;                   /* truncate past n */
    }

    ECHO_NEWLINE();
    echon();

    i = (i<n) ? i : (n-1);
    p[i]=0;                                        /* terminate string */
    return p;
}

#endif /* AMIGA */



#ifdef DOS_NT_OS2

char *getp(m, p, n)
    char *m;                /* prompt for password */
    char *p;                /* return value: line input */
    int n;                  /* bytes available in p[] */
{
    char c;                 /* one-byte buffer for read() to use */
    int i;                  /* number of characters input */
    char *w;                /* warning on retry */

    /* get password */
    w = "";
    do {
        fputs(w, stderr);   /* warning if back again */
        fputs(m, stderr);   /* prompt */
        fflush(stderr);
        i = 0;
        do {                /* read line, keeping n */
            if ((c = (char)getch()) == '\r')
                c = '\n';
            if (i < n)
                p[i++] = c;
        } while (c != '\n');
        PUTC('\n', stderr);  fflush(stderr);
        w = "(line too long--try again)\n";
    } while (p[i-1] != '\n');
    p[i-1] = 0;               /* terminate at newline */

    /* return pointer to password */
    return p;
}

#endif /* DOS_NT_OS2 */



#ifdef MACOS

char *getp(m, p, n)
    char *m;                /* prompt for password */
    char *p;                /* return value: line input */
    int n;                  /* bytes available in p[] */
{
    WindowPtr whichWindow;
    EventRecord theEvent;
    char c;                 /* one-byte buffer for read() to use */
    int i;                  /* number of characters input */
    char *w;                /* warning on retry */

    /* get password */
    w = "";
    do {
        fputs(w, stderr);   /* warning if back again */
        fputs(m, stderr);   /* prompt */
        i = 0;
        do {                /* read line, keeping n */
            do {
                SystemTask();
                if (!GetNextEvent(everyEvent, &theEvent))
                    theEvent.what = nullEvent;
                else {
                    switch (theEvent.what) {
                    case keyDown:
                        c = theEvent.message & charCodeMask;
                        break;
                    case mouseDown:
                        if (FindWindow(theEvent.where, &whichWindow) ==
                            inSysWindow)
                            SystemClick(&theEvent, whichWindow);
                        break;
                    case updateEvt:
#ifdef UNZIP
                        screenUpdate((WindowPtr)theEvent.message);
#endif
                        break;
                    }
                }
            } while (theEvent.what != keyDown);
            if (i < n)
                p[i++] = c;
        } while (c != '\r');
        PUTC('\n', stderr);
        w = "(line too long--try again)\n";
    } while (p[i-1] != '\r');
    p[i-1] = 0;               /* terminate at newline */

    /* return pointer to password */
    return p;
}

#endif /* MACOS */



#if (defined(UNIX) || defined(__MINT__))

char *getp(m, p, n)
    char *m;                  /* prompt for password */
    char *p;                  /* return value: line input */
    int n;                    /* bytes available in p[] */
{
    char c;                   /* one-byte buffer for read() to use */
    int i;                    /* number of characters input */
    char *w;                  /* warning on retry */
    int f;                    /* file descriptor for tty device */

#ifdef PASSWD_FROM_STDIN
    /* Read from stdin. This is unsafe if the password is stored on disk. */
    f = 0;
#else
    /* turn off echo on tty */
    if (!isatty(2))
        return NULL;          /* error if not tty */

    /* Convex C seems to want (char *) in front of ttyname:  compiler bug? */
    if ((f = open((char *)ttyname(2), 0)) == -1)
        return NULL;
#endif
    /* get password */
    w = "";
    do {
        fputs(w, stderr);     /* warning if back again */
        fputs(m, stderr);     /* prompt */
        fflush(stderr);
        i = 0;
        echoff(f);
        do {                  /* read line, keeping n */
            read(f, &c, 1);
            if (i < n)
                p[i++] = c;
        } while (c != '\n');
        echon();
        PUTC('\n', stderr);  fflush(stderr);
        w = "(line too long--try again)\n";
    } while (p[i-1] != '\n');
    p[i-1] = 0;               /* terminate at newline */

#ifndef PASSWD_FROM_STDIN
    close(f);
#endif
    /* return pointer to password */
    return p;
}

#endif /* UNIX || __MINT__ */

#ifdef VMS

char *getp(m, p, n)
    char *m;                  /* prompt for password */
    char *p;                  /* return value: line input */
    int n;                    /* bytes available in p[] */
{
    char c;                   /* one-byte buffer for read() to use */
    int i;                    /* number of characters input */
    char *w;                  /* warning on retry */

    /* get password */
    w = "";
    do {
        if (*w)               /* bug: VMS adds \n to NULL fputs (apparently) */
            fputs(w, stderr); /* warning if back again */
        fputs(m, stderr);     /* prompt */
        fflush(stderr);
        i = 0;
        echoff(f);
        do {                  /* read line, keeping n */
            if ((c = (char)getch()) == '\r')
                c = '\n';
            if (i < n)
                p[i++] = c;
        } while (c != '\n');
        echon();
        PUTC('\n', stderr);  fflush(stderr);
        w = "(line too long--try again)\n";
    } while (p[i-1] != '\n');
    p[i-1] = 0;               /* terminate at newline */

    /* return pointer to password */
    return p;
}

#endif /* VMS */



#if (defined(UNZIP) && !defined(FUNZIP))

/***********************************************************************
 * Get the password and set up keys for current zipfile member.  Return
 * PK_ class error.
 */
int decrypt()
{
    ush b;
    int n, r;
    static int nopwd=FALSE;
    char *m, *prompt;
    uch h[RAND_HEAD_LEN];

    Trace((stdout, "\n[incnt = %d]: ", incnt));

    /* get header once (turn off "encrypted" flag temporarily so we don't
     * try to decrypt the same data twice) */
    pInfo->encrypted = FALSE;
    for (n = 0; n < RAND_HEAD_LEN; n++) {
        b = NEXTBYTE;
        h[n] = (uch)b;
        Trace((stdout, " (%02x)", h[n]));
    }
    pInfo->encrypted = TRUE;

    if (newzip) {         /* this is first encrypted member in this zipfile */
        newzip = FALSE;
        if (key) {        /* get rid of previous zipfile's key */
            free(key);
            key = (char *)NULL;
        }
    }

    /* if have key already, test it; else allocate memory for it */
    if (key) {
        if (!testp(h))
            return PK_COOL;   /* existing password OK (else prompt for new) */
        else if (nopwd)
            return PK_WARN;   /* user indicated no more prompting */
    } else if ((key = (char *)malloc(PWLEN+1)) == (char *)NULL)
        return PK_MEM2;

    if ((prompt = (char *)malloc(FILNAMSIZ+15)) != (char *)NULL) {
        sprintf(prompt, "[%s] %s password: ", zipfn, filename);
        m = prompt;
    } else
        m = "Enter password: ";

    /* try a few keys */
    for (r = 0;  r < 3;  ++r) {
        m = getp(m, key, PWLEN+1);
        if (prompt != (char *)NULL) {
            free(prompt);
            prompt = (char *)NULL;
        }
        if (m == (char *)NULL)
            return PK_MEM2;
        if (!testp(h))
            return PK_COOL;
        if (*key == '\0') {
            nopwd = TRUE;
            return PK_WARN;
        }
        m = "password incorrect--reenter: ";
    }
    return PK_WARN;
} /* end function decrypt() */

/***********************************************************************
 * Test the password.  Return -1 if bad, 0 if OK.
 */
local int testp(h)
    uch *h;
{
    ush b, c;
    int n;
    uch *p;
    uch hh[RAND_HEAD_LEN]; /* decrypted header */

    /* set keys and save the encrypted header */
    init_keys(key);
    memcpy(hh, h, RAND_HEAD_LEN);

    /* check password */
    for (n = 0; n < RAND_HEAD_LEN; n++) {
        zdecode(hh[n]);
        Trace((stdout, " %02x", hh[n]));
    }
    c = hh[RAND_HEAD_LEN-2], b = hh[RAND_HEAD_LEN-1];

    Trace((stdout,
      "\n  lrec.crc= %08lx  crec.crc= %08lx  pInfo->ExtLocHdr= %s\n",
      lrec.crc32, pInfo->crc, pInfo->ExtLocHdr? "true":"false"));
    Trace((stdout, "  incnt = %d  unzip offset into zipfile = %ld\n", incnt,
      cur_zipfile_bufstart+(inptr-inbuf)));

    /* same test as in zipbare(): */

#ifdef ZIP10 /* check two bytes */
    Trace((stdout,
      "  (c | (b<<8)) = %04x  (crc >> 16) = %04x  lrec.time = %04x\n",
      (ush)(c | (b<<8)), (ush)(lrec.crc32 >> 16), lrec.last_mod_file_time));
    if ((ush)(c | (b<<8)) != (pInfo->ExtLocHdr? lrec.last_mod_file_time :
        (ush)(lrec.crc32 >> 16)))
        return -1;  /* bad */
#else
    Trace((stdout, "  b = %02x  (crc >> 24) = %02x  (lrec.time >> 8) = %02x\n",
      b, (ush)(lrec.crc32 >> 24), (lrec.last_mod_file_time >> 8)));
    if (b != (pInfo->ExtLocHdr? lrec.last_mod_file_time >> 8 :
        (ush)(lrec.crc32 >> 24)))
        return -1;  /* bad */
    c++;            /* avoid warning on unused variable */
#endif
    /* password OK:  decrypt current buffer contents before leaving */
    for (n = (long)incnt > csize ? (int)csize : incnt, p = inptr; n--; p++)
        zdecode(*p);
    return 0;       /* OK */

} /* end function testp() */

#endif /* UNZIP && !FUNZIP */
