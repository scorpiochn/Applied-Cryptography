/*
   This code is not copyrighted and is put in the public domain. It
   was originally written in Europe and can be freely distributed from
   any country except the U.S.A. If this code is imported in the U.S.A,
   it cannot be re-exported from the U.S.A to another country. (This
   restriction might seem curious but this is what US law requires.)
 */

#define UTIL
#include "revision.h"
#include "zip.h"
#include "crypt.h"
#include <signal.h>
#ifdef MSDOS
#  include <stdlib.h>
#endif


/* Local functions */
void err OF((int code, char *msg));

#ifdef CRYPT   /* defined (or not) in crypt.h */

local void handler OF((int sig));
local void license OF((void));
local void help OF((void));
void main OF((int argc, char **argv));

/* Temporary zip file name and file pointer */
local char *tempzip;
local FILE *tempzf;

#endif

/***********************************************************************
 * Issue a message for the error, clean up files and memory, and exit.
 */
void err(code, msg)
    int code;               /* error code from the ZE_ class */
    char *msg;              /* message about how it happened */
{
#ifdef CRYPT
    if (PERR(code)) perror("zipcloak error");
    fprintf(stderr, "zipcloak error: %s (%s)\n", errors[code-1], msg);
    if (tempzf != NULL) fclose(tempzf);
    if (tempzip != NULL) {
        destroy(tempzip);
        free((voidp *)tempzip);
    }
    if (zipfile != NULL) free((voidp *)zipfile);
#endif
#ifdef VMS
    exit(0);
#else
    exit(code);
#endif
}

/***********************************************************************
 * Print a warning message to stderr and return.
 */
void warn(msg1, msg2)
    char *msg1, *msg2;        /* message strings juxtaposed in output */
{
    fprintf(stderr, "zipcloak warning: %s%s\n", msg1, msg2);
}

#ifdef CRYPT

/***********************************************************************
 * Upon getting a user interrupt, turn echo back on for tty and abort
 * cleanly using err().
 */
local void handler(sig)
    int sig;                  /* signal number (ignored) */
{
#if !defined(MSDOS) && !defined(__human68k__)
    echon();
    putc('\n', stderr);
#endif
    err(ZE_ABORT +sig-sig, "aborting");
    /* dummy usage of sig to avoid compiler warnings */
}


static char *public[] = {
"The encryption code of this program is not copyrighted and is put in the",
"public domain. It was originally written in Europe and can be freely",
"distributed from any country except the U.S.A. If this program is imported",
"in the U.S.A, it cannot be re-exported from the U.S.A to another country.",
"The copyright notice of the zip program applies to the rest of the code."
};

/***********************************************************************
 * Print license information to stdout.
 */
local void license()
{
    extent i;             /* counter for copyright array */

    for (i = 0; i < sizeof(public)/sizeof(char *); i++) {
        puts(public[i]);
    }
    for (i = 0; i < sizeof(disclaimer)/sizeof(char *); i++) {
        puts(disclaimer[i]);
    }
}


static char *help_info[] = {
"",
"ZipCloak %s (%s)",
"Usage:  zipcloak [-d] [-b path] zipfile",
"  the default action is to encrypt all unencrypted entries in the zip file",
"  -d   decrypt--decrypt encrypted entries (copy if given wrong password)",
"  -b   use \"path\" for the temporary zip file",
"  -h   show this help               -L   show software license"
  };

/***********************************************************************
 * Print help (along with license info) to stdout.
 */
local void help()
{
    extent i;             /* counter for help array */

    for (i = 0; i < sizeof(public)/sizeof(char *); i++) {
        puts(public[i]);
    }
    for (i = 0; i < sizeof(help_info)/sizeof(char *); i++) {
        printf(help_info[i], VERSION, REVDATE);
        putchar('\n');
    }
}


/***********************************************************************
 * Encrypt or decrypt all of the entries in a zip file.  See the command
 * help in help() above.
 */

void main(argc, argv)
    int argc;             /* number of tokens in command line */
    char **argv;          /* command line tokens */
{
    int attr;             /* attributes of zip file */
    ulg start_offset;     /* start of central directory */
    int decrypt;          /* decryption flag */
    int temp_path;        /* 1 if next argument is path for temp files */
    char passwd[PWLEN+1]; /* password for encryption or decryption */
    char *q;              /* steps through option arguments */
    int r;                /* arg counter */
    int res;              /* result code */
    ulg length;           /* length of central directory */
    FILE *inzip, *outzip; /* input and output zip files */
    struct zlist far *z;  /* steps through zfiles linked list */


    /* If no args, show help */
    if (argc == 1) {
        help();
        exit(0);
    }

    init_upper();           /* build case map table */

    /* Go through args */
    zipfile = tempzip = NULL;
    tempzf = NULL;
    signal(SIGINT, handler);
#ifdef SIGTERM                /* Some don't have SIGTERM */
    signal(SIGTERM, handler);
#endif
    temp_path = decrypt = 0;
    for (r = 1; r < argc; r++) {
        if (*argv[r] == '-') {
            if (!argv[r][1]) err(ZE_PARMS, "zip file cannot be stdin");
            for (q = argv[r]+1; *q; q++) {
                switch(*q) {
                case 'b':   /* Specify path for temporary file */
                    if (temp_path) {
                        err(ZE_PARMS, "use -b before zip file name");
                    }
                    temp_path = 1;          /* Next non-option is path */
                    break;
                case 'd':
                    decrypt = 1;  break;
                case 'h':   /* Show help */
                    help();
                    exit(0);
                case 'l': case 'L':  /* Show copyright and disclaimer */
                    license();
                    exit(0);
                default:
                    err(ZE_PARMS, "unknown option");
                } /* switch */
            } /* for */

        } else if (temp_path == 0) {
            if (zipfile != NULL) {
                err(ZE_PARMS, "can only specify one zip file");

            } else if ((zipfile = ziptyp(argv[r])) == NULL) {
                err(ZE_MEM, "was processing arguments");
            }
        } else {
            tempath = argv[r];
            temp_path = 0;
        } /* if */
    } /* for */

    if (zipfile == NULL) err(ZE_PARMS, "need to specify zip file");

    /* Read zip file */
    if ((res = readzipfile()) != ZE_OK) err(res, zipfile);
    if (zfiles == NULL) err(ZE_NAME, zipfile);

    /* Check for something to do */
    for (z = zfiles; z != NULL; z = z->nxt) {
        if (decrypt ? z->flg & 1 : !(z->flg & 1)) break;
    }
    if (z == NULL) {
        err(ZE_NONE, decrypt ? "no encrypted files"
                       : "all files encrypted already");
    }

    /* Before we get carried away, make sure zip file is writeable */
    if ((inzip = fopen(zipfile, "a")) == NULL) err(ZE_CREAT, zipfile);
    fclose(inzip);
    attr = getfileattr(zipfile);

    /* Open output zip file for writing */
    if ((tempzf = outzip = fopen(tempzip = tempname(zipfile), FOPW)) == NULL) {
        err(ZE_TEMP, tempzip);
    }

    /* Get password */
    if (getp("Enter password: ", passwd, PWLEN+1) == NULL) {
        err(ZE_PARMS, "stderr is not a tty (you may never see this message!)");
    }

    /* Open input zip file again, copy preamble if any */
    if ((inzip = fopen(zipfile, FOPR)) == NULL) err(ZE_NAME, zipfile);

    if (zipbeg && (res = fcopy(inzip, outzip, zipbeg)) != ZE_OK) {
        err(res, res == ZE_TEMP ? tempzip : zipfile);
    }
    /* Go through local entries, copying, encrypting, or decrypting */
    for (z = zfiles; z != NULL; z = z->nxt) {
        if (decrypt && (z->flg & 1)) {
            printf("decrypting: %s", z->zname);
            fflush(stdout);
            if ((res = zipbare(z, inzip, outzip, passwd)) != ZE_OK) {
                if (res != ZE_MISS) err(res, "was decrypting an entry");
                printf(" (wrong password--just copying)");
            }
            putchar('\n');

        } else if ((!decrypt) && !(z->flg & 1)) {
            printf("encrypting: %s\n", z->zname);
            fflush(stdout);
            if ((res = zipcloak(z, inzip, outzip, passwd)) != ZE_OK) {
                err(res, "was encrypting an entry");
            }
        } else {
            printf("   copying: %s\n", z->zname);
            fflush(stdout);
            if ((res = zipcopy(z, inzip, outzip)) != ZE_OK) {
                err(res, "was copying an entry");
            }
        } /* if */
    } /* for */
    fclose(inzip);

    /* Write central directory and end of central directory */

    /* get start of central */
    if ((start_offset = ftell(outzip)) == -1L) err(ZE_TEMP, tempzip);

    for (z = zfiles; z != NULL; z = z->nxt) {
        if ((res = putcentral(z, outzip)) != ZE_OK) err(res, tempzip);
    }

    /* get end of central */
    if ((length = ftell(outzip)) == -1L) err(ZE_TEMP, tempzip);

    length -= start_offset;               /* compute length of central */
    if ((res = putend((int)zcount, length, start_offset, zcomlen,
                       zcomment, outzip)) != ZE_OK) {
        err(res, tempzip);
    }
    tempzf = NULL;
    if (fclose(outzip)) err(ZE_TEMP, tempzip);
    if ((res = replace(zipfile, tempzip)) != ZE_OK) {
        warn("new zip file left as: ", tempzip);
        free((voidp *)tempzip);
        tempzip = NULL;
        err(res, "was replacing the original zip file");
    }
    free((voidp *)tempzip);
    tempzip = NULL;
    setfileattr(zipfile, attr);
    free((voidp *)zipfile);
    zipfile = NULL;

    /* Done! */
    exit(0);
}
#else /* !CRYPT */

void main()
{
    fprintf(stderr, "\
This version of ZipCloak does not support encryption.  Get zcrypt20.zip (or\n\
a later version) and recompile.  The Info-ZIP file `Where' lists sites.\n");
    exit(1);
}

#endif /* ?CRYPT */
