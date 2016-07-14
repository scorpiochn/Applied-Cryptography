/*--- getsys.c -- System-dependent routines to return various
 *  information from the system or user.
 *
 *  I predict that this module will be the least portable of
 *  the modules in RIPEM, despite efforts on my part to adapt
 *  to different systems.
 *
 *  Mark Riordan  riordanmr@clvax1.cl.msu.edu   10 March 1991
 *  This code is hereby placed in the public domain.
 *
 *  Modified to be able to work even on OS which doesn't have
 *  statfs() function call by Uri Blumenthal  21 Dec 1992
 *                                      uri@watson.ibm.com
 */

#if defined(sgi) || defined(_AIX)
/* use POSIX flavour termios instead of BSD sgttyb */
#define USE_TERMIOS
#endif

#include <stdio.h>
#ifndef IBMRT
#include <stdlib.h>
#endif
#include <string.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "getsyspr.h"
#include "strutilp.h"

#ifdef MACTC
#include <console.h>
#include <time.h>
#include <unix.h>
static char *getenvRsrc(short strnum, char **fname);
#else

#if defined(__MSDOS__) || defined(_MSDOS)
#define MSDOS
#endif

#if defined(MSDOS)
#include <time.h>
#include <string.h>
#include <dos.h>
#ifdef __TURBOC__
#include <alloc.h>
#include <conio.h>
#else
#include <memory.h>
#ifndef IBMRT
#include <malloc.h>
#endif
#ifndef __GNUC__
#include <conio.h>
#endif
#endif
#endif

#ifdef WINNT
#include <time.h>
#include <string.h>
#include <dos.h>
#include <io.h>
#endif

#ifdef UNIX
#ifdef USE_TERMIOS
#include <termios.h>
#include <time.h>
#include <unistd.h>
#else
#include <sgtty.h>
#endif
#include <sys/time.h>
#endif

#ifdef USEBSD
#include <sys/types.h>
#include <sys/resource.h>
#if !defined(sgi) && !defined(sco) && !defined(apollo)
#ifdef ultrix
#include <sys/param.h>
#include <sys/mount.h>
#else
#if defined(I386BSD) || defined(_IBMESA)
#include <sys/stat.h>
#include <sys/mount.h>
#else
#include <sys/vfs.h>
#endif
#endif
#else
#include <sys/statfs.h>
#endif

#ifdef __MACH__
#include <libc.h>
#endif
#endif

#ifdef linux
#ifndef DOGETRUSAGE
#define DOGETRUSAGE
#endif
#include <unistd.h>
#include <sys/resource.h>
#endif

#ifdef UNISTD
#include <unistd.h>
#endif
#ifdef HP
#include <sys/unistd.h>
#endif
#ifdef AIX
#if defined(_AIX370) || defined(ps2)
#include <sys/stat.h>
#else
#include <sys/statfs.h>
#endif /* _AIX370 | ps2 */
#include <limits.h>
#endif

#ifdef UNIX
#include <pwd.h>
#endif

#ifdef SYSV
#include <sys/types.h>
#if defined(sgi) || defined(MOTOROLA) || defined(sco) || defined(SVR4) || defined(SVRV32)
#include <sys/statfs.h>
#else
#include <statfs.h>
#endif

#if defined(SVR4)
#include <sys/time.h>
#include <sys/rusage.h>
#include <sys/resource.h>
#endif

#endif

#ifdef _MSC_VER
#if _MSC_VER >= 700
#define REGS _REGS
#endif
#endif

#ifndef MSDOS
FILE *userstream;
#endif

#ifdef MSDOS
#if !defined(OS2) && !defined(__GNUC__) && !defined(WINNT)
#define TIMER_OK
#endif

#define TIMER_PORT                     0x40
#define TIMER_MODE_OFFSET              3
#define TIMER_SHIFT_SELECT_COUNTER     6
#define TIMER_SHIFT_READ_LOAD          4
#define TIMER_SHIFT_MODE               1
#endif

#endif
/* endif above is for ifdef MACTC */

extern FILE *DebugStream;
extern int   Debug;
#define LINESIZE 120

extern R_RANDOM_STRUCT RandomStruct;
extern int RandomStructInitialized;

/*--- function GetRandomBytes ----------------------------------------
 *
 *  Return an array of random bytes depending upon certain
 *  transient system-dependent information.
 *  Don't bet your life on the "randomness" of this information.
 *
 *  Entry    maxbytes is the maximum number of bytes to return.
 *
 *  Exit     bytes    contains a number of bytes containing
 *                    such information as the time, process
 *                    resources used, and other information that
 *                    will change from time to time.
 *           Returns the number of bytes placed in "bytes".
 */
int
GetRandomBytes(bytes,maxbytes)
unsigned char *bytes;
int maxbytes;
{
#ifdef MAX_PORTABLE
   return 0;
#else
   int numbytes = 0, thissize;
#ifdef MACTC
   clock_t myclock;
   time_t mytime;
   
   /* Obtain the elapsed processor time */

   if( (thissize = sizeof(myclock)) <= maxbytes ) {
      myclock = clock();
      CopyRandomBytes(&myclock,thissize,bytes,&numbytes,&maxbytes,
         "elapsed processor time");
      }
      
   /* Get the time of day.  */

   if( (thissize = sizeof(mytime)) <= maxbytes ) {
   time(&mytime);
      CopyRandomBytes(&mytime,thissize,bytes,&numbytes,&maxbytes,
         "time of day"); 
   }
      
   if((thissize=sizeof(long int)) <= maxbytes) {
      long int ncore;

      ncore = FreeMem();
      CopyRandomBytes(&ncore,thissize,bytes,&numbytes,&maxbytes,
       "free heap space");    
   }
#else

#ifdef MSDOS
   unsigned char buf[4];
   time_t myclock;
   time_t mytime;
   size_t biggestfree;

   /* Obtain the elapsed processor time (not really too useful).
    */
   if((thissize=sizeof(myclock)) <= maxbytes) {
      myclock = clock();
      CopyRandomBytes(&myclock,thissize,bytes,&numbytes,&maxbytes,
       "elapsed processor time");     
   }

#ifndef __GNUC__
#ifndef WINNT
#ifndef __TURBOC__
   /* Get the size of the largest free memory block. */

   if((thissize=sizeof(size_t)) <= maxbytes) {
      biggestfree = _memmax();
      CopyRandomBytes(&biggestfree,thissize,bytes,&numbytes,&maxbytes,
       "largest free mem block");     
   }
#else
   if((thissize=sizeof(unsigned long int)) <= maxbytes) {
      unsigned long int ncore;

      ncore = coreleft();
      CopyRandomBytes(&ncore,thissize,bytes,&numbytes,&maxbytes,
       "free heap space");    
   }
#endif
#endif
#endif

#if !defined(WINNT) && !defined(__GNUC__) && !defined(__TURBOC__)
   {
   struct _diskfree_t diskspace;
      /* Get the amount of free space on the default DOS disk. 
       * Use DOS function 0x36.
       */

      if((thissize=sizeof(diskspace)) <= maxbytes) {
         _dos_getdiskfree(0,&diskspace);
         CopyRandomBytes(&diskspace,thissize,bytes,&numbytes,&maxbytes,
          "free space on default drive");        
      }
   }
#endif

#ifdef __TURBOC__           /*EWS*/
   {
      struct dfree diskspace;
      /* Get the amount of free space on the default DOS disk.
       * Use Turbo C function getdfree
       */

      if((thissize=sizeof(diskspace)) <= maxbytes) {
          getdfree(0,&diskspace);
          CopyRandomBytes(&diskspace,thissize,bytes,&numbytes,&,
           "free space on default drive");
      }
   }
#endif

#ifdef __GNUCC__

   union REGS inregs, outregs;
   /* Get the amount of free space on the default DOS disk. */

   if((thissize=sizeof(outregs)) <= maxbytes) {
      inregs.h.ah = 0x36;  /* DOS function: Get disk free space */
      inregs.h.dl = 0;     /* Drive = default */
      intdos(&inregs,&outregs);
      CopyRandomBytes(&outregs,thissize,bytes,&numbytes,&maxbytes,
       "free space on default drive");        
   }
   }
#endif

   /* Get the time of day.  */

   if((thissize=sizeof(mytime)) <= maxbytes) {
      time(&mytime);
      CopyRandomBytes(&mytime,thissize,bytes,&numbytes,&maxbytes,
       "time of day");        
   }

   /* Get some arbitrary bytes from the timer. */
#if defined(TIMER_OK) || defined(__GNUC__)

   if((thissize=2*sizeof(buf[0])) <= maxbytes) {
#if defined(__GNUC__) || defined(__TURBOC__)
      buf[0] = (unsigned char)inportb(TIMER_PORT);
      buf[1] = (unsigned char)inportb(TIMER_PORT);
#else
      buf[0] = (unsigned char)_inp(TIMER_PORT);
      buf[1] = (unsigned char)_inp(TIMER_PORT);
#endif
      CopyRandomBytes(buf,thissize,bytes,&numbytes,&maxbytes,
       "2 timer bytes");      
   }

#if defined(__GNUC__)
   /* Get bytes from screen */
   thissize = maxbytes;
   if(thissize > 0) {
      extern unsigned int ScreenPrimary[];

      CopyRandomBytes(ScreenPrimary,thissize,bytes,&numbytes,
       &maxbytes,"Chars on screen");
   }
#endif

#endif


#endif

#ifdef UNIX
   {
      struct timeval tm;
#ifndef SVR4
      struct timezone tz;
#endif
#ifdef SVR4
      int gettimeofday(struct timeval *);
#endif

   /* Get the time of day.  */

      if((thissize=sizeof(tm)) <= maxbytes) {
#ifdef SVR4
    gettimeofday(&tm);
#else
    gettimeofday(&tm,&tz);
#endif
      CopyRandomBytes(&tm,thissize,bytes,&numbytes,&maxbytes,
       "time of day (gettimeofday)"); 
      }
   }
#endif

#ifdef DOGETRUSAGE

#ifndef RUSAGE_SELF
#define RUSAGE_SELF 0
#endif
   {
      struct rusage myusage;

      /* Get the process resource utilization. */

      if((thissize=sizeof(myusage)) <= maxbytes) { 
    getrusage(RUSAGE_SELF,&myusage);
      CopyRandomBytes(&myusage,thissize,bytes,&numbytes,&maxbytes,
       "process resource utilization");       
      }
   }
#endif

#ifdef SYSV
#define DOSTAT
#endif

#ifdef DOSTAT
   {
      struct statfs buf;
      char *path;

      /* Obtain information about the filesystem on which the user's
       * home directory resides.
       */

      if((thissize=sizeof(struct statfs)) <= maxbytes) {
         GetUserHome(&path);
         statfs(path, &buf, sizeof(struct statfs), 0);
         CopyRandomBytes(&buf,thissize,bytes,&numbytes,&maxbytes,
          "file system stats on user's home device");    
      }
   }
#else

#ifdef USEBSD
   {
#if defined(_AIX370) || defined(ps2)
#define STATFS struct stat
#else
#ifdef ultrix
#define STATFS struct fs_data
#else
#define STATFS struct statfs
#endif
#endif /* _AIX370 | ps2 */
      STATFS buf;
      char *path;

      /* Obtain information about the filesystem on which the user's
       * home directory resides.  This is only slightly different
       * between SYSV and BSD.
       */

      if((thissize=sizeof(STATFS)) <= maxbytes) {
    GetUserHome(&path);
#if defined(_AIX370) || defined(ps2)
    stat(path, &buf);
#else
    statfs(path, &buf);
#endif /* _AIX370 | ps2 */
      CopyRandomBytes(&buf,thissize,bytes,&numbytes,&maxbytes,
       "file system stats on user's home device");    
      }
   }
#endif
#endif

#ifdef WINNT
   /* Get info on the files in the current directory.
    */
   {
      long searchhand;
      struct _finddata_t filedata;

      searchhand = _findfirst("*.*",&filedata);
      if(searchhand >= 0) {
         do {
            /* The structure is >> 20 bytes, but usually most of it
             * does not contain useful info.  Therefore, we 
             * truncate it at this size, because our random byte
             * buffer is only so big.
             */
            thissize = 20;
            if(thissize <= maxbytes) {
               CopyRandomBytes(&filedata.time_write,thissize,bytes,
                &numbytes,&maxbytes,"WinNT file info");
            }
         } while(!_findnext(searchhand,&filedata));
         _findclose(searchhand);
      }
   }
#endif

#endif
/* #endif above is for ifdef MACTC */

   return (numbytes);
#endif
}

/*--- function CopyRandomBytes -------------------------------------
 *
 *  Copy system-derived data into the user's output buffer.
 *  Optionally report on what's going on.
 *
 *  Entry:      thisBuf         contains "random" bytes.
 *              thisSize        is the number of bytes in inBuf to add.
 *              userbuf  is the start of the user buffer.
 *              numbytes        is the current index into userbuf for where we
 *                              should add this data.
 *              maxbytes        is the number of bytes left in userbuf.
 *              message         is a text string to output for debugging.
 *
 *       Exit:  numbytes has been updated.
 *              maxbytes has been updated.
 */
void
CopyRandomBytes(thisBuf,thisSize,userBuf,numBytes,maxBytes,message)
void *thisBuf;
int  thisSize;
unsigned char *userBuf;
int *numBytes;
int *maxBytes;
char *message;
{
   int j, bytes_to_copy;

   bytes_to_copy = thisSize <= *maxBytes ? thisSize : *maxBytes;
   if(Debug>1) {
      fprintf(DebugStream,"%d bytes of %s obtained: ",bytes_to_copy,
       message);
      for(j=0; j<bytes_to_copy; j++) {
         if(j%36 == 0) fprintf(DebugStream,"\n ");
         fprintf(DebugStream,"%-2.2x",((unsigned char *)(thisBuf))[j]);
      }
      putc('\n',DebugStream);
   }
   memcpy((char *)userBuf+*numBytes,thisBuf,bytes_to_copy);
   *numBytes += bytes_to_copy;
   *maxBytes -= bytes_to_copy;
}

/*--- function ReportCPUTime ----------------------------------------
 *
 *  Print a report on debug output indicating current process
 *  CPU time consumption.
 *
 *  Entry:      msg     is a message to add to the report.
 */
void
ReportCPUTime(msg)
char *msg;
{
#ifdef DOGETRUSAGE

#ifndef RUSAGE_SELF
#define RUSAGE_SELF 0
#endif
   struct rusage myusage;

   /* Get the process resource utilization. */

   getrusage(RUSAGE_SELF,&myusage);
   fprintf(DebugStream,"%s:\n",msg);
   fprintf(DebugStream,"Process CPU time = %ld.%-6.6ldu %ld.%-6.6lds\n",
      myusage.ru_utime.tv_sec,myusage.ru_utime.tv_usec,
      myusage.ru_stime.tv_sec,myusage.ru_stime.tv_usec);
#endif
}


/*--- function GetUserInput -----------------------------------------
 *
 *  Get a string of bytes from the user, intended for use as
 *  a seed to a pseudo-random number generator or something similar.
 *
 *  Return not only those bytes but also an array of timing
 *  information based on the inter-keystroke times.
 *  This maximizes the amount of "random" information we obtain
 *  from the user.
 *
 *    Entry *num_userbytes   is the maximum number of bytes we can
 *                              put in userbytes.
 *          *num_timebytes   is the maximum number of bytes we can
 *                              put in timebytes.
 *          echo             is TRUE iff we want to echo characters
 *                           typed by the user.  (Non-echoing is
 *                           implemented only for MS-DOS.)
 *
 *    Exit  userbytes        is an array of bytes entered by the
 *                           user, not including the newline.
 *          *num_userbytes   is the number of data bytes in this array.
 *          timebytes        is an array of bytes reflecting inter-
 *                           keystroke timings.  (Only for MS-DOS.)
 *          *num_timebytes   is the number of data bytes in this array.
 */
void
GetUserInput(userbytes,num_userbytes,timebytes,num_timebytes,echo)
unsigned char userbytes[];
int *num_userbytes;
unsigned char timebytes[];
int *num_timebytes;
int echo;
{
#ifdef USE_TERMIOS
   int tvbuf[1024]; int tvc; int ii;
   struct timeval rtm;
#ifndef SVR4
   struct timezone rtz;
#endif
#endif
   int max_user = *num_userbytes;
#if defined(TIMER_OK) || defined(MACTC)
   int max_time = *num_timebytes;
#endif
   int done = 0;
   unsigned char *userby = userbytes;
   unsigned char *timeby = timebytes;
   int ch;
#ifdef TIMER_OK
   unsigned int counter = 1;
   unsigned char byte1, byte2;
   int databyte;
#endif

#ifdef MACTC
   clock_t time0, time1, time2;
   int contty = 0;

   time0 = time1 = clock();
   if( contty = isatty(fileno(stdin)) ) {
      if( echo ) csetmode(C_CBREAK, stdin); 
      else csetmode(C_RAW, stdin);
      }

   while( !done ) {
   
      if( contty ) while( (ch = fgetc(stdin)) == EOF );
      else ch = fgetc(stdin);
      
      done = ((ch == '\r') || (ch == '\n')) || (ch == EOF);
      if( !done && !echo ) putc('*', stderr);
      else if( done && !echo ) putc('\n', stderr);
      
      if( !done && (max_user > 0) ) {
         *userby++ = (unsigned char)ch;
         max_user--;                                     
         }
      
      if( max_time > 0 ) {
         time2 = clock();
         *timeby++ = (unsigned char)(time2 - time1);
         max_time--;
         time1 = time2;
         }
      }
   
   if( contty ) csetmode(C_ECHO, stdin);
      
   if( max_time > 0 ) {
      time1 = clock();
      *timeby++ = (unsigned char)(time1 - time0);
      max_time--;
      }
#else

#ifdef UNIX
#ifdef USE_TERMIOS
   struct termios mytty, origtty;
#else
   struct sgttyb mytty, origtty;
#endif
   FILE *userstream;
   int in_file_num;
#endif

#ifdef TIMER_OK
   /* Set the timer to its highest resolution.
    * This gives 65536*18.2 ticks/second--pretty high resolution.
    * There *are* some things
    * that a PC can do that a multiuser system can't!
    */

   databyte = (2<<TIMER_SHIFT_SELECT_COUNTER) |
         (3<<TIMER_SHIFT_READ_LOAD) |
         (3<<TIMER_SHIFT_MODE);
   outp(TIMER_PORT+TIMER_MODE_OFFSET,databyte);
   outp(TIMER_PORT+2,0xff&counter);
   outp(TIMER_PORT+2,counter>>8);
   byte1 = (unsigned char) inp(TIMER_PORT);
   byte2 = (unsigned char) inp(TIMER_PORT);
   if(max_time > 0) {
      *(timeby++) = byte2;
      max_time--;
   }
#endif

#ifdef UNIX
   userstream = fopen("/dev/tty","r");
   if(!userstream) {
      fputs("Unable to read from terminal\n",stderr);
   }
   in_file_num = fileno(userstream);
#endif

#ifdef UNIX
#ifdef USE_TERMIOS
   /* set raw mode and turn of echo is requested */
    tcdrain(in_file_num);
    tcgetattr(in_file_num, &origtty);
    memcpy((char *)&mytty,(char *)&origtty,sizeof mytty);
   tvc = 0;
    if (!echo)
        mytty.c_lflag &= ~(ECHO | ICANON);
    else
        mytty.c_lflag &= ~(ICANON);
    mytty.c_cc[VMIN] = 1;
    mytty.c_cc[VTIME] = 0;
    tcsetattr(in_file_num, TCSANOW, &mytty);
#else
   if(!echo) {
      ioctl(in_file_num,TIOCGETP,&origtty);
      memcpy((char *)&mytty,(char *)&origtty,sizeof mytty);
      mytty.sg_flags &= (-1 - ECHO);
      ioctl(in_file_num,TIOCSETP,&mytty);
   }
#endif
/* USE_TERMIOS */
#endif
/* UNIX */

   while(!done) {
#ifdef MSDOS
      if(echo) {
#if defined(__GNUC__) || defined(__TURBOC__) 
         ch = getch();
         putc(ch,stderr);
      } else {
         ch = getch();
      }
#else
         ch = _getche();
      } else {
         ch = _getch();
      }
#endif
#ifdef TIMER_OK
      byte1 = (unsigned char)inp(TIMER_PORT);
      byte2 = (unsigned char)inp(TIMER_PORT);
#endif
#else
      ch = fgetc(userstream);
#ifdef USE_TERMIOS
#ifdef SVR4
    gettimeofday(&rtm);
#else
    gettimeofday(&rtm,&rtz);
#endif
   if (tvc < 1024)
      tvbuf[tvc++] = rtm.tv_usec;
/* SVR4 */
#endif
/* USE_TERMIOS */
#endif
/* MSDOS */
      done = (ch=='\r') || (ch=='\n');
      if(!done) {
    if(max_user > 0) {
       *(userby++) = (unsigned char)ch;
       max_user--;
    }
#ifdef TIMER_OK
    if(max_time > 0) {
       *(timeby++) = byte2;
            max_time--;
    }
#ifdef DEBUG
    printf("ch=%c byte=%d\n",ch,byte2);
#endif
#endif
      }
   }
#ifdef MSDOS
   fputc('\n',stderr);
#else
   if(!echo) fputc('\n',stderr);
#endif

#endif
/* endif above is for MACTC */

   *num_userbytes = userby - userbytes;
   *num_timebytes = timeby - timebytes;

#ifdef UNIX
#ifdef USE_TERMIOS
   tcdrain(in_file_num);
   tcsetattr(in_file_num, TCSANOW, &origtty);
   if (RandomStructInitialized) {
      R_RandomUpdate(&RandomStruct, (POINTER) &tvbuf[0],
         (unsigned int)(sizeof(int)*tvc));
      if(Debug>1) {
         int j;
         fprintf(DebugStream,"%d bytes of timing data obtained: ", tvc*sizeof(int));
         for(j=0; j<tvc; j++) {
            if(j%9 == 0) fprintf(DebugStream,"\n ");
            fprintf(DebugStream,"%08x", tvbuf[j]);
         }
         putc('\n',DebugStream);
      }
   } else {
      if (Debug > 1) {
         fprintf(DebugStream, "tossed timing data\n");
      }
   }
#else
   if (!echo)
      ioctl(in_file_num,TIOCSETP,&origtty);
#endif

   fclose(userstream);
#endif
}


/*--- function GetUserName ------------------------------------------
 *
 *  Return the name of the user.
 *  Under Unix, get the user's name using time-honored techniques.
 *  Under MS-DOS, grab the value of an environment variable, or
 *  just use "me" if there's no such variable.
 *
 *  Entry:  name     is a pointer to a pointer.
 *
 *  Exit:   name     is the name of the user, zero-terminated.
 *          Returns non-zero if the username needs to have
 *            the hostname appended to it.
 */
int
GetUserName(name)
char **name;
{
   char *cptr=NULL;
   int need_host = 0;
   
#ifdef MACTC
   cptr = getlogin();
   GetEnvFileName(USER_NAME_ENV, USER_NAME_DEFAULT, name);
   if(cptr != NULL) {
      strcatrealloc(name, ",");
      strcatrealloc(name, cptr);
   }
#else 
   
#ifdef UNIX
   struct passwd *pwptr;
#endif
#if defined(ULTRIX) || defined(_AIX370) || defined(ps2)
   extern char *getlogin();
#endif

   cptr = getenv(USER_NAME_ENV);

#if defined(UNIX) && !defined(MAX_PORTABLE)

   if(!cptr) {
      cptr = getlogin();
      if(!cptr) {
         pwptr = getpwuid(getuid());
         if(pwptr) {
       cptr = pwptr->pw_name;
         } else {
       cptr = NULL;
         }
      }
      if(cptr) need_host = 1;
   }
#endif
   if(!cptr) cptr = USER_NAME_DEFAULT;
   
   strcpyalloc(name,cptr);
#endif
/* endif above is for MACTC */
   return need_host;
}

/*--- function GetPasswordFromUser ---------------------------------
 *
 *  Obtain a password, either from an environment variable
 *  or from the user at the keyboard.
 */
unsigned int
GetPasswordFromUser(prompt,verify,password,maxchars)
char *prompt;
BOOL verify;
unsigned char *password;
unsigned int maxchars;
{
   unsigned int num_userbytes = maxchars, num_timebytes=0;
   unsigned char timebytes[4];
   int echo=FALSE;
   BOOL pw_ok = FALSE;

   do {
      num_userbytes = maxchars;
      fputs(prompt,stderr);
      GetUserInput(password,(int *)&num_userbytes,timebytes,(int *)&num_timebytes,echo);
      if(verify) {
         unsigned char verifybytes[MAX_PASSWORD_SIZE];
         int num_verifybytes=(int)maxchars;

         fputs("Enter again to verify: ",stderr);
         num_timebytes = 0;
         GetUserInput(verifybytes,(int *)&num_verifybytes,timebytes,(int *)&num_timebytes,echo);
         if((int)num_userbytes != num_verifybytes ||
          strncmp((char *)password,(char *)verifybytes,num_userbytes)) {
            fputs("Passwords do not match.  Please enter them again.\n",stderr);
         } else {
            pw_ok = TRUE;
         }
      } else {
         pw_ok = TRUE;
      }
   } while(!pw_ok);

   return num_userbytes;
}


/*--- function GetUserAddress -------------------------------------------
 *
 *  Return the zero-terminated user's email address.
 *  For non-Unix hosts, it's just the user's name.
 *  For Unix, it's the name followed by @<hostname>.
 *
 *  Entry:  address  is a pointer to a pointer.
 *
 *  Exit:   address  contains the user's email address (as close
 *                   as we can figure it).
 */

void
GetUserAddress(address)
char **address;
{
#ifdef UNIX
#define HOSTSIZE 256
   char hostname[HOSTSIZE],domainname[HOSTSIZE];
#endif

   if(GetUserName(address)) {
#ifdef UNIX
#ifdef SVR4
   int gethostname(const char *, int);
   int getdomainname(const char *, int);
#endif

      /* Add "@hostname" to the username unless it's already there.  */
      if(!strchr(*address,'@')) {
         if(!gethostname(hostname,HOSTSIZE)) {
            strcatrealloc(address,"@");
         strcatrealloc(address,hostname);
#if !defined(IBMRT) && !defined(I386BSD) && !defined(linux) && !defined(SVRV32) && !defined(apollo)
            /* Now add the domain name, unless it's null. */
            if(!getdomainname(domainname,HOSTSIZE)) {
               if(domainname[0] && !match(domainname,"noname")) {
                  strcatrealloc(address,".");
                  strcatrealloc(address,domainname);
               }
            }
#endif
         }
      }
#endif
   }
}

/*--- function GetUserHome --------------------------------------
 *
 *  Return the pathname of the user's home directory.
 *  Implemented only under Unix; for other systems, just returns
 *  a string of 0 length followed by a zero byte.
 *
 *  Entry:  home      points to a pointer which we desire to be
 *                    be updated to point to the user's home dir.
 *
 *  Exit:   home      contains the home pathname, followed by a
 *                    zero byte.
 */
void
GetUserHome(home)
char **home;
{
#if defined(UNIX) && !defined(MAX_PORTABLE)
   struct passwd *pwptr;

   pwptr = getpwuid(getuid());

   if(pwptr) {
      strcpyalloc(home,pwptr->pw_dir);
   } else {
      strcpyalloc(home,"");
   }
#else
   strcpyalloc(home,"");
#endif
}

/*--- function ExpandFilename ----------------------------------------------
 *
 *  Expand a Unix filename that starts with ~ (indicating that the
 *  user's home directory should be prepended to the filename).
 * 
 *  Entry:  filename points to a filename.
 *
 *  Exit:   filename now points to the expanded file name if applicable,
 *                   else it is unchanged.
 *          Note: the pointer may have been changed.
 */
void
ExpandFilename(fileName)
char **fileName;
{
   char *homedir;

   if((*fileName)[0] == '~') {
      GetUserHome(&homedir);
      strcatrealloc(&homedir,*fileName+1);
      *fileName = homedir;
   }
}

/*--- function GetEnvFileName ------------------------------------------
 *
 *  Obtain a filename from an environment variable.
 *  Expand "~" Unix syntax.  Supply a default if the
 *  environment variable cannot be found.
 *
 *  Entry:
 *
 *       Exit:
 */

#ifndef MACTC

BOOL
GetEnvFileName(envName,defName,fileName)
char *envName;
char *defName;
char **fileName;
{
   char *cptr = getenv(envName);

   if(!cptr) cptr = defName;
#ifdef UNIX
   if(cptr[0] == '~') {
      GetUserHome(fileName);
      strcatrealloc(fileName,cptr+1);
   } else {
      strcpyalloc(fileName,cptr);
   }
#else
   strcpyalloc(fileName,cptr);
#endif
   return TRUE;
}

/*--- function GetEnvAlloc ---------------------------------------------------
 */
BOOL
GetEnvAlloc(envName,target)
char *envName;
char **target;
{
   char *cptr = getenv(envName);
   int found = FALSE;

   if(cptr) {
      strcpyalloc(target,cptr);
      found = TRUE;
   } else {
      *target = NULL;
   }
   return found;
}
#else

/*--- Macintosh versions of the above functions, by R. Outerbridge.  */

static char *getenvRsrc(short strnum, char **fname) {
   unsigned char **StrHandle;
   char *cp;

   StrHandle = GetString(strnum);
   if( StrHandle == NULL ) {
      *fname = NULL;
      return( (char *)NULL );
      }
   MoveHHi( (char **)StrHandle );
   HLock( (char **)StrHandle );
   cp = PtoCstr(*StrHandle);
   strcpyalloc(fname, cp); 
   HUnlock ( (char **)StrHandle );
   DisposHandle( (char **)StrHandle );
   return( *fname );
   }

BOOL
GetEnvFileName(envName,defName,fileName)
short envName;
char *defName;
char **fileName;
{
   if( getenvRsrc(envName, fileName) == NULL )
      strcpyalloc(fileName,defName);
   return TRUE;
}

BOOL
GetEnvAlloc(envName,target)
short envName;
char **target;
{
   int found = FALSE;

   if( getenvRsrc(envName, target) != NULL ) found = TRUE;
   return found;
}

#endif

