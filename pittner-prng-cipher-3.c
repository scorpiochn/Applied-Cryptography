From msuinfo!agate!howland.reston.ans.net!xlink.net!math.fu-berlin.de!jiri Sat Oct 23 10:48:49 1993
Newsgroups: sci.crypt
Path: msuinfo!agate!howland.reston.ans.net!xlink.net!math.fu-berlin.de!jiri
From: jiri@kirk.chemie.fu-berlin.de (Jiri Pittner)
Subject: crypto cracking, new version of my program (C source) posted here,
Message-ID: <EUDIBVSH@math.fu-berlin.de>
Summary: new version of my encryption presented here, now palso portable to CRAY
Keywords: encryption, cryptosystems, cracking
Sender: news@math.fu-berlin.de (Math Department)
Nntp-Posting-Host: spock.chemie.fu-berlin.de
Organization: Free University of Berlin, Germany
Date: Wed, 20 Oct 1993 12:49:12 GMT
Lines: 1389



/*
********************************************************
* crypting program (c) J. Pittner, 1991-3              *
* contact address: jiri@hpsiepsi.chemie.fu-berlin.de   *
* contact address 2: jiri@kirk.chemie.fu-berlin.de     *
* This is freeware - can be used for any non-profit    *
* purpose, without any warranty, of course ...         *
* provided that this copyright message is not removed  *
********************************************************


Compilation is simple -> no makefile necessary

always define system : -Damiga, -Dunix, ... 
on hp -Dhp_risc -Dunix
on sun like on convex -Dunix -Dconvex -lcurses -ltermcap
on amiga -lm32 -lc32 with long integer, add #define amiga, needs time.h
on cray x-mp: qsub -lt 0:0:19 <<!
cc -h olevel_2 /home/bf2130ef/pokusy/cry.c -lcurses
mv a.out /home/bf2130ef/pokusy/cr
crax did not have srandom and srand!!!
grep -v it away!!!

Attention: in the back compatible regime -BcCD
crypted files are portable between convex-sun-hp7xx-amiga | cray xmp-ymp
| means here that these two groups are not portable
It was due to different xoring of signed char to signed integer - 
see option newalgor6.


Short description of the method:


It is based on standard pseudorandom generators - congruential
and aditive one - and modified von Neumann's algorithm. The generators
are "coupled" together, which should increase the period and
avoid simple patterns typical for congruential generator.
I think, this 'random algorithm' did not degenerate in anything like
the Knuth's warning example of "superrandom generator".
The idea of Knuth's algorithm 'M' for combination of PRNG's has been also
used in the new version. 
The crypted text is xored by some PRNG and sequence of "modified" passwords,
but also the password lengths changes in some reasonable limits 
(not to become very short!). Not all of the information contained
in the generators is used in ciphertext production -> it is not
possible to use a sequence of blanks in plain text and use it
for decryption of the rest of the file.

The encryption is done twice, first with some product of the password modifications,
but also with randomly (time,pid,audio) initiated pseudorandom password,
which is in crypted way (depending on the real password) saved in the ciphertext.

There has been used a hash function in order to force the cryptanalyst to decrypt
once the whole buffer:
The first encryption is started with many times iterated originals password
xored by random 8 bytes. And these 8 bytes are stored in the header of the file, but
they are xored by 8B hash function of the buffer after the first encryption.
Than the buffer is encrypted once more using 16B random password, which is stored
also in the header, but encrypted using the original password.
Therefore, who would like to do systematic search on the user password, would have
to 1) decrypt the WHOLE BUFFER using the decrypted random password
   2) calculate hash of the buffer
   3) use the hash to prepare initial password for step 4
   4) decrypt beginning of the buffer to compare it with the known plain text
      or to check if it is english text or what
To decrypt (one pass) 20KB buffer costs approx 1.4s on 120MIPS machine
using the default slowness. Are you able to propose a way how to avoid the
step 1 above to make search of even a moderate number of password guesses possible?


The ciphertext created by this program has passed entropy and chi-square test.


There have been done things preventing people who don't know the algorithm
to even guess what's going on - the random encryption described above,
product file has different length than the input, each bit of the
product is important and ... 
The program does not allow its user to use passwords like lowercase words
or things like aaaa1111 and refuses to crypt too short files or 1KB of zeros ...

It also cleans its buffers as soon as possible, to decrease the risc of searching
in memory, but of course, the data stay unencrypted for considerable time.

The program is quite time consuming, not very practical on machines <10MIPS.

*/

/*
#define amiga
*/
/*
#define unix
*/


/* mozna pouzij jeste  binarni operaci def. tabulkou, k ni inverzni operaci */



#include <stdio.h>
#include <string.h>
#include <ctype.h>
#if __stdc__
#include <stdlib.h>
#ifdef convex
extern long random();
extern void srandom();
#endif
#else
extern char *malloc();
extern free();
#endif

#ifdef unix
#include <sys/time.h>
#include <unistd.h>
#endif
#ifdef amiga
#include <time.h>
#endif


#ifdef unix
#include <curses.h>
#include <signal.h>
#endif


/*you must not use minpassword <6*/
#define minfile 50
#define minpassword 9
/* maxpalen should not be changed because of backw. compatibility 
it is not just limit, but also the modifpas uses it, and the decision
if to hash too long passphrase etc.*/
#define maxpalen 41
#define hashlen 8
/* fieldinfo must be >=128+21+hashlen (for newalgor3) */
#define fieldinfo 160
/*minbufsize must be >= 256 + 256 + minfile +fieldinfo*/
#define minbufsize 2048

#ifdef unix
#define defbuflen 1048576
#define minslowness 50
#define maxslowness 1000
#define defslowness 300
#define minadit 0
/*must be >=0*/
#define defadit 0
#define maxadit 100
#endif

#ifdef amiga
#define defbuflen 32768
#define minslowness 50
#define maxslowness 600
#define defslowness 300
#define minadit 0
/*must be >=0*/
#define defadit 0
#define maxadit 30
#endif


#define BYTE1 unsigned char
#define BYTE4 unsigned long
#define boolean int
#define true 1
#define false 0



char *myname;
int slowness;
int aditional;
short minpalen;
boolean newalgor9;
boolean newalgor8;
boolean newalgor7;
boolean newalgor6;
boolean newalgor5;
boolean newalgor4;
boolean newalgor3;
boolean newalgor2;
boolean newalgor;
int mixsize; /* for algorithm M used in newalgor5 option */
/*for closing*/
static FILE *input=NULL;
static FILE *output=NULL;
BYTE1 pasw[maxpalen+2]; /* *buf lint:unused*/
short paslen;



/* this is not necessary on unix, but amiga-dos sometimes behaves very strangely */
void konec(f,n)
int n;
BYTE1 *f;
{
register int i;

if(f != (BYTE1 *)NULL) (void) free((char *)f);
if(input!=stdin && input!=NULL) fclose(input);
if(output!=stdout && output!=NULL) fclose(output);
for(i=0;i<=maxpalen;i++) pasw[i]= (BYTE1)0;
slowness=aditional=paslen=minpalen=0;
/*random generators are cleared with xrandclear*/
exit(n);
}





void usage()
{
fprintf(stderr,"Usage:\n%s -e|-d [-i file] [-o file] [-m buffer_size] [-k keyword] [-s slowness] [-a aditional]\n\
       -i   when you want different input file then stdin\n\
       -o   when you want different output file then stdout\n\
	    On some machines there could be problems with redirection of stdin\n\
	    and stdout when you want to specify password 'invisibly' from ter-\n\
	    minal, then this options become useful. Anyway, this version should\n\
	    have already all this problems fized.\n\
       -e   for encrypting\n\
       -d   for decrypting\n\
       -b   for oldest backward compatibility\n\
       -B   for older backward compatibility\n\
       -c   for old backward compatibility\n\
       -C   for new backward compatibility\n\
       -D   for newer backward compatibility\n\
       -E   for newer2 backward compatibility\n\
       -F   for newest backward compatibility\n\
       -k   it is not recomended to input password through command line\n\
	    in multiuser system - %s can prompt you for password as login\n\
	    The password must contain at least 3 lowercase letters and \n\
	    either at least one national (non-ASCII) character\n\
	    or at least 3 non-lowercase chars, 1 non-alphabetic character,\n\
	    and 1 uppercase letter on other than 1st position. Minimal and\n\
	    maximal password lengths are %d and %d characters.\n\
	    Also some simple test of 'uniformity' is used, but usually these\n\
	    conditions above are sufficient to pass it.\n\
       -s   when slowness is low, longer password is recomended!\n\
	    this option is due to use on very differently quick computers;\n\
	    remember that this factor is in some sense part of keyword -\n\
	    you must know which value was used for encrypting!\n\
	    default slowness is %d, minimum %d, maximum %d.\n\
       -a   aditional number of password modifications in crypting procedure\n\
            minimum is 0, default %d, maximum is %d\n\
	    remember that this factor is in some sense part of keyword -\n\
	    you must know which value was used for encrypting!\n\
       -A   number of bits to be used for mixing algorithm, must be between\n\
	    3 and 8. It is relevant only when no of the options bBcCD is used\n\
	    It is of course part of your password in the sense mentioned above\n\
       -m   must be specified when working on larger files then is the default\n\
	    value: %d bytes\n\n\
(c) Jiri Pittner, 1991-3.\n\n",myname,myname,minpassword,maxpalen,defslowness,minslowness,maxslowness,
defadit,maxadit,defbuflen);
konec((BYTE1 *)NULL,20);
}


/*machine independent pseudorandom generators */


/* several other random generators */

static int xrandm=100000000;
static int xrandm1=10000;
static int xrandb1=51723621;
static int xrandb2=98706421;
static int xrandb3=34245821;
static int xrandb4=79834621;
static int xrandb5=63429421;
static int xrandb6=81753821;



int xmult(p,q)
int p,q;
{
int p1,p0,q1,q0;

p1=p/xrandm1; p0=p%xrandm1;
q1=q/xrandm1; q0=q%xrandm1;
return ((((p0*q1+p1*q0)%xrandm1)*xrandm1+p0*q0)+1)%xrandm;
}



char rnd1(a)
int *a;
{
return (char) (0xff & ((*a = xmult(*a,xrandb1))>>8));
}




char rnd2(a)
int *a;
{
return (char) (0xff & ((*a = xmult(*a,xrandb2)) >> 9));
}


char rnd4(a)
int *a;
{
return (char) (0xff & ((*a = xmult(*a,xrandb4)) >> 10));
}


char rnd5(a)
int *a;
{
return (char) (0xff & ((*a = xmult(*a,xrandb5)) >> 9));
}


char rnd6(a)
int *a;
{
return (char) (0xff & ((*a = xmult(*a,xrandb6)) >> 8));
}




static int xrandaa[55];
static int xrandj;

void xrandinit(s,r,n)
int s,n;
char *r;
{
int j;
if(s) /*true initialisation else only modification! */
{
	xrandaa[0]=s; xrandj=0;
	do {
		xrandj++;
		/*xrandaa[xrandj]=(xmult(xrandb3,xrandaa[xrandj-1])+1)%xrandm;*/
		xrandaa[xrandj]=xmult(xrandb3,xrandaa[xrandj-1]);
		}while(xrandj<54);
}
if(newalgor6)
for(j=0;j<55;j++) xrandaa[j] ^= ((BYTE1)r[j%n]);
else
for(j=0;j<55;j++) xrandaa[j] ^= r[j%n];
}


xrandclear()
{
for(xrandj=0;xrandj<55;xrandj++) xrandaa[xrandj]=0;
}




char xrand55()
{
int tmp;
int i;

xrandj=(xrandj+1)%55;
i=(xrandj+38)%55;
tmp= (0xff & (xrandaa[i]>>16));
xrandaa[i] = ((xrandaa[i] <<8)& 0x00ffff00) | tmp;
return (0xff&(xrandaa[xrandj]=(xrandaa[(xrandj+23)%55]+xrandaa[(xrandj+54)%55])%xrandm)>>(6+xrandj%5+xrandj%3));
}






/*machine dependent, but does not matter - only for random seeds*/
void initrandom()
{
#ifdef unix
struct timeval t1;
struct timezone t2;

gettimeofday(&t1,&t2);
#ifdef hp_risc
srand((int)t1.tv_usec^t1.tv_sec^24350373);
#endif
#ifdef convex
srandom((int)t1.tv_usec^t1.tv_sec^78346723);
#endif
#ifdef cray_ymp
srandom((int)t1.tv_usec^t1.tv_sec^37342387);
#endif
#ifdef cray_xmp
/*srand((int)t1.tv_usec^t1.tv_sec^82378238);*/
#endif
#endif

#ifdef amiga
time_t t;

t=time(0);
srand((short) 21567^(t&0x7fff ^ (t>>15)&0x7fff ));
#endif
}



/*machine dependent*/
#ifdef hp_risc
#define RANDOM() rand()
#else
#define RANDOM() random()
#endif

BYTE1 randbyte0()
{
#ifdef unix
register short i,j;
struct timeval t1;
struct timezone t2;

gettimeofday(&t1,&t2);
j= (short) t1.tv_usec&0x03;
for(i=0; i<=j;i++) RANDOM();
return((BYTE1) (RANDOM()>>8)&0xff);
#endif


#ifdef amiga
register short p;

p= rand()>>4;
if(p&1024) p ^= 1023;
return((BYTE1)(p ^ (rand()>>4))&0xff);
#endif
}


/* this includes randomness generated through really random generator,
 if available; typically /dev/audio input noise 
 works quite well with ours otherwise unused audio device*/
BYTE1 noise()
{
#ifdef hp_risc
int i,j,k,l;
static FILE *f;
static int first=1;

if(first) {f=fopen("/dev/audio","r"); first=0;}
if(f==NULL) return 0xaa;
k=0;
j=fgetc(f);
for(i=0;i<255;i++) {l=j;j=fgetc(f); if(j!=l)k++;}
/*fclose(f);*/
return (BYTE1)(k&0xff);
#else
return 0xaa;
#endif
}



BYTE1 randbyte1()
{
static int b=12345678;
static int count=0;

#ifdef unix
struct timeval t1;
struct timezone t2;

gettimeofday(&t1,&t2);
b ^= (0xfffffff &((t1.tv_sec<<16)^t1.tv_usec));
#endif

(void) rnd5(&b);
b^= randbyte0();
if(!count) b ^= (((unsigned int)noise()) << 7);
count=(count+1)%3; /* not to call it too often */
return (BYTE1) rnd5(&b);
}



BYTE1 randbyte()
{
static int a=98345721;
int i;
BYTE1 x;
static int first=1;

#ifdef unix
if(first)
	{
	first=0;
	a ^= (getpid()^(((int)getppid())<<9));
	}
#endif
x=randbyte0();
for(i=0;i<(int)(x&7);i++ ) (void)rnd1(&a);
return x ^ rnd1(&a) ^ randbyte1();
}




/*machine dependent, unix version could be strongly improved - writes some
term. control garbage into stdout on some machines/terminals
perhaps proper flushing would help? But it suffices to use options -i/-o
to avoid the problem 
NOW FIXED! temporarily change stdout to be stderr! */

char *getpassword(line,prompt)
char *prompt, *line;
{
register char *p;
#ifdef unix
FILE *term;
FILE save;

save= *stdout;
*stdout= *stderr; 
/* this dirty (at least I think it is quite dirty) trick solves
the problem of control characters in the redirected
output! */

if((term=fopen("/dev/tty","r"))==NULL) 
	{
	fprintf(stderr,"%s: No terminal for this process!\n",myname);
	*stdout=save;
	konec((BYTE1 *)NULL,100);
	}

/* disable keyboard interrupts when noecho */
signal(SIGINT,SIG_IGN);
signal(SIGTSTP,SIG_IGN);
initscr();
noecho();
fprintf(stderr,"%s",prompt);
fgets(line,256,term);
fclose(term);
echo();
fprintf(stderr,"\n");
endwin();
*stdout=save;
signal(SIGINT,SIG_DFL);
signal(SIGTSTP,SIG_DFL);
#endif

#ifdef amiga
register int f1;
char title[256];
strcpy(title,"con:100/100/350/26/");
strcat(title,prompt);
if((f1=open(title,2))== -1) {fprintf(stderr,"%s: can't create window for password input!\n",myname); konec((BYTE1 *)NULL,100);};
write(f1,"\033[30m\033[40m",10*sizeof(char));
do
	{
	read(f1,line,sizeof(char));
	}
while(*(line++) != '\n');
*(line-1) = '\0';
close(f1);
#endif


p=line;
while(*p) if(*(p++)=='\n') *(p-1)='\0';
return(line);
}


/**********************************************************************/




void checkpasswd(pas,paslen)
BYTE1 *pas;
short paslen;
{
register short i,j,nasely,upcase,nasel,ndif,naselx,ndigit;
if(paslen<minpassword) {fprintf(stderr,"%s: Your password is too short!\n",myname); konec((BYTE1 *)NULL,10);}
nasely=upcase=nasel=ndif=naselx=ndigit=0;
for(i=0; i<paslen; i++) 
	{
	if(pas[i]&0x80 || !isalpha((char)pas[i])) nasel=1;
	if(pas[i]&0x80 || !islower((char)pas[i])) naselx++;
	if(!(pas[i]&0x80) && islower((char)pas[i])) nasely++;
	if(pas[i]&0x80 || (i && isupper((char)(0x7f&pas[i])))) upcase=1;
	if(!(pas[i]&0x80) && isdigit((char)pas[i])) ndigit++;
	for(j=0; j<i; j++) if(pas[i]==pas[j]) ndif++;
	}
if(ndigit>paslen-3 || (newalgor4 && upcase==0) || nasely<3 || naselx<3 || !nasel || ndif>0.35*paslen*(paslen-1))
	{fprintf(stderr,"%s: Your password is too uniform!\n",myname); konec((BYTE1 *)NULL,10);}
}




void pascpy(kam,od,del)
BYTE1 *kam,*od;
short del;
{
while(del-- > 0) *kam++ = *od++;
}




BYTE1 *getbuf(n)
int n;
{
BYTE1 *f;
f= (BYTE1 *) malloc((unsigned)n*sizeof(BYTE1));
if (f==NULL)
	{
	fprintf(stderr,"%s: not enough memory for requested buffer!\n",myname);
	konec((BYTE1 *)NULL,20);
	}
return(f);
}


/* this could be much improved in assembler! */
void rotbyte(b)
BYTE1 *b;
{
/* old version
register int j;
j= ((int)*b)<<1;
*b= (j&0x100? 1 : 0);
*b |= ((BYTE1) j&0xff);
*/
register unsigned int j;
j= (unsigned int) (*b);
*b = 0xff&((j<<1)|(j>>7));
}




void getsumxor(p,l,su,xo)
BYTE1 *p,*su,*xo;
int l;
{
register int i;
register unsigned long j;
BYTE1 tmp;

j = *xo =0;
for(i=0; i<l; i++, p++)
	{
	*xo ^= *p;
	j += *p;
	}
*su = (BYTE1) (j&0xff);

if(newalgor2)
	{
	tmp= (BYTE1)(l&0xff);
	*su ^= ((BYTE1) ((tmp<<3)&0xff));
	*xo ^= ((BYTE1)(tmp^0xff));
	}
}




/* this hash function does not have to be crypt. strong for this purpose
(and maybe is not), just it must depend on the whole buffer */

void myhash(buf,blen,hash,hlen)
BYTE1 *buf,*hash;
int blen,hlen;
{
int i,j,k,aa;
BYTE1 su,xo;

/*simple initialization*/
aa=89674523;
getsumxor(buf,blen,&su,&xo);
aa ^= ((((BYTE4)su)<<8)|xo);
for(j=0;j<hlen; j++) hash[j]=rnd6(&aa);

/*hashing itsself*/
for(k=0;k<=(newalgor9?1:0);k++) /* scan buffer twice */
{
i=0;
while(i<blen)
	{
	if(((aa>>11)&0x0f)==0x0f)
		{
		BYTE1 tmp;
		tmp=hash[0];
		for(j=1;j<hlen;j++) hash[j-1]=hash[j];
		hash[hlen-1]=tmp;
		}
	for(j=0;j<hlen && i<blen; j++, i++)
		{
		hash[j] ^= buf[i];
		if(rnd6(&aa) & (1<< (j&7)) ) rotbyte(hash+j);
		aa ^= (((BYTE4) (hash[j==0?hlen-1:j-1]))<<(hash[j]&7));
		if(newalgor4) hash[j] ^= rnd6(&aa);
		if(newalgor7 && i>0) hash[j]+=buf[i-1];
		}
	}
}
/*for(j=0;j<hlen; j++) fprintf(stderr,"hash %d\n",(int)hash[j]);*/
aa=0;
}





void zaxoruj(co,delka,cim)
BYTE1 *co,cim;
register int delka;
{
for(;delka>0;delka--) *co++ ^= cim; 
}



void modifpas1(pas,paslen)
BYTE1 *pas;
short *paslen;
{
BYTE1 sum,xor;
int k,aa;
register int j,i;
register BYTE4 x;

getsumxor(pas,(int)*paslen,&sum,&xor);

/*"randomly" modify length*/
j = ((int)xor)%17;
if(j <= 4 && *paslen < maxpalen) {(*paslen)++; pas[*paslen - 1]=sum;}
if(j >= 11 && *paslen > minpalen) (*paslen)--;

/*J.v.Neumann's old algorithm for pairs of bytes*/
if(*paslen %2) pas[*paslen]= *pas ^ (sum^0xff);
for(j=0; j< *paslen; j +=2)
	{
	x  =  (BYTE4) pas[j+1];
	x |= ((BYTE4) pas[j]) <<8;
	x *= x;
	pas[j+1]= (BYTE1) ((x>>8)  &0xff);
	pas[j]  = (BYTE1) ((x>>16) &0xff);
	}

/*further modifications for complexity*/
if(newalgor3)
	{
	aa=23456789;
	for(i=1;i<=2+aditional+slowness/191;i++)
	    for(j=0; j< *paslen; j++) 
		{
		aa = ((aa<<1)^pas[j])&0x3fffffff;
		pas[j>0?j-1:*paslen-1] ^= rnd4(&aa);
		}
	}
k= (int) (xor & 7);
if (slowness<=15) k &= 3;
for(j=1; j<=k; j++) rotbyte(&sum);
zaxoruj(pas,(int)*paslen + 1,sum);

/*here was originaly mistake in expression eval. priority, made option
to switch the behaviour; in fact it was not so important, just it was
taken bit 0 instead of bit 2 - does not matter, but keep it for backw. comp. */
/* could be sum&4 resp. sum&1 
if(newalgor3?((sum&4)==4):(sum&4 == 4))
*/
if(newalgor3?(sum&4):(sum&1))
	{
	xor=pas[*paslen-1];
	for(j= *paslen-1; j>0; j--) pas[j]=pas[j-1];
	pas[0]=xor;
	}
}




void modifpas(pas,paslen)
BYTE1 *pas;
short *paslen;
{
register int i;
for(i=0; i<=aditional; i++) modifpas1(pas,paslen);
}




void initpas(p,l,su,xo)
/*depends on global slowness and minpalen*/
BYTE1 *p,*su,*xo;
short *l;
{
register short i,j;

getsumxor(p,(int)*l,su,xo);
j = (short)*su;
j = (j%(1+slowness) + slowness+3)*10;
for(i=1; i<=j; i++) modifpas(p,l);
getsumxor(p,(int)*l,su,xo);
}



void zakryptuj(co,del,pas,plen,new,oper)
BYTE1 *co,*pas;
int del,new,oper;
short plen;
{
int aa,bb;
BYTE4 t1,t2,t3;
char tmp;
register short j;
register int i;
BYTE4 mask;
BYTE4 mixbufsize;
BYTE1 *mixbuf;
BYTE1 pas2[maxpalen+2];
short plen2;

if(newalgor)
{
if(new)
	{
	mask= (1<<new)-1;
	mixbufsize= 1<<(2*new);
	}

aa=84627589;
bb=76427643;

/*first initialize congruential generator*/
t1= (BYTE4)pas[0];
t2= (BYTE4)pas[1];
t3= (BYTE4)pas[2];
aa ^= ((int)(t1 | (t2<<8) | (t3<<16)));
for(i=0;i<=20+slowness/2;i++) (void)rnd2(&aa);
if(plen>=6)
	{
	t1= (BYTE4)pas[3];
	t2= (BYTE4)pas[4];
	t3= (BYTE4)pas[5];
	aa ^= ((int)(t1 | (t2<<8) | (t3<<16)));
	for(i=0;i<=10+((1+aditional)*slowness)/10;i++) (void)rnd2(&aa);
	}

/*also initialize additive generator*/
bb ^= aa;
if(newalgor6 && bb==0) /* not very probable to happen, but should be fixed */
	{
	if(aa==0) bb=21436587; else bb=aa;
	}
xrandinit(bb,(char *)pas,(int)plen);
for(i=0;i<150+slowness/5+(newalgor3?(int)plen:0);i++) (void)xrand55();

/* allocate and initialize initialize mixbuf */
if(new)
	{
	if((mixbuf=(BYTE1 *) malloc((unsigned)mixbufsize*sizeof(BYTE1)))== NULL)
		{fprintf(stderr,"%s: not enough memory for temporary buffer\n");
		t1=t2=t3=bb=aa=0; xrandclear();
		for(i=0;i<del;i++) co[i]=0;
		for(i=0;i<plen;i++) pas[i]=0;
		konec(co,20);
		}
	/*initialize the buffer with pseudorandom*/
	for(i=0;i<mixbufsize;i++)mixbuf[i]=(xrand55()^rnd1(&aa));
	}

/*the crypting itsself*/
i=0;
while(i<del)
	{
	/* couple the rnd generators together to make complicated algorithm */
	if((aa&0x30000)==0x30000)
		{tmp=xrand55();
		if((tmp&0xf8)==0xf8) modifpas(pas,&plen);
		}
	if(((pas[2]^pas[0])&7) ==7)
		{
		/* char transforms to negative signed integer before xor */
		if(newalgor6) aa ^= ((BYTE1) xrand55()); else aa ^= xrand55();
		(void)rnd1(&aa);
		tmp=(0x1f & (aa>>9));
		if(tmp==0x1f)
			{
			modifpas(pas,&plen);
			xrandinit(0,(char *)pas,(int)plen);
			for(j=0;j<=slowness/23;j++) (void)xrand55();
			}
		(void)rnd1(&aa);
		}
	if(new)
		{ /* prepare once more modifpas, for addressing in mixbuf */
		modifpas(pas,&plen);
		pascpy(pas2,pas,plen);
		plen2=plen;
		}
	modifpas(pas,&plen);
	if(new && plen>plen2)	for(j=plen2;j<plen;j++) pas2[j]=rnd2(&aa);

	/*use it for xoring*/
	for(j=0; j<plen; j++)
		if(i>=del) {goto clearit;}
			else
			   {
			   BYTE1 rndb,tmp;
			   rndb=0;
			   if(new)
				{
				int addr;
				addr= (rnd1(&aa)&mask)<<new;
				addr |= (pas2[j]&mask);
				rndb=mixbuf[addr];
				mixbuf[addr]^= (BYTE1)(xrand55()^(j&0xff));
				aa ^= i;
				}
			   if(newalgor7)
			   	tmp= (rndb ^ (pas[j] + ((BYTE1)rnd2(&aa))) ^ ((BYTE1)xrand55()));
			   else
			   	tmp= (rndb ^ pas[j] ^ ((BYTE1)rnd2(&aa)) ^ ((BYTE1)xrand55()));
			   if(oper==1) co[i++] += tmp;
			   else if (oper == -1) co[i++]-=tmp;
			   else co[i++] ^=tmp;
			   }
	}

clearit:
if(new)
	{
	for(i=0;i<mixbufsize;i++) mixbuf[i]=0;
	(void)free(mixbuf);
	}
t1=t2=t3=bb=aa=0; xrandclear();
plen2=0;
for(i=0;i<maxpalen;i++) pas2[i]=0;
}
else
{/*old algorithm*/
i=0;
while(i<del)
	{
	modifpas(pas,&plen);
	for(j=0; j<plen; j++)
		if(i>=del) return;
			else
			   co[i++] ^= pas[j];
	}
}
}




void overxor(co,lenco,cim,lencim)
BYTE1 *co, *cim;
int lenco, lencim;
{
register int i,j;

for(i=j=0; i<lenco; i++, j=(j+1)%lencim) co[i] ^= cim[j];
}




void prexoruj(co,dleceho,delkaceho)
BYTE1 *co,*dleceho;
int delkaceho;
{
BYTE1 sum,xor;
getsumxor(dleceho,delkaceho,&sum,&xor);
*co ^= sum;
*(co+1) ^= sum;
*(co+2) ^= xor;
*(co+3) ^= xor;
}




void myencrypt(buf,blen,pas,plen,output)
BYTE1 *buf,*pas;
int blen;
short plen;
FILE *output;
{
BYTE1 f[fieldinfo+1],fgarb1[256],fgarb2[256],pas2[maxpalen+2],pas3[maxpalen+2],hbuf[hashlen];
register int i,j,base;
int garb1,garb2,kolikrat;
BYTE1 sum,xor,cim,datasum,dataxor;
short plen3,plen2;


initpas(pas,&plen,&sum,&xor);
pascpy(pas2,pas,plen2=plen);
for(i=1; i<=10+(newalgor3?slowness/61+(sum&0x07):0); i++) modifpas(pas2,&plen2);
kolikrat = 7+ ((int)xor)%(slowness+5);
cim=sum;
if(newalgor8)
	{
	pascpy(pas3,pas2,plen3=plen2);
	for(i=1;i<23+slowness/7+blen%slowness;i++) modifpas(pas3,&plen3);
	}
for(i=0; i<fieldinfo; i++) f[i]=randbyte();

/*check uniformity of file*/
j=0;
for(i=0; i<blen-1; i++) if(buf[i] != buf[i-1]) j++;
if(j<10) {fprintf(stderr,"%s: Your file is too uniform!\n",myname); konec(buf,10);}

getsumxor(buf,blen,&datasum,&dataxor);
base = (int) (xor&0x7f);
garb1= (int) f[base];
garb2= (int) f[base+1];
for(i=0; i<=garb1; i++) fgarb1[i]=randbyte();
for(i=0; i<=garb2; i++) fgarb2[i]=randbyte();

/*Main part of the encryption*/
zaxoruj(pas,(int)plen,f[base+2]=datasum);
j= (int) (f[base+3]= dataxor);
for(i=0; i<=j; i++) modifpas(pas,&plen);

/*newalgor3: password is randomly xored by 8 bytes saved in the
cipher text, but overxored by hash of the encrypted buffer.
purpose: to force the cryptanalyst to decrypt the whole buffer
with the 16B password in order to be able to make the 2nd decryption
maybe is not necessary, because it was already quite complicated, but ... */

if(newalgor3)
	{
	overxor(pas,(int)plen,f+base+21,hashlen);
	j=slowness/29+13+kolikrat%17;
	for(i=0; i<=j; i++) modifpas(pas,&plen);
	}
zakryptuj(buf,blen,pas,plen,(newalgor5?mixsize:0),0);
if(newalgor3)
	{
	myhash(buf,blen,hbuf,hashlen);
	overxor(f+base+21,hashlen,hbuf,hashlen);
	}

plen=16;
pascpy(pas,f+base+5,16);
for(i=0; i<=kolikrat; i++) modifpas(pas,&plen);
zakryptuj(buf,blen,pas,plen,(newalgor5?mixsize:0),(newalgor7?1:0));
if(newalgor8) zakryptuj(buf,blen,pas3,plen3,(newalgor5?(mixsize>5?mixsize-2:mixsize):0),0);

zaxoruj(buf,blen,f[base+4]);
prexoruj(f+base+5,f,base);
prexoruj(f+base+7,f+base+(newalgor3?21+hashlen:21),fieldinfo-base-(newalgor3?21+hashlen:21));
prexoruj(f+base+9,fgarb1,garb1+1);
prexoruj(f+base+13,buf,blen);
prexoruj(f+base+17,fgarb2,garb2+1);

zakryptuj(f+base,(newalgor3?21+hashlen:21),pas2,plen2,0,0);
zaxoruj(f+base,(newalgor3?21+hashlen:21),cim);
/*end of the Main part*/

for(i=0; i<fieldinfo; i++) {fputc((char)f[i],output); f[i]= (BYTE1)0;}
for(i=0; i<=garb1; i++) {fputc((char)fgarb1[i],output); fgarb1[i]= (BYTE1)0;}
for(i=0; i<blen; i++) {fputc((char)buf[i],output); buf[i]= (BYTE1)0;}
for(i=0; i<=garb2; i++) {fputc((char)fgarb2[i],output); fgarb2[i]= (BYTE1)0;}
for(i=0;i<=maxpalen;i++) pas3[i]=pas2[i]=0;
for(i=0;i<=hashlen;i++) hbuf[i]=0;
i=0;
j=0;
base=0;
garb1=0;
garb2=0;
kolikrat=0;
blen=0;
plen=0;
plen2=0;
plen3=0;
sum=0;
xor=0;
cim=0;
datasum=0;
dataxor=0;
/*everything cleared*/
}




void mydecrypt(f,blen,pas,plen,output)
FILE *output;
BYTE1 *f,*pas;
int blen;
short plen;
{
BYTE1 *buf,*fgarb1,*fgarb2,workpas[maxpalen+2],pas3[maxpalen+2],pas2[maxpalen+2],hbuf[hashlen];
short workplen,plen2,plen3;
register int i,j,base;
int blen0,garb1,garb2,kolikrat;
BYTE1 sum,xor,cim,wsum,wxor;

initpas(pas,&plen,&sum,&xor);
blen0 = blen;
pascpy(pas2,pas,plen2=plen);
for(i=1; i<=10+(newalgor3?slowness/61+(sum&0x07):0); i++) modifpas(pas2,&plen2);
kolikrat = 7+ ((int)xor)%(slowness+5);
cim=sum;

if(newalgor8) pascpy(pas3,pas2,plen3=plen2);

base = (int) (xor&0x7f);

/*test of file sizes*/
if(blen < fieldinfo+minfile) /*this file cannot be a product of our encryption, but let us not tell this to the user*/
	{
	getsumxor(f,blen,&wsum,&wxor);
	blen -= (((int) xor^wsum)%(blen/4));
	buf=f;
	zaxoruj(f,blen,wxor^sum);
	zakryptuj(f,blen,pas,plen,(newalgor5?mixsize:0),0);
	for(i=0; i<blen; i++) fputc((char)buf[i],output);
	{
	for(i=0;i<=maxpalen;i++) workpas[i]=pas2[i]=pas3[i]=0;
	workplen=plen2=plen3=0;
	i=j=base=blen0=garb1=garb2=kolikrat=0;
	sum=xor=cim=wsum=wxor=0;
	/*everything cleared*/
	}
	return;
	}

zaxoruj(f+base,(newalgor3?21+hashlen:21),cim);
zakryptuj(f+base,(newalgor3?21+hashlen:21),pas2,plen2,0,0);
garb1= (int) f[base];
garb2= (int) f[base+1];
fgarb1= f+fieldinfo;
fgarb2= f+blen-garb2-1;
buf= f+fieldinfo+garb1+1;
blen -= (fieldinfo+garb1+1+garb2+1);
if(blen < minfile) /*bad password or file - udelat kamuflaz*/
	{
	blen += (fieldinfo+garb1+1+garb2+1);
	buf=f;
	fgarb1= f+5;
	fgarb2= f+10;
	garb1 &= 0x7f;
	garb2 &= 0x7f;
	getsumxor(f,blen,&wsum,&wxor);
	blen -= (((int) xor^wsum)%(blen/4));
	}

/*Main part of the decryption*/
prexoruj(f+base+5,f,base);
prexoruj(f+base+7,f+base+(newalgor3?21+hashlen:21),fieldinfo-base-(newalgor3?21+hashlen:21));
prexoruj(f+base+9,fgarb1,garb1+1);
prexoruj(f+base+13,buf,blen);
prexoruj(f+base+17,fgarb2,garb2+1);
zaxoruj(buf,blen,f[base+4]);

workplen=16;
pascpy(workpas,f+base+5,16);
for(i=0; i<=kolikrat; i++) modifpas(workpas,&workplen);

if(newalgor8)
	{
	for(i=1;i<23+slowness/7+blen%slowness;i++) modifpas(pas3,&plen3);
	zakryptuj(buf,blen,pas3,plen3,(newalgor5?(mixsize>5?mixsize-2:mixsize):0),0);
	}

zakryptuj(buf,blen,workpas,workplen,(newalgor5?mixsize:0),(newalgor7?-1:0));
if(newalgor3)
	{
	myhash(buf,blen,hbuf,hashlen);
	overxor(f+base+21,hashlen,hbuf,hashlen);
	}

zaxoruj(pas,(int)plen,f[base+2]);
j= (int)f[base+3];
for(i=0; i<=j; i++) modifpas(pas,&plen);
if(newalgor3)
	{
	overxor(pas,(int)plen,f+base+21,hashlen);
	j=slowness/29+13+kolikrat%17;
	for(i=0; i<=j; i++) modifpas(pas,&plen);
	}
zakryptuj(buf,blen,pas,plen,(newalgor5?mixsize:0),0);
/*end of the Main part*/

for(i=0; i<blen; i++) {fputc((char)buf[i],output); buf[i]= (BYTE1)0;}
for(i=0; i<blen0; i++) f[i]= (BYTE1)0;

{
for(i=0;i<=maxpalen;i++) workpas[i]=pas2[i]=pas3[i]=0;
for(i=0;i<=hashlen;i++) hbuf[i]=0;
workplen=plen2=plen3=0;
i=j=base=blen0=garb1=garb2=kolikrat=0;
sum=xor=cim=wsum=wxor=0;
/*everything cleared*/
}
}





/******************************************************************************/

main(argc,argv)
int argc;
char **argv;
{
boolean encrypt=false;
boolean decrypt=false;
boolean pasnaline=false;
boolean skipcheck=false;
int bufsize;
BYTE1 *buf;
int nread;
char *infile,*outfile,*s,line[2048];
register int i;


myname = argv[0];
newalgor9= newalgor8= newalgor7= newalgor6= newalgor5= newalgor4= newalgor3= newalgor2= newalgor = true;
mixsize=8;
bufsize=defbuflen;
slowness=defslowness;
aditional=defadit;
infile= outfile= (char *)NULL;
buf= (BYTE1 *)NULL;
input=stdin; output=stdout;

while (--argc >0 && (**++argv == '-') )
	for(s= *argv + 1; *s != '\0'; s++)
		switch(*s) {
		case 'b':
			newalgor=false;
		case 'B':
			newalgor2 =false;
		case 'c':
			newalgor3 =false;
		case 'C':
			newalgor4 =false;
		case 'D':
			newalgor6= newalgor5= false;
		case 'E':
			newalgor8= newalgor7= false;
		case 'F':
			newalgor9= false;

			break;
		case 'e':
			encrypt=true;
			break;
		case 'd':
			decrypt=true;
			break;
		case 's':
			if(--argc <= 0)
				   {fprintf(stderr,"%s: missing argument after\
 option -%c in command line\n\n",myname,*s); usage();}
			sscanf(*++argv,"%d",&slowness);
			if(slowness<minslowness) slowness=minslowness;
			if(slowness>maxslowness) slowness=maxslowness;
			break;
		case 'a':
			if(--argc <= 0)
				   {fprintf(stderr,"%s: missing argument after\
 option -%c in command line\n\n",myname,*s); usage();}
			sscanf(*++argv,"%d",&aditional);
			if(aditional <0) aditional *= -1;
			if(aditional>maxadit) aditional=maxadit;
			if(aditional<minadit) aditional=minadit;
			break;
		case 'm':
			if(--argc <= 0)
				   {fprintf(stderr,"%s: missing argument after\
 option -%c in command line\n\n",myname,*s); usage();}
			sscanf(*++argv,"%d",&bufsize);
			if(bufsize<0) bufsize *= -1;
			if(bufsize<minbufsize) bufsize= minbufsize;
			break;
		case 'A':
			if(--argc <= 0)
				   {fprintf(stderr,"%s: missing argument after\
 option -%c in command line\n\n",myname,*s); usage();}
			sscanf(*++argv,"%d",&mixsize);
			break;
		case 'k':
			if(--argc <= 0)
				   {fprintf(stderr,"%s: missing argument after\
 option -%c in command line\n\n",myname,*s); usage();}
			pasnaline=true;
			paslen=(short)strlen(*++argv);
			if(paslen>=maxpalen)
				{
				myhash((BYTE1)*argv,(int)paslen,pasw,maxpalen-1);
				skipcheck=true;
				paslen=maxpalen-1;
				}
			else strcpy((char *)pasw,*argv);
			for(i=0; i<paslen; i++) (*argv)[i]='\0'; /*this does not work on HP-UX however*/
			break;
		case 'i':
			if(--argc <= 0)
				   {fprintf(stderr,"%s: missing argument after\
 option -%c in command line\n\n",myname,*s); usage();}
			infile= *++argv;
			break;
		case 'o':
			if(--argc <= 0)
				   {fprintf(stderr,"%s: missing argument after\
 option -%c in command line\n\n",myname,*s); usage();}
			outfile= *++argv;
			break;
		default:
			fprintf(stderr,"%s: unknown option -%c\n\n",myname,*s);
			argc= -1;
			break;
		}
if (argc != 0) usage();
/* <0 => illegal option; >0 == argument without '-' */

if(encrypt==decrypt) usage();

/* make mixsize legal */
if(mixsize <3) mixsize=3;
if(mixsize >8)  mixsize=8;

/*open files for i/o if not stdin,stdout*/
if(infile != (char *)NULL) if((input= fopen(infile,"r"))==NULL) {fprintf(stderr,"%s: can't open input file: %s\n",myname,infile); konec(buf,20);}
if(outfile != (char *)NULL) if((output= fopen(outfile,"w"))==NULL) {fprintf(stderr,"%s: can't open output file: %s\n",myname,infile); konec(buf,20);}


if(!pasnaline)
{
getpassword(line,"Whisper the password:");
paslen=(short)strlen(line);
if(paslen>=maxpalen) /*if passphrase is too long, just take hash from it */
	{
	skipcheck=true;
	myhash((BYTE1)line,(int)paslen,pasw,maxpalen-1);
	paslen=maxpalen-1;
	}
else strcpy((char *)pasw,line);
for(i=0;i<2048;i++) line[i]=' ';
}

initrandom();
if(encrypt && (!skipcheck)) checkpasswd(pasw,paslen);
if(decrypt && paslen<minpassword)
	{
	/*don't tell to the naive user that password was illegal, even if he could
	find it by trying encryption with it*/
	paslen=minpassword+1;
	for(i=0; i<paslen; i++)
		if(!pasw[i]) pasw[i]=(BYTE1)(i+32);
	}

buf=getbuf(bufsize);
nread=0;
while(((i=fgetc(input))!=EOF) && (nread<bufsize)) buf[nread++]=(BYTE1)i;
if(i != EOF) {fprintf(stderr,"%s: Your file is too big, use option -m!\n",myname); konec(buf,10);}
if(nread<minfile) {fprintf(stderr,"%s: Your file is too short!\n",myname); konec(buf,10);}


minpalen= paslen+1-(paslen%2);

if(decrypt) mydecrypt(buf,nread,pasw,paslen,output);
else
if(encrypt) myencrypt(buf,nread,pasw,paslen,output);

konec(buf,0);
}

--
Jiri Pittner

jiri@hpsiepsi.chemie.fu-berlin.de
jiri@kirk.chemie.fu-berlin.de

