From msuinfo!agate!howland.reston.ans.net!xlink.net!math.fu-berlin.de!Glycin.Chemie.FU-Berlin.DE!jiri Sat Jun  5 20:54:55 1993
Newsgroups: sci.crypt
Path: msuinfo!agate!howland.reston.ans.net!xlink.net!math.fu-berlin.de!Glycin.Chemie.FU-Berlin.DE!jiri
From: jiri@chemie.fu-berlin.de (jiri pittner)
Subject: What does an expert say to my crypt program (source included)
Message-ID: <GQ6DBWIU@math.fu-berlin.de>
Summary: crypting program written in C is presented,
Keywords: encryption
Sender: news@math.fu-berlin.de (Math Department)
Organization: Free University of Berlin, Germany
Date: Sat, 5 Jun 1993 15:15:07 GMT
Lines: 1090


Greetings,

One year ago I have written a crypring program, since I was not
satisfied with standart Unix crypt. Just recently I have found
the existence of this network news service and I would appreciate
if some professional can have a look on this stuff ...

Of course, I have read the instructions in the FAQ file and I think
this program does not violate the basic rules , so I hope I don't
waste time of an expert ...

The source in C is included below as well as few of my comments to it ...

Thanks in advance.
Jiri Pittner, jiri@hpsiepsi.chemie.fu-berlin.de

---------------------------------

It is based on standard pseudorandom generators congruential
and aditive one and modified vob'Neumanns algorithm. The generators
are "coupled" together, which should increase the period and
avoid simple patterns typical for congruential generator.
The crypted text is xored by sequence of "modified" passwords,
but also the password lengths changes in some reasonable limits 
(not to become very short!). Not all of the information contained
in the generators is used in ciphertext production -> it is not
possible to use a sequence of blanks in plain text and use it
for decryption of the rest of the file.

The encryption is done twice, first with some product of the password,
but also with randomly (time) initiated pseudorandom password,
which is in crypted way (depending on the real password) saved in the ciphertext.
The ciphertext created by this program has passed entropy and chi-square test.


There have been done things preventing people who don't know the algorithm
to even guess what's going on - the random encryption described above,
product file has different length than the input, each bit of the
product is important and ... 
The program does not allow its user to use passwords like lowercase words
or things like aaaa1111 and refuses to crypt too short files or 1KB of zeros ...

Last, but not least, it cleans its buffers as soon as possible, to decrease
the chance of hackers reading /dev/mem .

The program is quite time consuming,  crypting of 1MB on 120MIPS
workstation takes about 30 seconds (with default options).
I thought about putting also DES inside and coupling it further with the generators
already used, but I was afraid that it will be unpracticably slow ...
(By the way, DES routines are also available in the library Numerical Recipes.)

Who does want to know more, has to read the source!


P.S. I used this program for maintaining of a secret file, containing
even PIN of my creditcard. DID I MAKE A MISTAKE?
---------------------------------------------------------

/*
********************************************************
* crypting program (c) Jiri Pittner, 1991-2            *
* contact address: jiri@hpsiepsi.chemie.fu-berlin.de   *
* This is freeware - can be used for any non-profit    *
* purpose, without any warranty, of course ...         *
* provided that this copyright message is not removed  *
********************************************************


on convex compile -lcurses -ltermcap,
on sun like on convex -Dunix -Dconvex -lcurses -ltermcap
on amiga -lm32 -lc32 with long integer, add #define amiga, needs time.h
on cray x-mp: qsub -lt 0:0:19 <<!
cc -h olevel_2 /home/bf2130ef/pokusy/cry.c -lcurses
mv a.out /home/bf2130ef/pokusy/cr
pozor - blbnou nejak ifdefy a v knihovne neni srandom ani srand!!!
proto grepem vyhod pred kompilaci srand!!!

POZOR!!!!! CRYPTED FILES ARE PORTABLE BETWEEN convex-sun-hp7xx-amiga | cray xmp&ymp
Why - different sizeof(int)? find it sometimes!!!!!!

Mozna nekdy udelej ty permutace navic ...


POZOR!!!!  na cray y-mp se stalo, ze pri pouziti knihovny curses a redirekci
se zapsaly do stdout i nejake ridici kody pro terminal, a tak se pochopitelne
cely file zmrsil. Lze davat heslo z povelove radky.
dodelany options pro primou specifikaci input a output filu

24.9. zmeneny ifdefy convex  na unix,   zkus  na convexu, vezmi domu na amigu
!
*/

/*
#define amiga
*/
/*
#define unix
*/



/*testovano s novym ANSI C na Convexu , je o 1/3 rychlejsi !! */

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
#endif
#ifdef amiga
#include <time.h>
#endif


#ifdef unix
#include <curses.h>
#endif


/*you must not use minpassword <6*/
#define minfile 50
#define minpassword 9
#define maxpalen 41
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
boolean newalgor2;
boolean newalgor;
/*for closing*/
static FILE *input=NULL;
static FILE *output=NULL;
BYTE1 pasw[maxpalen+2]; /* *buf lint:unused*/
short paslen;




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
	    On some machines there can be problems with redirection of stdin\n\
	    and stdout when you want to specify password 'invisibly' from ter-\n\
	    minal, then this options become useful.\n\
       -e   for encrypting\n\
       -d   for decrypting\n\
       -b   for older backward compatibility\n\
       -B   for newer backward compatibility\n\
       -k   it is not recomended to input password through command line\n\
	    in multiuser system - %s can prompt you for password as login\n\
       -s   when slowness is low, longer password is recomended!\n\
	    this option is due to use on very differently quick computers;\n\
	    remember that this factor is in some sense part of keyword -\n\
	    you must know which value was used for encrypting!\n\
	    default slowness is %d, minimum %d, maximum %d.\n\
       -a   aditional number of password modifications in crypting procedure\n\
            minimum is 0, default %d, maximum is %d\n\
	    remember that this factor is in some sense part of keyword -\n\
	    you must know which value was used for encrypting!\n\
       -m   must be specified when working on larger files then is the default\n\
	    value: %d bytes\n\n\
(c) J.Pittner, 1991.\n\n",myname,myname,defslowness,minslowness,maxslowness,
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



int xmult(p,q)
int p,q;
{
int p1,p0,q1,q0;

p1=p/xrandm1; p0=p%xrandm1;
q1=q/xrandm1; q0=q%xrandm1;
return (((p0*q1+p1*q0)%xrandm1)*xrandm1+p0*q0)%xrandm;
}



char rnd1(a)
int *a;
{
return (char) (0xff & ((*a = (xmult(*a,xrandb1)+1)%xrandm)>>8));
}




char rnd2(a)
int *a;
{
return (char) (0xff & ((*a = (xmult(*a,xrandb2)+1)%xrandm) >> 9));
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
		xrandaa[xrandj]=(xmult(xrandb3,xrandaa[xrandj-1])+1)%xrandm;
		}while(xrandj<54);
}
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



/*
main(argc,argv)
int argc;
char **argv;
{
int i;
int a=5234562;
xrandinit(a,argv[1],strlen(argv[1]));
for(i=0;i<1000;i++) (void)(xrand55());
for(i=0;i<100000;i++) fputc(xrand55(),stdout);
for(i=0;i<100000;i++) fputc(rnd2(&a),stdout);
}
*/










/*machine dependent*/
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



BYTE1 randbyte()
{
static int a=98345721;
int i;
BYTE1 x;
x=randbyte0();
for(i=0;i<(int)x&7;i++ ) (void)rnd1(&a);
return x ^ rnd1(&a);
}




/*machine dependent*/
char *getpassword(line,prompt)
char *prompt, *line;
{
register char *p;
#ifdef unix
FILE *term;

if((term=fopen("/dev/tty","r"))==NULL) 
	{
	fprintf(stderr,"%s: No terminal for this process!\n",myname);
	konec((BYTE1 *)NULL,100);
	}
initscr();
noecho();
fprintf(stderr,"%s",prompt);
fgets(line,256,term);
fclose(term);
echo();
fprintf(stderr,"\n");
endwin();
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
register short i,j,nasel,ndif,naselx,ndigit;
if(paslen<minpassword) {fprintf(stderr,"%s: Your password is too short!\n",myname); konec((BYTE1 *)NULL,10);}
nasel=ndif=naselx=ndigit=0;
for(i=0; i<paslen; i++) 
	{
	if(pas[i]&0x80 || !isalpha((char)pas[i])) nasel=1;
	if(pas[i]&0x80 || !islower((char)pas[i])) naselx++;
	if(!(pas[i]&0x80) && isdigit((char)pas[i])) ndigit++;
	for(j=0; j<i; j++) if(pas[i]==pas[j]) ndif++;
	}
if(ndigit>paslen-3 || naselx<3 || !nasel || ndif>0.35*paslen*(paslen-1))
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



void rotbyte(b)
BYTE1 *b;
{
register int j;
j= ((int)*b)<<1;
*b= (j&0x100? 1 : 0);
*b |= ((BYTE1) j&0xff);
}



/* maybe sometimes do crc32 or longer sequence */
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
int k;
register int j;
register BYTE4 x;

getsumxor(pas,(int)*paslen,&sum,&xor);

/*"randomly" modify length*/
j = ((int)xor)%17;
if(j <= 4 && *paslen < maxpalen) {(*paslen)++; pas[*paslen - 1]=sum;}
if(j >= 11 && *paslen > minpalen) (*paslen)--;

/*J.v.Neumann's old algorithm*/
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
k= (int) (xor & 7);
if (slowness<=15) k &= 3;
for(j=1; j<=k; j++) rotbyte(&sum);
zaxoruj(pas,(int)*paslen + 1,sum);
if(sum&4 == 4)
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



void zakryptuj(co,del,pas,plen)
BYTE1 *co,*pas;
int del;
short plen;
{
int aa,bb;
BYTE4 t1,t2,t3;
char tmp;
register short j;
register int i;

if(newalgor)
{
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
xrandinit(bb,(char *)pas,(int)plen);
for(i=0;i<150+slowness/5;i++) (void)xrand55();

/*the crypting itsself*/
i=0;
while(i<del)
	{
	/* couple the rnd generators together to make very complicated algorithm */
	if((aa&0x30000)==0x30000)
		{tmp=xrand55();
		if((tmp&0xf8)==0xf8) modifpas(pas,&plen);
		}
	if(((pas[2]^pas[0])&7) ==7)
		{
		aa ^= xrand55();
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
	modifpas(pas,&plen);
	/*use it for xoring*/
	for(j=0; j<plen; j++)
		if(i>=del) {goto clearit;}
			else
			   {
			   co[i++] ^= (pas[j] ^ ((BYTE1)rnd2(&aa)) ^ ((BYTE1)xrand55()));
			   }
	}

clearit:
t1=t2=t3=bb=aa=0; xrandclear();/*clear it at the end*/
}
else
{/*old algorithmus*/
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
BYTE1 f[fieldinfo+1],fgarb1[256],fgarb2[256],pas2[maxpalen+2];
register int i,j,base;
int garb1,garb2,kolikrat;
BYTE1 sum,xor,cim,datasum,dataxor;
short plen2;


initpas(pas,&plen,&sum,&xor);
pascpy(pas2,pas,plen2=plen);
for(i=1; i<=10; i++) modifpas(pas2,&plen2);
kolikrat = 7+ ((int)xor)%(slowness+5);
cim=sum;
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

/*hlavni cast cryptovani*/
zaxoruj(pas,(int)plen,f[base+2]=datasum);
j= (int) (f[base+3]= dataxor);
for(i=0; i<=j; i++) modifpas(pas,&plen);
zakryptuj(buf,blen,pas,plen);

plen=16;
pascpy(pas,f+base+5,16);
for(i=0; i<=kolikrat; i++) modifpas(pas,&plen);
zakryptuj(buf,blen,pas,plen);

zaxoruj(buf,blen,f[base+4]);
prexoruj(f+base+5,f,base);
prexoruj(f+base+7,f+base+21,fieldinfo-base-21);
prexoruj(f+base+9,fgarb1,garb1+1);
prexoruj(f+base+13,buf,blen);
prexoruj(f+base+17,fgarb2,garb2+1);

zakryptuj(f+base,21,pas2,plen2);
zaxoruj(f+base,21,cim);
/*konec vlastniho cryptu*/

for(i=0; i<fieldinfo; i++) {fputc((char)f[i],output); f[i]= (BYTE1)0;}
for(i=0; i<=garb1; i++) {fputc((char)fgarb1[i],output); fgarb1[i]= (BYTE1)0;}
for(i=0; i<blen; i++) {fputc((char)buf[i],output); buf[i]= (BYTE1)0;}
for(i=0; i<=garb2; i++) {fputc((char)fgarb2[i],output); fgarb2[i]= (BYTE1)0;}
for(i=0;i<=maxpalen;i++) pas2[i]=0;
i=0;
j=0;
base=0;
garb1=0;
garb2=0;
kolikrat=0;
blen=0;
plen=0;
plen2=0;
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
BYTE1 *buf,*fgarb1,*fgarb2,workpas[maxpalen+2],pas2[maxpalen+2];
short workplen,plen2;
register int i,j,base;
int blen0,garb1,garb2,kolikrat;
BYTE1 sum,xor,cim,wsum,wxor;

initpas(pas,&plen,&sum,&xor);
blen0 = blen;
pascpy(pas2,pas,plen2=plen);
for(i=1; i<=10; i++) modifpas(pas2,&plen2);
kolikrat = 7+ ((int)xor)%(slowness+5);
cim=sum;
base = (int) (xor&0x7f);

/*testy velikosti filu*/
if(blen < fieldinfo+minfile) /*kamuflaz, ze tento file nemohl vzniknout cryptem*/
	{
	getsumxor(f,blen,&wsum,&wxor);
	blen -= (((int) xor^wsum)%(blen/4));
	buf=f;
	zaxoruj(f,blen,wxor^sum);
	zakryptuj(f,blen,pas,plen);
	for(i=0; i<blen; i++) fputc((char)buf[i],output);
	{
	for(i=0;i<=maxpalen;i++) workpas[i]=pas2[i]=0;
	workplen=plen2=0;
	i=j=base=blen0=garb1=garb2=kolikrat=0;
	sum=xor=cim=wsum=wxor=0;
	/*everything cleared*/
	}
	return;
	}

zaxoruj(f+base,21,cim);
zakryptuj(f+base,21,pas2,plen2);
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

/*hlavni cast dekodovani*/
prexoruj(f+base+5,f,base);
prexoruj(f+base+7,f+base+21,fieldinfo-base-21);
prexoruj(f+base+9,fgarb1,garb1+1);
prexoruj(f+base+13,buf,blen);
prexoruj(f+base+17,fgarb2,garb2+1);
zaxoruj(buf,blen,f[base+4]);

workplen=16;
pascpy(workpas,f+base+5,16);
for(i=0; i<=kolikrat; i++) modifpas(workpas,&workplen);
zakryptuj(buf,blen,workpas,workplen);

zaxoruj(pas,(int)plen,f[base+2]);
j= (int)f[base+3];
for(i=0; i<=j; i++) modifpas(pas,&plen);
zakryptuj(buf,blen,pas,plen);
/*konec vlastniho cryptu*/

for(i=0; i<blen; i++) {fputc((char)buf[i],output); buf[i]= (BYTE1)0;}
for(i=0; i<blen0; i++) f[i]= (BYTE1)0;

{
for(i=0;i<=maxpalen;i++) workpas[i]=pas2[i]=0;
workplen=plen2=0;
i=j=base=blen0=garb1=garb2=kolikrat=0;
sum=xor=cim=wsum=wxor=0;
/*everything cleared*/
}
}




/* test of random generator ... 
void pripas(pa,l)
BYTE1 *pa;
short l;
{
register int i;
register int j;

for(i=0;i<l;i++) {j= pa[i]; printf("%d ",j);}
fputc('\n',stdout);
}

m a i n (argc,argv)
int argc;
char **argv;
{
BYTE1 pa[maxpalen+1];
short n,n0;
register int i,j,k;
int count[8],tot,max;
tot=0;
for(j=0;j<=7; j++) count[j]=0;

if(argc != 3) {fprintf(stderr,"Usage: %s kod pocet_iteraci\n",argv[0]); exit(10);}
strcpy((char *)pa,argv[1]);
n0=n=strlen(argv[1]);
sscanf(argv[2],"%d",&max);

for(i=1; i<=max; i++)
	{
	if(max <=100) pripas(pa,n);
	modifpas(pa,&n);
	tot += (int)n;
	for(j=0; j<n; j++)
	    for(k=0; k<=7; k++)
		if(pa[j] & (1<<k)) count[k]++;
	}
printf("total bytes = %d, average length = %6.3f, length ratio = %7.5f\n",tot
	,tot/(float)max,tot/(float)max/(float)n0);
for(j=0;j<=7; j++) printf("%7.5f ",count[j]*2.0/(float)tot);
printf("\n");
}
*/



/******************************************************************************/
main (argc,argv)
int argc;
char **argv;
{
boolean encrypt=false;
boolean decrypt=false;
boolean pasnaline=false;
int bufsize;
BYTE1 *buf;
int nread;
char *infile,*outfile,*s,line[256];
register int i;


newalgor2= newalgor = true;
myname = argv[0];
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
			newalgor2= newalgor=false;
			break;
		case 'B':
			newalgor2 =false;
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
		case 'k':
			if(--argc <= 0)
				   {fprintf(stderr,"%s: missing argument after\
 option -%c in command line\n\n",myname,*s); usage();}
			pasnaline=true;
			paslen=(short)strlen(*++argv);
			if(paslen>=maxpalen){fprintf(stderr,"%s: Your password is too long!\n",myname); konec(buf,10);}
			strcpy((char *)pasw,*argv);
			for(i=0; i<paslen; i++) (*argv)[i]='\0';
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
/* <0 => illegal option; >0 == argument neuvozeny '-' */

if(encrypt==decrypt) usage();

/*open files for i/o if not stdin,stdout*/
if(infile != (char *)NULL) if((input= fopen(infile,"r"))==NULL) {fprintf(stderr,"%s: can't open input file: %s\n",myname,infile); konec(buf,20);}
if(outfile != (char *)NULL) if((output= fopen(outfile,"w"))==NULL) {fprintf(stderr,"%s: can't open output file: %s\n",myname,infile); konec(buf,20);}


if(!pasnaline)
{
getpassword(line,"Whisper the password:");
paslen=(short)strlen(line);
if(paslen>=maxpalen){fprintf(stderr,"%s: Your password is too long!\n",myname); konec(buf,10);}
strcpy((char *)pasw,line);
for(i=0;i<256;i++) line[i]=' ';
}

initrandom();
if(encrypt) checkpasswd(pasw,paslen);
if(decrypt && paslen<minpassword)
	{
	/*kamuflaz*/
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


