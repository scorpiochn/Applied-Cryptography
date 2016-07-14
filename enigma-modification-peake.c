cat crypt
From philip@axis.UUCP Sun Feb 15 14:33:00 1987
Path: beno!seismo!mcvax!inria!axis!philip
From: philip@axis.UUCP
Newsgroups: net.sources
Subject: A crypt program
Keywords: A public domain crypt program
Message-ID: <177@axis.UUCP>
Date: 15 Feb 87 19:33:00 GMT
Organization: Axis Digital, Paris
Lines: 262
Posted: Sun Feb 15 19:33:00 1987


                        Crypt - Decrypt Program
                        ~~~~~~~~~~~~~~~~~~~~~~~

This program is based upon the German WW2 enigma machine.

This worked as follows:

The machine contained several (3 or 4, depending upon the service) rotors,
with contacts on each face. Each rotor had a different mapping (ie wiring)
scheme between the contacts.

Each contact on the input side of rotor 1 was connected to input keys
(letters and numbers). Pressing the key marked 'A' would pass an electric
current into the corresponding contact on the input rotor, this current would
exit on some other contact on the output side, depending upon the internal
wiring.

After each key press, the input rotor would turn one position (thus, pressing
'A' again, would result in a current flowing out of a different output
contact.

After completing one revolution, rotor number two would move one position.

The key to this depended upon the order of the rotors, and their starting
positions.

To decode, simply reverse the current flow, ie, connect the keyboard to the
output, and replace the input by a series of lamps corresponding to the
keys.

This program simulates one of these machines, with several refinements:

1)      Each rotor has 256 positions

2)      The key is not the ordering and starting positions of the rotors,
        since new and different rotors are created for each input key.

3)      The movement of the rotors is not a simple as described above.
        It is basically that, but with rotors selected on a random basis,
        they are advanced a random number of positions.

The result is (I believe - not being a Cryptologist), somewhat more
secure than the original machines, and certainly more secure than the
original UNIX crypt - which has a single rotor, with a reciprocal
mapping - ie if an input of 'A' maps to an output of 'Z', then in the
same rotor position, a 'Z' must map to an 'A'.

if anyone finds a method of breaking this crypt program, I would be glad
to hear about it.

Philip Peake    (philip@axis.uucp)

NOTES:
        The program must have two links, one called crypt, and the other
        called decrypt. Passing a crypted document through crypt again,
        even with the same key, will not decrypt it.

===============================================================================
#include <stdio.h>

#define ROTORSIZ        256
#define MASK            0377
#define EMPTY           07777
#define X_SIZE          4099

char    *strrchr();

unsigned        r1[ROTORSIZ];
unsigned        r2[ROTORSIZ];
unsigned        r3[ROTORSIZ];

unsigned char   x[X_SIZE];

init(password, decrypt)
char    *password;
int     decrypt;
{
        register int    index;
        register int    i;
        int             pipe_fd[2];
        unsigned        random;
        long            seed = 123L;
        char            buf[13];

        strncpy(buf, password, 8);
        while (*password) *password++ = '\0';
        buf[8] = buf[0];
        buf[9] = buf[1];

        pipe(pipe_fd);

        if (fork() == 0)
        {
                close(0);
                close(1);
                dup(pipe_fd[0]);
                dup(pipe_fd[1]);
                execl("/usr/lib/makekey", "-", 0);
                execl("/lib/makekey", "-", 0);
                exit(1);
        }

        write(pipe_fd[1], buf, 10);
        wait((int *) NULL);

        if (read(pipe_fd[0], buf, 13) != 13)
        {
                fprintf(stderr, "crypt: cannot generate key\n");
                exit(1);
        }

        for (i = 0 ; i < ROTORSIZ; i++) r1[i] = r2[i] = r3[i] = EMPTY;

        for (i = 2; i < 13; i++) seed = seed * buf[i] + i;

        i = 0;
        while (i < ROTORSIZ)
        {
                seed = (long)(5L * seed + (long)i);
                random = (unsigned)(seed % 65521L);
                index = (int)(random & MASK);
                if (r1[index] == EMPTY)
                        r1[index] = i++;
                else
                        continue;
        }

        i = 0;
        while (i < ROTORSIZ)
        {
                seed = (long)(5L * seed + (long)i);
                random = (unsigned)(seed % 65521L);
                index = (int)(random & MASK);
                if (r2[index] == EMPTY)
                        r2[index] = i++;
                else
                        continue;
        }

        i = 0;
        while (i < ROTORSIZ)
        {
                seed = (long)(5L * seed + (long)i);
                random = (unsigned)(seed % 65521L);
                index = (int)(random & MASK);
                if (r3[index] == EMPTY)
                        r3[index] = i++;
                else
                        continue;
        }

        for (i = 0; i < X_SIZE; i++)
        {
                seed = (long)(5L * seed + (long)i);
                random = (unsigned)(seed % 65521L);
                x[i] = random & 03;
        }

        if (decrypt)
        {
                invert(r1);
                invert(r2);
                invert(r3);
        }
}

invert(r)
unsigned r[ROTORSIZ];
{
        unsigned        t[ROTORSIZ];
        register int    i;

        for (i = 0; i < ROTORSIZ; i++) t[i] = r[i];
        for (i = 0; i < ROTORSIZ; i++) r[t[i]] = i;
}

crypt()
{
        register        int             ch;
        register        int             i    = 0;
        register        unsigned        ofs1 = 0;
        register        unsigned        ofs2 = 0;
        register        unsigned        ofs3 = 0;

        while ((ch = getchar()) != EOF)
        {
                putchar(r3[r2[r1[ch+ofs1&MASK]+ofs2&MASK]+ofs3&MASK]);

                switch (x[i]){
                case 00:
                                ofs1 = ++ofs1 & MASK;
                                break;
                case 01:
                                ofs2 = ++ofs2 & MASK;
                                break;
                case 02:
                                ofs3 = ++ofs3 & MASK;
                                break;
                }

                if (ofs1 == 0) ofs2 = ++ofs2 & MASK;
                if (ofs2 == 0) ofs3 = ++ofs3 & MASK;

                if (++i == X_SIZE) i = 0;
        }
}

decrypt()
{
        register        int             ch;
        register        int             i    = 0;
        register        unsigned        ofs1 = 0;
        register        unsigned        ofs2 = 0;
        register        unsigned        ofs3 = 0;

        while ((ch = getchar()) != EOF)
        {
                putchar(r1[r2[r3[ch]-ofs3&MASK]-ofs2&MASK]-ofs1&MASK);

                switch (x[i]){
                case 00:
                                ofs1 = ++ofs1 & MASK;
                                break;
                case 01:
                                ofs2 = ++ofs2 & MASK;
                                break;
                case 02:
                                ofs3 = ++ofs3 & MASK;
                                break;
                }

                if (ofs1 == 0) ofs2 = ++ofs2 & MASK;
                if (ofs2 == 0) ofs3 = ++ofs3 & MASK;

                if (++i == X_SIZE) i = 0;
        }
}

main(argc, argv)
int     argc;
char    *argv[];
{
        int     flag;
        char    *p;

        p = strrchr(argv[0], '/');

        if (p == NULL) p = argv[0];
        else ++p;

        if (strcmp(p, "crypt") == 0) flag = 0;
        else                               flag = 1;

        if (argc != 2)
                init(getpass("Enter key: "), flag);
        else
                init(argv[1], flag);

        if (flag) decrypt();
        else      crypt();
}


From philip@axis.UUCP Wed Feb 18 06:17:24 1987
Path: beno!seismo!mcvax!inria!axis!philip
From: philip@axis.UUCP
Newsgroups: net.sources
Subject: Crypt program - mods.
Keywords: makekey replacement code
Message-ID: <180@axis.UUCP>
Date: 18 Feb 87 11:17:24 GMT
Organization: Axis Digital, Paris
Lines: 73
Posted: Wed Feb 18 11:17:24 1987

In the crypt program I recently posted, there was a call made to a
small program "/usr/lib/makekey". Apparently this does not exist on all
*IX* machines.

I really dont see why - it is a 4 or 5 line program which reads a
password on its stdin, and prints the encrypted result on its stdout,
using exactly the same routines as passwd does.

Rather than re-write the program, I have made some mods to the crypt source
to make the calls directly.

Since the library routine is called 'crypt', the routine within my program
has to change its name, 'encrypt' is also used in the library, so the
final name change is to 'encode'.

The following is a diff of the changes required (actually, the source becomes
smaller and simpler .... )

============================================================================

19a20
>       char            *crypt();
22d22
<       int             pipe_fd[2];
25c25,27
<       char            buf[13];
---
>       char            buf[14];
>       char            key[9];
>       char            salt[3];
27,30c29,32
<       strncpy(buf, password, 8);
<       while (*password) *password++ = '\0';
<       buf[8] = buf[0];
<       buf[9] = buf[1];
---
>       strncpy(key, password, 8);
>       salt[0] = key[0];
>       salt[1] = key[1];
>       salt[2] = '\0';
32c34
<       pipe(pipe_fd);
---
>       strncpy(buf, crypt(key, salt), 13);
34,53d35
<       if (fork() == 0)
<       {
<               close(0);
<               close(1);
<               dup(pipe_fd[0]);
<               dup(pipe_fd[1]);
<               execl("/usr/lib/makekey", "-", 0);
<               execl("/lib/makekey", "-", 0);
<               exit(1);
<       }
< 
<       write(pipe_fd[1], buf, 10);
<       wait((int *) NULL);
< 
<       if (read(pipe_fd[0], buf, 13) != 13)
<       {
<               fprintf(stderr, "crypt: cannot generate key\n");
<               exit(1);
<       }
< 
119c101
< crypt()
---
> encode()
202c184
<       else      crypt();
---
>       else      encode();


[nestey] 32) 