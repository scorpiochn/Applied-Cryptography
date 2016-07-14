/* isomorph.c -- find isomorphs from a dictionary */

/* Copyright (c) 1994 by PC Leyland */

/* This code may be freely copied or adapted, as long as you
   give me credit for my work, and don't blame me for your bugs.
   What you do about your own work is entirely up to you, but I take
   no responsibility for the effects of my bugs, if any.
*/

/* Usage: isomorph PATTERN < dictionary
   writes all words from the dictionary isomorphic to PATTERN (e.g. belling,
   freeman, ...
*/

#include <stdio.h>

main (argc, argv)
char **argv;
int argc;
{
   char word[30], map[128];
   int i;
   int getword (), isomorphic();

   while (getword (word))
      if (isomorphic (word, argv[1], map))
	 printf ("%s\n", word);
}

int getword (word)
char *word;
{
   int c;

   if (feof (stdin)) return 0;
   while ((c = getchar ()) != '\n' && c != EOF) *word++ = c;
   *word = '\0';
   return 1;
}

int isomorphic (s, p, map)
char *s, *p, *map;
{
   int i;
   char revmap[128];

   if (strlen (s) != strlen (p)) return 0;
   for (i = 0; i < 128; i++) map[i] = revmap[i] = 0;
   
   while (*p)
   {
      if (!map[*p])
      {
	 if (!revmap[*s])
	 {
	    map[*p] = *s;
	    revmap[*s] = *p;
	 }
	 else
	    return 0;
      }
      else
	 if (map[*p] != *s || revmap[*s] != *p) return 0;
      
      p++;
      s++;
   }
   return 1;
}

