/* Playfair encryption and decryption */

/*
   All non-alphabetics in the input text are silently ignored, as is
   the final odd character if any.  Converting the keyword to the
   keysquare is done in the traditional manner of dropping repeats and
   completing the square with unused letters in alphabetical order,
   despite its relative insecurity.  Hey, this is a toy cipher!
   Anyway, you can always give a keyword of 26 letters in your desired
   order.  The direction of en/decryption is seet by dir: >0 means
   encrypt, <=0 means decrypt.  The input text is always *pt, the
   output is *ct.  The code has been written for transparency more
   than efficiency.  I repeat, this is a toy cipher.

   Copyright (c) 1994 by PC Leyland, pcl@ox.ac.uk

   Permission is granted to make any use of this code as you feel
   fit,as long as you give me credit for writing it and do not blame
   me for any bugs you may introduce.  I take no responsibility
   whatsoever for any bugs I may have introduced.

*/

void playfair (int dir, char *key, char *pt, char *ct)
{
	char *alph = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
	char keycopy[25], pt0, pt1;
	char *ptcopy = ct;
	int i, j, k, lk, lp, rpt0, rpt1, cpt0, cpt1;
	int alphabet [25], row[25], col[25];

	for (i = 0; i < 25; i++) alphabet[i] = -1;

	lk = strlen (key);
	j = 0;
	for (i = 0; i < lk; i++)
	{
		k = toupper (key[i]);
		if (!isalpha (k)) continue;
		if (k == 'J') k = 'I';
		k = strchr (alph, k) - alph;
		if (alphabet[k]	!= -1) continue;	/* Repeat char */
		alphabet[k] = j;
		keycopy[j++] = alph[k];
	}
	for (i = 0; i < 25; i++)
	{
		if (alphabet[i] == -1)
		{
			alphabet[i] = j;
			keycopy[j++] = alph[i];
		}
	}
	for (i = 0; i < 25; i++)
	{
		row[i] = alphabet[i] / 5;
		col[i] = alphabet[i] % 5;
	}
/*
 * Copy plain text, stripping out non-alphabetics and converting to
 * uppercase.  Use ct as the buffer, but will use ptcopy as the name.
 */
	j = 0;
	lp = strlen (pt);

	for (i = 0; i < lp; i++)
		if (isalpha (pt[i]))
			ptcopy [j++] = toupper (pt[i]);
	lp = j;

	if (lp & 1)
	{		/* Odd length plaintext.  Warn and truncate */
		fprintf (stdout,
		         "Odd number of characters in pt -- ignoring last.\n");
		lp--;
	}

	ptcopy[lp] = '\0';

	for (i = 0; i < lp; i += 2)
	{
		pt0 = strchr (alph, ptcopy[i]) - alph;
		pt1 = strchr (alph, ptcopy[i+1]) - alph;
		cpt0 = col[pt0];
		cpt1 = col[pt1];
		rpt0 = row[pt0];
		rpt1 = row[pt1];

		if (pt0 == pt1)
		{
			if (dir > 0)
			{
				ct[i] = ct[i+1] = keycopy[(cpt0 + 5 * rpt0 + 1) % 25];
			}
			else
			{
				ct[i] = ct[i+1] = keycopy[(cpt0 + 5 * rpt0 + 24) % 25];
			}
		}
		else
		if (rpt0 == rpt1)
		{
			if (dir > 0)
			{
				ct[i] = keycopy[(cpt0+1) % 5 + 5 * rpt0];
				ct[i+1] = keycopy[(cpt1+1) % 5 + 5 * rpt1];
			}
			else
			{
				ct[i] = keycopy[(cpt0+4) % 5 + 5 * rpt0];
				ct[i+1] = keycopy[(cpt1+4) % 5 + 5 * rpt1];
			}
		}
		else
		if (cpt0 == cpt1)
		{
			if (dir > 0)
			{
				ct[i] = keycopy[cpt0 + 5 * ((rpt0 + 1) % 5)];
				ct[i+1] = keycopy[cpt1 + 5 * ((rpt1 + 1) % 5)];
			}
			else
			{
				ct[i] = keycopy[cpt0 + 5 * ((rpt0 + 4) % 5)];
				ct[i+1] = keycopy[cpt1 + 5 * ((rpt1 + 4) % 5)];
			}
		}
		else
		{
			ct[i] = keycopy[cpt1 + 5 * rpt0];
			ct[i+1] = keycopy [cpt0 + 5 * rpt1];
		}
	}
}

