#ifndef lint
static char sccsid[] = "@(#)life.c	23.5 90/10/28 XLOCK SMI";
#endif
/*-
 * life.c - Conway's game of Life for the xlock X11 terminal locker.
 *
 * Copyright (c) 1989,90 by Sun Microsystems, Inc.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation.
 *
 * This file is provided AS IS with no warranties of any kind.	The author
 * shall have no liability with respect to the infringement of copyrights,
 * trade secrets or any patents by this file or any part thereof.  In no
 * event will the author be liable for any lost revenue or profits or
 * other special, indirect and consequential damages.
 *
 * Comments and additions should be sent to the authors:
 *
 *		       flar@eng.sun.com and naughton@eng.sun.com
 *
 *		       James A. Graham
 *		       Patrick J. Naughton
 *		       MS 14-01
 *		       Windows and Graphics Group
 *		       Sun Microsystems, Inc.
 *		       2550 Garcia Ave
 *		       Mountain View, CA  94043
 *
 * Revision History:
 * 29-Jul-90: support for multiple screens.
 * 07-Feb-90: remove bogus semi-colon after #include line.
 * 15-Dec-89: Fix for proper skipping of {White,Black}Pixel() in colors.
 * 08-Oct-89: Moved seconds() to an extern.
 * 20-Sep-89: Written.
 */

#include "xlock.h"
#include "lifeicon.bit"

static XImage logo = {
    0, 0,			/* width, height */
    0, XYBitmap, 0,		/* xoffset, format, data */
    LSBFirst, 8,		/* byte-order, bitmap-unit */
    LSBFirst, 8, 1		/* bitmap-bit-order, bitmap-pad, depth */
};
#define min(a, b) ((a)<(b)?(a):(b))
#define	MAXROWS	55
#define MAXCOLS	44

typedef struct {
    int         shooter;
    int         pixelmode;
    int         xs;
    int         ys;
    int         xb;
    int         yb;
    long        startTime;
    long        elapsedTime;
    int         nrows;
    int         ncols;
    int         width;
    int         height;
    unsigned char buffer[(MAXROWS + 2) * (MAXCOLS + 2) + 2];
    unsigned char tempbuf[MAXCOLS * 2];
    unsigned char agebuf[(MAXROWS + 2) * (MAXCOLS + 2)];
}           lifestruct;

static lifestruct lifes[MAXSCREENS];
static int  icon_width,
            icon_height;

/* Buffer stores the data for each cell. Each cell is stored as
 * 8 bits representing the presence of a critter in each of it's
 * surrounding 8 cells. There is an empty row and column around
 * the whole array to allow stores without bounds checking as well
 * as an extra row at the end for the fetches into tempbuf.
 *
 * Tempbuf stores the data for the next two rows so that we know
 * the state of those critter before he was modified by the fate
 * of the critters that have already been processed.
 *
 * Agebuf stores the age of each critter.
 */

#define	UPLT	0x01
#define UP	0x02
#define UPRT	0x04
#define LT	0x08
#define RT	0x10
#define DNLT	0x20
#define DN	0x40
#define DNRT	0x80

/* Fates is a lookup table for the fate of a critter. The 256
 * entries represent the 256 possible combinations of the 8
 * neighbor cells. Each entry is one of BIRTH (create a cell
 * or leave one alive), SAME (leave the cell alive or dead),
 * or DEATH (kill anything in the cell).
 */
#define BIRTH	0
#define SAME	1
#define DEATH	2
static unsigned char fates[256];
static int  initialized = 0;

static int  patterns[][128] = {
    {				/* EIGHT */
	-3, -3, -2, -3, -1, -3,
	-3, -2, -2, -2, -1, -2,
	-3, -1, -2, -1, -1, -1,
	0, 0, 1, 0, 2, 0,
	0, 1, 1, 1, 2, 1,
	0, 2, 1, 2, 2, 2,
	99
    },
    {				/* PULSAR */
	1, 1, 2, 1, 3, 1, 4, 1, 5, 1,
	1, 2, 5, 2,
	99
    },
    {				/* BARBER */
	-7, -7, -6, -7,
	-7, -6, -5, -6,
	-5, -4, -3, -4,
	-3, -2, -1, -2,
	-1, 0, 1, 0,
	1, 2, 3, 2,
	3, 4, 5, 4,
	4, 5, 5, 5,
	99
    },
    {				/* HERTZ */
	-2, -6, -1, -6,
	-2, -5, -1, -5,
	-7, -3, -6, -3, -2, -3, -1, -3, 0, -3, 1, -3, 5, -3, 6, -3,
	-7, -2, -5, -2, -3, -2, 2, -2, 4, -2, 6, -2,
	-5, -1, -3, -1, -2, -1, 2, -1, 4, -1,
	-7, 0, -5, 0, -3, 0, 2, 0, 4, 0, 6, 0,
	-7, 1, -6, 1, -2, 1, -1, 1, 0, 1, 1, 1, 5, 1, 6, 1,
	-2, 3, -1, 3,
	-2, 4, -1, 4,
	99
    },
    {				/* TUMBLER */
	-6, -6, -5, -6, 6, -6, 7, -6,
	-6, -5, -5, -5, 6, -5, 7, -5,
	-5, 5, 6, 5,
	-7, 6, -5, 6, 6, 6, 8, 6,
	-7, 7, -5, 7, 6, 7, 8, 7,
	-7, 8, -6, 8, 7, 8, 8, 8,
	99
    },
    {				/* PERIOD4 */
	-5, -8, -4, -8,
	-7, -7, -5, -7,
	-8, -6, -2, -6,
	-7, -5, -3, -5, -2, -5,
	-5, -3, -3, -3,
	-4, -2,
	99
    },
    {				/* PERIOD5 */
	-5, -8, -4, -8,
	-6, -7, -3, -7,
	-7, -6, -2, -6,
	-8, -5, -1, -5,
	-8, -4, -1, -4,
	-7, -3, -2, -3,
	-6, -2, -3, -2,
	-5, -1, -4, -1,
	99
    },
    {				/* PERIOD6 */
	-4, -8, -3, -8,
	-8, -7, -7, -7, -5, -7,
	-8, -6, -7, -6, -4, -6, -1, -6,
	-3, -5, -1, -5,
	-2, -4,
	-3, -2, -2, -2,
	-3, -1, -2, -1,
	99
    },
    {				/* PINWHEEL */
	-4, -8, -3, -8,
	-4, -7, -3, -7,
	-4, -5, -3, -5, -2, -5, -1, -5,
	-5, -4, -3, -4, 0, -4, 2, -4, 3, -4,
	-5, -3, -1, -3, 0, -3, 2, -3, 3, -3,
	-8, -2, -7, -2, -5, -2, -2, -2, 0, -2,
	-8, -1, -7, -1, -5, -1, 0, -1,
	-4, 0, -3, 0, -2, 0, -1, 0,
	-2, 2, -1, 2,
	-2, 3, -1, 3,
	99
    },
    {				/* ] */
	-1, -1, 0, -1, 1, -1,
	0, 0, 1, 0,
	-1, 1, 0, 1, 1, 1,
	99
    },
    {				/* cc: */
	-3, -1, -2, -1, -1, -1, 1, -1, 2, -1, 3, -1,
	-3, 0, -2, 0, 1, 0, 2, 0,
	-3, 1, -2, 1, -1, 1, 1, 1, 2, 1, 3, 1,
	99
    },
    {				/* DOLBY */
	-3, -1, -2, -1, -1, -1, 1, -1, 2, -1, 3, -1,
	-3, 0, -2, 0, 2, 0, 3, 0,
	-3, 1, -2, 1, -1, 1, 1, 1, 2, 1, 3, 1,
	99
    },
    {				/* HORIZON */
	-15, 0, -14, 0, -13, 0, -12, 0, -11, 0,
	-10, 0, -9, 0, -8, 0, -7, 0, -6, 0,
	-5, 0, -4, 0, -3, 0, -2, 0, -1, 0,
	4, 0, 3, 0, 2, 0, 1, 0, 0, 0,
	9, 0, 8, 0, 7, 0, 6, 0, 5, 0,
	14, 0, 13, 0, 12, 0, 11, 0, 10, 0,
	99
    },
    {				/* SHEAR */
	-7, -2, -6, -2, -5, -2, -4, -2, -3, -2,
	-2, -2, -1, -2, 0, -2, 1, -2, 2, -2,
	-5, -1, -4, -1, -3, -1, -2, -1, -1, -1,
	0, -1, 1, -1, 2, -1, 3, -1, 4, -1,
	-3, 0, -2, 0, -1, 0, 0, 0, 1, 0,
	2, 0, 3, 0, 4, 0, 5, 0, 6, 0,
	-10, 1, -9, 1, -8, 1, -7, 1, -6, 1,
	-5, 1, -4, 1, -3, 1, -2, 1, -1, 1,
	-10, 2, -9, 2, -8, 2, -7, 2, -6, 2,
	-5, 2, -4, 2, -3, 2, -2, 2, -1, 2,
	99
    },
    {				/* VERTIGO */
	0, -7,
	0, -6,
	0, -5,
	0, -4,
	0, -3,
	0, -2,
	0, -1,
	0, 0,
	0, 7,
	0, 6,
	0, 5,
	0, 4,
	0, 3,
	0, 2,
	0, 1,
	99
    },
    {				/* CROSSBAR */
	-5, 0, -4, 0, -3, 0, -2, 0, -1, 0, 4, 0, 3, 0, 2, 0, 1, 0, 0, 0,
	99
    },
    {				/* GOALPOSTS */
	-8, -7, 8, -7,
	-8, -6, 8, -6,
	-8, -5, 8, -5,
	-8, -4, 8, -4,
	-8, -3, 8, -3,
	-8, -2, 8, -2,
	-8, -1, 8, -1,
	-8, 0, 8, 0,
	-8, 1, 8, 1,
	-8, 2, 8, 2,
	-8, 3, 8, 3,
	-8, 4, 8, 4,
	-8, 5, 8, 5,
	-8, 6, 8, 6,
	-8, 7, 8, 7,
	99
    },
    {				/* \ */
	-8, -8, -7, -8,
	-7, -7, -6, -7,
	-6, -6, -5, -6,
	-5, -5, -4, -5,
	-4, -4, -3, -4,
	-3, -3, -2, -3,
	-2, -2, -1, -2,
	-1, -1, 0, -1,
	0, 0, 1, 0,
	1, 1, 2, 1,
	2, 2, 3, 2,
	3, 3, 4, 3,
	4, 4, 5, 4,
	5, 5, 6, 5,
	6, 6, 7, 6,
	7, 7, 8, 7,
	99
    },
    {				/* LABYRINTH */
	-4, -4, -3, -4, -2, -4, -1, -4, 0, -4, 1, -4, 2, -4, 3, -4, 4, -4,
	-4, -3, 0, -3, 4, -3,
	-4, -2, -2, -2, -1, -2, 0, -2, 1, -2, 2, -2, 4, -2,
	-4, -1, -2, -1, 2, -1, 4, -1,
	-4, 0, -2, 0, -1, 0, 0, 0, 1, 0, 2, 0, 4, 0,
	-4, 1, -2, 1, 2, 1, 4, 1,
	-4, 2, -2, 2, -1, 2, 0, 2, 1, 2, 2, 2, 4, 2,
	-4, 3, 0, 3, 4, 3,
	-4, 4, -3, 4, -2, 4, -1, 4, 0, 4, 1, 4, 2, 4, 3, 4, 4, 4,
	99
    }
};

#define NPATS	(sizeof patterns / sizeof patterns[0])

static void
drawcell(win, row, col)
    Window      win;
    int         row,
                col;
{
    lifestruct *lp = &lifes[screen];

    XSetForeground(dsp, Scr[screen].gc, WhitePixel(dsp, screen));
    if (!mono && Scr[screen].npixels > 2) {
	unsigned char *loc = lp->buffer + ((row + 1) * (lp->ncols + 2)) + col + 1;
	unsigned char *ageptr = lp->agebuf + (loc - lp->buffer);
	unsigned char age = *ageptr;

	if (++age >= Scr[screen].npixels)
	    age = 0;
	XSetForeground(dsp, Scr[screen].gc, Scr[screen].pixels[age]);
	*ageptr = age + 1;
    }
    if (lp->pixelmode)
	XFillRectangle(dsp, win, Scr[screen].gc,
	       lp->xb + lp->xs * col, lp->yb + lp->ys * row, lp->xs, lp->ys);
    else
	XPutImage(dsp, win, Scr[screen].gc, &logo,
		  0, 0, lp->xb + lp->xs * col, lp->yb + lp->ys * row,
		  icon_width, icon_height);
}

static void
erasecell(win, row, col)
    Window      win;
    int         row,
                col;
{
    lifestruct *lp = &lifes[screen];
    XSetForeground(dsp, Scr[screen].gc, BlackPixel(dsp, screen));
    XFillRectangle(dsp, win, Scr[screen].gc,
	       lp->xb + lp->xs * col, lp->yb + lp->ys * row, lp->xs, lp->ys);
}

static void
spawn(loc)
    unsigned char *loc;
{
    lifestruct *lp = &lifes[screen];
    *(loc - lp->ncols - 2 - 1) |= UPLT;
    *(loc - lp->ncols - 2) |= UP;
    *(loc - lp->ncols - 2 + 1) |= UPRT;
    *(loc - 1) |= LT;
    *(loc + 1) |= RT;
    *(loc + lp->ncols + 2 - 1) |= DNLT;
    *(loc + lp->ncols + 2) |= DN;
    *(loc + lp->ncols + 2 + 1) |= DNRT;
    *(lp->agebuf + (loc - lp->buffer)) = 0;
}

static void
kill(loc)
    unsigned char *loc;
{
    lifestruct *lp = &lifes[screen];
    *(loc - lp->ncols - 2 - 1) &= ~UPLT;
    *(loc - lp->ncols - 2) &= ~UP;
    *(loc - lp->ncols - 2 + 1) &= ~UPRT;
    *(loc - 1) &= ~LT;
    *(loc + 1) &= ~RT;
    *(loc + lp->ncols + 2 - 1) &= ~DNLT;
    *(loc + lp->ncols + 2) &= ~DN;
    *(loc + lp->ncols + 2 + 1) &= ~DNRT;
}

static void
setcell(win, row, col)
    Window      win;
    int         row;
    int         col;
{
    lifestruct *lp = &lifes[screen];
    unsigned char *loc;

    loc = lp->buffer + ((row + 1) * (lp->ncols + 2)) + col + 1;
    spawn(loc);
    drawcell(win, row, col);
}

void
drawlife(win)
    Window      win;
{
    unsigned char *loc,
               *temploc;
    int         row,
                col,
                cells = 0;
    unsigned char fate;
    lifestruct *lp = &lifes[screen];

    loc = lp->buffer + lp->ncols + 2 + 1;
    temploc = lp->tempbuf;
    /* copy the first 2 rows to the tempbuf */
    bcopy(loc, temploc, lp->ncols);
    bcopy(loc + lp->ncols + 2, temploc + lp->ncols, lp->ncols);
    for (row = 0; row < lp->nrows; ++row) {
	for (col = 0; col < lp->ncols; ++col) {
	    fate = fates[*temploc];
	    *temploc = *(loc + (lp->ncols + 2) * 2);
	    switch (fate) {
	    case BIRTH:
		if (!(*(loc + 1) & RT)) {
		    spawn(loc);
		}
		/* NO BREAK */
	    case SAME:
		if (*(loc + 1) & RT) {
		    ++cells;
		    drawcell(win, row, col);
		}
		break;
	    case DEATH:
		if (*(loc + 1) & RT) {
		    kill(loc);
		    erasecell(win, row, col);
		}
		break;
	    }
	    loc++;
	    temploc++;
	}
	loc += 2;
	if (temploc >= lp->tempbuf + lp->ncols * 2)
	    temploc = lp->tempbuf;
    }
    if (!cells)
	lp->startTime = 0;
    lp->elapsedTime = seconds() - lp->startTime;

    if (!lp->shooter && lp->elapsedTime > timeout / 2) {
	setcell(win, 0, 2);
	setcell(win, 1, 2);
	setcell(win, 2, 2);
	setcell(win, 2, 1);
	setcell(win, 1, 0);
	lp->shooter = 1;
    }
}

static void
init_fates()
{
    int         i,
                bits,
                neighbors;

    for (i = 0; i < 256; i++) {
	neighbors = 0;
	for (bits = i; bits; bits &= (bits - 1))
	    neighbors++;
	if (neighbors == 3)
	    fates[i] = BIRTH;
	else if (neighbors == 2)
	    fates[i] = SAME;
	else
	    fates[i] = DEATH;
    }
}


void
initlife(win)
    Window      win;
{
    int         row,
                col;
    int        *patptr;
    XWindowAttributes xgwa;
    lifestruct *lp = &lifes[screen];

    lp->startTime = seconds();
    lp->shooter = 0;
    icon_width = lifeicon_width;
    icon_height = lifeicon_height;

    if (!initialized) {
	initialized = 1;
	srandom(time((long *) 0));
	init_fates();
	logo.data = lifeicon_bits;
	logo.width = icon_width;
	logo.height = icon_height;
	logo.bytes_per_line = (icon_width + 7) / 8;
    }
    XGetWindowAttributes(dsp, win, &xgwa);
    lp->width = xgwa.width;
    lp->height = xgwa.height;
    lp->pixelmode = (lp->width < 4 * icon_width);
    if (lp->pixelmode) {
	lp->ncols = 32;
	lp->nrows = 32;
    } else {
	lp->ncols = min(lp->width / icon_width, MAXCOLS);
	lp->nrows = min(lp->height / icon_height, MAXROWS);
    }
    lp->xs = lp->width / lp->ncols;
    lp->ys = lp->height / lp->nrows;
    lp->xb = (lp->width - lp->xs * lp->ncols) / 2;
    lp->yb = (lp->height - lp->ys * lp->nrows) / 2;

    XSetForeground(dsp, Scr[screen].gc, BlackPixel(dsp, screen));
    XFillRectangle(dsp, win, Scr[screen].gc, 0, 0, lp->width, lp->height);

    bzero(lp->buffer, sizeof(lp->buffer));
    patptr = &patterns[random() % NPATS][0];
    while ((col = *patptr++) != 99) {
	row = *patptr++;
	col += lp->ncols / 2;
	row += lp->nrows / 2;
	setcell(win, row, col);
    }
}
