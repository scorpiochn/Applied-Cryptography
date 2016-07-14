#ifndef lint
static char sccsid[] = "@(#)hopalong.c	23.7 90/10/29 XLOCK SMI";
#endif
/*-
 * hopalong.c - Real Plane Fractals for the xlock X11 terminal locker.
 *
 * Copyright (c) 1988-90 by Patrick Naughton and Sun Microsystems, Inc.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation.
 *
 * This file is provided AS IS with no warranties of any kind.  The author
 * shall have no liability with respect to the infringement of copyrights,
 * trade secrets or any patents by this file or any part thereof.  In no
 * event will the author be liable for any lost revenue or profits or
 * other special, indirect and consequential damages.
 *
 * Comments and additions should be sent to the author:
 *
 *		       naughton@eng.sun.com
 *
 *		       Patrick J. Naughton
 *		       MS 14-01
 *		       Windows and Graphics Group
 *		       Sun Microsystems, Inc.
 *		       2550 Garcia Ave
 *		       Mountain View, CA  94043
 *
 * Revision History:
 * 29-Oct-90: fix bad (int) cast.
 * 29-Jul-90: support for multiple screens.
 * 08-Jul-90: new timing and colors and new algorithm for fractals.
 * 15-Dec-89: Fix for proper skipping of {White,Black}Pixel() in colors.
 * 08-Oct-89: Fixed long standing typo bug in RandomInitHop();
 *	      Fixed bug in memory allocation in inithop();
 *	      Moved seconds() to an extern.
 *	      Got rid of the % mod since .mod is slow on a sparc.
 * 20-Sep-89: Lint.
 * 31-Aug-88: Forked from xlock.c for modularity.
 * 23-Mar-88: Coded HOPALONG routines from Scientific American Sept. 86 p. 14.
 */

#include "xlock.h"
#include <math.h>

typedef struct {
    int         centerx;
    int         centery;	/* center of the screen */
    double      a;
    double      b;
    double      c;
    double      i;
    double      j;		/* hopalong parameters */
    int         inc;
    int         pix;
    long        startTime;
}           hopstruct;

static hopstruct hops[MAXSCREENS];
static XPoint *pointBuffer = 0;	/* pointer for XDrawPoints */

#define TIMEOUT 30
#define MAXRAND (4294967296.0)	/* 2^32 */

void
inithop(win)
    Window      win;
{
    double      range;
    XWindowAttributes xgwa;
    hopstruct  *hp = &hops[screen];


    XGetWindowAttributes(dsp, win, &xgwa);
    hp->centerx = xgwa.width / 2;
    hp->centery = xgwa.height / 2;
    range = sqrt((double) hp->centerx * hp->centerx +
		 (double) hp->centery * hp->centery) /
	(10.0 + random() % 10);

    hp->pix = 0;
    hp->inc = (int) ((random() / MAXRAND) * 400) - 200;
    hp->a = (random() / MAXRAND) * range - range / 2.0;
    hp->b = (random() / MAXRAND) * range - range / 2.0;
    hp->c = (random() / MAXRAND) * range - range / 2.0;
    if (!(random() % 2))
	hp->c = 0.0;

    hp->i = hp->j = 0.0;

    if (!pointBuffer)
	pointBuffer = (XPoint *) malloc(batchcount * sizeof(XPoint));

    XSetForeground(dsp, Scr[screen].gc, BlackPixel(dsp, screen));
    XFillRectangle(dsp, win, Scr[screen].gc, 0, 0,
		   hp->centerx * 2, hp->centery * 2);
    XSetForeground(dsp, Scr[screen].gc, WhitePixel(dsp, screen));
    hp->startTime = seconds();
}


void
drawhop(win)
    Window      win;
{
    double      oldj;
    int         k = batchcount;
    XPoint     *xp = pointBuffer;
    hopstruct  *hp = &hops[screen];

    hp->inc++;
    if (!mono && Scr[screen].npixels > 2) {
	XSetForeground(dsp, Scr[screen].gc, Scr[screen].pixels[hp->pix]);
	if (++hp->pix >= Scr[screen].npixels)
	    hp->pix = 0;
    }
    while (k--) {
	oldj = hp->j;
	hp->j = hp->a - hp->i;
	hp->i = oldj + (hp->i < 0
			? sqrt(fabs(hp->b * (hp->i + hp->inc) - hp->c))
			: -sqrt(fabs(hp->b * (hp->i + hp->inc) - hp->c)));
	xp->x = hp->centerx + (int) (hp->i + hp->j);
	xp->y = hp->centery - (int) (hp->i - hp->j);
	xp++;
    }
    XDrawPoints(dsp, win, Scr[screen].gc,
		pointBuffer, batchcount, CoordModeOrigin);
    if (seconds() - hp->startTime > TIMEOUT)
	inithop(win);
}
