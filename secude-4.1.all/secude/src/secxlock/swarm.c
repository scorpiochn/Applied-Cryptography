#ifndef lint
static char sccsid[] = "@(#)swarm.c	1.3 90/10/28 XLOCK SMI";
#endif
/*-
 * swarm.c - swarm of bees for the xlock X11 terminal locker.
 *
 * Copyright (c) 1990 by Sun Microsystems Inc.
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
 * 31-Aug-90: Adapted from xswarm by Jeff Butterworth. (butterwo@ncsc.org)
 */

#include "xlock.h"

#define TIMES	4		/* number of time positions recorded */
#define BEEACC	3		/* acceleration of bees */
#define WASPACC 5		/* maximum acceleration of wasp */
#define BEEVEL	11		/* maximum bee velocity */
#define WASPVEL 12		/* maximum wasp velocity */
#define BORDER	50		/* wasp won't go closer than this to the edge */

/* Macros */
#define X(t,b)	(sp->x[(t)*sp->beecount+(b)])
#define Y(t,b)	(sp->y[(t)*sp->beecount+(b)])
#define RAND(v)	((random()%(v))-((v)/2))	/* random number around 0 */

typedef struct {
    int         pix;
    long        startTime;
    int         width;
    int         height;
    int         beecount;	/* number of bees */
    XSegment   *segs;		/* bee lines */
    XSegment   *old_segs;	/* old bee lines */
    short      *x;
    short      *y;		/* bee positions x[time][bee#] */
    short      *xv;
    short      *yv;		/* bee velocities xv[bee#] */
    short       wx[3];
    short       wy[3];
    short       wxv;
    short       wyv;
}           swarmstruct;

static swarmstruct swarms[MAXSCREENS];

void
initswarm(win)
    Window      win;
{
    XWindowAttributes xgwa;
    swarmstruct *sp = &swarms[screen];
    int         b;

    sp->startTime = seconds();
    srandom(time((long *) 0));

    sp->beecount = batchcount;

    XGetWindowAttributes(dsp, win, &xgwa);
    sp->width = xgwa.width;
    sp->height = xgwa.height;

    /* Clear the background. */
    XSetForeground(dsp, Scr[screen].gc, BlackPixel(dsp, screen));
    XFillRectangle(dsp, win, Scr[screen].gc, 0, 0, sp->width, sp->height);

    /* Get the random number generator reasp->dy. */
    srandom((int) time(0) % 231);

    /* Allocate memory. */

    if (!sp->segs) {
	sp->segs = (XSegment *) malloc(sizeof(XSegment) * sp->beecount);
	sp->old_segs = (XSegment *) malloc(sizeof(XSegment) * sp->beecount);
	sp->x = (short *) malloc(sizeof(short) * sp->beecount * TIMES);
	sp->y = (short *) malloc(sizeof(short) * sp->beecount * TIMES);
	sp->xv = (short *) malloc(sizeof(short) * sp->beecount);
	sp->yv = (short *) malloc(sizeof(short) * sp->beecount);
    }
    /* Initialize point positions, velocities, etc. */

    /* wasp */
    sp->wx[0] = BORDER + random() % (sp->width - 2 * BORDER);
    sp->wy[0] = BORDER + random() % (sp->height - 2 * BORDER);
    sp->wx[1] = sp->wx[0];
    sp->wy[1] = sp->wy[0];
    sp->wxv = 0;
    sp->wyv = 0;

    /* bees */
    for (b = 0; b < sp->beecount; b++) {
	X(0, b) = random() % sp->width;
	X(1, b) = X(0, b);
	Y(0, b) = random() % sp->height;
	Y(1, b) = Y(0, b);
	sp->xv[b] = RAND(7);
	sp->yv[b] = RAND(7);
    }
}



void
drawswarm(win)
    Window      win;
{
    swarmstruct *sp = &swarms[screen];
    int         b;

    /* <=- Wasp -=> */
    /* Age the arrays. */
    sp->wx[2] = sp->wx[1];
    sp->wx[1] = sp->wx[0];
    sp->wy[2] = sp->wy[1];
    sp->wy[1] = sp->wy[0];
    /* Accelerate */
    sp->wxv += RAND(WASPACC);
    sp->wyv += RAND(WASPACC);

    /* Speed Limit Checks */
    if (sp->wxv > WASPVEL)
	sp->wxv = WASPVEL;
    if (sp->wxv < -WASPVEL)
	sp->wxv = -WASPVEL;
    if (sp->wyv > WASPVEL)
	sp->wyv = WASPVEL;
    if (sp->wyv < -WASPVEL)
	sp->wyv = -WASPVEL;

    /* Move */
    sp->wx[0] = sp->wx[1] + sp->wxv;
    sp->wy[0] = sp->wy[1] + sp->wyv;

    /* Bounce Checks */
    if ((sp->wx[0] < BORDER) || (sp->wx[0] > sp->width - BORDER - 1)) {
	sp->wxv = -sp->wxv;
	sp->wx[0] += sp->wxv;
    }
    if ((sp->wy[0] < BORDER) || (sp->wy[0] > sp->height - BORDER - 1)) {
	sp->wyv = -sp->wyv;
	sp->wy[0] += sp->wyv;
    }
    /* Don't let things settle down. */
    sp->xv[random() % sp->beecount] += RAND(3);
    sp->yv[random() % sp->beecount] += RAND(3);

    /* <=- Bees -=> */
    for (b = 0; b < sp->beecount; b++) {
	int         distance,
	            dx,
	            dy;
	/* Age the arrays. */
	X(2, b) = X(1, b);
	X(1, b) = X(0, b);
	Y(2, b) = Y(1, b);
	Y(1, b) = Y(0, b);

	/* Accelerate */
	dx = sp->wx[1] - X(1, b);
	dy = sp->wy[1] - Y(1, b);
	distance = abs(dx) + abs(dy);	/* approximation */
	if (distance == 0)
	    distance = 1;
	sp->xv[b] += (dx * BEEACC) / distance;
	sp->yv[b] += (dy * BEEACC) / distance;

	/* Speed Limit Checks */
	if (sp->xv[b] > BEEVEL)
	    sp->xv[b] = BEEVEL;
	if (sp->xv[b] < -BEEVEL)
	    sp->xv[b] = -BEEVEL;
	if (sp->yv[b] > BEEVEL)
	    sp->yv[b] = BEEVEL;
	if (sp->yv[b] < -BEEVEL)
	    sp->yv[b] = -BEEVEL;

	/* Move */
	X(0, b) = X(1, b) + sp->xv[b];
	Y(0, b) = Y(1, b) + sp->yv[b];

	/* Fill the segment lists. */
	sp->segs[b].x1 = X(0, b);
	sp->segs[b].y1 = Y(0, b);
	sp->segs[b].x2 = X(1, b);
	sp->segs[b].y2 = Y(1, b);
	sp->old_segs[b].x1 = X(1, b);
	sp->old_segs[b].y1 = Y(1, b);
	sp->old_segs[b].x2 = X(2, b);
	sp->old_segs[b].y2 = Y(2, b);
    }

    XSetForeground(dsp, Scr[screen].gc, BlackPixel(dsp, screen));
    XDrawLine(dsp, win, Scr[screen].gc,
	      sp->wx[1], sp->wy[1], sp->wx[2], sp->wy[2]);
    XDrawSegments(dsp, win, Scr[screen].gc, sp->old_segs, sp->beecount);

    XSetForeground(dsp, Scr[screen].gc, WhitePixel(dsp, screen));
    XDrawLine(dsp, win, Scr[screen].gc,
	      sp->wx[0], sp->wy[0], sp->wx[1], sp->wy[1]);
    if (!mono && Scr[screen].npixels > 2) {
	XSetForeground(dsp, Scr[screen].gc, Scr[screen].pixels[sp->pix]);
	if (++sp->pix >= Scr[screen].npixels)
	    sp->pix = 0;
    }
    XDrawSegments(dsp, win, Scr[screen].gc, sp->segs, sp->beecount);
}
