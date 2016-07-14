#ifndef lint
static char sccsid[] = "@(#)image.c	1.5 90/10/28 XLOCK SMI";
#endif
/*-
 * image.c - image bouncer for the xlock X11 terminal locker.
 *
 * Copyright (c) 1990 by Sun Microsystems, Inc.
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
 * 29-Jul-90: Written.
 */

#include "xlock.h"
#include "sunlogo.bit"

static XImage logo = {
    0, 0,			/* width, height */
    0, XYBitmap, 0,		/* xoffset, format, data */
    LSBFirst, 8,		/* byte-order, bitmap-unit */
    LSBFirst, 8, 1		/* bitmap-bit-order, bitmap-pad, depth */
};

#define MAXICONS 256

typedef struct {
    int         x;
    int         y;
}           point;

typedef struct {
    int         width;
    int         height;
    int         nrows;
    int         ncols;
    int         xb;
    int         yb;
    int         iconmode;
    int         iconcount;
    point       icons[MAXICONS];
    long        startTime;
}           imagestruct;

static imagestruct ims[MAXSCREENS];

void
drawimage(win)
    Window      win;
{
    imagestruct *ip = &ims[screen];
    int         i;

    XSetForeground(dsp, Scr[screen].gc, BlackPixel(dsp, screen));
    for (i = 0; i < ip->iconcount; i++) {
	if (!ip->iconmode)
	    XFillRectangle(dsp, win, Scr[screen].gc,
			   ip->xb + sunlogo_width * ip->icons[i].x,
			   ip->yb + sunlogo_height * ip->icons[i].y,
			   sunlogo_width, sunlogo_height);

	ip->icons[i].x = random() % ip->ncols;
	ip->icons[i].y = random() % ip->nrows;
    }
    if (Scr[screen].npixels == 2)
	XSetForeground(dsp, Scr[screen].gc, WhitePixel(dsp, screen));
    for (i = 0; i < ip->iconcount; i++) {
	if (Scr[screen].npixels > 2)
	    XSetForeground(dsp, Scr[screen].gc,
			 Scr[screen].pixels[random() % Scr[screen].npixels]);

	XPutImage(dsp, win, Scr[screen].gc, &logo,
		  0, 0,
		  ip->xb + sunlogo_width * ip->icons[i].x,
		  ip->yb + sunlogo_height * ip->icons[i].y,
		  sunlogo_width, sunlogo_height);
    }
}

void
initimage(win)
    Window      win;
{
    XWindowAttributes xgwa;
    imagestruct *ip = &ims[screen];

    ip->startTime = seconds();
    srandom(time((long *) 0));

    logo.data = sunlogo_bits;
    logo.width = sunlogo_width;
    logo.height = sunlogo_height;
    logo.bytes_per_line = (sunlogo_width + 7) / 8;

    XGetWindowAttributes(dsp, win, &xgwa);
    ip->width = xgwa.width;
    ip->height = xgwa.height;
    ip->ncols = ip->width / sunlogo_width;
    ip->nrows = ip->height / sunlogo_height;
    ip->iconmode = (ip->ncols < 2 || ip->nrows < 2);
    if (ip->iconmode) {
	ip->xb = 0;
	ip->yb = 0;
	ip->iconcount = 1;	/* icon mode */
    } else {
	ip->xb = (ip->width - sunlogo_width * ip->ncols) / 2;
	ip->yb = (ip->height - sunlogo_height * ip->nrows) / 2;
	ip->iconcount = batchcount;
    }
    XSetForeground(dsp, Scr[screen].gc, BlackPixel(dsp, screen));
    XFillRectangle(dsp, win, Scr[screen].gc, 0, 0, ip->width, ip->height);
}
