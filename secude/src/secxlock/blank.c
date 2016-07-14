#ifndef lint
static char sccsid[] = "@(#)blank.c	1.3 90/10/28 XLOCK SMI";
#endif
/*-
 * blank.c - blank screen for the xlock X11 terminal locker.
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
 * 31-Aug-90: Written.
 */

#include "xlock.h"

/*ARGSUSED*/
void
drawblank(win)
    Window      win;
{
}

void
initblank(win)
    Window      win;
{
    XClearWindow(dsp, win);
}
