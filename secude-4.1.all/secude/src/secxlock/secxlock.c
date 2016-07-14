#ifndef lint
static char sccsid[] = "@(#)xlock.c	23.16 90/10/29 XLOCK SMI";
#endif
/*-
 * xlock.c - X11 client to lock a display and show a screen saver.
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
 * 29-Oct-90: added cast to XFree() arg.
 *	      added volume arg to call to XBell().
 * 28-Oct-90: center prompt screen.
 *	      make sure Xlib input buffer does not use up all of swap.
 *	      make displayed text come from resource file for better I18N.
 *	      add backward compatible signal handlers for pre 4.1 machines.
 * 31-Aug-90: added blank mode.
 *	      added swarm mode.
 *	      moved usleep() and seconds() out to usleep.c.
 *	      added SVR4 defines to xlock.h
 * 29-Jul-90: added support for multiple screens to be locked by one xlock.
 *	      moved global defines to xlock.h
 *	      removed use of allowsig().
 * 07-Jul-90: reworked commandline args and resources to use Xrm.
 *	      moved resource processing out to resource.c
 * 02-Jul-90: reworked colors to not use dynamic colormap.
 * 23-May-90: added autoraise when obscured.
 * 15-Apr-90: added hostent alias searching for host authentication.
 * 18-Feb-90: added SunOS3.5 fix.
 *	      changed -mono -> -color, and -saver -> -lock.
 *	      allow non-locking screensavers to display on remote machine.
 *	      added -echokeys to disable echoing of '?'s on input.
 *	      cleaned up all of the parameters and defaults.
 * 20-Dec-89: added -xhost to allow access control list to be left alone.
 *	      added -screensaver (don't disable screen saver) for the paranoid.
 *	      Moved seconds() here from all of the display mode source files.
 *	      Fixed bug with calling XUngrabHosts() in finish().
 * 19-Dec-89: Fixed bug in GrabPointer.
 *	      Changed fontname to XLFD style.
 * 23-Sep-89: Added fix to allow local hostname:0 as a display.
 *	      Put empty case for Enter/Leave events.
 *	      Moved colormap installation later in startup.
 * 20-Sep-89: Linted and made -saver mode grab the keyboard and mouse.
 *	      Replaced SunView code for life mode with Jim Graham's version,
 *		so I could contrib it without legal problems.
 *	      Sent to expo for X11R4 contrib.
 * 19-Sep-89: Added '?'s on input.
 * 27-Mar-89: Added -qix mode.
 *	      Fixed GContext->GC.
 * 20-Mar-89: Added backup font (fixed) if XQueryLoadFont() fails.
 *	      Changed default font to lucida-sans-24.
 * 08-Mar-89: Added -nice, -mode and -display, built vector for life and hop.
 * 24-Feb-89: Replaced hopalong display with life display from SunView1.
 * 22-Feb-89: Added fix for color servers with n < 8 planes.
 * 16-Feb-89: Updated calling conventions for XCreateHsbColormap();
 *	      Added -count for number of iterations per color.
 *	      Fixed defaulting mechanism.
 *	      Ripped out VMS hacks.
 *	      Sent to expo for X11R3 contrib.
 * 15-Feb-89: Changed default font to pellucida-sans-18.
 * 20-Jan-89: Added -verbose and fixed usage message.
 * 19-Jan-89: Fixed monochrome gc bug.
 * 16-Dec-88: Added SunView style password prompting.
 * 19-Sep-88: Changed -color to -mono. (default is color on color displays).
 *	      Added -saver option. (just do display... don't lock.)
 * 31-Aug-88: Added -time option.
 *	      Removed code for fractals to separate file for modularity.
 *	      Added signal handler to restore host access.
 *	      Installs dynamic colormap with a Hue Ramp.
 *	      If grabs fail then exit.
 *	      Added VMS Hacks. (password 'iwiwuu').
 *	      Sent to expo for X11R2 contrib.
 * 08-Jun-88: Fixed root password pointer problem and changed PASSLENGTH to 20.
 * 20-May-88: Added -root to allow root to unlock.
 * 12-Apr-88: Added root password override.
 *	      Added screen saver override.
 *	      Removed XGrabServer/XUngrabServer.
 *	      Added access control handling instead.
 * 01-Apr-88: Added XGrabServer/XUngrabServer for more security.
 * 30-Mar-88: Removed startup password requirement.
 *	      Removed cursor to avoid phosphor burn.
 * 27-Mar-88: Rotate fractal by 45 degrees clockwise.
 * 24-Mar-88: Added color support. [-color]
 *	      wrote the man page.
 * 23-Mar-88: Added HOPALONG routines from Scientific American Sept. 86 p. 14.
 *	      added password requirement for invokation
 *	      removed option for command line password
 *	      added requirement for display to be "unix:0".
 * 22-Mar-88: Recieved Walter Milliken's comp.windows.x posting.
 * 03-Aug-93  SecuDE hooks added by Zhu Shixiong (GMD and SCI, Chengdu, China)
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <pwd.h>
#include <X11/cursorfont.h>
#include "af.h"
#include "xlock.h"

Boolean	    SC_PSE;	     /* TRUE if we xlock'ed with an SC, FALSE if we used a SW-PSE    */
int	    xlock_pid;       /* Pid if the xlock-child process. Used only if SC_PSE == TRUE  */
Certificate *verifierCertificate;   /* Certificate if the user who xlock'ed 
                                       (includes verifier's public key)                      */
Certificates *verifierCertificates; /* generated from verifierCertificate                    */
PKRoot       *verifierPKRoot;       /* generated from verifierCertificate                    */

char	   *psepath;	     /* Pathname of the PSE which was used to xlock	             */

extern char *crypt();
extern char *getenv();

char       *ProgramName;	/* argv[0] */
perscreen   Scr[MAXSCREENS];
Display    *dsp = NULL;		/* server display connection */
int         screen;		/* current screen */
void        (*callback) () = NULL;
void        (*init) () = NULL;

static int  screens;		/* number of screens */
static Window win[MAXSCREENS];	/* window used to cover screen */
static Window icon[MAXSCREENS];	/* window used during password typein */
static Window root[MAXSCREENS];	/* convenience pointer to the root window */
static GC   textgc[MAXSCREENS];	/* graphics context used for text rendering */
static XColor fgcol[MAXSCREENS];/* used for text rendering */
static XColor bgcol[MAXSCREENS];/* background of text screen */
static int  iconx[MAXSCREENS];	/* location of left edge of icon */
static int  icony[MAXSCREENS];	/* location of top edge of icon */
static Cursor mycursor;		/* blank cursor */
static Pixmap lockc;
static Pixmap lockm;		/* pixmaps for cursor and mask */
static char no_bits[] = {
	0};	/* dummy array for the blank cursor */
static int  passx;		/* position of the ?'s */
static int  passy;
static XFontStruct *font;
static int  sstimeout;		/* screen saver parameters */
static int  ssinterval;
static int  ssblanking;
static int  ssexposures;

#define FALLBACK_FONTNAME	"fixed"
#define ICONW			64
#define ICONH			64

#define AllPointerEventMask \
	(ButtonPressMask | ButtonReleaseMask | \
	EnterWindowMask | LeaveWindowMask | \
	PointerMotionMask | PointerMotionHintMask | \
	Button1MotionMask | Button2MotionMask | \
	Button3MotionMask | Button4MotionMask | \
	Button5MotionMask | ButtonMotionMask | \
	KeymapStateMask)


/* VARARGS1 */
void
error(s1, s2)
char       *s1,
*s2;
{
	/*fprintf(stderr, s1, ProgramName, s2);*/
	exit(1);
}

/*
 * Server access control support.
 */

static XHostAddress *XHosts;	/* the list of "friendly" client machines */
static int  HostAccessCount;	/* the number of machines in XHosts */
static Bool HostAccessState;	/* whether or not we even look at the list */

static void
XGrabHosts(dsp)
Display    *dsp;
{
	XHosts = XListHosts(dsp, &HostAccessCount, &HostAccessState);
	if (XHosts)
		XRemoveHosts(dsp, XHosts, HostAccessCount);
	XEnableAccessControl(dsp);
}

static void
XUngrabHosts(dsp)
Display    *dsp;
{
	if (XHosts) {
		XAddHosts(dsp, XHosts, HostAccessCount);
		XFree((char *)XHosts);
	}
	if (HostAccessState == False)
		XDisableAccessControl(dsp);
}


/*
 * Simple wrapper to get an asynchronous grab on the keyboard and mouse.
 * If either grab fails, we sleep for one second and try again since some
 * window manager might have had the mouse grabbed to drive the menu choice
 * that picked "Lock Screen..".  If either one fails the second time we print
 * an error message and exit.
 */
static void
GrabKeyboardAndMouse()
{
	Status      status;

	status = XGrabKeyboard(dsp, win[0], True,
	    GrabModeAsync, GrabModeAsync, CurrentTime);
	if (status != GrabSuccess) {
		sleep(1);
		status = XGrabKeyboard(dsp, win[0], True,
		    GrabModeAsync, GrabModeAsync, CurrentTime);

	}
	status = XGrabPointer(dsp, win[0], True, AllPointerEventMask,
	    GrabModeAsync, GrabModeAsync, None, mycursor,
	    CurrentTime);
	if (status != GrabSuccess) {
		sleep(1);
		status = XGrabPointer(dsp, win[0], True, AllPointerEventMask,
		    GrabModeAsync, GrabModeAsync, None, mycursor,
		    CurrentTime);

		if (status != GrabSuccess) 
			error("%s: couldn't grab pointer! (%d)\n", status);
	}
}


/*
 * Assuming that we already have an asynch grab on the pointer,
 * just grab it again with a new cursor shape and ignore the return code.
 */
static void
XChangeGrabbedCursor(cursor)
Cursor      cursor;
{
#ifndef DEBUG
	(void) XGrabPointer(dsp, win[0], True, AllPointerEventMask,
	    GrabModeAsync, GrabModeAsync, None, cursor, CurrentTime);
#endif
}


/*
 * Restore all grabs, reset screensaver, restore colormap, close connection.
 */
static void
finish()
{
	XSync(dsp, False);
	if (!nolock && !allowaccess)
		XUngrabHosts(dsp);
	XUngrabPointer(dsp, CurrentTime);
	XUngrabKeyboard(dsp, CurrentTime);
	if (!enablesaver)
		XSetScreenSaver(dsp, sstimeout, ssinterval, ssblanking, ssexposures);
	XFlush(dsp);
	XCloseDisplay(dsp);
}


static int
ReadXString(s, slen)
char       *s;
int         slen;
{
	XEvent      event;
	char        keystr[20];
	char        c;
	int         i;
	int         bp;
	int         len;
	int         thisscreen = screen;
	char       *pwbuf = (char *) malloc(slen);
#ifdef DEBUG
	XSetInputFocus(dsp, win[screen], RevertToPointerRoot, CurrentTime);
#endif
	for (screen = 0; screen < screens; screen++)
		if (thisscreen == screen)
			init(icon[screen]);
		else
			init(win[screen]);
	bp = 0;
	nice(-nicelevel);		/* make sure we can read the keys... */
	while (True) {
		unsigned long lasteventtime = seconds();
		while (!XPending(dsp)) {
			for (screen = 0; screen < screens; screen++)
				if (thisscreen == screen)
					callback(icon[screen]);
				else
					callback(win[screen]);
			XFlush(dsp);
			usleep(delay);
			if (seconds() - lasteventtime > timeout) {
				nice(nicelevel);
				free(pwbuf);
				screen = thisscreen;
				return 1;
			}
		}
		screen = thisscreen;
		XNextEvent(dsp, &event);
		switch (event.type) {
		case KeyPress:
			len = XLookupString((XKeyEvent *) & event, keystr, 20, NULL, NULL);
			for (i = 0; i < len; i++) {
				c = keystr[i];
				switch (c) {
				case 8:	/* ^H */
				case 127:	/* DEL */
					if (bp > 0)
						bp--;
					break;
				case 10:	/* ^J */
				case 13:	/* ^M */
					s[bp] = '\0';
					nice(nicelevel);
					free(pwbuf);
					return 0;
				case 21:	/* ^U */
					bp = 0;
					break;
				default:
					s[bp] = c;
					if (bp < slen - 1)
						bp++;
					else
						XSync(dsp, True);	/* flush input buffer */

				}
			}
			if (echokeys) {
				memset(pwbuf, '?', slen);
				XSetForeground(dsp, Scr[screen].gc, bgcol[screen].pixel);
				XFillRectangle(dsp, win[screen], Scr[screen].gc,
				    passx, passy - font->ascent,
				    XTextWidth(font, pwbuf, slen),
				    font->ascent + font->descent);
				XDrawString(dsp, win[screen], textgc[screen],
				    passx, passy, pwbuf, bp);
			}
			/*
	     * eat all events if there are more than enough pending... this
	     * keeps the Xlib event buffer from growing larger than all
	     * available memory and crashing xlock.
	     */
			if (XPending(dsp) > 100) {	/* 100 is arbitrarily big enough */
				register Status status;
				do {
					status = XCheckMaskEvent(dsp,
					    KeyPressMask | KeyReleaseMask, &event);
				} while (status);
				XBell(dsp, 100);
			}
			break;

		case ButtonPress:
			if (((XButtonEvent *) & event)->window == icon[screen]) {
				nice(nicelevel);
				free(pwbuf);
				return 1;
			}
			break;

		case VisibilityNotify:
			if (event.xvisibility.state != VisibilityUnobscured) {
#ifndef DEBUG
				XRaiseWindow(dsp, win[screen]);
#endif
				s[0] = '\0';
				nice(nicelevel);
				free(pwbuf);
				return 1;
			}
			break;

		case KeymapNotify:
		case KeyRelease:
		case ButtonRelease:
		case MotionNotify:
		case LeaveNotify:
		case EnterNotify:
			break;

		default:
			fprintf(stderr, "%s: unexpected event: %d\n",
			    ProgramName, event.type);
			break;
		}
	}
}


static int
getPassword()


{
#define PASSLENGTH 20
	char        pin[PASSLENGTH];
	XWindowAttributes xgwa;
	char       *user = getenv(USERNAME);
	int         y, x,left,done, rc;

	if(SC_PSE) return(1);

	XGetWindowAttributes(dsp, win[screen], &xgwa);
	XChangeGrabbedCursor(XCreateFontCursor(dsp, XC_left_ptr));

	XSetForeground(dsp, Scr[screen].gc, bgcol[screen].pixel);
	XFillRectangle(dsp, win[screen], Scr[screen].gc,
	    0, 0, xgwa.width, xgwa.height);

	XMapWindow(dsp, icon[screen]);
	XRaiseWindow(dsp, icon[screen]);

	left = iconx[screen] + ICONW + font->max_bounds.width;
	y = icony[screen] + font->ascent;

	XDrawString(dsp, win[screen], textgc[screen],
	    left, y, text_name, strlen(text_name));
	XDrawString(dsp, win[screen], textgc[screen],
	    left + 1, y, text_name, strlen(text_name));
	XDrawString(dsp, win[screen], textgc[screen],
	    left + XTextWidth(font, text_name, strlen(text_name)), y,
	    user, strlen(user));

	y += font->ascent + font->descent + 2;
	x=y;
	passy = y;

	y = icony[screen] + ICONH + font->ascent + 2;
	XDrawString(dsp, win[screen], textgc[screen],
	    iconx[screen], y, text_info, strlen(text_info));

	XFlush(dsp);

	y += font->ascent + font->descent + 2;

	done = False;
	while (!done) {
		strcpy(text_pass, "Please Enter PIN");
		strcat(text_pass, " for ");
		strcat(text_pass, psepath);
		strcat(text_pass, ":");
		XDrawString(dsp, win[screen], textgc[screen],
		    left, x, text_pass, strlen(text_pass));
		XDrawString(dsp, win[screen], textgc[screen],
		    left + 1, x, text_pass, strlen(text_pass));

		passx = left + 1 + XTextWidth(font, text_pass,
		    strlen(text_pass))
		    + XTextWidth(font, " ", 1);

		if (ReadXString(pin, PASSLENGTH)) {
			XChangeGrabbedCursor(mycursor);
			XUnmapWindow(dsp, icon[screen]);
			XSetForeground(dsp, Scr[screen].gc, bgcol[screen].pixel);
			return 1;
		}
		XSetForeground(dsp, Scr[screen].gc, bgcol[screen].pixel);

		rc = sign_verify(pin);

		if(rc == 0) done = TRUE;
		else done = FALSE;

		XFillRectangle(dsp, win[screen], Scr[screen].gc,
		    iconx[screen], y - font->ascent,
		    XTextWidth(font, text_invalid, strlen(text_invalid)),
		    font->ascent + font->descent + 2);

		XDrawString(dsp, win[screen], textgc[screen],
		    iconx[screen], y, text_valid, strlen(text_valid));


		if (!done) {
			XSync(dsp, True);	/* flush input buffer */
			sleep(1);
			XFillRectangle(dsp, win[screen], Scr[screen].gc,
			    iconx[screen], y - font->ascent,
			    XTextWidth(font, text_valid, strlen(text_valid)),
			    font->ascent + font->descent + 2);

			XDrawString(dsp, win[screen], textgc[screen],
			    iconx[screen], y, text_invalid, strlen(text_invalid));
		}
	}

	return 0;

}


static void
justDisplay()
{
	XEvent      event;
	int	j;
	char	str[10];
	extern	int m;
	for (screen = 0; screen < screens; screen++)
		init(win[screen]);
	do {
		while (!XPending(dsp)) {
			for (screen = 0; screen < screens; screen++)
				callback(win[screen]);

			XFlush(dsp);
			usleep(delay);
		}
		XNextEvent(dsp, &event);
#ifndef DEBUG
		if (event.type == VisibilityNotify)
			XRaiseWindow(dsp, event.xany.window);
#endif
	} while (event.type != ButtonPress && event.type != KeyPress);

	for (screen = 0; screen < screens; screen++) 
		if (event.xbutton.root == RootWindow(dsp, screen))
			break;

	return;
}


static void
sigcatch()
{
	finish();
	error("%s: caught terminate signal.\nAccess control list restored.\n");
}


static void
lockDisplay()

{
		if (!allowaccess) {
#ifdef SYSV
			sigset_t    oldsigmask;
			sigset_t    newsigmask;

			sigemptyset(&newsigmask);
			sigaddset(&newsigmask, SIGHUP);
			sigaddset(&newsigmask, SIGINT);
			sigaddset(&newsigmask, SIGQUIT);
			sigaddset(&newsigmask, SIGTERM);
			sigprocmask(SIG_BLOCK, &newsigmask, &oldsigmask);
#else
			int         oldsigmask;

			oldsigmask = sigblock(sigmask(SIGHUP) |
			    sigmask(SIGINT) |
			    sigmask(SIGQUIT) |
			    sigmask(SIGTERM));
#endif

			signal(SIGHUP, sigcatch);
			signal(SIGINT, sigcatch);
			signal(SIGQUIT, sigcatch);
			signal(SIGTERM, sigcatch);

			XGrabHosts(dsp);

#ifdef SYSV
			sigprocmask(SIG_SETMASK, &oldsigmask, &oldsigmask);
#else
			sigsetmask(oldsigmask);
#endif
		}
		do {
			justDisplay();
		} while (getPassword());
	}


int
main(argc, argv)
int         argc;
char       *argv[];
{
	extern char	*optarg;
	extern int	optind, opterr;
	char            opt;
	char		*cadir = NULL, *psename;
	int		i;
	XSetWindowAttributes xswa;
	XGCValues   	xgcv;
	int		j;
	char		str[10];
	PSESel 		*std_pse;

	ProgramName = strrchr(argv[0], '/');
	if (ProgramName)
		ProgramName++;
	else
		ProgramName = argv[0];


	/*********************************************************/
	optind = 1;
	opterr = 0;

	psename = getenv("PSE");
	cadir = getenv("CADIR");
	while ((opt = getopt(argc, argv, "c:p:h")) != -1) switch (opt) {
		
		case 'c':
			cadir = optarg;
			continue;
		case 'p':
			psename = optarg;
			continue;
		case 'h':
			usage(LONG_HELP);
			continue;
		default:
			usage(SHORT_HELP);
	}

	if (!psename) {
		if (cadir) psename = DEF_CAPSE;
		else psename = DEF_PSE;
	}


	if (cadir) {
		psepath = (char *) malloc(strlen(cadir) + strlen(psename) + 2);
		strcpy(psepath, cadir);
		if (psepath[strlen(psepath) - 1] != '/') strcat(psepath, "/");
		strcat(psepath, psename);
	} 
	else psepath = psename;

	if (aux_create_AFPSESel(psepath, (char *)0) < 0)  {
		fprintf(stderr, "Have no PSE name\n");
		exit(-1);
	}	

	if (!(std_pse = af_pse_open((ObjId * )0, FALSE))) {
		fprintf(stderr, "Can't open PSE %s\n", psepath);
#ifdef SCA
		sec_sc_eject(CURRENT_SCT);
#endif
		exit(-1);
	}
	aux_free_PSESel(&std_pse);

	if((verifierCertificate = af_pse_get_Certificate(SIGNATURE, (DName *)0, 0)) == (Certificate *)0) {
		fprintf(stderr, "Can't read certificate from PSE %s\n", psepath);
#ifdef SCA
		sec_sc_eject(CURRENT_SCT);
#endif
		exit(-1);
	}

#ifdef SCA
        sec_sc_eject(CURRENT_SCT);
#endif

	if(!(verifierCertificates = aux_create_Certificates(verifierCertificate, (FCPath *)0))) {
		fprintf(stderr, "Can't create Certificates\n");
		exit(-1);
	}

		
	if(!(verifierPKRoot = aux_create_PKRoot(verifierCertificate, (Certificate *)0))) {
		fprintf(stderr, "Can't create PKRoot\n");
		exit(-1);
	}

	SC_PSE = sec_sctest(psepath);
	if(SC_PSE) {

		if((xlock_pid = fork()) != 0) {
			while(sign_verify((char *)0));
			exit(0);
		}
	}

	/*********************************************************/


	GetResources(argc, argv);

	CheckResources();

	font = XLoadQueryFont(dsp, fontname);
	if (font == NULL) {
		fprintf(stderr, "%s: can't find font: %s, using %s...\n",
		    ProgramName, fontname, FALLBACK_FONTNAME);
		font = XLoadQueryFont(dsp, FALLBACK_FONTNAME);
		if (font == NULL)
			error("%s: can't even find %s!!!\n", FALLBACK_FONTNAME);
	}
	screens = ScreenCount(dsp);
	if (screens > MAXSCREENS)
		error("%s: can only support %d screens.\n", MAXSCREENS);
	for (screen = 0; screen < screens; screen++) {
		XColor      tmp;
		Screen     *scr = ScreenOfDisplay(dsp, screen);
		Colormap    cmap = DefaultColormapOfScreen(scr);

		root[screen] = RootWindowOfScreen(scr);
		if (mono || CellsOfScreen(scr) == 2) {
			XAllocNamedColor(dsp, cmap, "Black", &fgcol[screen], &tmp);
			XAllocNamedColor(dsp, cmap, "White", &bgcol[screen], &tmp);
			Scr[screen].pixels[0] = fgcol[screen].pixel;
			Scr[screen].pixels[1] = bgcol[screen].pixel;
			Scr[screen].npixels = 2;
		} else {
			int         colorcount = NUMCOLORS;
			u_char      red[NUMCOLORS];
			u_char      green[NUMCOLORS];
			u_char      blue[NUMCOLORS];
			int         i;

			if (!XAllocNamedColor(dsp, cmap, background,
			    &bgcol[screen], &tmp)) {
				fprintf(stderr, "couldn't allocate: %s\n", background);
				XAllocNamedColor(dsp, cmap, "White", &bgcol[screen], &tmp);
			}
			if (!XAllocNamedColor(dsp, cmap, foreground,
			    &fgcol[screen], &tmp)) {
				fprintf(stderr, "couldn't allocate: %s\n", foreground);
				XAllocNamedColor(dsp, cmap, "Black", &fgcol[screen], &tmp);
			}
			hsbramp(0.0, saturation, 1.0, 1.0, saturation, 1.0, colorcount,
			    red, green, blue);
			Scr[screen].npixels = 0;
			for (i = 0; i < colorcount; i++) {
				XColor      xcolor;

				xcolor.red = red[i] << 8;
				xcolor.green = green[i] << 8;
				xcolor.blue = blue[i] << 8;
				xcolor.flags = DoRed | DoGreen | DoBlue;

				if (!XAllocColor(dsp, cmap, &xcolor))
					break;

				Scr[screen].pixels[i] = xcolor.pixel;
				Scr[screen].npixels++;
			}
			if (verbose)
				fprintf(stderr, "%d pixels allocated\n", Scr[screen].npixels);
		}

		xswa.override_redirect = True;
		xswa.background_pixel = BlackPixelOfScreen(scr);
		xswa.event_mask = KeyPressMask | ButtonPressMask | VisibilityChangeMask;

		win[screen] = XCreateWindow(dsp, root[screen],
		    0, 0,
		    WidthOfScreen(scr),
		    HeightOfScreen(scr),
		    0, CopyFromParent, InputOutput, CopyFromParent,
		    CWOverrideRedirect | CWBackPixel | CWEventMask, &xswa);

		xswa.background_pixel = bgcol[screen].pixel;
		xswa.event_mask = ButtonPressMask;

		iconx[screen] = (DisplayWidth(dsp, screen) -
		    XTextWidth(font, text_info, strlen(text_info))) / 2;

		icony[screen] = DisplayHeight(dsp, screen) / 6;
		icon[screen] = XCreateWindow(dsp, win[screen],
		    iconx[screen], icony[screen],
		    ICONW, ICONH,
		    1, CopyFromParent,
		    InputOutput, CopyFromParent,
		    CWBackPixel | CWEventMask, &xswa);

		XMapWindow(dsp, win[screen]);
		XRaiseWindow(dsp, win[screen]);

		xgcv.foreground = WhitePixelOfScreen(scr);
		xgcv.background = BlackPixelOfScreen(scr);
		Scr[screen].gc = XCreateGC(dsp, win[screen],
		    GCForeground | GCBackground, &xgcv);

		xgcv.foreground = fgcol[screen].pixel;
		xgcv.background = bgcol[screen].pixel;
		xgcv.font = font->fid;
		textgc[screen] = XCreateGC(dsp, win[screen],
		    GCFont | GCForeground | GCBackground, &xgcv);
	}
	lockc = XCreateBitmapFromData(dsp, root[0], no_bits, 1, 1);
	lockm = XCreateBitmapFromData(dsp, root[0], no_bits, 1, 1);
	mycursor = XCreatePixmapCursor(dsp, lockc, lockm,
	    &fgcol[screen], &bgcol[screen], 0, 0);
	XFreePixmap(dsp, lockc);
	XFreePixmap(dsp, lockm);


	if (!enablesaver) {
		XGetScreenSaver(dsp, &sstimeout, &ssinterval,
		    &ssblanking, &ssexposures);
		XSetScreenSaver(dsp, 0, 0, 0, 0);	/* disable screen saver */
	}
#ifndef DEBUG
	GrabKeyboardAndMouse();
#endif

	srandom(getpid());



	nice(nicelevel);

	if (nolock)
		justDisplay();
	else
		lockDisplay();

	finish();

	return 0;
}

static
void usage(help)
int     help;
{
	aux_fprint_version(stderr);

        fprintf(stderr, "secxlock  Locks the local X display using strong authentication with your PSE\n\n");
        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "secxlock [-h] [-p <pse>] [-c <cadir>]\n\n");

        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <psename>     PSE name (default: Environment variable PSE or .pse)\n");
        fprintf(stderr, "-c <cadir>       name of CA-directory (default: Environment variable CADIR or .ca)\n");
        fprintf(stderr, "-h               Write this help text\n");
        }


        exit(-1);                                /* IRREGULAR EXIT FROM SECXLOCK */
}
