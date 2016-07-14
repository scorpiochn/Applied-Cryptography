/*
 *  SecuDE Release 4.1 (GMD)
 */
/********************************************************************
 * Copyright (C) 1991, GMD. All rights reserved.                    *
 *                                                                  *
 *                                                                  *
 *                         NOTICE                                   *
 *                                                                  *
 *    Acquisition, use, and distribution of this module             *
 *    and related materials are subject to restrictions             *
 *    mentioned in each volume of the documentation.                *
 *                                                                  *
 ********************************************************************/

/*-----------------------sect_inc.h---------------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institut fuer TeleKooperationsTechnik (I2)         */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991,92,93                */
/* 	Grimm/Nausester/Schneider/Viebeg/Vollmer/                   */
/* 	Surkau/Reichelt/Kolletzki                     et alii       */
/*------------------------------------------------------------------*/
/* INCLUDE FILE  sect_inc.h                                         */
/* load all needed SecuDE/X11/XView-include-files for SecuDE Tool   */
/*	Kolletzki						    */
/*------------------------------------------------------------------*/


#define TRUE 1
#define FALSE 0
#define NL '\012'
#define ALL 6
#define ENC 5


/* System */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

/* X */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <xview/xview.h>
#include <xview/panel.h>
#include <xview/textsw.h>
#include <xview/xv_xrect.h>
#include <xview/notice.h>
#include <xview/cursor.h>
#include <xview/screen.h>
#include <xview/server.h>
#include <xview/fullscreen.h>
#include <xview/font.h>
#include <xview/window.h>
#include <xview/win_input.h>
#include <xview/seln.h>
#include <xview/dragdrop.h>

/* SecuDE */
#include "af.h"
#ifdef MFCHECK
#include "MF_check.h"
#endif

/* SecTool */
#include "sectool.h"


