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

#ifndef __MFCHECK
#define __MFCHECK

/* extern char *malloc(), *calloc(), *realloc(); */
#include <malloc.h>

#define malloc(x) aux_malloc(proc, x)
#define calloc(x, y) aux_calloc(proc, x, y)
#define realloc(x, y) aux_realloc(proc, x, y, proc)
#define free(x) aux_free(proc, x)
extern char *proc;
extern char MF_check;
extern int sec_debug;
char *aux_malloc(), *aux_calloc(), *aux_realloc();
void aux_free(), MF_fprint(), MF_fprint_stderr();

#endif
