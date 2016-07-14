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


	   /*-------------------------------------------------*/
	   /* Definition der maximalen Feld - groessen	      */
	   /*-------------------------------------------------*/
#define  MINKEYL    64       /* Minimale Key Laenge           */
#define  MAXRNDM    521      /*Maximale laenge einer Zufallsz.*/

/*------------------------------------------------------------*/
/* Typ - Definitionen					      */
/*------------------------------------------------------------*/
	   /*-------------------------------------------------*/
	   /* Teile des RSA-Schluessels als 'lange Zahlen'    */
	   /*-------------------------------------------------*/

typedef struct	 {
	      L_NUMBER   modul[MAXGENL],
		    p[MAXGENL],
		    q[MAXGENL];
	      }
	      rndmstart;

typedef	struct	{
	L_NUMBER        p[MAXLGTH];
	L_NUMBER        q[MAXLGTH];
	L_NUMBER        sp[MAXLGTH];
	L_NUMBER        sq[MAXLGTH];
	L_NUMBER        u[MAXLGTH];
	}       Skeys;

typedef	struct	{
	L_NUMBER        n[MAXLGTH];
	L_NUMBER        e[MAXLGTH];
	}       Pkeys;

typedef union {
	Skeys   sk;
	Pkeys   pk;
	}       RSAkeys;
