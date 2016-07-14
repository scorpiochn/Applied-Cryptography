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
#define MAXMODULUSL	1024	/*	maximum length of prim p 	*/
#define MINMODULUSL	512	/*	minimum length of prim p	*/
#define MODULUSSTEPS	64	/*	length of p must be dividable by 64	*/
#define HASHWORDS	5	/*	length of sha hash bitstring	*/
#define HASHOCTETS	(WBYTES*HASHWORDS)	/*	length of sha hash bitstring	*/
#define HASHBITS	(BYTEL*HASHOCTETS)	/*	length of sha hash bitstring	*/
#define SEEDWORDS	5	/*	length of random number	*/
#define SEEDOCTETS	(WBYTES*SEEDWORDS)	/*	length of random number	*/
#define SEEDBITS	(BYTEL*SEEDOCTETS)	/*	length of random number	*/

	
/*------------------------------------------------------------*/
/* Typ - Definitionen					      */
/*------------------------------------------------------------*/
	   /*-------------------------------------------------*/
	   /* Teile des RSA-Schluessels als 'lange Zahlen'    */
	   /*-------------------------------------------------*/
typedef	struct	{
	L_NUMBER        x[MAXLGTH];
	L_NUMBER        p[MAXLGTH];
	L_NUMBER        q[MAXLGTH];
	L_NUMBER        g[MAXLGTH];
	}       DSA_Skeys;

typedef	struct	{
	L_NUMBER        y[MAXLGTH];
	L_NUMBER        p[MAXLGTH];
	L_NUMBER        q[MAXLGTH];
	L_NUMBER        g[MAXLGTH];
	}       DSA_Pkeys;

typedef union {
	DSA_Skeys   sk;
	DSA_Pkeys   pk;
	}       DSA_keys;

typedef struct {
	L_NUMBER   r[MAXLGTH];
	L_NUMBER   s[MAXLGTH];
	}       DSA_sig;

typedef	struct	{
	L_NUMBER        p[MAXLGTH];
	L_NUMBER        q[MAXLGTH];
	L_NUMBER        g[MAXLGTH];
	}       DSA_public_part;
extern DSA_public_part dsa_public_part[];
