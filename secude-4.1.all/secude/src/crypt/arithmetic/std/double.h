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


#define L_NUMBER        unsigned int
typedef union {
	struct {
#if !defined(vax) && !defined(ntohl) && !defined(lint) && !defined(LITTLE_ENDIAN)
		unsigned short  h_part, l_part;
#else
		unsigned short  l_part, h_part;
#endif
	}               hw;
	L_NUMBER        ln;
}               Word;

#define HSW(x)  (x).hw.h_part
#define LSW(x)  (x).hw.l_part
#define W(x)    (x).ln
