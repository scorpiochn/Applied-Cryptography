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

/*
 *  DES interface module between sec_encrypt/sec_decrypt
 *  and Phil Karn's DES package
 *
 *  WS 6.12.90
 *
 *  Last change: 7.12.90
 *
 *  Imports from Karn's:
 *
 *  desinit(mode) int mode;
 *  setkey(key) char *key;
 *  endes(block) char *block;
 *  dedes(block) char *block;
 *  desdone()
 *
 *  Exports to libdes.a:
 *
 *  des_encrypt(in_octets, out_bits, more, keyinfo)
 *  des_decrypt(in_bits, out_octets, more, keyinfo)
 *  read_dec(fd, buf, len, pin)
 *  write_enc(fd, buf, len, pin)
 *  string_to_key(pin) 
 *
 */

#define STD 0
#define PEM 1
#define RAW 2

#include "secure.h"
#include <stdio.h>
#include <fcntl.h>

#ifdef MAC
#include <Unix.h>
#include <stdlib.h>
#include <string.h>
#include "Mac.h"
#endif /* MAC */

static char	iv[8];  /* Initialization vector */
static int	DESINIT = FALSE;
static char     des3;
static unsigned char	des_hash_key1[8] = 
{ 
	0x9a, 0xd3, 0xbc, 0x24, 0x10, 0xe2, 0x8f, 0x0e };


static unsigned char	des_hash_key2[8] = 
{ 
	0xe2, 0x95, 0x14, 0x33, 0x59, 0xc3, 0xec, 0xa8 };

void endes_cbc(), endes_ecb(), dedes_cbc(), dedes_ecb();
static desfirst();

des_encrypt(in_octets, out_bits, more, keyinfo)
OctetString *in_octets;
BitString *out_bits;
More more;
KeyInfo *keyinfo;
{
	static int	first = TRUE, des_type, padding;
        AlgEnc   algenc;
	AlgMode  algmode;
        AlgSpecial algspecial;
	static unsigned int	remaining_octets;
	static char	remaining_buf[8];

	register int	encrypted_blocks, octets_to_be_encrypted, encrypted_octets;
	register char	*inp, *outp;
	register int	i;
	unsigned int	remaining_octets_new;
	char	*proc = "des_encrypt";

	if (first) {
                algenc = aux_ObjId2AlgEnc(keyinfo->subjectAI->objid);
                algmode = aux_ObjId2AlgMode(keyinfo->subjectAI->objid);
                algspecial = aux_ObjId2AlgSpecial(keyinfo->subjectAI->objid);

                if(algenc == DES3) des3 = TRUE;
                else des3 = FALSE;

		if (algmode == CBC) des_type = CBC;
		else des_type = ECB;

		padding = RAW;
		if (algspecial == WITH_PEM_PADDING) padding = PEM;
		if (algspecial == WITH_PADDING)	padding = STD;

		remaining_octets = 0;
		if (desfirst(keyinfo, des_type) < 0) {
			aux_add_error(EINVALID, "desfirst failed", 0, 0, proc);
			return(-1);
		}
		first = FALSE;
	}
	if (more == END) first = TRUE;

	octets_to_be_encrypted = in_octets->noctets;
	inp = in_octets->octets;
	outp = out_bits->bits + (out_bits->nbits / 8);

	encrypted_octets = 0;

	if (remaining_octets) {

		for (i = remaining_octets; i < 8; i++) {
			if (octets_to_be_encrypted - 1 >= 0) {
				remaining_buf[i] = *inp++;
				octets_to_be_encrypted--;
				remaining_octets++;
			} else break;
		}
		if (i == 8) {
			bcopy(remaining_buf, outp, 8);
			if (des_type == CBC) 
                                endes_cbc(outp);
			else 
				endes_ecb(outp);
			outp += 8;
			encrypted_octets = 8;
			remaining_octets = 0;
		}

	}

	encrypted_blocks = octets_to_be_encrypted / 8;
	remaining_octets_new = octets_to_be_encrypted % 8;

	if (encrypted_blocks) {
		octets_to_be_encrypted = encrypted_blocks * 8;
		if (inp != outp) 
			bcopy(inp, outp, octets_to_be_encrypted);
		for (i = 0; i < encrypted_blocks; i++) {
			if (des_type == CBC) 
				endes_cbc(outp);
			else 
				endes_ecb(outp);
			inp += 8;
			outp += 8;
		}
		encrypted_octets += octets_to_be_encrypted;
	}

	out_bits->nbits += (encrypted_octets * 8);

	if (remaining_octets_new) {
		for (i = remaining_octets; i < remaining_octets + remaining_octets_new; i++) 
			remaining_buf[i] = *inp++;
		remaining_octets += remaining_octets_new;
	}

	if (more == END) {
		switch (padding) {
		case STD:
			remaining_buf[7] = remaining_octets;
			bcopy(remaining_buf, outp, 8);
			if (des_type == CBC) 
				endes_cbc(outp);
			else 
				endes_ecb(outp);
			encrypted_octets += 8;
			out_bits->nbits += 64;
			break;
		case PEM:
			for (i = remaining_octets; i < 8; i++) 
				remaining_buf[i] = 8 - remaining_octets;
			bcopy(remaining_buf, outp, 8);
			if (des_type == CBC) 
				endes_cbc(outp);
			else 
				endes_ecb(outp);
			encrypted_octets += 8;
			out_bits->nbits += 64;
			break;
		case RAW:
			if (remaining_octets == 0) 
				break;
			for (i = remaining_octets; i < 8; i++) 
				remaining_buf[i] = 0;
			bcopy(remaining_buf, outp, 8);
			if (des_type == CBC) 
				endes_cbc(outp);
			else 
				endes_ecb(outp);
			encrypted_octets += 8;
			out_bits->nbits += 64;
			break;
		}
		c_desdone(des3);
	}

	return(encrypted_octets * 8);
}


void
endes_cbc(outblock)
char	*outblock;
{
	register char	*cp, *cp1;
	register int	i;

	/* CBC mode; chain in last cipher word */

	cp = outblock;
	cp1 = iv;
	for (i = 8; i != 0; i--) *cp++ ^= *cp1++;

	endes_ecb(outblock);	/* in-block encryption */

	/* Save outblockgoing ciphertext for chain */

	bcopy(outblock, iv, 8);
}

void
endes_ecb(outblock)
char	*outblock;
{
        if(des3) {
                endes(outblock);
                dedes1(outblock);
                endes(outblock);
        }
        else endes(outblock);
        return;
}

des_decrypt(in_bits, out_octets, more, keyinfo)
BitString *in_bits;
OctetString *out_octets;
More more;
KeyInfo *keyinfo;
{
	static int	first = TRUE, des_type, padding;
        AlgEnc   algenc;
        AlgMode  algmode;
        AlgSpecial  algspecial;
	static unsigned int	remaining_bits, remaining_octets;
	static unsigned char	remaining_buf[8];

	register int	decrypted_blocks, octets_to_be_decrypted, bits_to_be_decrypted, decrypted_octets;
	register char	*inp, *outp;
	register int	i;
	unsigned int	remaining_bits_new, remaining_octets_new;
	char	*proc = "des_decrypt";

	if (first) {
                algenc = aux_ObjId2AlgEnc(keyinfo->subjectAI->objid);
                algmode = aux_ObjId2AlgMode(keyinfo->subjectAI->objid);
                algspecial = aux_ObjId2AlgSpecial(keyinfo->subjectAI->objid);

                if(algenc == DES3) des3 = TRUE;
                else des3 = FALSE;

		if (algmode == CBC) des_type = CBC;
		else des_type = ECB;

		padding = RAW;
		if (algspecial == WITH_PEM_PADDING) padding = PEM;
		if (algspecial == WITH_PADDING)	padding = STD;

		remaining_bits = 0;
		remaining_octets = 0;
		if (desfirst(keyinfo, des_type) < 0) {
			aux_add_error(EINVALID, "desfirst failed", 0, 0, proc);
			return(-1);
		}
		first = FALSE;
	}
	if (more == END) first = TRUE;

	bits_to_be_decrypted = in_bits->nbits;
	inp = in_bits->bits;
	outp = out_octets->octets + out_octets->noctets;

	decrypted_octets = 0;

	if (remaining_bits) {

		/* This works only if remaining_bits is a multiple of 8.
                   Major stuff must be inserted here to handle arbitrary in_bits->nbits  */

		for (i = remaining_octets; i < 8; i++) {
			if (bits_to_be_decrypted - 8 >= 0) {
				remaining_buf[i] = *inp++;
				bits_to_be_decrypted -= 8;
				remaining_bits += 8;
				remaining_octets++;
			} else 
				break;
		}
		if (i == 8) {
			bcopy(remaining_buf, outp, 8);
			if (des_type == CBC) 
				dedes_cbc(outp);
			else 
				dedes_ecb(outp);
			outp += 8;
			decrypted_octets = 8;
			remaining_octets = 0;
			remaining_bits = 0;
		}

	}

	decrypted_blocks = bits_to_be_decrypted / 64;
	remaining_bits_new = bits_to_be_decrypted % 64;
	if (decrypted_blocks) {
		octets_to_be_decrypted = decrypted_blocks * 8;
		if (inp != outp) 
			bcopy(inp, outp, octets_to_be_decrypted);
		for (i = 0; i < decrypted_blocks; i++) {
			if (des_type == CBC) 
				dedes_cbc(outp);
			else 
				dedes_ecb(outp);
			inp += 8;
			outp += 8;
		}
		decrypted_octets += octets_to_be_decrypted;
	}

	out_octets->noctets += decrypted_octets;

	if (remaining_bits_new) {
		if (more == END) {
			aux_add_error(EINVALID, "input not multiple of eight", 0, 0, proc);
			return(-1);
		}
		remaining_octets_new = remaining_bits_new / 8;
		if (remaining_bits_new % 8) 
			remaining_octets_new++;
		for (i = remaining_octets; i < remaining_octets + remaining_octets_new; i++) 
			remaining_buf[i] = *inp++;
		remaining_octets += remaining_octets_new;
		remaining_bits += remaining_bits_new;
	}

	if (more == END) {
		c_desdone(des3);
		switch (padding) {
		case STD:
			outp--;
			i = *outp;
			if (i < 0 || i > 7) {
				aux_add_error(EDECRYPT, "wrong bytecount (STD)", 0, 0, proc);
				return(-1);
			}
			i = 8 - i;
			out_octets->noctets -= i;
			decrypted_octets -= i;
			break;
		case PEM:
			outp--;
			i = *outp;
			if (i <= 0 || i > 8) {
				aux_add_error(EDECRYPT, "wrong bytecount (PEM)", 0, 0, proc);
				return(-1);
			}
			out_octets->noctets -= i;
			decrypted_octets -= i;
			break;
		}
	}

	return(decrypted_octets);
}


void
dedes_cbc(outblock)
char	*outblock;
{
	char	ivtmp[8];
	register char	*cp, *cp1;
	register int	i;


	/* Save incoming ciphertext for chain */

	bcopy(outblock, ivtmp, 8);

	dedes_ecb(outblock);   /* in-block decryption */

	/* Unchain block, save ciphertext for next */

	cp = outblock;
	cp1 = iv;
	for (i = 8; i != 0; i--)	
		*cp++ ^= *cp1++;
	bcopy(ivtmp, iv, 8);
}

void
dedes_ecb(outblock)
char	*outblock;
{
        if(des3) {
                dedes(outblock);
                endes1(outblock);
                dedes(outblock);
        }
        else dedes(outblock);
        return;
}


static
desfirst(keyinfo, des_type)
KeyInfo *keyinfo;
int	des_type;
{
	OctetString *algparm;
	char	*proc = "desfirst";

	if (DESINIT == FALSE) {
		if (desinit(0, des3) < 0) return(-1);
		DESINIT = TRUE;
	}

	if (keyinfo->subjectkey.nbits == 64 && !des3) setkey(keyinfo->subjectkey.bits);
        else if(keyinfo->subjectkey.nbits == 128 && des3) setdoublekey(keyinfo->subjectkey.bits);
	else {
		aux_add_error(EINVALID, "wrong key length", 0, 0, proc);
		return(-1);
	}
	if (des_type == CBC) {
		/* Initialization Vector */
		if ((algparm = (OctetString * )keyinfo->subjectAI->parm))
			if (algparm->noctets == 8) 
				bcopy(algparm->octets, iv, 8);
			else bzero(iv, 8);
	}
	return(0);
}

setdoublekey(key)  /* this is for DES3 only */
char *key;
{
        setkey(key);
        setkey1(key + 8);
        return(0);
}

read_dec(fd, buf, len, key)
int	fd, len;
char	*buf, *key;
{
	Key deskey;
	static FILE *ff;
	static int	first = TRUE, in, des_type, wout;
	static char	work[8], nwork[8], *w, *nw, *ww;
	int	out = 0, rest;
	AlgMode algmode;
	register int	block;
	register char	*bb;
	char	*proc = "read_dec";

	if (!buf && first == FALSE) {
		c_desdone(FALSE);
		fclose(ff);
		first = TRUE;
		return(0);
	}

	if (!len) return(0);

	if (!key || !strlen(key)) return(read(fd, buf, len));

	if (first) {
		deskey.keyref = 0;
		deskey.pse_sel = (PSESel * )0;
		if (sec_string_to_key(key, &deskey) < 0) {
			aux_add_error(EINVALID, "sec_string_to_key failed", 0, 0, proc);
			return(-1);
		}
		algmode = aux_ObjId2AlgMode(deskey.key->subjectAI->objid);
		if (algmode == CBC) des_type = CBC;
		else des_type = ECB;

                des3 = FALSE;

		if (desfirst(deskey.key, des_type) < 0) {
			aux_free_KeyInfo(&(deskey.key));
			aux_add_error(EINVALID, "desfirst failed", 0, 0, proc);
			return(-1);
		}

		aux_free_KeyInfo(&(deskey.key));
		if (!(ff = fdopen(fd, "r"))) {
			aux_add_error(ESYSTEM, "fdopen failed", 0, 0, proc);
			return(-1);
		}
		if ((in = fread(work, 1, 8, ff)) != 8) {
			aux_add_error(ESYSTEM, "fread failed", 0, 0, proc);
			return(-1);
		}

		w = work;
		nw = nwork;
		wout = 0;
		if (des_type == CBC) dedes_cbc(w);
		else dedes_ecb(w);
		first = FALSE;
	}

	bb = buf;

	if (len % 8 == 0 && wout == 0) {
		if (in) {
			bcopy(w, bb, 8);
			bb += 8;
			len -= 8;
			out += 8;
		} 
		else return(0);
		if ((in = fread(bb, 1, len, ff))) {
			for (block = 0; block < in / 8; block++) {
				if (des_type == CBC) dedes_cbc(bb);
				else dedes_ecb(bb);
				bb += 8;
				out += 8;
			}
		}
		if (in < len || ((in = fread(w, 1, 8, ff)) != 8)) {
			rest = *(bb - 1);
			if (rest < 0 || rest > 7) {
				aux_add_error(EINVALID, "DES decryption error: wrong bytecount", 0, 0, proc);
				return(-1);
			}
			out -= (8 - rest);
			in = 0;
			return(out);
		}
		if (des_type == CBC) dedes_cbc(w);
		else dedes_ecb(w);
		return(out);
	}

	while (1) {
		if (wout) {
			if (len < wout) {
				bcopy(ww, bb, len);
				ww += len;
				wout -= len;
				out += len;
				return(out);
			}
			bcopy(ww, bb, wout);
			len -= wout;
			out += wout;
			bb += wout;
			wout = 0;
			if (w == &work[0]) {
				w = nwork;
				nw = work;
			} 
			else {
				w = work;
				nw = nwork;
			}
		}
		if (len == 0 || in == 0) return(out);
		if ((in = fread(nw, 1, 8, ff))) {
			if (des_type == CBC) dedes_cbc(nw);
			else dedes_ecb(nw);
		}
		ww = w;
		if (in == 8) wout = 8;
		else wout = w[7];
		if (wout == 0) return(out);
	}
}


write_enc(fd, buf, len, key)
int	fd, len;
char	*buf, *key;
{
	Key deskey;
	static int	first = TRUE;
	static FILE *ff;
	static char	work[8];
	static char	*w;
	static int	des_type, wout;
	int	out = 0;
	AlgMode algmode;
	register int	block;
	register char	*bb;
	int	i;
	char	*proc = "write_enc";

	if (!buf && first == FALSE) {
		work[7] = wout;
		if (des_type == CBC) endes_cbc(work);
		else endes_ecb(work);
		fwrite(work, 1, 8, ff);
		fclose(ff);
		c_desdone(FALSE);
		first = TRUE;
		return(0);
	}

	if (!len) return(0);

	if (!key || !strlen(key)) return(write(fd, buf, len));

	if (first) {
		deskey.keyref = 0;
		deskey.pse_sel = (PSESel * )0;
		if (sec_string_to_key(key, &deskey) < 0) {
			aux_add_error(EINVALID, "sec_string_to_key failed", 0, 0, proc);
			return(-1);
		}

		algmode = aux_ObjId2AlgMode(deskey.key->subjectAI->objid);
		if (algmode == CBC) des_type = CBC;
		else des_type = ECB;

                des3 = FALSE;

		if (desfirst(deskey.key, des_type) < 0) {
			aux_free_KeyInfo(&(deskey.key));
			aux_add_error(EINVALID, "desfirst failed", 0, 0, proc);
			return(-1);
		}

		aux_free_KeyInfo(&(deskey.key));
		if (!(ff = fdopen(fd, "w"))) {
			aux_add_error(ESYSTEM, "fdopen failed", 0, 0, proc);
			return(-1);
		}

		w = work;
		wout = 0;
		first = FALSE;
	}

	bb = buf;
	if (wout == 0 && len > 8) {
		for (block = 0; block < len / 8; block++) {
			if (des_type == CBC) endes_cbc(bb);
			else endes_ecb(bb);
			bb += 8;
		}
		out = bb - buf;
		fwrite(buf, 1, out, ff);
		len -= out;
	}
	while (len) {
		*w++ = *bb++;
		wout++;
		out++;
		if (wout == 8) {
			if (des_type == CBC) endes_cbc(work);
			else endes_ecb(work);
			fwrite(work, 1, 8, ff);
			wout = 0;
			w = work;
		}
		len--;
	}
	return(out);
}


close_dec(fd)
int	fd;
{
	read_dec(fd, CNULL, 0, CNULL);
	close(fd);

	return(0);
}


close_enc(fd)
int	fd;
{
	write_enc(fd, CNULL, 0, CNULL);
	close(fd);

	return(0);
}


c_desdone(des3)
Boolean des3; 
{

        desdone(des3);
        DESINIT = FALSE;

	return(0);
}


/* This is supposed to be a one-way string-to-key function. */

char	*string_to_key(asckey)
char	*asckey;
{
	register char	*p;
	register int	i;
	char	k1[8], k2[8];
	char	*key;
	char	*proc = "string_to_key";

	if (!(key = (char *)malloc(8))) {
		aux_add_error(EMALLOC, "key", 0, 0, proc);
		return(CNULL);
	}
	if (DESINIT == FALSE) {
		if (desinit(0, FALSE) < 0) {
			aux_add_error(EINVALID, "desinit failed", 0, 0, proc);
			free(key);
			return(CNULL);
		}

		DESINIT = TRUE;
	}

	for (i = 0; i < 8; i++) {
		k1[i] = k2[i] = 0;
	}
	for (i = 0, p = asckey; *p; p++, i++) {
		i %= 8;
		k1[i] |= *p;
		k2[i] |= *p;
		setkey(des_hash_key1);
		endes(k1);
		setkey(des_hash_key2);
		endes(k2);
	}
	for (i = 0; i < 8; i++) {
		key[i] = k1[i] ^ k2[i];
	}
	return(key);
}


