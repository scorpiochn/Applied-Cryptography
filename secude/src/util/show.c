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

#include <stdio.h>
#include "af.h"

int             verbose = 0;
static void     usage();


main(cnt, parm) 
int cnt;
char **parm; 
{
        ObjId 	      		  object_oid;
        DName 	     		* dname;
        Name         		* name;
        OctetString  		* ostr, *object, * tmp_ostr;
        Certificate  		* certificate;
	Certificates 		* certificates;
        KeyInfo      		* keyinfo;
	KeyBits      		* keybits;
	BitString     		  bitstring, *bstr;
        SET_OF_Certificate 	* certset;
        FCPath       		* fcpath;
        PKRoot       		* pkroot;
        PKList       		* pklist;
	PemCrl      		* pemcrl;
	AliasList   		* aliaslist;
        SET_OF_CertificatePair  * cpairset;
        int 			  i;
	extern char		* optarg;
	extern int		  optind, opterr;
	char	        	* cmd = *parm, opt;
	char           		* psename = NULL, *psepath = NULL, *cadir = NULL, *pin;

	char 			* proc = "main (show)";



        print_cert_flag = TBS | ALG | SIGNAT;
        print_keyinfo_flag = ALGID | BSTR | KEYBITS;

	optind = 1;
	opterr = 0;

	MF_check = FALSE;

	while ( (opt = getopt(cnt, parm, "hvVW")) != -1 ) { 
		switch(opt) {
		case 'v':
			verbose = 1;
			continue;
		case 'V':
			verbose = 2;
			continue;
		case 'W':
			verbose = 2;
			af_verbose = TRUE;
			sec_verbose = TRUE;
			continue;
		case 'h':
			usage(LONG_HELP);
			continue;
		default:
		case '?':
			usage(SHORT_HELP);
		}
	}



        if(optind < cnt) ostr = aux_file2OctetString(parm[optind]);
        else ostr = aux_file2OctetString(0);
        if(!ostr) {
        	fprintf(stderr, "Can't read file\n");
		aux_add_error(EINVALID, "Can't read", 0, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}


	bitstring.nbits = ostr->noctets * 8;
	bitstring.bits = ostr->octets;
	bstr = &bitstring;

        if((object = d_PSEObject(&object_oid, ostr))) { 
                /*
                 * PSE object of the form SEQUENCE { 
                 *                            objectType  OBJECT IDENTIFIER, 
                 *                            objectValue ANY DEFINED BY objectType
                 *                        }
                 */

                if(aux_cmp_ObjId(&object_oid, SignSK_OID) == 0
                   || aux_cmp_ObjId(&object_oid, DecSKnew_OID) == 0 
                   || aux_cmp_ObjId(&object_oid, DecSKold_OID) == 0
                   || aux_cmp_ObjId(&object_oid, SKnew_OID) == 0 
                   || aux_cmp_ObjId(&object_oid, SKold_OID) == 0) {
                        fprintf(stdout, "PSE object %s:\n", aux_ObjId2PSEObjectName(&object_oid));
                        if(!(keyinfo = d_KeyInfo(ostr))) goto decodeerr;
                        print_keyinfo_flag |= SK;
                        aux_fprint_KeyInfo(stdout, keyinfo);                                      
                }
                else if(aux_cmp_ObjId(&object_oid, Name_OID) == 0) {
                        fprintf(stdout, "PSE object %s:\n", aux_ObjId2PSEObjectName(&object_oid));
                        if(!(dname = d_DName(ostr))) goto decodeerr;
        		if(!(name = aux_DName2Name(dname))) {
  			      	fprintf(stderr, "Can't build printable repr. of dname\n");
 				aux_add_error(EINVALID, "Can't build printable repr. of dname", 0, 0, proc);
				if(verbose) aux_fprint_error(stderr, 0);
        			exit(-1);
        		}
                        fprintf(stdout, "%s\n", name);
                }
                else if(aux_cmp_ObjId(&object_oid, SignCert_OID) == 0
                   || aux_cmp_ObjId(&object_oid, EncCert_OID) == 0
		   || aux_cmp_ObjId(&object_oid, Cert_OID) == 0) { 
                        fprintf(stdout, "PSE object %s:\n", aux_ObjId2PSEObjectName(&object_oid));
                        if(!(certificate = d_Certificate(ostr))) goto decodeerr;
                        print_keyinfo_flag |= PK;
                        aux_fprint_Certificate(stdout, certificate);
                }
                else if(aux_cmp_ObjId(&object_oid, SignCSet_OID) == 0
                   || aux_cmp_ObjId(&object_oid, EncCSet_OID) == 0
                   || aux_cmp_ObjId(&object_oid, CSet_OID) == 0) { 
                        fprintf(stdout, "PSE object %s:\n", aux_ObjId2PSEObjectName(&object_oid));
                        if(!(certset = d_CertificateSet(ostr))) goto decodeerr;
                        print_keyinfo_flag |= PK;
                        aux_fprint_CertificateSet(stdout, certset);
                }
                else if(aux_cmp_ObjId(&object_oid, FCPath_OID) == 0) {
                        fprintf(stdout, "PSE object %s:\n", aux_ObjId2PSEObjectName(&object_oid));
                        if(!(fcpath = d_FCPath(ostr))) goto decodeerr;
                        print_keyinfo_flag |= PK;
                        aux_fprint_FCPath(stdout, fcpath);
                }
                else if(aux_cmp_ObjId(&object_oid, PKRoot_OID) == 0) {
                        fprintf(stdout, "PSE object %s:\n", aux_ObjId2PSEObjectName(&object_oid));
                        if(!(pkroot = d_PKRoot(ostr))) goto decodeerr;
                        print_keyinfo_flag |= PK;
                        aux_fprint_PKRoot(stdout, pkroot);
                }
                else if(aux_cmp_ObjId(&object_oid, PKList_OID) == 0
                   || aux_cmp_ObjId(&object_oid, EKList_OID) == 0) { 
                        fprintf(stdout, "PSE object %s:\n", aux_ObjId2PSEObjectName(&object_oid));
                        if(!(pklist = d_PKList(ostr))) goto decodeerr;
                        print_keyinfo_flag |= PK;
                        aux_fprint_PKList(stdout, pklist);
                }
                else if(aux_cmp_ObjId(&object_oid, CrossCSet_OID) == 0) {
                        fprintf(stdout, "PSE object %s:\n", aux_ObjId2PSEObjectName(&object_oid));
                        if(!(cpairset = d_CertificatePairSet(ostr))) goto decodeerr;
                        print_keyinfo_flag |= PK;
                        aux_fprint_CertificatePairSet(stdout, cpairset);
                }
                else {
                        printf("Object OID { ");
                        for(i = 0; i < object_oid.oid_nelem; i++) {
             	                printf("%d ", object_oid.oid_elements[i]);
                        }
                        printf(" }\n");
                        aux_xdump(ostr->octets, ostr->noctets, 0);
                }
        }
        else {
                if((keyinfo = d_KeyInfo(ostr))) {
                        fprintf(stdout, "KeyInfo:\n");
                        aux_fprint_KeyInfo(stdout, keyinfo);
                }
                else if((keybits = d_KeyBits(bstr))) {
                        fprintf(stdout, "KeyBits:\n");
                        aux_fprint_KeyBits(stdout, keybits);
                }
                else if((dname = d_DName(ostr))) {
        		if(!(name = aux_DName2Name(dname)))  {
  			      	fprintf(stderr, "Can't build printable repr. of dname\n");
 				aux_add_error(EINVALID, "Can't build printable repr. of dname", 0, 0, proc);
				if(verbose) aux_fprint_error(stderr, 0);
        			exit(-1);
        		}
                        fprintf(stdout, "DName: ");
                        fprintf(stdout, "%s\n", name);
                }
                else if((certificate = d_Certificate(ostr))) {
                        fprintf(stdout, "Certificate:\n");
                        aux_fprint_Certificate(stdout, certificate);
                }
                else if((certificates = d_Certificates(ostr))) {
                        fprintf(stdout, "Certificates:\n");
                        aux_fprint_Certificates(stdout, certificates);
                }
                else if((certset = d_CertificateSet(ostr))) {
                        fprintf(stdout, "SET_OF_Certificate:\n");
                        aux_fprint_CertificateSet(stdout, certset);
                }
                else if((fcpath = d_FCPath(ostr))) {
                        fprintf(stdout, "FCPath:\n");
                        aux_fprint_FCPath(stdout, fcpath);
                }
                else if((pkroot = d_PKRoot(ostr))) {
                        fprintf(stdout, "PKRoot:\n");
                        aux_fprint_PKRoot(stdout, pkroot);
                }
                else if((pklist = d_PKList(ostr))) {
                        fprintf(stdout, "PKList or EKList:\n");
                        aux_fprint_PKList(stdout, pklist);
                }
                else if((cpairset = d_CertificatePairSet(ostr))) {
                        fprintf(stdout, "SET_OF_CertificatePair:\n");
                        aux_fprint_CertificatePairSet(stdout, cpairset);
                }
                else if((pemcrl = d_PemCrl(ostr))) {
                        fprintf(stdout, "Revocation List (PEM syntax):\n");
                        aux_fprint_PemCrl(stdout, pemcrl);
                }
                else if((aliaslist = d_AliasList(ostr))) {
        		if (optind < cnt) {
				tmp_ostr = af_SignedFile2OctetString(parm[optind]);
				if(verbose) aux_fprint_VerificationResult(stderr, verifresult);
			}
                        fprintf(stdout, "AliasList:\n");
                        aux_fprint_AliasList(stdout, aliaslist);
                }
                else {
                        fprintf(stdout, "Unknown object:\n");
                        aux_xdump(ostr->octets, ostr->noctets, 0);
                }
        }
        exit(0);
decodeerr:
	fprintf(stderr, "Can't decode objectValue\n");
  	aux_add_error(EINVALID, "Can't decode objectValue", 0, 0, proc);
	if(verbose) aux_fprint_error(stderr, 0);
        exit(-1);
}



static
void usage(help)
int     help;
{
	aux_fprint_version(stderr);

        fprintf(stderr, "show  Show ASN.1-coded SecuDE Object in Suitable Form\n\n");
        fprintf(stderr, "usage:\n\n");
	fprintf(stderr,"show [-hvVW] [file (containing ASN.1 code)]\n\n");
 

        if(help == LONG_HELP) {
        	fprintf(stderr, "with:\n\n");
        	fprintf(stderr, "-h               write this help text\n");
        	fprintf(stderr, "-v               verbose\n");
        	fprintf(stderr, "-V               Verbose\n");
        	fprintf(stderr, "-W               Grand Verbose (for testing only)\n");
        }


        exit(-1);                                /* IRREGULAR EXIT FROM SHOW */
}
