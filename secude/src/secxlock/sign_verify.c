#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#include "af.h"


extern Boolean	SC_PSE;	    /* TRUE if we xlock'ed with an SC, FALSE if we used a SW-PSE     */
extern int	xlock_pid;  /* Pid if the xlock-child process. Used only if SC_PSE == TRUE   */
extern char	*psepath;   /* Pathname of the PSE which was used to xlock	             */

/*
 *	Verifier's Information
 */

extern Certificate *verifierCertificate;  /* Certificate if the user who xlock'ed 
                                             (includes verifier's public key)                */
extern Certificates *verifierCertificates; /* generated from verifierCertificate             */
extern PKRoot       *verifierPKRoot;       /* generated from verifierCertificate             */

/*
 * 	Sign_verify produces a challenge message, signs it with the claimant's PSE,
 *	and verifies it using the verifier's user certificate which xlock got before
 *      the verifier was xlock'ed. If the verification succeeds, xlock disappears.
 *
 *	If anything fails, sign_verify returns -1. Otherwise, it returns 0.
 *	In case of an SC PSE, it kills the waiting xlock parent process with signal 9.
 */

int
sign_verify(pin)
char	*pin;
{

	int		 i,in, rc;
	PSESel  	 claimant_pse;
	UTCTime 	*utctime;
	OctetString      challenge;
	Signature        claimantSignature;
	char            *random, *currenttime;
	char             challenge_buf[64];

	claimantSignature.signAI = aux_cpy_AlgId(md5WithRsaEncryption);	/* default signature algorithm */

/*
 *	Generate challenge message
 */
								                 
	utctime = aux_current_UTCTime();
	currenttime = aux_readable_UTCTime(utctime);
	random = sec_random_str(16, (char *)0);

	strcpy(challenge_buf, currenttime);
	strcat(challenge_buf, random);

	free(currenttime);
	free(random);

	challenge.octets = challenge_buf;
	challenge.noctets = strlen(challenge.octets);


/*
 *      sign the challenge with the claimant's PSE
 */

#ifdef SCA
	SC_timer = 0;
#endif

	if ((rc = af_sign(&challenge, &claimantSignature, END)) != 0){
#ifdef SCA
		if(SC_PSE) sec_sc_eject(CURRENT_SCT);
#endif
		return(-1);
	}
	
	if(!(claimantSignature.signature.bits) || !(claimantSignature.signature.nbits)) {
#ifdef SCA
		if (SC_PSE) sec_sc_eject(CURRENT_SCT);
#endif
		return(-1);
	}


/*
 *	verify the claimant's signature with the verifier's certificate
 */

	if ((rc = af_verify(&challenge, &claimantSignature, END, verifierCertificates, (UTCTime * ) 0,
                             verifierPKRoot)) != 0) {
#ifdef SCA
		if(SC_PSE) sec_sc_eject(CURRENT_SCT);
#endif
		aux_free2_Signature(&claimantSignature);
		return(-1);
	}
	aux_free2_Signature(&claimantSignature);


	if(SC_PSE) kill(xlock_pid, 9);

	return(0);

}






