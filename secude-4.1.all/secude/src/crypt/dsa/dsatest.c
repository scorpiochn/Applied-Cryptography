#include "arithmetic.h"
#include "dsa.h"
#include "../../include/af.h"
#include <stdio.h>
int println(a)
        L_NUMBER        a[];
{
	int n;
	for(n=0;n<=a[0];n++) {
		printf("%13u",a[n]);
		if(! n%8) printf("\n");
	}
 	printf("\n");

}

main(cnt, parm)
int	cnt;
char	**parm;
{
	OctetString mess,hash;
	char oct[64];

        L_NUMBER        a[MAXLGTH];
        L_NUMBER        b[MAXLGTH];
        L_NUMBER        c[MAXLGTH];
        L_NUMBER        d[MAXLGTH];
	int m;
	double *dou;
	int n=1;
	BitString  *skey, *pkey;
	BitString  sign;
	char	signbits[100];
	RC rc;
	sec_verbose = 0;
	sign.bits = signbits;

	mess.octets= (char*)malloc(1000);
	for(m=0;m<1000;m++) mess.octets[m] = m % 96 + ' ';
	mess.noctets=1000;
	hash.octets=oct;
	sha_hash(&mess,&hash,END);
	aux_fprint_OctetString(stderr, &hash);
	sec_dsa_predefined = 1;
	for(m=512; m<=1024;m+=64) dsa_gen_key(m, &skey, &pkey);
	dsa_get_key(skey, 1);
	dsa_sign(&hash,&sign);

	dsa_get_key(pkey, 1);
	rc = dsa_verify(&hash,&sign);

	printf("%d\n", rc);
	return;

	if(cnt>=2) {
	a[0] = atoi(parm[n++]);
	for (m=1; m<=a[0];m++) a[m] = atoi(parm[n++]);

	b[0] = atoi(parm[n++]);
	for (m=1; m<=b[0];m++) b[m] = atoi(parm[n++]);
	m=1;
	} else m=10;
for(n=0;n<m;n++){

	if(cnt<2) {
	rndm(566, a);
	rndm(879, b);
	}
	println(a);
	println(b);

/*	ln_ggt(a,b,c);
	printf(" ggt: ");
	println(c);
	div(a,c,d,d);
	
	printf(" testggt1: ");
	println(d);

	div(b,c,d,d);
	
	printf(" testggt2: ");
	println(d);

*/

	ln_inv(a,b,c);
	printf(" inv: ");
	println(c);
	mmult(a,c,d,b);
	printf(" testinv: ");
	println(d);


}
}
