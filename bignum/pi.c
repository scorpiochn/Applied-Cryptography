#include <stdio.h>
#include "bignum.h"

void
pi_calc(talj1, kvot1, prod, sum)
bignum *talj1;
bignum *kvot1;
bignum *prod;
bignum *sum;
{
    bignum qfactor, talj, kvot, tmp1, tmp2, b2;

    big_create(&qfactor);
    big_create(&talj);
    big_create(&kvot);
    big_create(&tmp1);
    big_create(&tmp2);
    big_create(&b2);

    big_set_long((long)0, sum);
    big_set_long((long)1, &qfactor);
    big_mul(talj1, prod, &talj);
    big_set_big(kvot1, &kvot);
    big_set_long((long)2, &b2);

    do
    {
	big_floor(&talj, &kvot, &talj, &tmp1);
	big_floor(&talj, &qfactor, &tmp1, &tmp2);
	big_add(sum, &tmp1, sum);
	big_add(&qfactor, &b2, &qfactor);
    } while (!big_zerop(&talj));

    big_destroy(&b2);
    big_destroy(&tmp2);
    big_destroy(&tmp1);
    big_destroy(&kvot);
    big_destroy(&talj);
    big_destroy(&qfactor);
}

int
main(argc, argv)
int argc;
char *argv[];
{
    bignum prod, sum1, sum2, b10, x1, y1, x2, y2;
    int n;

    big_init_pkg();

    big_create(&prod);
    big_create(&b10);
    big_create(&sum1);
    big_create(&sum2);
    big_create(&x1);
    big_create(&y1);
    big_create(&x2);
    big_create(&y2);

    if ((argc < 2) || (sscanf(argv[1], "%d", &n) != 1))
    {
	printf("Number of digits: ");
	scanf("%d", &n);
    }

    big_set_long((long)10, &b10);
    big_expt(&b10, (unsigned long)n, &prod);

    big_set_long((long)-80, &x1);
    big_set_long((long)-25, &y1);
   
    pi_calc(&x1, &y1, &prod, &sum1);

    big_set_long((long)956, &x2);
    big_set_long((long)-57121, &y2);

    pi_calc(&x2, &y2, &prod, &sum2);

    big_add(&sum1, &sum2, &sum1);
    printf("pi = %s\n", big_string(&sum1, 10));

    big_destroy(&prod);
    big_destroy(&b10);
    big_destroy(&sum1);
    big_destroy(&sum2);
    big_destroy(&x1);
    big_destroy(&y1);
    big_destroy(&x2);
    big_destroy(&y2);

    big_release_pkg();

    exit(0);
    return 0;
}
