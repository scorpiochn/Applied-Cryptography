#include <stdio.h>
#include "bignum.h"

extern void exit();
extern int fflush();
extern int strcmp();

struct qr_struct
{
    char *q, *r;
};

struct qr_arr
{
    struct qr_struct qr[4];
};

struct div_tbl
{
    char *a, *b;
    struct qr_arr trunc_vals;
    struct qr_arr floor_vals;
    struct qr_arr ceil_vals;
    struct qr_arr round_vals;
};

struct div_tbl div_t1 =
{
    "15", "4",
     "3",  "3", "-3",  "3", "-3", "-3", "3", "-3",
     "3",  "3", "-4", "-1", "-4",  "1", "3", "-3",
     "4", "-1", "-3",  "3", "-3", "-3", "4",  "1",
     "4", "-1", "-4", "-1", "-4",  "1", "4",  "1"
};

struct div_tbl div_t2 =
{
    "13", "4",
     "3",  "1", "-3",  "1", "-3", "-1", "3", "-1",
     "3",  "1", "-4", "-3", "-4",  "3", "3", "-1",
     "4", "-3", "-3",  "1", "-3", "-1", "4",  "3",
     "3",  "1", "-3",  "1", "-3", "-1", "3", "-1"
};

struct div_tbl div_t3 =
{
     "3", "4",
     "0",  "3", "0",  "3", "0", "-3", "0", "-3",
     "0",  "3", "-1", "-1", "-1",  "1", "0", "-3",
     "1", "-1", "0",  "3", "0", "-3", "1",  "1",
     "1", "-1", "-1", "-1", "-1",  "1", "1",  "1"
};

struct div_tbl div_t4 =
{
     "1", "4",
     "0",  "1", "0",  "1", "0", "-1", "0", "-1",
     "0",  "1", "-1", "-3", "-1",  "3", "0", "-1",
     "1", "-3", "0",  "1", "0", "-1", "1",  "3",
     "0",  "1", "0",  "1", "0", "-1", "0", "-1"
};

struct struct_exptmod
{
    char *a, *z, *n, *x;
};

struct struct_exptmod exptmod_tbl[] =
{
    { "3", "5", "7", "5" },
    { "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "0" },
    { "283395980622834004688895000843405174774912791074404383884800541068631020189087447019470810805905868916802106437778130955",
      "7157412354671606079596556534200756195331778638320479322370266215801268111984956994162386762949758472",
      "940230711174892668395661854248424627649570719747278791674749103769025903998812837646712260756442342942254645962006367181510572769555890244950751985773",
	"217861016864404044984236457445890664214306588714800792464139323092206342638072482120836594088547962710214505432559729364779671321959421617130932823235"},
    { "13", "15", "17", "4" },
    { "314", "719", "581", "510" },
    { "70001", "70003", "70500", "28001" },
    { "5000000001", "5000000003", "5000000007", "4287285222" }, 
      { "94501169810786918656",
      "71421854567728744621441",
      "12984016512127375695841",
      "9480694975759097571797" },
    { "283395980622834004688895000843405174774912791074404383884800541068631020189087447019470810805905868916802106437778130955",
      "7157412354671606079596556534200756195331778638320479322370266215801268111984956994162386762949758472",
      "940230711174892668395661854248424627649570719747278791674749103769025903998812837646712260756442342942254645962006367181510572769555890244950751985773",
      "217861016864404044984236457445890664214306588714800792464139323092206342638072482120836594088547962710214505432559729364779671321959421617130932823235" }

};

int size_exptmod_tbl = sizeof(exptmod_tbl) / sizeof(struct struct_exptmod);

struct gcd_struct
{
    char *a, *b, *g;
};

struct gcd_struct gcd_tbl[] =
{
    { "123456789", "345", "3" },
    { "345", "123456789", "3" },
    { "10", "0", "10" },
    { "0", "10", "10" },
    { "2523533737", "855322739", "1" },
    { "855322739", "2523533737", "1" },
    { "101611479673163974026724715741235467160607959655653420075620",
      "533177863832047932237026621580126811198495699416238676294977",
      "1" },
    { "30729415811", "323233683197", "31071199" }
};

int size_gcd_tbl = sizeof(gcd_tbl) / sizeof(struct gcd_struct);

/* ----------------------------------------------------------------------
 * Testing functions
 */

void
t_repr(str, base, num)
char *str;
int base;
bignum *num;
{
    char *str_num;

    str_num = big_string(num, base);
    if (strcmp(str, str_num) != 0)
    {
	printf("Error in t_repr()!\n");
	printf("Expected %s\nbut got %s\n", str, str_num);
	exit(10);
    }
}

void
t_alg_div2(a, b, q, r, qr_ptr, func_name)
bignum *a;
bignum *b;
bignum *q;
bignum *r;
struct qr_struct *qr_ptr;
char *func_name;
{
    if (strcmp(big_string(q, 10), qr_ptr->q) != 0)
    {
	printf("\tError when dividing:\n");
	printf("\t%s(%s, ", func_name, big_string(a, 10));
	printf("%s) -> q = ", big_string(b, 10));
	printf("%s\n", big_string(q, 10));
	printf("\tExpected %s\n", qr_ptr->q);
	exit(10);
    }
    if (strcmp(big_string(r, 10), qr_ptr->r) != 0)
    {
	printf("\tError when dividing:\n");
	printf("\t%s(%s, ", func_name, big_string(a, 10));
	printf("%s) -> r = ", big_string(b, 10));
	printf("%s\n", big_string(r, 10));
	printf("\tExpected %s\n", qr_ptr->r);
	exit(10);
    }
}

void
t_div_alg(a, b, qr_vals, div_func, func_name)
bignum *a;
bignum *b;
struct qr_arr *qr_vals;
int (* div_func)();
char *func_name;
{
    bignum q, r;

    big_create(&q);
    big_create(&r);
    
    div_func(a, b, &q, &r);
    t_alg_div2(a, b, &q, &r, &qr_vals->qr[0], func_name);

    big_negate(b, b);
    div_func(a, b, &q, &r);
    t_alg_div2(a, b, &q, &r, &qr_vals->qr[1], func_name);

    big_negate(a, a);
    big_negate(b, b);
    div_func(a, b, &q, &r);
    t_alg_div2(a, b, &q, &r, &qr_vals->qr[2], func_name);
    
    big_negate(b, b);
    div_func(a, b, &q, &r);
    t_alg_div2(a, b, &q, &r, &qr_vals->qr[3], func_name);

    big_destroy(&r);
    big_destroy(&q);
}

void
t_div2(tbl)
struct div_tbl *tbl;
{
    bignum a, b, old_a, old_b;

    big_create(&a);
    big_create(&b);
    big_create(&old_a);
    big_create(&old_b);

    big_set_string(tbl->a, 10, &a);
    t_repr(tbl->a, 10, &a);
    big_set_big(&a, &old_a);
    big_set_string(tbl->b, 10, &b);
    t_repr(tbl->b, 10, &b);
    big_set_big(&b, &old_b);

#if 0
    printf("Testing division with a = %s, ", big_string(&a, 10));
    printf("and b = %s\n", big_string(&b, 10));
    fflush(stdout);
#endif

    printf("1, ");
    fflush(stdout);
    t_div_alg(&a, &b, &tbl->trunc_vals, big_trunc, "trunc");
    big_set_big(&old_a, &a);
    big_set_big(&old_b, &b);
    printf("2, ");
    fflush(stdout);
    t_div_alg(&a, &b, &tbl->floor_vals, big_floor, "floor");
    big_set_big(&old_a, &a);
    big_set_big(&old_b, &b);
    printf("3, ");
    fflush(stdout);
    t_div_alg(&a, &b, &tbl->ceil_vals, big_ceil,   "ceil");
    big_set_big(&old_a, &a);
    big_set_big(&old_b, &b);
    printf("4 ");
    fflush(stdout);
    t_div_alg(&a, &b, &tbl->round_vals, big_round, "round");
    printf("\n");
    fflush(stdout);

    big_destroy(&old_b);
    big_destroy(&old_a);
    big_destroy(&b);
    big_destroy(&a);
}

void
t_div3(a_str, b_str, q_str, r_str)
char *a_str;
char *b_str;
char *q_str;
char *r_str;
{
    bignum a, b, q, r;

    big_create(&a);
    big_create(&b);
    big_create(&q);
    big_create(&r);

    big_set_string(a_str, 10, &a);
    t_repr(a_str, 10, &a);
    big_set_string(b_str, 10, &b);
    t_repr(b_str, 10, &b);
    big_trunc(&a, &b, &q, &r);
    if (strcmp(q_str, big_string(&q, 10)) != 0)
    {
	printf("trunc(%s, ", big_string(&a, 10));
	printf("%s) -> ", big_string(&b, 10));
	printf("q = %s, ", big_string(&q, 10));
	printf("Expected %s\n", q_str);
	exit(10);
    }
    if (strcmp(r_str, big_string(&r, 10)) != 0)
    {
	printf("trunc(%s, ", big_string(&a, 10));
	printf("%s) -> ", big_string(&b, 10));
	printf("r = %s, ", big_string(&r, 10));
	printf("Expected %s\n", r_str);
	exit(10);
    }

    big_destroy(&a);
    big_destroy(&b);
    big_destroy(&q);
    big_destroy(&r);
}    

void
t_div()
{
    printf("a: ");
    t_div2(&div_t1);
    printf("b: ");
    t_div2(&div_t2);
    printf("c: ");
    t_div2(&div_t3);
    printf("d: ");
    t_div2(&div_t4);

    t_div3("16823725525212291009", "5000000007",
	      "3364745100", "1659075309");
}

void
t_expt()
{
    bignum a, z, n, x;
    int i;

    big_create(&a);
    big_create(&z);
    big_create(&n);
    big_create(&x);

    for (i = 0; i < size_exptmod_tbl; i++)
    {
	big_set_string(exptmod_tbl[i].a, 10, &a);
	t_repr(exptmod_tbl[i].a, 10, &a);
	big_set_string(exptmod_tbl[i].z, 10, &z);
	t_repr(exptmod_tbl[i].z, 10, &z);
	big_set_string(exptmod_tbl[i].n, 10, &n);
	t_repr(exptmod_tbl[i].n, 10, &n);
	big_exptmod(&a, &z, &n, &x);
	if (strcmp(big_string(&x, 10), exptmod_tbl[i].x) != 0)
	{
	    printf("\nIn exptmod test %d:\n\n", i);
	    printf("\texptmod(%s, ", big_string(&a, 10));
	    printf("%s, ", big_string(&z, 10));
	    printf("%s) = ", big_string(&n, 10));
	    printf("%s\n", big_string(&x, 10));
	    printf("\tExpected %s\n", exptmod_tbl[i].x);
	    exit(10);
	}
	printf("%d", i);
	if (i < size_exptmod_tbl - 1)
	{
	    printf(", ");
	}
	fflush(stdout);
    }

    printf("\n");
    fflush(stdout);

    big_destroy(&x);
    big_destroy(&n);
    big_destroy(&z);
    big_destroy(&a);
}

void
t_gcd()
{
    bignum a, b, g;
    int i;

    big_create(&a);
    big_create(&b);
    big_create(&g);

    for (i = 0; i < size_gcd_tbl; i++)
    {
	big_set_string(gcd_tbl[i].a, 10, &a);
	big_set_string(gcd_tbl[i].b, 10, &b);
	big_gcd(&a, &b, &g);
	if (strcmp(big_string(&g, 10), gcd_tbl[i].g) != 0)
	{
	    printf("\nIn gcd test %d:\n\n", i);
	    printf("\tgcd(%s, ", big_string(&a, 10));
	    printf("%s) = ", big_string(&b, 10));
	    printf("%s\n", big_string(&g, 10));
	    printf("\tExpected %s\n", gcd_tbl[i].g);
	    exit(10);
	}
	printf("%d", i);
	if (i < size_gcd_tbl - 1)
	{
	    printf(", ");
	}
	fflush(stdout);
    }

    printf("\n");
    fflush(stdout);

    big_destroy(&g);
    big_destroy(&b);
    big_destroy(&a);
}

int
main()
{
    big_init_pkg();

    printf("Doing division tests...\n");
    fflush(stdout);
    t_div();
    printf("passed.\n");
    
    printf("Doing gcd tests...\n");
    fflush(stdout);
    t_gcd();
    printf("passed.\n");

    printf("Doing exponentiation tests (hang on - they take a while)...\n");
    fflush(stdout);
    t_expt();
    printf("passed.\n");

    big_release_pkg();

    exit(0);
    return 0;			/* Keep gcc from complaining */
}
