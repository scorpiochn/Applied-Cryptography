#include <stdio.h>

extern void exit();
extern int fclose();

#define TRUE (1 == 1)
#define FALSE (1 != 1)

struct description_int
{
    int int_size;
    char int_name[20];
};
struct description_int int_descrs[] =
{
#ifdef LONGLONG
    sizeof(unsigned long long), "unsigned long long",
#endif
    sizeof(unsigned long),	"unsigned long",
    sizeof(unsigned int), 	"unsigned int",
    sizeof(unsigned short),	"unsigned short",
    sizeof(unsigned char),	"unsigned char"
};
int size_count = sizeof(int_descrs) / sizeof(struct description_int);

struct trnc_data
{
    long a, b, q, r;
};
struct trnc_data trunc_tbl[] =
{
     13,  4,  3,  1,
     13, -4, -3,  1,
    -13,  4, -3, -1,
    -13, -4,  3, -1,
     15,  4,  3,  3,
     15, -4, -3,  3,
    -15,  4, -3, -3,
    -15, -4,  3, -3
};
int size_trunc_tbl = sizeof(trunc_tbl) / sizeof(struct trnc_data);

struct rand_data
{
    unsigned long dig_size, a1, c1, a2, c2;
};
struct rand_data rand_tbl[] =
{
    {  8,   197,   11,    37,    37 },
    { 16,   805,  345,   925,   767 },
    { 18, 13405, 4801, 20325, 19777 },
    { 32, 13405, 4801, 20325, 19777 }
};
int size_rand_tbl = sizeof(rand_tbl) / sizeof(struct rand_data);

int digit_bits;

int
div_trunc_p()
{
    int i;

    for (i = 0; i < size_trunc_tbl; i++)
    {
	if (trunc_tbl[i].a / trunc_tbl[i].b != trunc_tbl[i].q)
	{
	    printf("%ld / %ld = %ld, should have been %ld\n",
		   trunc_tbl[i].a,
		   trunc_tbl[i].b,
		   trunc_tbl[i].a / trunc_tbl[i].b,
		   trunc_tbl[i].q);
	    printf("when division truncates towards zero.\n");
	    return FALSE;
	}
	if (trunc_tbl[i].a % trunc_tbl[i].b != trunc_tbl[i].r)
	{
	    printf("%ld % %ld = %ld, should have been %ld\n",
		   trunc_tbl[i].a,
		   trunc_tbl[i].b,
		   trunc_tbl[i].a % trunc_tbl[i].b,
		   trunc_tbl[i].r);
	    printf("when division truncates towards zero.\n");
	    printf("Here a != q*b + r.  Very strange!\n");
	    return FALSE;
	}
    }
    return TRUE;
}

int
charsize()
{
    int i = 0;
    unsigned char ch = 1;
    unsigned char oldch = 0;

    while (ch > oldch)
    {
	oldch = ch;
	ch <<= 1;
	i++;
    }
    return i;
}

void
RandDefsOut(fpOut, dig_size)
FILE *fpOut;
int dig_size;
{
    int i = 0;

    while ((i < size_rand_tbl) && (dig_size != rand_tbl[i].dig_size))
    {
	i++;
    }
    if (i == size_rand_tbl)
    {
	if (dig_size < rand_tbl[0].dig_size)
	{
	    printf("Digit size %d too small.\n", dig_size);
	    exit(10);
	}
	while (rand_tbl[--i].dig_size > dig_size)
	{
	    /* Count down `i' */
	}
    }
    fprintf(fpOut, "\n#define BIG_RAND_A1 %d\n", rand_tbl[i].a1);
    fprintf(fpOut,   "#define BIG_RAND_C1 %d\n", rand_tbl[i].c1);
    fprintf(fpOut,   "#define BIG_RAND_A2 %d\n", rand_tbl[i].a2);
    fprintf(fpOut,   "#define BIG_RAND_C2 %d\n", rand_tbl[i].c2);
}

int
main()
{
    int i, j, ints_found = FALSE, char_bits;
    FILE *fpOut;

    if (!div_trunc_p())
    {
	printf("Can't do division on this machine!\n");
	exit(10);
    }

    if ((fpOut = fopen("internal.h", "w")) == NULL)
    {
	printf("Could not create \"internal.h\".\n");
	exit(10);
    }

    fprintf(fpOut, "#ifndef _BIGNUM_INTERNAL_H_\n");
    fprintf(fpOut, "#define _BIGNUM_INTERNAL_H_\n\n");

    char_bits = charsize();

    for (i = 0; (i < size_count - 1) && !ints_found; i++)
    {
	for (j = i + 1; (j < size_count) && !ints_found; j++)
	{
	    if (int_descrs[i].int_size >= 2 * int_descrs[j].int_size)
	    {
		fprintf(fpOut,
			"#define BIGNUM_DIGIT %s\n",
			int_descrs[j].int_name);
		fprintf(fpOut,
			"#define BIGNUM_TWO_DIGITS %s\n\n",
			int_descrs[i].int_name);
		ints_found = TRUE;
	    }
	}
    }

    if (!ints_found)
    {
	fprintf(stderr, "Strange, no integer type was two times bigger ");
	fprintf(stderr, "than another integer type.\n");
	fprintf(stderr, "Can't create header file.\nExiting.\n");
	exit(10);
    }

    i--;
    j--;

    digit_bits = char_bits * int_descrs[j].int_size;
    fprintf(fpOut, "#define BIG_CHARBITS %d\n", char_bits);
    fprintf(fpOut, "#define BIGNUM_DIGIT_BITS %d\n", digit_bits);
    fprintf(fpOut, "#define BIGNUM_TWO_DIGITS_BITS %d\n\n",
	    char_bits * int_descrs[i].int_size);

    fprintf(fpOut, "struct big_struct\n{\n    int sign;\n");
    fprintf(fpOut, "    unsigned long dgs_alloc;\n");
    fprintf(fpOut, "    unsigned long dgs_used;\n");
    fprintf(fpOut, "    BIGNUM_DIGIT *dp;\n};\n");

    RandDefsOut(fpOut, char_bits * int_descrs[j].int_size);

    if (sizeof(long) == sizeof(int))
    {
	fprintf(fpOut, "\n#define MEMCPY_LONG_COUNTER\n");
    }

#ifdef BIG_SHORT_NAMES
    fprintf(fpOut, "\n#define BIG_SHORT_NAMES\n");
#endif

    fprintf(fpOut, "\n#endif\n");
    fclose(fpOut);
    exit(0);
    return 0;			/* Keep gcc from complaining */
}		
