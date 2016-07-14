/*
  Author:  Pate Williams (c) 1997

  2.143 Algorithm Repeated sqaure-and-mutiply
  algorithm for exponentiation in Zn
  See "Handbook of Applied Cryptography" by
  Alfred J. Menezes et al page 71.
*/

#include <stdio.h>

#define BITS_PER_LONG 32l
#define DEBUG

long long_to_binary(long K, long *k)
{
  int found = 0;
  long a = K, i, l = 0, length;

  while (!found && l < BITS_PER_LONG) {
    found = ((a & 0x80000000l) >> 31) == 1;
    if (!found) a <<= 1, l++;
  }
  length = BITS_PER_LONG - l;
  for (i = 0; i < length; i++)
    k[i] = K & 1, K >>= 1;
  return length;
}

long powmod(long a, long K, long n)
{
  long A = a, b = 1, i, k[32];
  long t = long_to_binary(K, k);

  if (K == 0) return b;
  if (k[0] == 1) b = a;
  #ifdef DEBUG
  printf("-------------\n");
  printf("i k   A    B \n");
  printf("-------------\n");
  printf("%ld %ld %4ld %4ld\n", i = 0, k[i], A, b);
  #endif
  for (i = 1; i < t; i++) {
    A = (A * A) % n;
    if (k[i]) b = (A * b) % n;
    #ifdef DEBUG
    printf("%ld %ld %4ld %4ld\n", i, k[i], A, b);
    #endif
  }
  #ifdef DEBUG
  printf("-------------\n");
  #endif
  return b;
}

int main(void)
{
  long a = 5, K = 596, n = 1234;

  powmod(a, K, n);
  return 0;
}