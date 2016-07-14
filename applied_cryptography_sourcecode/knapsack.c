/*
  Author:  Pate Williams (c) 1997

  Solution of the subset problem using LLL
  reduction. See "Handbook of Applied
  Cryptography" by Alfred J. Menezes et al
  pages 120 - 121.
*/

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void system_error(char error_message[])
{
  printf("%s",error_message);
  exit(1);
}

double **allocate_real_matrix(long m, long n)
{
  long i;
  double **p = calloc(m, sizeof(double *));

  if (!p) system_error("Failure in allocate_real_matrix().");
  for (i = 0; i < m; i++){
    p[i]= calloc(n, sizeof(double));
	 if (!p[i]) system_error("Failure in allocate_real_matrix().");
  }
  return p;
}

double *allocate_real_vector(long n)
{
  double *p = calloc(n, sizeof(double));

  if (!p) system_error("Failure in allocate_real_vector().");
  return p;
}

void free_real_matrix(double **m, long n)
{
  long i;

  for (i = 0; i < n; i++) free(m[i]);
  free(m);
}

void free_real_vector(double *v)
{
  free(v);
}

double Scalar(long n, double *u, double *v)
{
  double sum = 0.0;
  long i;

  for (i = 0; i < n; i++) sum += u[i] * v[i];
  return sum;
}

void Reduce(long k, long l, long n, double **b, double **mu)
{
  long i, j, r = 0.5 + mu[k][l];

  if (fabs(mu[k][l]) > 0.5) {
    for (i = 0; i < n; i++) b[k][i] -= r * b[l][i];
    for (j = 0; j < l; j++) mu[k][j] -= r * mu[l][j];
    mu[k][l] -= r;
  }
}

int LLL(long n, double **b)
{
  /* Lattice reduction algorithm. */
  double *B = allocate_real_vector(n);
  double **bs = allocate_real_matrix(n, n);
  double **mu = allocate_real_matrix(n, n);
  double C, t, temp, x, y;
  long i, j, k, l;

  for (i = 0; i < n; i++) bs[0][i] = b[0][i];
  B[0] = Scalar(n, bs[0], bs[0]);
  for (i = 1; i < n; i++) {
    for (j = 0; j < n; j++) bs[i][j] = b[i][j];
    for (j = 0; j < i; j++) {
      mu[i][j] = Scalar(n, b[i], bs[j]) / B[j];
      for (k = 0; k < n; k++)
        bs[i][k] -= mu[i][j] * bs[j][k];
    }
    B[i] = Scalar(n, bs[i], bs[i]);
  }
  L3:
    k = 1;
  L4:
    l = k - 1;
    Reduce(k, l, n, b, mu);
    x = mu[k][l];
    y = 0.75 - x * x;
    if (B[k] < y * B[l]) {
      C = B[k] + x * x * B[l];
      mu[k][l] = x * B[l] / C;
      B[k] *= B[l] / C;
      B[l] = C;
      for (i = 0; i < n; i++) {
        temp = b[k][i];
        b[k][i] = b[l][i];
        b[l][i] = temp;
      }
      if (k > 1) {
        for (j = 0; j < k - 1; j++) {
          temp = mu[k][j];
          mu[k][j] = mu[l][j];
          mu[l][j] = temp;
        }
      }
      for (i = k + 1; i < n; i++) {
        t = mu[i][k];
        mu[i][k] = mu[i][l] - x * t;
        mu[i][l] = t + mu[k][l] * mu[i][k];
      }
      k = max(1, k - 1);
      goto L4;
    }
    for (l = k - 2; l >= 0; l--) Reduce(k, l, n, b, mu);
    k++;
    if (k < n) goto L4;
  free_real_matrix(bs, n);
  free_real_matrix(mu, n);
  free_real_vector(B);
  return 1;
}

int SubsetSum(long n, double s, double *a, double *x)
{
  long n1 = n + 1;
  double **b = allocate_real_matrix(n1, n1);
  double sum;
  long i, j, m = ceil(sqrt(n) / 2.0);

  for (i = 0; i < n1; i++) {
    if (i < n) {
      for (j = 0; j < n1; j++) b[i][j] = 0.0;
      b[i][i] = 1.0;
      b[i][n1 - 1] = m * a[i];
    }
    else {
      for (j = 0; j < n; j++) b[i][j] = 0.5;
      b[i][n1 - 1] = m * s;
    }
  }
  printf("the matrix to be reduced is:\n\n");
  for (i = 0; i < n1; i++) {
    for (j = 0; j < n1; j++)
      printf("%6.2f ", b[i][j]);
    printf("\n");
  }
  printf("\n");
  if (!LLL(n1, b)) {
    free_real_matrix(b, n1);
    return 0;
  }
  printf("the reduced matrix is:\n\n");
  for (i = 0; i < n1; i++) {
    for (j = 0; j < n1; j++)
      printf("%6.2f ", b[i][j]);
    printf("\n");
  }
  printf("\n");
  for (i = 0; i < n1; i++) {
    for (j = 0; j < n; j++) x[j] = b[i][j] + 0.5;
    sum = 0.0;
    for (j = 0; j < n; j++) sum += a[j] * x[j];
    if (sum == s) {
      free_real_matrix(b, n1);
      return 1;
    }
    for (j = 0; j < n; j++) x[j] = - b[i][j] + 0.5;
    sum = 0.0;
    for (j = 0; j < n; j++) sum += a[j] * x[j];
    if (sum == s) {
      free_real_matrix(b, n1);
      return 1;
    }
  }
  free_real_matrix(b, n1);
  return 0;
}

int main(void)
{
  long i, n = 8;
  double *a = allocate_real_vector(n);
  double *x = allocate_real_vector(n);
  double s;

  srand(time(NULL));
  printf("\n");
  for (i = 0; i < n; i++) a[i] = pow(2, i);
  s = a[rand() % n] + a[rand() % n];
  if (SubsetSum(n, s, a, x)) {
    printf("sum: %f\n\n", s);
    printf("x[i]\t\ta[i]\n\n");
    for (i = 0; i < n; i++)
      printf("%f\t%f\n", x[i], a[i]);
  }
  else printf("subset sum has no solution\n");
  free_real_vector(a);
  free_real_vector(x);
  return 0;
}
