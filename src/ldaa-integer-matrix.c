#include "ldaa-integer-matrix.h"
#include "Tpm.h"
#include "ldaa-permutation.h"
#include "ldaa-params.h"
#include "ldaa-uniform-int.h"

void ldaa_integer_matrix_pext_permute(ldaa_integer_matrix_pext_t *this,
		    ldaa_permutation_perm_t *p)
{
    size_t i;

    UINT32 *v = p->v;
    UINT32 coeffs[(2*(1<<LDAA_LOG_W)-2)*LDAA_N];
    for (i = 0; i < (2*(1<<LDAA_LOG_W)-2)*LDAA_N; i++) {
        coeffs[v[i]] = this->coeffs[i];
    }

    for (i = 0; i < (2*(1<<LDAA_LOG_W)-2)*LDAA_N; i++) {
        this->coeffs[i] = coeffs[i];
    }
}

void ldaa_integer_matrix_append_rows_pext(ldaa_integer_matrix_t *this,
			ldaa_integer_matrix_pext_t *a)
{
  size_t i, j;

  for (i = LDAA_N; i < (LDAA_N + ((2*(1<<LDAA_LOG_W)-2)*LDAA_N)); i++) {
    for (j = 0; j < 1; j++) {
      this->coeffs[i + j] = a->coeffs[(i - LDAA_N) + j];
    }
  }
}

void ldaa_integer_matrix_sample_u(ldaa_integer_matrix_t *this)
{
  size_t i, j;

  for (i = 0; i < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; i++) {
    for (j = 0; j < 1; j++) {
      this->coeffs[i + j] = ldaa_uniform_int_sample(0, LDAA_Q);
    }
  }
}

void ldaa_integer_matrix_add(ldaa_integer_matrix_t *this,
		ldaa_integer_matrix_t *a,
		ldaa_integer_matrix_t *b)
{
  size_t i;

  for (i = 0; i < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; i++) {
    this->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    if (this->coeffs[i] >= LDAA_Q)
      this->coeffs[i] -= LDAA_Q;
  }
}
