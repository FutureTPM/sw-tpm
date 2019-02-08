#include "ldaa-polynomial-ntt.h"
#include "ldaa-polynomial.h"
#include <stddef.h>

void ldaa_poly_ntt_mul(ldaa_poly_ntt_t *this,
		ldaa_poly_ntt_t *a,
		ldaa_poly_ntt_t *b)
{
  size_t i;

  for (i = 0; i < LDAA_N; i++) {
    this->coeffs[i] = ldaa_reduce((UINT64)a->coeffs[i] * b->coeffs[i]);
  }
}

void ldaa_poly_ntt_add(ldaa_poly_ntt_t *this,
		ldaa_poly_ntt_t *a,
		ldaa_poly_ntt_t *b)
{
  size_t i;

  for (i = 0; i < LDAA_N; i++) {
    this->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    if (this->coeffs[i] >= LDAA_Q) {
      this->coeffs[i] -= LDAA_Q;
    }
  }
}

void ldaa_poly_ntt_from_canonical(ldaa_poly_ntt_t *this,
			   ldaa_poly_t *a)
{
  size_t i;

  for (i = 0; i < LDAA_N; i++) {
    this->coeffs[i] = a->coeffs[i];
  }

  ldaa_poly_ntt(this->coeffs);
}
