#ifndef LDAA_POLYNOMIAL_NTT_H
#define LDAA_POLYNOMIAL_NTT_H
#include "BaseTypes.h"
#include "ldaa-params.h"
#include "ldaa-polynomial.h"

typedef struct {
  UINT32 coeffs[LDAA_N];
} ldaa_poly_ntt_t;

void ldaa_poly_ntt_from_canonical(ldaa_poly_ntt_t *this, ldaa_poly_t *a);
void ldaa_poly_ntt_mul(ldaa_poly_ntt_t *this,
		ldaa_poly_ntt_t *a,
		ldaa_poly_ntt_t *b);
void ldaa_poly_ntt_add(ldaa_poly_ntt_t *this,
		ldaa_poly_ntt_t *a,
		ldaa_poly_ntt_t *b);

#endif
