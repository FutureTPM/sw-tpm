#ifndef LDAA_POLYNOMIAL_MIX_H
#define LDAA_POLYNOMIAL_MIX_H
#include "ldaa-polynomial-ntt.h"
#include "ldaa-polynomial.h"

void ldaa_poly_mul_ntt_1(ldaa_poly_t *this, ldaa_poly_ntt_t *a, ldaa_poly_t *ba, uint64_t n, uint64_t q);
void ldaa_poly_from_ntt(ldaa_poly_t *this, ldaa_poly_ntt_t *a, uint64_t n, uint64_t q);

#endif
